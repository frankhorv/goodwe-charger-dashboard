use anyhow::{anyhow, Context, Result};
use chrono::Datelike as _;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Default, Clone)]
pub struct TokenData {
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub token: String,
    // API returns timestamp as a string (e.g. "1778955297376").
    #[serde(default, deserialize_with = "de_string_or_i64")]
    pub timestamp: i64,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub region: String,
}

fn de_string_or_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    use serde::Deserialize as _;
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Number(n) => Ok(n.as_i64().unwrap_or(0)),
        serde_json::Value::String(s) => s.parse().map_err(serde::de::Error::custom),
        _ => Ok(0),
    }
}

pub struct FetchResult {
    pub records: Vec<Record>,
    pub total_green_kwh: f64,
    pub total_import_kwh: f64,
}

pub struct Record {
    pub session: usize,
    pub start: String,
    pub end: String,
    pub duration_min: u64,
    pub total_kwh: f64,
    pub green_kwh: f64,
    pub import_kwh: f64,
    pub range_km: f64,
    pub end_cause: String,
}

/// Sentinel string returned (as an anyhow error) when the API says the
/// session token is no longer valid (code C0602 / C0607).
pub const SESSION_EXPIRED: &str = "SESSION_EXPIRED";

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// x-signature = Base64(SHA256("timestamp@uid@token") + "@" + timestamp)
///
/// Formula reverse-engineered from `encodeSignature` in the GoodWe SEMS Plus
/// JS bundle (index_main.js) and verified against mitmproxy captures.
fn compute_signature(uid: &str, token: &str, ts: u64) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(format!("{ts}@{uid}@{token}").as_bytes()));
    STANDARD.encode(format!("{hash}@{ts}"))
}

/// Password encoding: Base64(hex(MD5(password)))
fn hash_password(password: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(format!("{:x}", md5::compute(password.as_bytes())).as_bytes())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn json_f64(v: &serde_json::Value) -> f64 {
    match v {
        serde_json::Value::Number(n) => n.as_f64().unwrap_or(0.0),
        serde_json::Value::String(s) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn common_headers<'a>(
    rb: reqwest::RequestBuilder,
    token_json: &'a str,
    uid: &'a str,
    token: &'a str,
    language: &'a str,
) -> reqwest::RequestBuilder {
    let ts = now_ms();
    let sig = compute_signature(uid, token, ts);
    rb.header("accept", "application/json, text/plain, */*")
        .header("content-type", "application/json")
        .header("token", token_json)
        .header("x-signature", sig)
        .header("currentlang", language)
        .header("neutral", "0")
        .header("access-control-allow-origin", "*")
        .header("origin", "https://semsplus.goodwe.com")
        .header("referer", "https://semsplus.goodwe.com/")
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

const LOGIN_URL: &str =
    "https://eu-gateway.semsportal.com/web/sems/sems-user/api/v1/auth/cross-login";

/// Authenticate with GoodWe. Returns the `TokenData` and its JSON string,
/// both of which are needed for subsequent authenticated requests.
pub async fn do_login(
    client: &reqwest::Client,
    username: &str,
    password: &str,
) -> Result<(TokenData, String)> {
    let default_json =
        r#"{"uid":"","timestamp":0,"token":"","client":"semsPlusWeb","version":"","language":"en"}"#;

    let resp: serde_json::Value = common_headers(
        client.post(LOGIN_URL),
        default_json,
        "",
        "",
        "en",
    )
    .json(&serde_json::json!({
        "account": username,
        "pwd": hash_password(password),
    }))
    .send()
    .await
    .context("Login request failed")?
    .json()
    .await
    .context("Failed to parse login response")?;

    tracing::debug!("Login response: {resp}");

    let code = resp["code"].as_str().unwrap_or("");
    if code != "00000" {
        return Err(anyhow!(
            "Login failed ({}): {}",
            code,
            resp["description"].as_str().unwrap_or("unknown error")
        ));
    }

    let mut map = resp["data"]
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("Login response missing 'data'"))?;

    map.entry("client")
        .or_insert_with(|| serde_json::Value::String("semsPlusWeb".into()));
    map.entry("language")
        .or_insert_with(|| serde_json::Value::String("en".into()));
    if map.get("api").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
        map.insert(
            "api".into(),
            serde_json::Value::String(
                "https://eu-gateway.semsportal.com/web/sems".into(),
            ),
        );
    }

    let token_json = serde_json::to_string(&map).context("Serialize token")?;
    let token: TokenData =
        serde_json::from_value(serde_json::Value::Object(map)).context("Parse token")?;

    tracing::info!(uid = %token.uid, "Login successful");
    Ok((token, token_json))
}

// ---------------------------------------------------------------------------
// Fetch charging records
// ---------------------------------------------------------------------------

const CHARGE_LOG_URL: &str =
    "https://eu-gateway.semsportal.com/web/sems/sems-plant/api/v1/chargePile/queryChargeLogList";

/// Fetch charging records for a given month using an existing session token.
///
/// Returns `Err(anyhow!(SESSION_EXPIRED))` when the server reports an expired
/// session (C0602 / C0607), so the caller can clear state and prompt re-login.
pub async fn do_fetch(
    client: &reqwest::Client,
    token: &TokenData,
    token_json: &str,
    year: i32,
    month: u32,
    device_sn: &str,
) -> Result<FetchResult> {
    let last_day = chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
        .or_else(|| chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1))
        .ok_or_else(|| anyhow!("Invalid year/month"))?
        .pred_opt()
        .ok_or_else(|| anyhow!("Date arithmetic error"))?
        .day();

    let start_time = format!("{year}-{month:02}-01 00:00:00");
    let end_time = format!("{year}-{month:02}-{last_day:02} 23:59:59");

    let mut records: Vec<Record> = Vec::new();
    let mut page: u64 = 1;

    loop {
        let resp: serde_json::Value = common_headers(
            client.post(CHARGE_LOG_URL),
            token_json,
            &token.uid,
            &token.token,
            &token.language,
        )
        .json(&serde_json::json!({
            "sn":        device_sn,
            "startTime": start_time,
            "endTime":   end_time,
            "pageNum":   page,
            "pageSize":  100,
        }))
        .send()
        .await
        .context("Charge log request failed")?
        .json()
        .await
        .context("Failed to parse charge log response")?;

        let code = resp["code"].as_str().unwrap_or("");
        if code == "C0602" || code == "C0607" {
            return Err(anyhow!(SESSION_EXPIRED));
        }
        if code != "00000" {
            return Err(anyhow!(
                "API error ({}): {}",
                code,
                resp["description"].as_str().unwrap_or("unknown")
            ));
        }

        let data = &resp["data"];
        let entries = data["dataList"]
            .as_array()
            .ok_or_else(|| anyhow!("API response missing 'dataList'"))?;

        if entries.is_empty() {
            break;
        }

        for entry in entries {
            let session = records.len() + 1;
            records.push(Record {
                session,
                start:        entry["chargeStartTime"].as_str().unwrap_or("").to_owned(),
                end:          entry["chargeEndTime"].as_str().unwrap_or("").to_owned(),
                duration_min: entry["chargeTimeLength"].as_u64().unwrap_or(0),
                total_kwh:    json_f64(&entry["currentChargeQuantity"]),
                green_kwh:    json_f64(&entry["greenElec"]),
                import_kwh:   json_f64(&entry["purElec"]),
                range_km:     json_f64(&entry["mileage"]),
                end_cause:    entry["chargeEndCause"].as_str().unwrap_or("").to_owned(),
            });
        }

        let total = data["total"].as_u64().unwrap_or(0);
        tracing::info!(page, fetched = records.len(), total, "Page fetched");

        if records.len() as u64 >= total {
            break;
        }
        page += 1;
    }

    let total_green: f64 = records.iter().map(|r| r.green_kwh).sum();
    let total_import: f64 = records.iter().map(|r| r.import_kwh).sum();

    tracing::info!(
        sessions = records.len(),
        green_kwh = total_green,
        import_kwh = total_import,
        "Fetch complete"
    );

    Ok(FetchResult { records, total_green_kwh: total_green, total_import_kwh: total_import })
}
