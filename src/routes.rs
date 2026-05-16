use axum::{extract::State, response::Html, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};

use crate::goodwe::{self, TokenData, SESSION_EXPIRED};

// ---------------------------------------------------------------------------
// Shared application state  (stateless — session lives in the client cookie)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            )
            .build()
            .expect("build HTTP client");
        Self { client }
    }
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

const COOKIE_NAME: &str = "gw_session";

#[derive(Serialize, Deserialize)]
struct SessionCookie {
    token_json: String,
    username: String,
}

fn read_session(jar: &CookieJar) -> Option<SessionCookie> {
    jar.get(COOKIE_NAME)
        .and_then(|c| serde_json::from_str(c.value()).ok())
}

fn make_cookie(sc: &SessionCookie) -> Cookie<'static> {
    let value = serde_json::to_string(sc).unwrap();
    let mut c = Cookie::new(COOKIE_NAME, value);
    c.set_http_only(true);
    c.set_path("/");
    c
}

fn removal_cookie() -> Cookie<'static> {
    let mut c = Cookie::new(COOKIE_NAME, "");
    c.set_path("/");
    c
}

// ---------------------------------------------------------------------------
// GET /
// ---------------------------------------------------------------------------

pub async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

// ---------------------------------------------------------------------------
// GET /api/status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(untagged)]
pub enum StatusResponse {
    LoggedIn  { logged_in: bool, username: String },
    LoggedOut { logged_in: bool },
}

pub async fn status(jar: CookieJar) -> Json<StatusResponse> {
    match read_session(&jar) {
        Some(s) => Json(StatusResponse::LoggedIn { logged_in: true, username: s.username }),
        None    => Json(StatusResponse::LoggedOut { logged_in: false }),
    }
}

// ---------------------------------------------------------------------------
// POST /api/login
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Ok  { ok: bool, username: String },
    Err { ok: bool, error: String },
}

pub async fn login(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> (CookieJar, Json<LoginResponse>) {
    tracing::info!(username = %req.username, "Login request");

    match goodwe::do_login(&state.client, &req.username, &req.password).await {
        Ok((_, token_json)) => {
            let sc = SessionCookie { token_json, username: req.username.clone() };
            let jar = jar.add(make_cookie(&sc));
            (jar, Json(LoginResponse::Ok { ok: true, username: req.username }))
        }
        Err(e) => {
            tracing::error!("Login failed: {e:#}");
            (jar, Json(LoginResponse::Err { ok: false, error: format!("{e:#}") }))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/logout
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LogoutResponse {
    pub ok: bool,
}

pub async fn logout(jar: CookieJar) -> (CookieJar, Json<LogoutResponse>) {
    let jar = jar.remove(removal_cookie());
    tracing::info!("Session cookie cleared");
    (jar, Json(LogoutResponse { ok: true }))
}

// ---------------------------------------------------------------------------
// POST /api/fetch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FetchRequest {
    pub year: i32,
    pub month: u32,
    pub device_sn: String,
}

#[derive(Serialize)]
pub struct RecordJson {
    session: usize,
    start: String,
    end: String,
    duration_min: u64,
    total_kwh: f64,
    green_kwh: f64,
    import_kwh: f64,
    range_km: f64,
    end_cause: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum FetchResponse {
    Ok {
        ok: bool,
        records: Vec<RecordJson>,
        total_green_kwh: f64,
        total_import_kwh: f64,
    },
    Err {
        ok: bool,
        error: String,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        session_expired: bool,
    },
}

pub async fn fetch_records(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(req): Json<FetchRequest>,
) -> (CookieJar, Json<FetchResponse>) {
    let Some(sc) = read_session(&jar) else {
        return (jar, Json(FetchResponse::Err {
            ok: false,
            error: "Not signed in.".into(),
            session_expired: true,
        }));
    };

    let token: TokenData = match serde_json::from_str(&sc.token_json) {
        Ok(t) => t,
        Err(e) => return (jar, Json(FetchResponse::Err {
            ok: false,
            error: format!("Corrupt session cookie: {e}"),
            session_expired: true,
        })),
    };

    tracing::info!(year = req.year, month = req.month, "Fetch request");

    match goodwe::do_fetch(
        &state.client,
        &token,
        &sc.token_json,
        req.year,
        req.month,
        &req.device_sn,
    )
    .await
    {
        Ok(result) => (jar, Json(FetchResponse::Ok {
            ok: true,
            records: result
                .records
                .into_iter()
                .map(|r| RecordJson {
                    session:      r.session,
                    start:        r.start,
                    end:          r.end,
                    duration_min: r.duration_min,
                    total_kwh:    r.total_kwh,
                    green_kwh:    r.green_kwh,
                    import_kwh:   r.import_kwh,
                    range_km:     r.range_km,
                    end_cause:    r.end_cause,
                })
                .collect(),
            total_green_kwh: result.total_green_kwh,
            total_import_kwh: result.total_import_kwh,
        })),
        Err(e) if e.to_string() == SESSION_EXPIRED => {
            tracing::warn!("Session expired, clearing cookie");
            let jar = jar.remove(removal_cookie());
            (jar, Json(FetchResponse::Err {
                ok: false,
                error: "Session expired. Please sign in again.".into(),
                session_expired: true,
            }))
        }
        Err(e) => {
            tracing::error!("Fetch failed: {e:#}");
            (jar, Json(FetchResponse::Err {
                ok: false,
                error: format!("{e:#}"),
                session_expired: false,
            }))
        }
    }
}
