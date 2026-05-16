mod goodwe;
mod routes;

use axum::{routing::{get, post}, Router};
use routes::AppState;

const PORT: u16 = 8787;

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "goodwe_web=debug".parse().unwrap()),
        )
        .init();

    let state = AppState::new();

    let app = Router::new()
        .route("/",            get(routes::index))
        .route("/api/status",  get(routes::status))
        .route("/api/login",   post(routes::login))
        .route("/api/logout",  post(routes::logout))
        .route("/api/fetch",   post(routes::fetch_records))
        .with_state(state);

    let addr = format!("127.0.0.1:{PORT}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind {addr}: {e}"));

    let url = format!("http://{addr}");
    println!("Listening on {url}");

    let url2 = url.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if open::that(&url2).is_err() {
            println!("Open browser manually: {url2}");
        }
    });

    axum::serve(listener, app).await.unwrap();
}
