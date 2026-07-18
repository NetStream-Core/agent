use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio::sync::watch;

static IS_READY: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_TX: std::sync::OnceLock<watch::Sender<()>> = std::sync::OnceLock::new();

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

pub async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn ready_handler() -> impl IntoResponse {
    if IS_READY.load(Ordering::Acquire) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

pub fn mark_ready() {
    IS_READY.store(true, Ordering::Release);
}

pub async fn shutdown_health_server() {
    if let Some(tx) = SHUTDOWN_TX.get() {
        let _ = tx.send(());
    }
}

pub fn start_health_server() {
    tokio::spawn(async {
        let port = env::var("HEALTH_PORT").unwrap_or_else(|_| "8081".to_string());

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/ready", get(ready_handler));

        let addr = format!("0.0.0.0:{}", port);

        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => {
                log::info!("Health server started on http://{}", addr);
                l
            }
            Err(e) => {
                log::error!("Failed to bind health server on {}: {}", addr, e);
                return;
            }
        };

        let (tx, mut rx) = watch::channel(());
        let _ = SHUTDOWN_TX.set(tx);

        let server = axum::serve(listener, app);

        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    log::error!("Health server error: {}", e);
                }
            }
            _ = rx.changed() => {
                log::info!("Health server received shutdown signal");
            }
        }

        log::info!("Health server stopped");
    });
}
