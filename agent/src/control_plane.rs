//! Talks to the backend control plane (`backend/internal/api`): registers
//! this sensor and periodically checks whether an operator has pushed a new
//! desired config version.
//!
//! The control plane is optional and the agent must keep monitoring traffic
//! whether or not one is configured or reachable: every request failure is
//! logged and swallowed here, never propagated to the caller in a way that
//! could stop `telemetry::run::run`'s main loop. Registration doubles as the
//! heartbeat (the backend's own `Register` upserts by `host_id` and
//! refreshes `last_seen` on every call), so there is a single request per
//! tick rather than a separate register/heartbeat pair.
//!
//! This only detects and logs a new `config_version`; applying the payload
//! to the running agent (response mode, quarantine allowlist, ...) is not
//! wired up yet, tracked as a follow-up.

use log::{info, warn};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use tokio::time::interval;

#[derive(Debug, Serialize)]
struct RegisterRequest<'a> {
    host_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    agent_version: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct AgentConfigResponse {
    version: i64,
    payload: Value,
}

async fn register(
    client: &reqwest::Client,
    base_url: &str,
    host_id: &str,
    hostname: Option<&str>,
    agent_version: &str,
) -> Result<(), reqwest::Error> {
    let response = client
        .post(format!("{base_url}/api/v1/sensors/register"))
        .json(&RegisterRequest {
            host_id,
            hostname,
            agent_version,
        })
        .send()
        .await?;
    response.error_for_status().map(|_| ())
}

/// `Ok(None)` means the sensor has never had a config pushed to it (a plain
/// 404), which is the normal state until an operator sets one — not an
/// error worth logging as one.
async fn fetch_config(
    client: &reqwest::Client,
    base_url: &str,
    host_id: &str,
) -> Result<Option<AgentConfigResponse>, reqwest::Error> {
    let response = client
        .get(format!("{base_url}/api/v1/sensors/{host_id}/config"))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(response.error_for_status()?.json().await?))
}

/// Registers with the control plane and polls its desired config for this
/// sensor on `poll_interval`, logging whenever `config_version` advances.
/// Spawned once at startup and left running for the life of the process,
/// the same way `reload::spawn_blocklist_reload` is.
pub fn spawn(
    client: reqwest::Client,
    base_url: String,
    host_id: String,
    hostname: Option<String>,
    agent_version: String,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        let mut tick = interval(poll_interval);
        let mut last_seen_version: Option<i64> = None;

        loop {
            tick.tick().await;

            if let Err(e) = register(
                &client,
                &base_url,
                &host_id,
                hostname.as_deref(),
                &agent_version,
            )
            .await
            {
                warn!("Control plane registration failed: {e}");
                continue;
            }

            match fetch_config(&client, &base_url, &host_id).await {
                Ok(Some(config)) if last_seen_version != Some(config.version) => {
                    info!(
                        "Control plane pushed config version {} for {host_id}: {}",
                        config.version, config.payload
                    );
                    last_seen_version = Some(config.version);
                }
                Ok(_) => {}
                Err(e) => warn!("Failed to fetch desired config from control plane: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A minimal HTTP/1.1 responder for exactly one request, run on a
    /// background thread so the async test code can talk to a real socket
    /// without pulling in a mock-server crate for this one module.
    fn respond_once(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn register_succeeds_on_a_2xx_response() {
        let base_url = respond_once("HTTP/1.1 200 OK", "{}");
        let client = reqwest::Client::new();

        let result = register(&client, &base_url, "sensor-1", Some("host-1"), "0.1.0").await;

        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn register_reports_an_error_on_a_4xx_response() {
        let base_url = respond_once("HTTP/1.1 400 Bad Request", "{\"error\":\"bad host_id\"}");
        let client = reqwest::Client::new();

        let result = register(&client, &base_url, "", None, "0.1.0").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fetch_config_returns_none_on_404() {
        let base_url = respond_once("HTTP/1.1 404 Not Found", "{\"error\":\"not found\"}");
        let client = reqwest::Client::new();

        let result = fetch_config(&client, &base_url, "sensor-1").await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_config_parses_the_version_and_payload() {
        let base_url = respond_once(
            "HTTP/1.1 200 OK",
            r#"{"sensor_id":1,"version":3,"payload":{"response_mode":"enforce"},"created_at":"2026-01-01T00:00:00Z"}"#,
        );
        let client = reqwest::Client::new();

        let config = fetch_config(&client, &base_url, "sensor-1")
            .await
            .unwrap()
            .expect("a config");

        assert_eq!(config.version, 3);
        assert_eq!(config.payload["response_mode"], "enforce");
    }
}
