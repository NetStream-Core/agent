//! Talks to the backend control plane (`backend/internal/api`): registers
//! this sensor, periodically checks whether an operator has pushed a new
//! desired config version, and applies what it can of that config to the
//! running agent.
//!
//! The control plane is optional and the agent must keep monitoring traffic
//! whether or not one is configured or reachable: every request failure is
//! logged and swallowed here, never propagated to the caller in a way that
//! could stop `telemetry::run::run`'s main loop. Registration doubles as the
//! heartbeat (the backend's own `Register` upserts by `host_id` and
//! refreshes `last_seen` on every call), so there is a single request per
//! tick rather than a separate register/heartbeat pair.
//!
//! Only `payload.allowlist_extra` (the same string format as the
//! `QUARANTINE_ALLOWLIST` env var) is applied live, by inserting/removing
//! entries in the `quarantine_allowlist` eBPF map the same way
//! `reload::spawn_blocklist_reload` already does for the domain blocklist.
//! `response_mode` and `quarantine_ttl_secs` are deliberately **not**
//! applied: `bpf/loader.rs` bakes them into the program's `.rodata` via
//! `EbpfLoader::set_global` at load time, which the verifier treats as a
//! compile-time constant — changing them for real would mean reloading the
//! whole eBPF program, not writing to a map, so a config that sets them
//! just gets a warning instead of silently being ignored.

use crate::response::{Ipv4Prefix, ResponseConfig};
use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use log::{info, warn};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
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

fn allowlist_key(prefix: &Ipv4Prefix) -> Key<u32> {
    Key::new(prefix.len as u32, u32::from_ne_bytes(prefix.addr.octets()))
}

/// Reads `payload.allowlist_extra` (a JSON array of the same
/// `"10.0.0.1"`/`"192.168.0.0/16"` strings `QUARANTINE_ALLOWLIST` accepts).
/// A missing field means "no remote entries"; an invalid entry is skipped
/// with a warning rather than discarding the whole list.
fn remote_allowlist_from_payload(payload: &Value) -> HashSet<Ipv4Prefix> {
    let Some(raw) = payload.get("allowlist_extra") else {
        return HashSet::new();
    };
    let Some(entries) = raw.as_array() else {
        warn!("Control plane config: `allowlist_extra` is not a JSON array, ignoring it");
        return HashSet::new();
    };
    entries
        .iter()
        .filter_map(|entry| entry.as_str())
        .filter_map(|raw| match raw.parse::<Ipv4Prefix>() {
            Ok(prefix) => Some(prefix),
            Err(e) => {
                warn!("Control plane config: invalid allowlist_extra entry {raw:?}: {e}");
                None
            }
        })
        .collect()
}

/// Inserts/removes only what changed between `previous_remote` and
/// `new_remote` in the live `quarantine_allowlist` map, leaving `base`
/// (the local addresses, resolvers, gateway and `QUARANTINE_ALLOWLIST`
/// computed once at startup by `ResponseConfig::from_settings`) alone: an
/// entry that is in both `base` and a remote list that later drops it must
/// stay allowlisted, since removing it here would also undo the static
/// configuration that happens to share the same prefix.
async fn apply_allowlist_delta(
    bpf: &Mutex<Ebpf>,
    base: &HashSet<Ipv4Prefix>,
    previous_remote: &HashSet<Ipv4Prefix>,
    new_remote: &HashSet<Ipv4Prefix>,
) -> anyhow::Result<()> {
    if previous_remote == new_remote {
        return Ok(());
    }
    let mut bpf = bpf.lock().await;
    let map = bpf
        .map_mut("quarantine_allowlist")
        .ok_or_else(|| anyhow::anyhow!("Map 'quarantine_allowlist' not found"))?;
    let mut allowlist: LpmTrie<_, u32, u8> = LpmTrie::try_from(map)?;

    for prefix in new_remote.difference(previous_remote) {
        allowlist.insert(&allowlist_key(prefix), 1, 0)?;
    }
    for prefix in previous_remote.difference(new_remote) {
        if !base.contains(prefix) {
            let _ = allowlist.remove(&allowlist_key(prefix));
        }
    }
    Ok(())
}

pub struct SpawnOptions {
    pub client: reqwest::Client,
    pub base_url: String,
    pub host_id: String,
    pub hostname: Option<String>,
    pub agent_version: String,
    pub poll_interval: Duration,
    pub bpf: Arc<Mutex<Ebpf>>,
    pub response: ResponseConfig,
}

/// Registers with the control plane and polls its desired config for this
/// sensor on `poll_interval`. When `config_version` advances, applies
/// `allowlist_extra` to the live `quarantine_allowlist` map and warns about
/// any `response_mode`/`quarantine_ttl_secs` in the payload, which cannot
/// be hot-applied (see the module docs). Spawned once at startup and left
/// running for the life of the process, the same way
/// `reload::spawn_blocklist_reload` is.
pub fn spawn(options: SpawnOptions) {
    let SpawnOptions {
        client,
        base_url,
        host_id,
        hostname,
        agent_version,
        poll_interval,
        bpf,
        response,
    } = options;

    tokio::spawn(async move {
        let mut tick = interval(poll_interval);
        let mut last_seen_version: Option<i64> = None;
        let base_allowlist: HashSet<Ipv4Prefix> = response.allowlist.iter().copied().collect();
        let mut applied_remote_allowlist: HashSet<Ipv4Prefix> = HashSet::new();

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
                    if config.payload.get("response_mode").is_some()
                        || config.payload.get("quarantine_ttl_secs").is_some()
                    {
                        warn!(
                            "Config version {} sets response_mode/quarantine_ttl_secs, but \
                             hot-applying those isn't supported yet — restart the agent to \
                             pick them up",
                            config.version
                        );
                    }

                    let new_remote_allowlist = remote_allowlist_from_payload(&config.payload);
                    match apply_allowlist_delta(
                        &bpf,
                        &base_allowlist,
                        &applied_remote_allowlist,
                        &new_remote_allowlist,
                    )
                    .await
                    {
                        Ok(()) => applied_remote_allowlist = new_remote_allowlist,
                        Err(e) => warn!("Failed to apply allowlist_extra to the eBPF map: {e}"),
                    }

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
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn prefix(s: &str) -> Ipv4Prefix {
        s.parse().expect("valid prefix")
    }

    #[test]
    fn remote_allowlist_is_empty_without_the_field() {
        assert!(remote_allowlist_from_payload(&json!({})).is_empty());
    }

    #[test]
    fn remote_allowlist_parses_valid_entries_and_skips_invalid_ones() {
        let payload = json!({"allowlist_extra": ["10.0.0.1", "192.168.0.0/16", "nope", 5]});

        let allowlist = remote_allowlist_from_payload(&payload);

        assert_eq!(
            allowlist,
            HashSet::from([prefix("10.0.0.1"), prefix("192.168.0.0/16")])
        );
    }

    #[test]
    fn remote_allowlist_is_empty_when_the_field_is_not_an_array() {
        let payload = json!({"allowlist_extra": "10.0.0.1"});
        assert!(remote_allowlist_from_payload(&payload).is_empty());
    }

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
