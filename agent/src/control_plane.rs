//! Talks to the backend control plane (`backend/internal/api`): registers
//! this sensor, periodically checks whether an operator has pushed a new
//! desired config version, applies what it can of that config to the
//! running agent, and acks back the version it actually applied — closing
//! the desired/actual loop the backend's `sensors.actual_config_version`
//! is there to track.
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
//!
//! The connection itself is TLS if `CONTROL_PLANE_URL` is `https://`, so a
//! MITM on the network between the agent and the backend cannot tamper with
//! the desired config in transit (`build_client`). This is server-side TLS
//! only — the backend's certificate is checked, the agent presents no
//! client certificate — so it does not by itself let the backend verify
//! *which* agent is talking to it.

use crate::response::{Ipv4Prefix, ResponseConfig};
use anyhow::Context;
use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use log::{info, warn};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::interval;

/// Builds the HTTP client used to talk to the control plane. Without
/// `ca_file` it trusts only the platform's own root certificates (works
/// against a backend with a certificate from a real CA); with it, the PEM
/// file's certificate is trusted in addition — needed for the lab's
/// self-signed backend certificate, which is in no system trust store.
pub fn build_client(ca_file: Option<&Path>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .with_context(|| format!("read CONTROL_PLANE_CA_FILE {}", path.display()))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .with_context(|| format!("parse CONTROL_PLANE_CA_FILE {} as PEM", path.display()))?;
        builder = builder.add_root_certificate(cert);
    }
    builder.build().context("build control plane HTTP client")
}

#[derive(Debug, Serialize)]
struct RegisterRequest<'a> {
    host_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    agent_version: &'a str,
}

#[derive(Debug, Serialize)]
struct AckConfigRequest {
    version: i64,
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

/// Reports the config version the agent has actually applied (see the
/// `actual_config_version` column and `PUT .../config/ack` in
/// `backend/internal/sensors`), so an operator watching the fleet can tell
/// "sent" apart from "converged" rather than assuming every sensor catches
/// up to the desired version instantly.
async fn ack_config(
    client: &reqwest::Client,
    base_url: &str,
    host_id: &str,
    version: i64,
) -> Result<(), reqwest::Error> {
    let response = client
        .put(format!("{base_url}/api/v1/sensors/{host_id}/config/ack"))
        .json(&AckConfigRequest { version })
        .send()
        .await?;
    response.error_for_status().map(|_| ())
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
                        Ok(()) => {
                            applied_remote_allowlist = new_remote_allowlist;
                            if let Err(e) =
                                ack_config(&client, &base_url, &host_id, config.version).await
                            {
                                warn!(
                                    "Failed to ack applied config version {} to the control \
                                     plane: {e}",
                                    config.version
                                );
                            }
                        }
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

    // A throwaway self-signed certificate (openssl req -x509 -newkey rsa:2048
    // -nodes -days 3650 -subj "/CN=test"), used only to check that a valid
    // PEM is accepted; it signs nothing real and is not a secret.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIC/zCCAeegAwIBAgIURdK3jpfqCkuwvw/Ea+lRqQ89yScwDQYJKoZIhvcNAQEL\n\
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA5MjcxODI3NDFaFw0zNjA5MjQxODI3\n\
NDFaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
AoIBAQD5pWyITNVx0+HKIvsu6eJSq7s+o+9r80t4hIr4Nb1goAAscrtAUo29Thkr\n\
sM2IHKzA1qfRavSIHZkiuh+ZkGva3wU3ESYQXD0B9pYXQx5jyjhJRKJ/jazkIWaS\n\
ZecKCjV6cTQO9rhVP8LR6FI4m2zFZHVOta0R0W4ZXOn56accwzCT9bUnN16ieyXu\n\
GVBO4z6EbiFGt5XlrA32vuLHAlCsGnyQebgrrRg/HtvVXiyFGqbmO4JRKakC8r5g\n\
oPiVJSm0VygTmx2xi5bGifvY9qrsUZI4p1IDi2bHO29hgkd51215T5ElN4kMOEDH\n\
kZ9LENDoLhXgnsNrDB9nR9KNoSAzAgMBAAGjUzBRMB0GA1UdDgQWBBQskfTwGEin\n\
oTsFvLwhQKjsS6JGoTAfBgNVHSMEGDAWgBQskfTwGEinoTsFvLwhQKjsS6JGoTAP\n\
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDQY6Go6F1s7pKNQQNf\n\
CiEldNYjHpf9DZ2V0fhXC+4jgDn2Q0VABDBrseWkCbuqy4UIoIDFLwUGiFl1t+H/\n\
s54mLu/QYyt6hfzvCs7eBO3ZNW+5YG/3CQghRHtlEgcGEhT9MoHJyToCYDEuU6yr\n\
Srnt9536vuLPch1YLBnwzd3IhsOipQGKPOZVkFGRQi8yBj0OMhhaeFF7JIox97Ad\n\
Dt95WUfDVcfrLhmTIKR0XQTc6NtK5bd3OHootbgkZoP8PAP7VlG5qiZ3/67Fkf23\n\
1pjnBW59C57oaB5aAEEtZ4b0RS64TTYLN7kvj9LF2inZbjqxnaUlJOhAthXmizI7\n\
qGLp\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn build_client_without_a_ca_file_succeeds() {
        assert!(build_client(None).is_ok());
    }

    #[test]
    fn build_client_with_a_valid_ca_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CERT_PEM).unwrap();

        assert!(build_client(Some(&path)).is_ok());
    }

    #[test]
    fn build_client_with_a_missing_ca_file_fails() {
        let result = build_client(Some(Path::new("/no/such/file.pem")));
        assert!(result.is_err());
    }

    #[test]
    fn build_client_with_an_invalid_pem_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\nnot valid base64 content!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let result = build_client(Some(&path));
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "needs a running control-plane backend over TLS, set CONTROL_PLANE_TLS_TEST_URL \
                and CONTROL_PLANE_TLS_TEST_CA"]
    async fn register_and_fetch_config_work_over_a_real_tls_connection() {
        let base_url =
            std::env::var("CONTROL_PLANE_TLS_TEST_URL").expect("CONTROL_PLANE_TLS_TEST_URL");
        let ca_path =
            std::env::var("CONTROL_PLANE_TLS_TEST_CA").expect("CONTROL_PLANE_TLS_TEST_CA");

        let client = build_client(Some(Path::new(&ca_path))).expect("build TLS client");

        register(&client, &base_url, "tls-e2e-sensor", None, "0.1.0")
            .await
            .expect("register over TLS");

        let config = fetch_config(&client, &base_url, "tls-e2e-sensor")
            .await
            .expect("fetch config over TLS");
        assert!(
            config.is_none(),
            "a freshly registered sensor has no config yet"
        );
    }

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
    async fn ack_config_succeeds_on_a_2xx_response() {
        let base_url = respond_once("HTTP/1.1 200 OK", "{}");
        let client = reqwest::Client::new();

        let result = ack_config(&client, &base_url, "sensor-1", 3).await;

        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn ack_config_reports_an_error_on_a_4xx_response() {
        let base_url = respond_once("HTTP/1.1 404 Not Found", "{\"error\":\"sensor not found\"}");
        let client = reqwest::Client::new();

        let result = ack_config(&client, &base_url, "no-such-sensor", 3).await;

        assert!(result.is_err());
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
