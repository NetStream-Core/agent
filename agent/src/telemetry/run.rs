use anyhow::{Context, Result, anyhow};
use aya::Ebpf;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::xdp::XdpLinkId;
use aya::programs::{SchedClassifier, Xdp};
use futures_util::StreamExt;
use log::{info, warn};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;

use opentelemetry::global;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use opentelemetry_otlp::tonic_types::transport::{Certificate, ClientTlsConfig};
use opentelemetry_otlp::{MetricExporter, WithExportConfig, WithTonicConfig};

use crate::bpf::{
    CollectContext, FlowTracker, LoadOptions, OverheadReporter, collect_and_report_metrics, setup,
    spawn_event_monitor,
};
use crate::config::Settings;
use crate::dns::monitor::spawn_dns_monitor;
use crate::dns::suffixes::PublicSuffixList;
use crate::health;
use crate::reload::spawn_blocklist_reload;
use crate::response::ResponseConfig;
use crate::telemetry::logs::{EventLog, LogPipeline, init_otlp_logs};
use crate::telemetry::resource;
use crate::utils::{ephemeral_port_range, get_default_interface};

/// Reads a PEM file into a tonic `ClientTlsConfig` trusting that certificate
/// in addition to the platform's own roots — needed for the lab's
/// self-signed `otel-edge` certificate, which is in no system trust store.
/// `None` (no `OTEL_EXPORTER_OTLP_CERTIFICATE`) means use the platform
/// roots only, which is correct for an endpoint with a certificate from a
/// real CA and a no-op for a plain (non-TLS) endpoint.
fn otlp_tls_config(ca_file: Option<&Path>) -> Result<Option<ClientTlsConfig>> {
    let Some(path) = ca_file else {
        return Ok(None);
    };
    let pem = std::fs::read(path)
        .with_context(|| format!("read OTEL_EXPORTER_OTLP_CERTIFICATE {}", path.display()))?;
    Ok(Some(
        ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem)),
    ))
}

fn init_otlp_metrics(
    endpoint: &str,
    resource: Resource,
    tls: Option<ClientTlsConfig>,
) -> Result<SdkMeterProvider> {
    let mut builder = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .with_timeout(Duration::from_secs(2));
    if let Some(tls) = tls {
        builder = builder.with_tls_config(tls);
    }
    let exporter = builder.build()?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(5))
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    global::set_meter_provider(provider.clone());
    Ok(provider)
}

fn detach_xdp(bpf: &mut Ebpf, link_id: XdpLinkId) -> Result<()> {
    let xdp: &mut Xdp = bpf
        .program_mut("xdp_monitor")
        .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?
        .try_into()?;
    xdp.detach(link_id)?;
    Ok(())
}

fn detach_tc(bpf: &mut Ebpf, link_id: SchedClassifierLinkId) -> Result<()> {
    let tc_prog: &mut SchedClassifier = bpf
        .program_mut("tc_dns_monitor")
        .ok_or_else(|| anyhow!("Program 'tc_dns_monitor' not found"))?
        .try_into()?;
    tc_prog.detach(link_id)?;
    Ok(())
}

pub async fn run(settings: &Settings) -> Result<()> {
    let collect_context = |interval_ms: u64| CollectContext {
        interval_ms,
        top_n: settings.flow_log_top_n,
        capacity: settings.flow_table_entries as usize,
    };
    let mut signals = Signals::new([SIGINT, SIGTERM])?.fuse();

    let mut domain_mgr_raw = crate::domain_manager::DomainManager::new();
    let path = &settings.malware_domains_file;

    if !path.exists() {
        return Err(anyhow!(
            "Malware domains file not found: {}",
            path.display()
        ));
    }

    let hashes = domain_mgr_raw.load_from_file(path)?;
    let malware_domains_file = path.clone();
    let domain_mgr = Arc::new(tokio::sync::RwLock::new(domain_mgr_raw));

    let psl = match PublicSuffixList::load_from_file(&settings.public_suffix_list_file) {
        Ok(psl) => psl,
        Err(e) => {
            warn!("Falling back to the top-level-only registered domain heuristic: {e}");
            PublicSuffixList::default()
        }
    };
    let psl = Arc::new(psl);

    let interface = get_default_interface()?;
    let (resource, boot_id, host_id, hostname) =
        resource::build(settings.host_id.clone(), &interface);

    let otlp_tls = otlp_tls_config(settings.otlp_ca_file.as_deref())?;
    let meter_provider =
        init_otlp_metrics(&settings.otlp_endpoint, resource.clone(), otlp_tls.clone())?;
    let log_pipeline: Option<LogPipeline> = if settings.export_logs {
        Some(init_otlp_logs(
            &settings.otlp_endpoint,
            resource,
            &boot_id,
            otlp_tls,
        )?)
    } else {
        None
    };
    let events = log_pipeline
        .as_ref()
        .map(|pipeline| pipeline.events.clone())
        .unwrap_or_else(EventLog::disabled);
    info!(
        "OpenTelemetry OTLP pipeline initialized targeting {}",
        settings.otlp_endpoint
    );

    let response = ResponseConfig::from_settings(settings);
    let loaded = setup(
        &LoadOptions {
            interface: &interface,
            dns_events: settings.dns_events,
            flow_table_entries: settings.flow_table_entries,
            new_flows_per_second: settings.new_flows_per_second,
            collapse_ephemeral_ports: settings.collapse_ephemeral_ports,
            ephemeral_range: ephemeral_port_range(),
        },
        &hashes,
        &response,
    )
    .await?;
    let bpf_shared = loaded.bpf;
    let packet_counts = loaded.packet_counts;
    let xdp_link_id = loaded.xdp_link_id;
    let tc_link_id = loaded.tc_link_id;
    let mut flow_tracker = FlowTracker::default();
    let mut overhead = OverheadReporter::new(settings.bpf_stats);

    spawn_event_monitor(
        loaded.malware_events,
        Arc::clone(&domain_mgr),
        events.clone(),
    );
    spawn_blocklist_reload(
        Arc::clone(&bpf_shared),
        Arc::clone(&domain_mgr),
        malware_domains_file,
        settings.reload_poll_interval,
    );
    if let Some(base_url) = &settings.control_plane_url {
        match crate::control_plane::build_client(settings.control_plane_ca_file.as_deref()) {
            Ok(client) => {
                crate::control_plane::spawn(crate::control_plane::SpawnOptions {
                    client,
                    base_url: base_url.clone(),
                    host_id: host_id.clone(),
                    hostname: hostname.clone(),
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    poll_interval: settings.control_plane_poll_interval,
                    bpf: Arc::clone(&bpf_shared),
                    response: response.clone(),
                });
                info!("Control plane polling enabled, targeting {base_url}");
            }
            Err(e) => warn!("Control plane disabled, failed to build its HTTP client: {e}"),
        }
    }
    if settings.dns_events {
        spawn_dns_monitor(
            loaded.dns_queries,
            loaded.dns_events_lost,
            events.clone(),
            Arc::clone(&psl),
        );
    }

    health::mark_ready();
    info!("Agent is ready");

    let mut tick = interval(settings.report_interval);
    let mut last_collect = Instant::now();

    loop {
        tokio::select! {
            biased;

            _ = signals.next() => {
                info!("Shutdown signal received");
                health::mark_not_ready();
                break;
            }

            _ = tick.tick() => {
                let interval_ms = last_collect.elapsed().as_millis() as u64;
                last_collect = Instant::now();
                if let Err(e) = collect_and_report_metrics(&packet_counts, &mut flow_tracker, &events, &collect_context(interval_ms)).await {
                    warn!("Failed to process eBPF maps: {e}");
                }
                overhead.report(&bpf_shared).await;
            }
        }
    }

    info!("Unloading eBPF programs...");
    {
        let mut bpf = bpf_shared.lock().await;

        match detach_xdp(&mut bpf, xdp_link_id) {
            Ok(()) => info!("Detached XDP program"),
            Err(e) => warn!("Failed to detach XDP program: {e}"),
        }

        match detach_tc(&mut bpf, tc_link_id) {
            Ok(()) => info!("Detached TC egress program"),
            Err(e) => warn!("Failed to detach TC egress program: {e}"),
        }
    }

    if let Some(pipeline) = &log_pipeline {
        pipeline.shutdown();
    }

    if let Err(e) = meter_provider.shutdown() {
        warn!("Error during OpenTelemetry provider shutdown: {e}");
    }

    info!("Agent stopped gracefully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway self-signed certificate (openssl req -x509 -newkey
    // rsa:2048 -nodes -days 3650 -subj "/CN=test"), used only to check that
    // a valid PEM is accepted; it signs nothing real and is not a secret.
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
    fn otlp_tls_config_without_a_ca_file_is_none() {
        assert!(otlp_tls_config(None).unwrap().is_none());
    }

    #[test]
    fn otlp_tls_config_with_a_valid_ca_file_is_some() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otlp-ca.pem");
        std::fs::write(&path, TEST_CERT_PEM).unwrap();

        assert!(otlp_tls_config(Some(&path)).unwrap().is_some());
    }

    #[test]
    fn otlp_tls_config_with_a_missing_ca_file_fails() {
        let result = otlp_tls_config(Some(Path::new("/no/such/file.pem")));
        assert!(result.is_err());
    }
}
