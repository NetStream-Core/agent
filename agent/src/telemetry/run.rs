use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use log::{info, warn};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

use opentelemetry::global;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use opentelemetry_otlp::{MetricExporter, WithExportConfig};

use crate::bpf::{collect_and_report_metrics, setup, spawn_event_monitor};
use crate::config::{METRICS_SERVER_ADDR, REPORT_INTERVAL, malware_domains};

fn init_otlp_metrics() -> Result<SdkMeterProvider> {
    let resource = Resource::builder()
        .with_attributes(vec![opentelemetry::KeyValue::new(
            "service.name",
            "netstream-monitor-agent",
        )])
        .build();

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(METRICS_SERVER_ADDR.to_string())
        .with_timeout(Duration::from_secs(5))
        .build()?;

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

pub async fn run() -> Result<()> {
    let mut signals = Signals::new([SIGINT, SIGTERM])?.fuse();

    let mut domain_mgr_raw = crate::domain_manager::DomainManager::new();
    let path = malware_domains();

    if !path.exists() {
        return Err(anyhow!(
            "Malware domains file not found: {}",
            path.display()
        ));
    }

    let hashes = domain_mgr_raw.load_from_file(&path)?;
    let domain_mgr = Arc::new(domain_mgr_raw);

    let meter_provider = init_otlp_metrics()?;
    info!("OpenTelemetry OTLP pipeline initialized targeting {METRICS_SERVER_ADDR}");

    let (bpf_shared, packet_counts, ring_buf, xdp_link_id) = setup(&hashes).await?;

    spawn_event_monitor(ring_buf, Arc::clone(&domain_mgr));

    let mut tick = interval(REPORT_INTERVAL);

    loop {
        tokio::select! {
            biased;

            _ = signals.next() => {
                info!("Shutdown signal received");
                break;
            }

            _ = tick.tick() => {
                if let Err(e) = collect_and_report_metrics(&packet_counts).await {
                    warn!("Failed to process eBPF maps: {e}");
                }
            }
        }
    }

    info!("Unloading eBPF programs...");
    {
        let mut bpf = bpf_shared.lock().await;

        if let Some(prog) = bpf.program_mut("xdp_monitor") {
            use aya::programs::Xdp;
            use std::convert::TryInto;

            let xdp: &mut Xdp = match TryInto::<&mut Xdp>::try_into(prog) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to convert program to Xdp: {e}");
                    return Ok(());
                }
            };

            if let Err(e) = xdp.detach(xdp_link_id) {
                warn!("Failed to detach XDP program: {e}");
            } else {
                info!("Detached XDP program");
            }
        }
    }

    if let Err(e) = meter_provider.shutdown() {
        warn!("Error during OpenTelemetry provider shutdown: {e}");
    }

    info!("Agent stopped gracefully");
    Ok(())
}
