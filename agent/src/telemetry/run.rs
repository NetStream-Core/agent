use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::xdp::XdpLinkId;
use aya::programs::{SchedClassifier, Xdp};
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
use crate::config::Settings;
use crate::health;

fn init_otlp_metrics(endpoint: &str) -> Result<SdkMeterProvider> {
    let resource = Resource::builder()
        .with_attributes(vec![opentelemetry::KeyValue::new(
            "service.name",
            "netstream-monitor-agent",
        )])
        .build();

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
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
    let domain_mgr = Arc::new(domain_mgr_raw);

    let meter_provider = init_otlp_metrics(&settings.otlp_endpoint)?;
    info!(
        "OpenTelemetry OTLP pipeline initialized targeting {}",
        settings.otlp_endpoint
    );

    let (bpf_shared, packet_counts, ring_buf, xdp_link_id, tc_link_id) =
        setup(&settings.bpf_object_file, &hashes).await?;

    spawn_event_monitor(ring_buf, Arc::clone(&domain_mgr));

    health::mark_ready();
    info!("Agent is ready");

    let mut tick = interval(settings.report_interval);

    loop {
        tokio::select! {
            biased;

            _ = signals.next() => {
                info!("Shutdown signal received");
                health::mark_not_ready();
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

        match detach_xdp(&mut bpf, xdp_link_id) {
            Ok(()) => info!("Detached XDP program"),
            Err(e) => warn!("Failed to detach XDP program: {e}"),
        }

        match detach_tc(&mut bpf, tc_link_id) {
            Ok(()) => info!("Detached TC egress program"),
            Err(e) => warn!("Failed to detach TC egress program: {e}"),
        }
    }

    if let Err(e) = meter_provider.shutdown() {
        warn!("Error during OpenTelemetry provider shutdown: {e}");
    }

    info!("Agent stopped gracefully");
    Ok(())
}
