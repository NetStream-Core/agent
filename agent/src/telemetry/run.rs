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
use std::time::{Duration, Instant};
use tokio::time::interval;

use opentelemetry::global;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use opentelemetry_otlp::{MetricExporter, WithExportConfig};

use crate::bpf::{
    CollectContext, FlowTracker, LoadOptions, collect_and_report_metrics, setup,
    spawn_event_monitor,
};
use crate::config::Settings;
use crate::dns::monitor::spawn_dns_monitor;
use crate::health;
use crate::response::ResponseConfig;
use crate::telemetry::logs::{EventLog, LogPipeline, init_otlp_logs};
use crate::telemetry::resource;
use crate::utils::{ephemeral_port_range, get_default_interface};

fn init_otlp_metrics(endpoint: &str, resource: Resource) -> Result<SdkMeterProvider> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .with_timeout(Duration::from_secs(2))
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
    let domain_mgr = Arc::new(domain_mgr_raw);

    let interface = get_default_interface()?;
    let resource = resource::build(settings.host_id.clone(), &interface);

    let meter_provider = init_otlp_metrics(&settings.otlp_endpoint, resource.clone())?;
    let log_pipeline: Option<LogPipeline> = if settings.export_logs {
        Some(init_otlp_logs(&settings.otlp_endpoint, resource)?)
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
            bpf_object: &settings.bpf_object_file,
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

    spawn_event_monitor(
        loaded.malware_events,
        Arc::clone(&domain_mgr),
        events.clone(),
    );
    if settings.dns_events {
        spawn_dns_monitor(loaded.dns_queries, loaded.dns_events_lost, events.clone());
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
