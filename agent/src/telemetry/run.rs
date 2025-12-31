use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use log::{info, warn};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::sync::Arc;
use tokio::time::sleep;

use crate::bpf::{collect_metrics, setup, spawn_event_monitor};
use crate::config::{METRICS_SERVER_ADDR, REPORT_INTERVAL, malware_domains};
use crate::telemetry::{CompressedMetricsBatch, MetricsBatch, MetricsServiceClient};

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

    let (bpf_shared, packet_counts, ring_buf, xdp_link_id) = setup().await?;

    {
        let mut bpf = bpf_shared.lock().await;
        crate::bpf::maps::fill_malware_map(&mut bpf, &hashes)?;
    }

    spawn_event_monitor(ring_buf, Arc::clone(&domain_mgr));

    let mut client = MetricsServiceClient::connect(METRICS_SERVER_ADDR)
        .await
        .map_err(|e| anyhow!("Failed to connect to server: {e}"))?;

    info!("Connected to gRPC server at {METRICS_SERVER_ADDR}");

    loop {
        tokio::select! {
            _ = signals.next() => {
                info!("Shutdown signal received");
                break;
            }

            result = collect_metrics(&packet_counts) => {
                match result {
                    Ok(metrics) if !metrics.is_empty() => {
                        let batch = MetricsBatch { metrics };
                        let encoded = zstd::encode_all(prost::Message::encode_to_vec(&batch).as_slice(), 3)?;
                        let request = CompressedMetricsBatch { compressed_data: encoded };

                        if let Err(e) = client.send_metrics(request).await {
                            warn!("Failed to send batch: {e}");
                        }
                    }
                    Ok(_) => sleep(REPORT_INTERVAL).await,
                    Err(e) => {
                        warn!("Failed to collect metrics: {e}");
                        sleep(REPORT_INTERVAL).await;
                    }
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

    info!("Agent stopped gracefully");
    Ok(())
}
