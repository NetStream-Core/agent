use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use log::{info, warn};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use tokio::time::sleep;

use crate::bpf::{collect_metrics, load_hashes, setup, spawn_event_monitor};
use crate::config::{METRICS_SERVER_ADDR, REPORT_INTERVAL, malware_domains};
use crate::telemetry::{CompressedMetricsBatch, MetricsBatch, MetricsServiceClient};

pub async fn run() -> Result<()> {
    let mut signals = Signals::new([SIGINT, SIGTERM])?.fuse();

    let (bpf_shared, packet_counts, ring_buf, xdp_link_id) = setup().await?;

    let path = malware_domains();
    if !path.exists() {
        return Err(anyhow!(
            "malware domains file not found: {}",
            path.display()
        ));
    }

    let domain_hashes = load_hashes(&path)?;
    spawn_event_monitor(ring_buf, domain_hashes);

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
        } else {
            warn!("Program 'xdp_monitor' not found during shutdown");
        }
    }

    info!("Agent stopped gracefully");
    Ok(())
}
