use anyhow::{Result, anyhow};
use log::{info, warn};
use tokio::time::sleep;

use crate::bpf::loader;
use crate::bpf::{events, maps};

use crate::config::paths::malware_domains;
use crate::config::runtime::{METRICS_SERVER_ADDR, REPORT_INTERVAL};

use super::models::proto::{
    CompressedMetricsBatch, MetricsBatch, metrics_service_client::MetricsServiceClient,
};

pub async fn run() -> Result<()> {
    let (_bpf, packet_counts, ring_buf) = loader::setup().await?;

    let path = malware_domains();
    if !path.exists() {
        return Err(anyhow!(
            "malware domains file not found: {}",
            path.display()
        ));
    }

    let domain_hashes = events::load_hashes(&path)?;

    events::spawn_event_monitor(ring_buf, domain_hashes);

    let mut client = MetricsServiceClient::connect(METRICS_SERVER_ADDR)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to server: {e}"))?;

    info!("Connected to gRPC server at {METRICS_SERVER_ADDR}");

    loop {
        let metrics = maps::collect_metrics(&packet_counts).await?;

        if !metrics.is_empty() {
            let batch = MetricsBatch { metrics };
            let encoded = zstd::encode_all(prost::Message::encode_to_vec(&batch).as_slice(), 3)?;
            let compressed_batch = CompressedMetricsBatch {
                compressed_data: encoded,
            };

            info!(
                "Sending batch with {} metrics, compressed size: {} bytes",
                batch.metrics.len(),
                compressed_batch.compressed_data.len()
            );

            if let Err(e) = client.send_metrics(compressed_batch).await {
                warn!("Failed to send batch: {e}");
            }
        }

        sleep(REPORT_INTERVAL).await;
    }
}
