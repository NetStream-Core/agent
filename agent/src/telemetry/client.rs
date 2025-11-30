use super::models::proto::{
    CompressedMetricsBatch, MetricsBatch, metrics_service_client::MetricsServiceClient,
};
use crate::bpf::loader;
use crate::bpf::{events, maps};
use anyhow::Result;
use log::{info, warn};

pub async fn run() -> Result<()> {
    let (_bpf, packet_counts, ring_buf) = loader::setup().await?;
    let domain_hashes = events::load_hashes("malware_domains.txt")?;
    events::spawn_event_monitor(ring_buf, domain_hashes);

    let mut client = MetricsServiceClient::connect("http://[::1]:50051")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to server: {}", e))?;
    info!("Connected to gRPC server");

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
                warn!("Failed to send batch: {}", e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
