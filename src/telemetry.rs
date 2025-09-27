use crate::domains::{load_hashes, spawn_trace_monitor};
use crate::init;
use crate::metrics::proto::{MetricsBatch, metrics_service_client::MetricsServiceClient};
use anyhow::Result;
use log::{info, warn};

pub async fn run() -> Result<()> {
    let (_bpf, packet_counts, malware_domains) = init::setup().await?;
    let domain_hashes = load_hashes("malware_domains.txt")?;

    spawn_trace_monitor(malware_domains.clone(), domain_hashes);
    let mut client = MetricsServiceClient::connect("http://[::1]:50051").await?;

    loop {
        let metrics = crate::maps::collect_metrics(&packet_counts).await?;
        let batch = MetricsBatch { metrics };
        let encoded = zstd::encode_all(prost::Message::encode_to_vec(&batch).as_slice(), 3)?;

        info!(
            "Sending batch with {} metrics, compressed size: {} bytes",
            batch.metrics.len(),
            encoded.len()
        );

        if let Err(e) = client.send_metrics(batch.clone()).await {
            warn!("Failed to send batch: {}", e);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
