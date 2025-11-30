pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/metrics.rs"));
}

pub use proto::{
    CompressedMetricsBatch, MetricsBatch, PacketMetric,
    metrics_service_client::MetricsServiceClient,
};
