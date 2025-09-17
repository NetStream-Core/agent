pub mod proto {
    include!("../proto/metrics.rs");
}

use crate::metrics::proto::PacketMetric;
use prost::Message;

pub fn serialize_metrics(metrics: Vec<PacketMetric>) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut results = vec![];
    for metric in metrics {
        let mut buf = vec![];
        metric.encode(&mut buf)?;
        results.push(buf);
    }
    Ok(results)
}
