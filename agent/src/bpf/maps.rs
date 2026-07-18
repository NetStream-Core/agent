use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{PacketKey, PacketValue};
use log;
use opentelemetry::{KeyValue, global};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

pub async fn collect_and_report_metrics(
    packet_counts: &Arc<Mutex<HashMap<MapData, PacketKey, PacketValue>>>,
) -> Result<usize> {
    let mut keys_to_remove = Vec::new();
    let mut processed_count = 0;

    let meter = global::meter("netstream_agent");

    let packet_counter = meter
        .u64_counter("netstream_packets_total")
        .with_description("Total volume of processed network packets")
        .build();

    let payload_counter = meter
        .u64_counter("netstream_payload_bytes_total")
        .with_description("Total volume of payload bytes passing through")
        .build();

    let mut map = packet_counts.lock().await;

    let entries: Vec<_> = map.iter().flatten().collect();

    for entry in entries {
        let (key, value) = entry;
        processed_count += 1;

        let attributes = [
            KeyValue::new("protocol", key.protocol.to_string()),
            KeyValue::new("src_ip", Ipv4Addr::from(key.src_ip).to_string()),
            KeyValue::new("dst_ip", Ipv4Addr::from(key.dst_ip).to_string()),
            KeyValue::new("src_port", (key.src_port as i64).to_string()),
            KeyValue::new("dst_port", (key.dst_port as i64).to_string()),
        ];

        packet_counter.add(value.count, &attributes);
        payload_counter.add(value.payload_size as u64, &attributes);

        keys_to_remove.push(key);
    }

    for key in &keys_to_remove {
        let _ = map.remove(key);
    }

    if processed_count > 0 {
        log::debug!("Processed {} packets total", processed_count);
    }

    Ok(processed_count)
}
