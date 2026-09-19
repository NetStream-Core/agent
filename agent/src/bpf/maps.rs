use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{PacketKey, PacketValue};
use log;
use opentelemetry::{KeyValue, global};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

fn ipv4_from_network_order(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(raw))
}

fn flow_attributes(key: &PacketKey) -> [KeyValue; 5] {
    [
        KeyValue::new("protocol", key.protocol.to_string()),
        KeyValue::new("src_ip", ipv4_from_network_order(key.src_ip).to_string()),
        KeyValue::new("dst_ip", ipv4_from_network_order(key.dst_ip).to_string()),
        KeyValue::new("src_port", (key.src_port as i64).to_string()),
        KeyValue::new("dst_port", (key.dst_port as i64).to_string()),
    ]
}

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

        let attributes = flow_attributes(&key);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(attributes: &[KeyValue], name: &str) -> String {
        attributes
            .iter()
            .find(|kv| kv.key.as_str() == name)
            .map(|kv| kv.value.as_str().into_owned())
            .expect("attribute present")
    }

    #[test]
    fn converts_network_order_bytes_to_ipv4() {
        let raw = u32::from_ne_bytes([192, 168, 1, 1]);
        assert_eq!(ipv4_from_network_order(raw), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn flow_attributes_use_dotted_ipv4_in_wire_order() {
        let key = PacketKey {
            protocol: 6,
            src_ip: u32::from_ne_bytes([192, 168, 1, 10]),
            dst_ip: u32::from_ne_bytes([8, 8, 4, 4]),
            src_port: 44321,
            dst_port: 443,
        };

        let attributes = flow_attributes(&key);

        assert_eq!(attribute(&attributes, "src_ip"), "192.168.1.10");
        assert_eq!(attribute(&attributes, "dst_ip"), "8.8.4.4");
        assert_eq!(attribute(&attributes, "protocol"), "6");
        assert_eq!(attribute(&attributes, "src_port"), "44321");
        assert_eq!(attribute(&attributes, "dst_port"), "443");
    }
}
