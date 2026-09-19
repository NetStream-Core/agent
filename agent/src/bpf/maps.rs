use anyhow::Result;
use aya::maps::{MapData, PerCpuHashMap};
use common::{PacketKey, PacketValue};
use log;
use opentelemetry::{KeyValue, global};
use std::collections::{HashMap, HashSet};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Totals {
    count: u64,
    payload_size: u64,
}

fn sum_cpus(values: &[PacketValue]) -> Totals {
    values.iter().fold(Totals::default(), |acc, v| Totals {
        count: acc.count.saturating_add(v.count),
        payload_size: acc.payload_size.saturating_add(v.payload_size),
    })
}

#[derive(Default)]
pub struct FlowTracker {
    previous: HashMap<PacketKey, Totals>,
}

impl FlowTracker {
    fn advance(&mut self, key: PacketKey, current: Totals) -> Totals {
        let previous = self.previous.insert(key, current).unwrap_or_default();
        if current.count < previous.count {
            current
        } else {
            Totals {
                count: current.count - previous.count,
                payload_size: current.payload_size.saturating_sub(previous.payload_size),
            }
        }
    }

    fn retain_seen(&mut self, seen: &HashSet<PacketKey>) {
        self.previous.retain(|key, _| seen.contains(key));
    }
}

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
    packet_counts: &Arc<Mutex<PerCpuHashMap<MapData, PacketKey, PacketValue>>>,
    tracker: &mut FlowTracker,
) -> Result<usize> {
    let meter = global::meter("netstream_agent");

    let packet_counter = meter
        .u64_counter("netstream_packets_total")
        .with_description("Total volume of processed network packets")
        .build();

    let payload_counter = meter
        .u64_counter("netstream_payload_bytes_total")
        .with_description("Total volume of payload bytes passing through")
        .build();

    let map = packet_counts.lock().await;

    let mut seen = HashSet::new();
    let mut reported = 0;

    for entry in map.iter() {
        let (key, values) = entry?;
        seen.insert(key);

        let delta = tracker.advance(key, sum_cpus(&values));
        if delta.count == 0 {
            continue;
        }
        reported += 1;

        let attributes = flow_attributes(&key);
        packet_counter.add(delta.count, &attributes);
        payload_counter.add(delta.payload_size, &attributes);
    }

    tracker.retain_seen(&seen);

    if reported > 0 {
        log::debug!("Reported {} active flows", reported);
    }

    Ok(reported)
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

    fn key(src_port: u16) -> PacketKey {
        PacketKey {
            protocol: 6,
            src_ip: 1,
            dst_ip: 2,
            src_port,
            dst_port: 443,
        }
    }

    fn totals(count: u64, payload_size: u64) -> Totals {
        Totals {
            count,
            payload_size,
        }
    }

    fn value(count: u64, payload_size: u64) -> PacketValue {
        PacketValue {
            count,
            timestamp: 0,
            payload_size,
        }
    }

    #[test]
    fn per_cpu_values_are_summed() {
        let cpus = [value(3, 300), value(5, 500), value(0, 0)];
        assert_eq!(sum_cpus(&cpus), totals(8, 800));
    }

    #[test]
    fn first_observation_reports_full_totals() {
        let mut tracker = FlowTracker::default();
        assert_eq!(tracker.advance(key(1), totals(10, 1000)), totals(10, 1000));
    }

    #[test]
    fn later_observations_report_only_the_increase() {
        let mut tracker = FlowTracker::default();
        tracker.advance(key(1), totals(10, 1000));
        assert_eq!(tracker.advance(key(1), totals(14, 1400)), totals(4, 400));
        assert_eq!(tracker.advance(key(1), totals(14, 1400)), totals(0, 0));
    }

    #[test]
    fn flows_are_tracked_independently() {
        let mut tracker = FlowTracker::default();
        tracker.advance(key(1), totals(10, 1000));
        assert_eq!(tracker.advance(key(2), totals(3, 30)), totals(3, 30));
        assert_eq!(tracker.advance(key(1), totals(11, 1100)), totals(1, 100));
    }

    #[test]
    fn counter_reset_after_eviction_reports_current_totals() {
        let mut tracker = FlowTracker::default();
        tracker.advance(key(1), totals(100, 10_000));
        assert_eq!(tracker.advance(key(1), totals(2, 200)), totals(2, 200));
    }

    #[test]
    fn flows_missing_from_the_map_are_forgotten() {
        let mut tracker = FlowTracker::default();
        tracker.advance(key(1), totals(10, 1000));
        tracker.advance(key(2), totals(10, 1000));

        tracker.retain_seen(&HashSet::from([key(2)]));

        assert_eq!(tracker.advance(key(1), totals(4, 400)), totals(4, 400));
        assert_eq!(tracker.advance(key(2), totals(12, 1200)), totals(2, 200));
    }
}
