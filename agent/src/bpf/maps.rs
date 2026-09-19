use anyhow::Result;
use aya::maps::{MapData, PerCpuHashMap};
use common::{DIRECTION_EGRESS, DIRECTION_INGRESS, PacketKey, PacketValue};
use log;
use opentelemetry::{KeyValue, global};
use std::collections::{HashMap, HashSet};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Totals {
    count: u64,
    payload_size: u64,
    ip_bytes: u64,
    tcp_syn: u64,
    tcp_synack: u64,
    tcp_fin: u64,
    tcp_rst: u64,
}

impl Totals {
    fn from_cpus(values: &[PacketValue]) -> Self {
        values.iter().fold(Self::default(), |acc, v| Self {
            count: acc.count.saturating_add(v.count),
            payload_size: acc.payload_size.saturating_add(v.payload_size),
            ip_bytes: acc.ip_bytes.saturating_add(v.ip_bytes),
            tcp_syn: acc.tcp_syn.saturating_add(v.tcp_syn),
            tcp_synack: acc.tcp_synack.saturating_add(v.tcp_synack),
            tcp_fin: acc.tcp_fin.saturating_add(v.tcp_fin),
            tcp_rst: acc.tcp_rst.saturating_add(v.tcp_rst),
        })
    }

    fn since(self, previous: Self) -> Self {
        if self.count < previous.count {
            return self;
        }
        Self {
            count: self.count - previous.count,
            payload_size: self.payload_size.saturating_sub(previous.payload_size),
            ip_bytes: self.ip_bytes.saturating_sub(previous.ip_bytes),
            tcp_syn: self.tcp_syn.saturating_sub(previous.tcp_syn),
            tcp_synack: self.tcp_synack.saturating_sub(previous.tcp_synack),
            tcp_fin: self.tcp_fin.saturating_sub(previous.tcp_fin),
            tcp_rst: self.tcp_rst.saturating_sub(previous.tcp_rst),
        }
    }

    fn add_tcp_flags(&mut self, other: &Self) {
        self.tcp_syn = self.tcp_syn.saturating_add(other.tcp_syn);
        self.tcp_synack = self.tcp_synack.saturating_add(other.tcp_synack);
        self.tcp_fin = self.tcp_fin.saturating_add(other.tcp_fin);
        self.tcp_rst = self.tcp_rst.saturating_add(other.tcp_rst);
    }

    fn tcp_flags(&self) -> [(&'static str, u64); 4] {
        [
            ("syn", self.tcp_syn),
            ("synack", self.tcp_synack),
            ("fin", self.tcp_fin),
            ("rst", self.tcp_rst),
        ]
    }
}

#[derive(Default)]
pub struct FlowTracker {
    previous: HashMap<PacketKey, Totals>,
}

impl FlowTracker {
    fn advance(&mut self, key: PacketKey, current: Totals) -> Totals {
        let previous = self.previous.insert(key, current).unwrap_or_default();
        current.since(previous)
    }

    fn retain_seen(&mut self, seen: &HashSet<PacketKey>) {
        self.previous.retain(|key, _| seen.contains(key));
    }
}

fn ipv4_from_network_order(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(raw))
}

fn direction_label(direction: u8) -> &'static str {
    match direction {
        DIRECTION_INGRESS => "rx",
        DIRECTION_EGRESS => "tx",
        _ => "unknown",
    }
}

fn flow_attributes(key: &PacketKey) -> [KeyValue; 6] {
    [
        KeyValue::new("protocol", key.protocol.to_string()),
        KeyValue::new("direction", direction_label(key.direction)),
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

    let ip_bytes_counter = meter
        .u64_counter("netstream_ip_bytes_total")
        .with_description("Total volume of IP bytes including headers")
        .build();

    let tcp_flags_counter = meter
        .u64_counter("netstream_tcp_flags_total")
        .with_description("Total TCP packets by flag, aggregated over all flows")
        .build();

    let map = packet_counts.lock().await;

    let mut seen = HashSet::new();
    let mut flags_by_direction: HashMap<u8, Totals> = HashMap::new();
    let mut reported = 0;

    for entry in map.iter() {
        let (key, values) = entry?;
        seen.insert(key);

        let delta = tracker.advance(key, Totals::from_cpus(&values));
        if delta.count == 0 {
            continue;
        }
        reported += 1;

        let attributes = flow_attributes(&key);
        packet_counter.add(delta.count, &attributes);
        payload_counter.add(delta.payload_size, &attributes);
        ip_bytes_counter.add(delta.ip_bytes, &attributes);

        flags_by_direction
            .entry(key.direction)
            .or_default()
            .add_tcp_flags(&delta);
    }

    tracker.retain_seen(&seen);

    for (direction, totals) in &flags_by_direction {
        for (flag, value) in totals.tcp_flags() {
            if value > 0 {
                tcp_flags_counter.add(
                    value,
                    &[
                        KeyValue::new("direction", direction_label(*direction)),
                        KeyValue::new("flag", flag),
                    ],
                );
            }
        }
    }

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

    fn key(src_port: u16) -> PacketKey {
        PacketKey {
            src_ip: 1,
            dst_ip: 2,
            src_port,
            dst_port: 443,
            protocol: 6,
            direction: DIRECTION_INGRESS,
            _padding: 0,
        }
    }

    fn totals(count: u64, payload_size: u64) -> Totals {
        Totals {
            count,
            payload_size,
            ..Totals::default()
        }
    }

    fn value(count: u64, payload_size: u64) -> PacketValue {
        PacketValue {
            count,
            timestamp: 0,
            payload_size,
            ip_bytes: 0,
            tcp_syn: 0,
            tcp_synack: 0,
            tcp_fin: 0,
            tcp_rst: 0,
        }
    }

    #[test]
    fn converts_network_order_bytes_to_ipv4() {
        let raw = u32::from_ne_bytes([192, 168, 1, 1]);
        assert_eq!(ipv4_from_network_order(raw), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn flow_attributes_use_dotted_ipv4_in_wire_order() {
        let key = PacketKey {
            src_ip: u32::from_ne_bytes([192, 168, 1, 10]),
            dst_ip: u32::from_ne_bytes([8, 8, 4, 4]),
            src_port: 44321,
            dst_port: 443,
            protocol: 6,
            direction: DIRECTION_EGRESS,
            _padding: 0,
        };

        let attributes = flow_attributes(&key);

        assert_eq!(attribute(&attributes, "src_ip"), "192.168.1.10");
        assert_eq!(attribute(&attributes, "dst_ip"), "8.8.4.4");
        assert_eq!(attribute(&attributes, "protocol"), "6");
        assert_eq!(attribute(&attributes, "direction"), "tx");
        assert_eq!(attribute(&attributes, "src_port"), "44321");
        assert_eq!(attribute(&attributes, "dst_port"), "443");
    }

    #[test]
    fn direction_labels() {
        assert_eq!(direction_label(DIRECTION_INGRESS), "rx");
        assert_eq!(direction_label(DIRECTION_EGRESS), "tx");
        assert_eq!(direction_label(7), "unknown");
    }

    #[test]
    fn per_cpu_values_are_summed_including_flags_and_ip_bytes() {
        let mut a = value(3, 300);
        a.ip_bytes = 400;
        a.tcp_syn = 2;
        a.tcp_fin = 1;
        let mut b = value(5, 500);
        b.ip_bytes = 700;
        b.tcp_syn = 1;
        b.tcp_synack = 4;
        b.tcp_rst = 6;

        let sum = Totals::from_cpus(&[a, b, value(0, 0)]);

        assert_eq!(
            sum,
            Totals {
                count: 8,
                payload_size: 800,
                ip_bytes: 1100,
                tcp_syn: 3,
                tcp_synack: 4,
                tcp_fin: 1,
                tcp_rst: 6,
            }
        );
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
    fn flag_counters_are_reported_as_deltas() {
        let mut tracker = FlowTracker::default();
        let first = Totals {
            count: 5,
            tcp_syn: 5,
            ..Totals::default()
        };
        let second = Totals {
            count: 9,
            tcp_syn: 7,
            tcp_rst: 2,
            ..Totals::default()
        };

        tracker.advance(key(1), first);
        let delta = tracker.advance(key(1), second);

        assert_eq!(delta.count, 4);
        assert_eq!(delta.tcp_syn, 2);
        assert_eq!(delta.tcp_rst, 2);
    }

    #[test]
    fn flows_are_tracked_independently() {
        let mut tracker = FlowTracker::default();
        tracker.advance(key(1), totals(10, 1000));
        assert_eq!(tracker.advance(key(2), totals(3, 30)), totals(3, 30));
        assert_eq!(tracker.advance(key(1), totals(11, 1100)), totals(1, 100));
    }

    #[test]
    fn directions_are_tracked_independently() {
        let mut tracker = FlowTracker::default();
        let mut egress = key(1);
        egress.direction = DIRECTION_EGRESS;

        tracker.advance(key(1), totals(10, 1000));
        assert_eq!(tracker.advance(egress, totals(3, 30)), totals(3, 30));
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

    #[test]
    fn tcp_flags_are_aggregated_by_name() {
        let mut total = Totals::default();
        total.add_tcp_flags(&Totals {
            tcp_syn: 3,
            tcp_rst: 1,
            ..Totals::default()
        });
        total.add_tcp_flags(&Totals {
            tcp_syn: 2,
            tcp_fin: 4,
            ..Totals::default()
        });

        assert_eq!(
            total.tcp_flags(),
            [("syn", 5), ("synack", 0), ("fin", 4), ("rst", 1)]
        );
    }
}
