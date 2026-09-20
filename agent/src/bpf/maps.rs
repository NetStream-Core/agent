use anyhow::Result;
use aya::maps::{MapData, PerCpuHashMap};
use common::{
    DIRECTION_EGRESS, DIRECTION_INGRESS, KEY_FLAG_AGGREGATED, KEY_FLAG_PORTS_MERGED, PacketKey,
    PacketValue,
};
use log;
use opentelemetry::{KeyValue, global};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

use crate::telemetry::logs::{EventLog, FlowRecord, network_transport};

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

    fn accumulate(&mut self, other: &Self) {
        self.count = self.count.saturating_add(other.count);
        self.payload_size = self.payload_size.saturating_add(other.payload_size);
        self.ip_bytes = self.ip_bytes.saturating_add(other.ip_bytes);
        self.add_tcp_flags(other);
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
    under_pressure: bool,
    overflowing: bool,
}

impl FlowTracker {
    fn advance(&mut self, key: PacketKey, current: Totals) -> Totals {
        let previous = self.previous.insert(key, current).unwrap_or_default();
        current.since(previous)
    }

    fn retain_seen(&mut self, seen: &HashSet<PacketKey>) {
        self.previous.retain(|key, _| seen.contains(key));
    }

    fn note_overflow(&mut self, overflowing: bool) -> bool {
        let started = overflowing && !self.overflowing;
        self.overflowing = overflowing;
        started
    }

    fn note_pressure(&mut self, active: usize, capacity: usize) -> bool {
        let pressured = capacity > 0 && active * 2 >= capacity;
        let started = pressured && !self.under_pressure;
        self.under_pressure = pressured;
        started
    }
}

pub struct CollectContext {
    pub interval_ms: u64,
    pub top_n: usize,
    pub capacity: usize,
}

fn aggregation_level(flags: u16) -> u8 {
    if flags & KEY_FLAG_PORTS_MERGED != 0 {
        2
    } else if flags & KEY_FLAG_AGGREGATED != 0 {
        1
    } else {
        0
    }
}

fn select_top(
    mut deltas: Vec<(PacketKey, Totals)>,
    top_n: usize,
) -> (Vec<(PacketKey, Totals)>, usize) {
    if top_n == 0 || deltas.len() <= top_n {
        return (deltas, 0);
    }

    deltas.sort_by_key(|delta| Reverse(delta.1.count));
    let leftover = deltas.split_off(top_n);
    let merged_flows = leftover.len();

    let mut merged: HashMap<PacketKey, Totals> = HashMap::new();
    for (key, delta) in leftover {
        let aggregated = PacketKey {
            src_port: 0,
            dst_port: 0,
            flags: key.flags | KEY_FLAG_AGGREGATED | KEY_FLAG_PORTS_MERGED,
            ..key
        };
        merged.entry(aggregated).or_default().accumulate(&delta);
    }

    for (key, delta) in merged {
        match deltas.iter_mut().find(|(kept, _)| *kept == key) {
            Some((_, existing)) => existing.accumulate(&delta),
            None => deltas.push((key, delta)),
        }
    }

    (deltas, merged_flows)
}

fn metric_attributes(direction: u8, protocol: u8) -> [KeyValue; 2] {
    [
        KeyValue::new("direction", direction_label(direction)),
        KeyValue::new("transport", network_transport(protocol)),
    ]
}

fn ipv4_from_network_order(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(raw))
}

pub fn direction_label(direction: u8) -> &'static str {
    match direction {
        DIRECTION_INGRESS => "rx",
        DIRECTION_EGRESS => "tx",
        _ => "unknown",
    }
}

pub async fn collect_and_report_metrics(
    packet_counts: &Arc<Mutex<PerCpuHashMap<MapData, PacketKey, PacketValue>>>,
    tracker: &mut FlowTracker,
    events: &EventLog,
    context: &CollectContext,
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

    let table_entries = meter
        .u64_gauge("netstream_flow_table_entries")
        .with_description("Flows currently held in the kernel flow table")
        .build();

    let active_flows = meter
        .u64_gauge("netstream_flow_active")
        .with_description("Flows that carried packets during the last interval")
        .build();

    let overflow_counter = meter
        .u64_counter("netstream_flow_overflow_packets_total")
        .with_description(
            "Packets counted in aggregated flows because the new-flow budget was exhausted",
        )
        .build();

    let omitted_counter = meter
        .u64_counter("netstream_flow_logs_merged_total")
        .with_description("Flows merged into aggregated records by the per-interval log limit")
        .build();

    let map = packet_counts.lock().await;

    let mut seen = HashSet::new();
    let mut deltas = Vec::new();

    for entry in map.iter() {
        let (key, values) = entry?;
        seen.insert(key);

        let delta = tracker.advance(key, Totals::from_cpus(&values));
        if delta.count > 0 {
            deltas.push((key, delta));
        }
    }

    tracker.retain_seen(&seen);

    table_entries.record(seen.len() as u64, &[]);
    active_flows.record(deltas.len() as u64, &[]);
    if tracker.note_pressure(deltas.len(), context.capacity) {
        log::warn!(
            "{} flows were active in one interval, more than half of the {} entry table: live flows may be evicted and undercounted, consider raising FLOW_TABLE_ENTRIES",
            deltas.len(),
            context.capacity
        );
    }

    let overflow_packets: u64 = deltas
        .iter()
        .filter(|(key, _)| key.flags & KEY_FLAG_AGGREGATED != 0)
        .map(|(_, delta)| delta.count)
        .sum();
    if overflow_packets > 0 {
        overflow_counter.add(overflow_packets, &[]);
    }
    if tracker.note_overflow(overflow_packets > 0) {
        log::warn!(
            "New-flow budget exhausted: {overflow_packets} packets in this interval were counted in aggregated flows without ports"
        );
    }

    let mut totals_by_group: HashMap<(u8, u8), Totals> = HashMap::new();
    let mut flags_by_direction: HashMap<u8, Totals> = HashMap::new();
    for (key, delta) in &deltas {
        totals_by_group
            .entry((key.direction, key.protocol))
            .or_default()
            .accumulate(delta);
        flags_by_direction
            .entry(key.direction)
            .or_default()
            .add_tcp_flags(delta);
    }

    for ((direction, protocol), totals) in &totals_by_group {
        let attributes = metric_attributes(*direction, *protocol);
        packet_counter.add(totals.count, &attributes);
        payload_counter.add(totals.payload_size, &attributes);
        ip_bytes_counter.add(totals.ip_bytes, &attributes);
    }

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

    let reported = deltas.len();
    let (kept, omitted) = select_top(deltas, context.top_n);

    for (key, delta) in &kept {
        events.flow(&FlowRecord {
            direction: key.direction,
            protocol: key.protocol,
            src_ip: ipv4_from_network_order(key.src_ip),
            dst_ip: ipv4_from_network_order(key.dst_ip),
            src_port: key.src_port,
            dst_port: key.dst_port,
            interval_ms: context.interval_ms,
            packets: delta.count,
            ip_bytes: delta.ip_bytes,
            payload_bytes: delta.payload_size,
            tcp_syn: delta.tcp_syn,
            tcp_synack: delta.tcp_synack,
            tcp_fin: delta.tcp_fin,
            tcp_rst: delta.tcp_rst,
            aggregated: aggregation_level(key.flags),
        });
    }

    if omitted > 0 {
        omitted_counter.add(omitted as u64, &[]);
        log::warn!(
            "Merged {} of {} active flows into aggregated records (FLOW_LOG_TOP_N={})",
            omitted,
            reported,
            context.top_n
        );
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
            flags: 0,
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
    fn metric_attributes_carry_no_addresses_or_ports() {
        let attributes = metric_attributes(DIRECTION_EGRESS, 17);

        assert_eq!(attributes.len(), 2);
        assert_eq!(attribute(&attributes, "direction"), "tx");
        assert_eq!(attribute(&attributes, "transport"), "udp");
    }

    #[test]
    fn top_flows_are_kept_and_the_rest_is_merged_without_losing_packets() {
        let deltas: Vec<_> = (1..=5)
            .map(|port| (key(port), totals(port as u64 * 10, port as u64 * 100)))
            .collect();

        let (records, merged) = select_top(deltas, 2);

        assert_eq!(merged, 3);
        assert_eq!(records.len(), 3);
        assert_eq!(records.iter().map(|(_, t)| t.count).sum::<u64>(), 150);
        assert_eq!(
            records.iter().map(|(_, t)| t.payload_size).sum::<u64>(),
            1500
        );

        let aggregated: Vec<_> = records
            .iter()
            .filter(|(k, _)| k.flags & KEY_FLAG_AGGREGATED != 0)
            .collect();
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].0.src_port, 0);
        assert_eq!(aggregated[0].1.count, 60);
    }

    #[test]
    fn aggregation_levels_follow_the_key_flags() {
        assert_eq!(aggregation_level(0), 0);
        assert_eq!(aggregation_level(KEY_FLAG_AGGREGATED), 1);
        assert_eq!(
            aggregation_level(KEY_FLAG_AGGREGATED | KEY_FLAG_PORTS_MERGED),
            2
        );
    }

    #[test]
    fn merged_flows_of_different_host_pairs_stay_separate() {
        let mut other = key(9);
        other.dst_ip = 99;
        let deltas = vec![
            (key(1), totals(100, 0)),
            (key(2), totals(3, 0)),
            (other, totals(4, 0)),
        ];

        let (records, merged) = select_top(deltas, 1);

        assert_eq!(merged, 2);
        assert_eq!(records.len(), 3);
        assert_eq!(records.iter().map(|(_, t)| t.count).sum::<u64>(), 107);
    }

    #[test]
    fn merged_flows_join_an_existing_aggregated_record() {
        let mut aggregated_key = key(0);
        aggregated_key.src_port = 0;
        aggregated_key.dst_port = 0;
        aggregated_key.flags = KEY_FLAG_AGGREGATED | KEY_FLAG_PORTS_MERGED;
        let deltas = vec![
            (aggregated_key, totals(1000, 0)),
            (key(1), totals(5, 0)),
            (key(2), totals(6, 0)),
        ];

        let (records, _) = select_top(deltas, 1);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1.count, 1011);
    }

    #[test]
    fn zero_or_large_limits_keep_every_flow() {
        let deltas: Vec<_> = (1..=4).map(|port| (key(port), totals(1, 0))).collect();
        assert_eq!(select_top(deltas.clone(), 0).1, 0);
        assert_eq!(select_top(deltas.clone(), 0).0.len(), 4);
        assert_eq!(select_top(deltas, 4).0.len(), 4);
    }

    #[test]
    fn pressure_warning_fires_once_per_episode() {
        let mut tracker = FlowTracker::default();

        assert!(!tracker.note_pressure(400, 1000));
        assert!(tracker.note_pressure(500, 1000));
        assert!(!tracker.note_pressure(900, 1000));
        assert!(!tracker.note_pressure(100, 1000));
        assert!(tracker.note_pressure(1000, 1000));
        assert!(!tracker.note_pressure(1, 0));
    }

    #[test]
    fn overflow_warning_fires_when_a_burst_starts() {
        let mut tracker = FlowTracker::default();

        assert!(!tracker.note_overflow(false));
        assert!(tracker.note_overflow(true));
        assert!(!tracker.note_overflow(true));
        assert!(!tracker.note_overflow(false));
        assert!(tracker.note_overflow(true));
    }

    #[test]
    fn totals_accumulate_volumes_and_flags() {
        let mut sum = Totals::default();
        sum.accumulate(&Totals {
            count: 3,
            payload_size: 30,
            ip_bytes: 40,
            tcp_syn: 2,
            ..Totals::default()
        });
        sum.accumulate(&Totals {
            count: 1,
            payload_size: 5,
            ip_bytes: 6,
            tcp_rst: 1,
            ..Totals::default()
        });

        assert_eq!(
            sum,
            Totals {
                count: 4,
                payload_size: 35,
                ip_bytes: 46,
                tcp_syn: 2,
                tcp_rst: 1,
                ..Totals::default()
            }
        );
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
