use aya::maps::{MapData, PerCpuArray, RingBuf};
use common::DnsEvent;
use log::{debug, warn};
use opentelemetry::{KeyValue, global};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::time::interval;

use super::features::{SubdomainTracker, decode_qname, features, qtype_label};
use crate::bpf::direction_label;
use crate::telemetry::logs::{DnsRecord, EventLog};

const SUBDOMAIN_WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_DOMAINS: usize = 4096;
const MAX_TRACKED_SUBDOMAINS: usize = 1024;
const LOST_REPORT_INTERVAL: Duration = Duration::from_secs(1);

fn lost_total(lost: &PerCpuArray<MapData, u64>) -> u64 {
    lost.get(&0, 0)
        .map(|values| values.iter().copied().fold(0u64, u64::saturating_add))
        .unwrap_or(0)
}

pub fn spawn_dns_monitor(
    ring_buf: RingBuf<MapData>,
    lost: PerCpuArray<MapData, u64>,
    events: EventLog,
) {
    tokio::spawn(async move {
        let meter = global::meter("netstream_agent");
        let queries = meter
            .u64_counter("netstream_dns_queries_total")
            .with_description("DNS queries seen by the sensor")
            .build();
        let length = meter
            .u64_histogram("netstream_dns_qname_length")
            .with_description("Length of the queried name in characters")
            .with_boundaries(vec![
                8.0, 16.0, 24.0, 32.0, 48.0, 64.0, 96.0, 128.0, 192.0, 253.0,
            ])
            .build();
        let entropy = meter
            .f64_histogram("netstream_dns_qname_entropy")
            .with_description("Shannon entropy of the queried name in bits per character")
            .with_boundaries(vec![1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5])
            .build();
        let unique = meter
            .u64_histogram("netstream_dns_unique_subdomains")
            .with_description("Unique subdomains of the registered domain seen in the last minute")
            .with_boundaries(vec![
                1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0,
            ])
            .build();
        let lost_counter = meter
            .u64_counter("netstream_dns_events_lost_total")
            .with_description("DNS events dropped because the ring buffer was full")
            .build();

        let mut async_fd = match AsyncFd::with_interest(ring_buf, Interest::READABLE) {
            Ok(fd) => fd,
            Err(e) => {
                warn!("Failed to create AsyncFd for DNS events: {e}");
                return;
            }
        };

        let mut tracker = SubdomainTracker::new(
            SUBDOMAIN_WINDOW,
            MAX_TRACKED_DOMAINS,
            MAX_TRACKED_SUBDOMAINS,
        );
        let mut reported_lost = 0u64;
        let mut lost_tick = interval(LOST_REPORT_INTERVAL);

        loop {
            tokio::select! {
                _ = lost_tick.tick() => {
                    let total = lost_total(&lost);
                    if total > reported_lost {
                        lost_counter.add(total - reported_lost, &[]);
                        warn!("Dropped {} DNS events (ring buffer full)", total - reported_lost);
                        reported_lost = total;
                    }
                }

                ready = async_fd.readable_mut() => {
                    let mut guard = match ready {
                        Ok(guard) => guard,
                        Err(e) => {
                            warn!("DNS ring buffer error: {e}");
                            continue;
                        }
                    };

                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        let Some(event) = DnsEvent::parse(&item) else {
                            continue;
                        };

                        let direction = direction_label(event.direction);
                        let qtype = qtype_label(event.qtype);
                        queries.add(1, &[
                            KeyValue::new("direction", direction),
                            KeyValue::new("qtype", qtype),
                        ]);

                        let Some(name) = decode_qname(event.qname_wire()) else {
                            debug!("Skipping DNS event with a malformed name");
                            continue;
                        };

                        let f = features(&name);
                        let unique_subdomains = tracker.observe(Instant::now(), &name);
                        let attributes = [KeyValue::new("direction", direction)];
                        length.record(f.length as u64, &attributes);
                        entropy.record(f.entropy, &attributes);
                        unique.record(unique_subdomains as u64, &attributes);

                        events.dns_query(&DnsRecord {
                            direction: event.direction,
                            src_ip: Ipv4Addr::from(u32::from_be(event.src_ip)),
                            dst_ip: Ipv4Addr::from(u32::from_be(event.dst_ip)),
                            qtype,
                            name: &name,
                            features: &f,
                            unique_subdomains,
                        });

                        debug!(
                            "dns query dir={} src={} dst={} qtype={} name={} len={} labels={} longest={} entropy={:.3} digits={:.3} unique_subdomains={}",
                            direction,
                            Ipv4Addr::from(u32::from_be(event.src_ip)),
                            Ipv4Addr::from(u32::from_be(event.dst_ip)),
                            qtype,
                            name,
                            f.length,
                            f.label_count,
                            f.longest_label,
                            f.entropy,
                            f.digit_ratio,
                            unique_subdomains,
                        );
                    }
                    guard.clear_ready();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use common::DnsEvent;

    fn event_bytes(qtype: u16, direction: u8, wire: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(1u32.to_ne_bytes());
        bytes.extend(2u32.to_ne_bytes());
        bytes.extend(qtype.to_ne_bytes());
        bytes.push(direction);
        bytes.push(wire.len() as u8);
        let mut name = [0u8; 256];
        name[..wire.len()].copy_from_slice(wire);
        bytes.extend(name);
        bytes
    }

    #[test]
    fn dns_event_is_parsed_from_ring_buffer_bytes() {
        let wire = [3, b'w', b'w', b'w', 3, b'c', b'o', b'm'];
        let bytes = event_bytes(16, 1, &wire);
        assert_eq!(bytes.len(), 268);

        let event = DnsEvent::parse(&bytes).expect("parsed");

        assert_eq!(event.qtype, 16);
        assert_eq!(event.direction, 1);
        assert_eq!(event.qname_wire(), wire);
    }

    #[test]
    fn short_buffers_are_rejected() {
        let bytes = event_bytes(1, 0, &[1, b'a']);
        assert!(DnsEvent::parse(&bytes[..267]).is_none());
        assert!(DnsEvent::parse(&[]).is_none());
    }
}
