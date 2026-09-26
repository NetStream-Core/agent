use anyhow::Result;
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::dns::features::QueryFeatures;
use common::{DIRECTION_EGRESS, DIRECTION_INGRESS, SIZE_BINS};

pub const EVENT_FLOW: &str = "netstream.flow";
pub const EVENT_DNS_QUERY: &str = "netstream.dns.query";
pub const EVENT_BLOCKLIST_HIT: &str = "netstream.blocklist.hit";

const EXPORT_TIMEOUT: Duration = Duration::from_secs(2);

pub type Attributes = Vec<(&'static str, AnyValue)>;

pub struct FlowRecord {
    pub direction: u8,
    pub protocol: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub interval_ms: u64,
    pub packets: u64,
    pub ip_bytes: u64,
    pub payload_bytes: u64,
    pub tcp_syn: u64,
    pub tcp_synack: u64,
    pub tcp_fin: u64,
    pub tcp_rst: u64,
    pub aggregated: u8,
    pub size_bins: [u64; SIZE_BINS],
    pub iat_count: u64,
    pub iat_sum_us: u64,
    pub iat_sumsq_us: u64,
}

pub struct DnsRecord<'a> {
    pub direction: u8,
    pub protocol: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub qtype: &'static str,
    pub name: &'a str,
    pub features: &'a QueryFeatures,
    pub unique_subdomains: usize,
}

pub struct HitRecord {
    pub src_ip: Ipv4Addr,
    pub domain: String,
    pub action: &'static str,
}

pub fn network_io_direction(direction: u8) -> &'static str {
    match direction {
        DIRECTION_INGRESS => "receive",
        DIRECTION_EGRESS => "transmit",
        _ => "unknown",
    }
}

pub fn network_transport(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

fn int(value: u64) -> AnyValue {
    AnyValue::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn text(value: impl Into<String>) -> AnyValue {
    AnyValue::from(value.into())
}

pub fn flow_attributes(r: &FlowRecord) -> Attributes {
    vec![
        (
            "network.io.direction",
            text(network_io_direction(r.direction)),
        ),
        ("network.transport", text(network_transport(r.protocol))),
        ("source.address", text(r.src_ip.to_string())),
        ("destination.address", text(r.dst_ip.to_string())),
        ("source.port", int(r.src_port.into())),
        ("destination.port", int(r.dst_port.into())),
        ("netstream.flow.interval_ms", int(r.interval_ms)),
        ("netstream.flow.packets", int(r.packets)),
        ("netstream.flow.bytes.ip", int(r.ip_bytes)),
        ("netstream.flow.bytes.payload", int(r.payload_bytes)),
        ("netstream.flow.tcp.syn", int(r.tcp_syn)),
        ("netstream.flow.tcp.synack", int(r.tcp_synack)),
        ("netstream.flow.tcp.fin", int(r.tcp_fin)),
        ("netstream.flow.tcp.rst", int(r.tcp_rst)),
        ("netstream.flow.aggregated", int(r.aggregated.into())),
        ("netstream.flow.size.le64", int(r.size_bins[0])),
        ("netstream.flow.size.le128", int(r.size_bins[1])),
        ("netstream.flow.size.le256", int(r.size_bins[2])),
        ("netstream.flow.size.le512", int(r.size_bins[3])),
        ("netstream.flow.size.le1024", int(r.size_bins[4])),
        ("netstream.flow.size.gt1024", int(r.size_bins[5])),
        ("netstream.flow.iat.count", int(r.iat_count)),
        ("netstream.flow.iat.sum_us", int(r.iat_sum_us)),
        ("netstream.flow.iat.sumsq_us", int(r.iat_sumsq_us)),
    ]
}

pub fn dns_attributes(r: &DnsRecord) -> Attributes {
    vec![
        (
            "network.io.direction",
            text(network_io_direction(r.direction)),
        ),
        ("network.transport", text(network_transport(r.protocol))),
        ("source.address", text(r.src_ip.to_string())),
        ("destination.address", text(r.dst_ip.to_string())),
        ("dns.question.name", text(r.name)),
        ("netstream.dns.question.type", text(r.qtype)),
        ("netstream.dns.qname.length", int(r.features.length as u64)),
        (
            "netstream.dns.qname.labels",
            int(r.features.label_count as u64),
        ),
        (
            "netstream.dns.qname.longest_label",
            int(r.features.longest_label as u64),
        ),
        (
            "netstream.dns.qname.entropy",
            AnyValue::Double(r.features.entropy),
        ),
        (
            "netstream.dns.qname.digit_ratio",
            AnyValue::Double(r.features.digit_ratio),
        ),
        (
            "netstream.dns.unique_subdomains",
            int(r.unique_subdomains as u64),
        ),
    ]
}

pub fn hit_attributes(r: &HitRecord) -> Attributes {
    vec![
        ("source.address", text(r.src_ip.to_string())),
        ("netstream.hit.domain", text(r.domain.clone())),
        ("netstream.hit.action", text(r.action)),
    ]
}

#[derive(Clone, Default)]
pub struct EventLog {
    logger: Option<SdkLogger>,
    boot_id: String,
    sequence: Arc<AtomicU64>,
}

impl EventLog {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn new(logger: SdkLogger, boot_id: impl Into<String>) -> Self {
        Self {
            logger: Some(logger),
            boot_id: boot_id.into(),
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    fn emit(&self, event: &'static str, severity: Severity, mut attributes: Attributes) {
        let Some(logger) = &self.logger else {
            return;
        };

        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        attributes.push(("netstream.event.sequence", int(sequence)));
        attributes.push((
            "netstream.event.id",
            text(format!("{}-{sequence}", self.boot_id)),
        ));

        let mut record = logger.create_log_record();
        record.set_event_name(event);
        record.set_timestamp(SystemTime::now());
        record.set_severity_number(severity);
        for (key, value) in attributes {
            record.add_attribute(key, value);
        }
        logger.emit(record);
    }

    pub fn flow(&self, record: &FlowRecord) {
        self.emit(EVENT_FLOW, Severity::Info, flow_attributes(record));
    }

    pub fn dns_query(&self, record: &DnsRecord) {
        self.emit(EVENT_DNS_QUERY, Severity::Info, dns_attributes(record));
    }

    pub fn blocklist_hit(&self, record: &HitRecord) {
        self.emit(EVENT_BLOCKLIST_HIT, Severity::Warn, hit_attributes(record));
    }
}

pub struct LogPipeline {
    provider: SdkLoggerProvider,
    pub events: EventLog,
}

impl LogPipeline {
    pub fn shutdown(&self) {
        if let Err(e) = self.provider.shutdown_with_timeout(EXPORT_TIMEOUT) {
            log::warn!("Error during OpenTelemetry logs shutdown: {e}");
        }
    }
}

pub fn init_otlp_logs(endpoint: &str, resource: Resource, boot_id: &str) -> Result<LogPipeline> {
    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .with_timeout(EXPORT_TIMEOUT)
        .build()?;

    let provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();
    let events = EventLog::new(provider.logger("netstream_agent"), boot_id);

    Ok(LogPipeline { provider, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::Key;
    use opentelemetry_sdk::logs::InMemoryLogExporter;
    use std::collections::HashMap;

    fn as_map(attributes: Attributes) -> HashMap<&'static str, AnyValue> {
        attributes.into_iter().collect()
    }

    fn string(value: &AnyValue) -> String {
        match value {
            AnyValue::String(s) => s.to_string(),
            other => panic!("expected a string, got {other:?}"),
        }
    }

    fn int_of(value: &AnyValue) -> i64 {
        match value {
            AnyValue::Int(i) => *i,
            other => panic!("expected an int, got {other:?}"),
        }
    }

    fn flow() -> FlowRecord {
        FlowRecord {
            direction: DIRECTION_INGRESS,
            protocol: 6,
            src_ip: Ipv4Addr::new(10, 1, 2, 3),
            dst_ip: Ipv4Addr::new(10, 9, 8, 7),
            src_port: 44321,
            dst_port: 443,
            interval_ms: 1000,
            packets: 42,
            ip_bytes: 4200,
            payload_bytes: 3000,
            tcp_syn: 5,
            tcp_synack: 0,
            tcp_fin: 2,
            tcp_rst: 1,
            aggregated: 0,
            size_bins: [10, 12, 8, 6, 4, 2],
            iat_count: 41,
            iat_sum_us: 990000,
            iat_sumsq_us: 24000000,
        }
    }

    #[test]
    fn directions_and_transports_use_semantic_convention_values() {
        assert_eq!(network_io_direction(DIRECTION_INGRESS), "receive");
        assert_eq!(network_io_direction(DIRECTION_EGRESS), "transmit");
        assert_eq!(network_io_direction(9), "unknown");
        assert_eq!(network_transport(6), "tcp");
        assert_eq!(network_transport(17), "udp");
        assert_eq!(network_transport(1), "icmp");
        assert_eq!(network_transport(47), "other");
    }

    #[test]
    fn flow_attributes_follow_the_contract() {
        let a = as_map(flow_attributes(&flow()));

        assert_eq!(a.len(), 24);
        assert_eq!(string(&a["network.io.direction"]), "receive");
        assert_eq!(string(&a["network.transport"]), "tcp");
        assert_eq!(string(&a["source.address"]), "10.1.2.3");
        assert_eq!(string(&a["destination.address"]), "10.9.8.7");
        assert_eq!(int_of(&a["source.port"]), 44321);
        assert_eq!(int_of(&a["destination.port"]), 443);
        assert_eq!(int_of(&a["netstream.flow.interval_ms"]), 1000);
        assert_eq!(int_of(&a["netstream.flow.packets"]), 42);
        assert_eq!(int_of(&a["netstream.flow.bytes.ip"]), 4200);
        assert_eq!(int_of(&a["netstream.flow.bytes.payload"]), 3000);
        assert_eq!(int_of(&a["netstream.flow.tcp.syn"]), 5);
        assert_eq!(int_of(&a["netstream.flow.tcp.synack"]), 0);
        assert_eq!(int_of(&a["netstream.flow.tcp.fin"]), 2);
        assert_eq!(int_of(&a["netstream.flow.tcp.rst"]), 1);
        assert_eq!(int_of(&a["netstream.flow.aggregated"]), 0);
        assert_eq!(int_of(&a["netstream.flow.size.le64"]), 10);
        assert_eq!(int_of(&a["netstream.flow.size.le128"]), 12);
        assert_eq!(int_of(&a["netstream.flow.size.le256"]), 8);
        assert_eq!(int_of(&a["netstream.flow.size.le512"]), 6);
        assert_eq!(int_of(&a["netstream.flow.size.le1024"]), 4);
        assert_eq!(int_of(&a["netstream.flow.size.gt1024"]), 2);
        assert_eq!(int_of(&a["netstream.flow.iat.count"]), 41);
        assert_eq!(int_of(&a["netstream.flow.iat.sum_us"]), 990000);
        assert_eq!(int_of(&a["netstream.flow.iat.sumsq_us"]), 24000000);
    }

    #[test]
    fn aggregated_flows_carry_their_aggregation_level() {
        for level in [1u8, 2] {
            let mut record = flow();
            record.aggregated = level;
            assert_eq!(
                int_of(&as_map(flow_attributes(&record))["netstream.flow.aggregated"]),
                level as i64
            );
        }
    }

    #[test]
    fn counters_beyond_i64_are_clamped_not_wrapped() {
        let mut record = flow();
        record.packets = u64::MAX;
        assert_eq!(
            int_of(&as_map(flow_attributes(&record))["netstream.flow.packets"]),
            i64::MAX
        );
    }

    #[test]
    fn dns_attributes_follow_the_contract() {
        let features = crate::dns::features::features("nb2xgzlsmvzgs3tfebzgk4tp.t.tunnel.test");
        let record = DnsRecord {
            direction: DIRECTION_EGRESS,
            protocol: 17,
            src_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            qtype: "TXT",
            name: "nb2xgzlsmvzgs3tfebzgk4tp.t.tunnel.test",
            features: &features,
            unique_subdomains: 30,
        };

        let a = as_map(dns_attributes(&record));

        assert_eq!(a.len(), 12);
        assert_eq!(string(&a["network.io.direction"]), "transmit");
        assert_eq!(string(&a["dns.question.name"]), record.name);
        assert_eq!(string(&a["netstream.dns.question.type"]), "TXT");
        assert_eq!(int_of(&a["netstream.dns.qname.length"]), 38);
        assert_eq!(int_of(&a["netstream.dns.qname.labels"]), 4);
        assert_eq!(int_of(&a["netstream.dns.qname.longest_label"]), 24);
        assert_eq!(int_of(&a["netstream.dns.unique_subdomains"]), 30);
        assert!(matches!(a["netstream.dns.qname.entropy"], AnyValue::Double(e) if e > 3.0));
        assert!(matches!(
            a["netstream.dns.qname.digit_ratio"],
            AnyValue::Double(_)
        ));
    }

    #[test]
    fn hit_attributes_follow_the_contract() {
        let a = as_map(hit_attributes(&HitRecord {
            src_ip: Ipv4Addr::new(10, 0, 0, 7),
            domain: "blocked-test.example".to_string(),
            action: "quarantined",
        }));

        assert_eq!(a.len(), 3);
        assert_eq!(string(&a["source.address"]), "10.0.0.7");
        assert_eq!(string(&a["netstream.hit.domain"]), "blocked-test.example");
        assert_eq!(string(&a["netstream.hit.action"]), "quarantined");
    }

    #[test]
    fn emitted_records_carry_event_name_severity_attributes_and_resource() {
        let exporter = InMemoryLogExporter::default();
        let (resource, boot_id) =
            crate::telemetry::resource::build(Some("sensor-1".into()), "eth0");
        let provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .with_simple_exporter(exporter.clone())
            .build();
        let events = EventLog::new(provider.logger("test"), boot_id.clone());

        events.flow(&flow());
        events.blocklist_hit(&HitRecord {
            src_ip: Ipv4Addr::new(10, 0, 0, 7),
            domain: "x.example".to_string(),
            action: "dropped",
        });

        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 2);

        let flow_log = &emitted[0];
        assert_eq!(flow_log.record.event_name(), Some(EVENT_FLOW));
        assert_eq!(flow_log.record.severity_number(), Some(Severity::Info));
        assert!(flow_log.record.timestamp().is_some());
        let flow_attrs: HashMap<String, AnyValue> = flow_log
            .record
            .attributes_iter()
            .map(|(key, value)| (key.as_str().to_string(), value.clone()))
            .collect();
        assert_eq!(flow_attrs.len(), 26);
        assert_eq!(
            string(&flow_attrs["netstream.event.id"]),
            format!("{boot_id}-0")
        );
        assert_eq!(
            flow_log
                .resource
                .get(&Key::from_static_str("host.id"))
                .unwrap()
                .as_str(),
            "sensor-1"
        );
        assert_eq!(
            flow_log
                .resource
                .get(&Key::from_static_str("service.instance.id"))
                .unwrap()
                .as_str(),
            boot_id
        );

        let hit_log = &emitted[1];
        assert_eq!(hit_log.record.event_name(), Some(EVENT_BLOCKLIST_HIT));
        assert_eq!(hit_log.record.severity_number(), Some(Severity::Warn));
        let hit_attrs: HashMap<String, AnyValue> = hit_log
            .record
            .attributes_iter()
            .map(|(key, value)| (key.as_str().to_string(), value.clone()))
            .collect();
        assert_eq!(
            string(&hit_attrs["netstream.event.id"]),
            format!("{boot_id}-1")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a running collector, set OTLP_TEST_ENDPOINT"]
    async fn records_are_exported_to_a_collector() {
        let endpoint = std::env::var("OTLP_TEST_ENDPOINT").expect("OTLP_TEST_ENDPOINT");
        let (resource, boot_id) = crate::telemetry::resource::build(Some("rust-test".into()), "lo");
        let pipeline = init_otlp_logs(&endpoint, resource, &boot_id).expect("logs pipeline");

        let features = crate::dns::features::features("www.example.com");
        pipeline.events.flow(&flow());
        pipeline.events.dns_query(&DnsRecord {
            direction: DIRECTION_EGRESS,
            protocol: 17,
            src_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            qtype: "A",
            name: "www.example.com",
            features: &features,
            unique_subdomains: 1,
        });
        pipeline.events.blocklist_hit(&HitRecord {
            src_ip: Ipv4Addr::new(10, 0, 0, 7),
            domain: "blocked-test.example".to_string(),
            action: "observed",
        });
        pipeline.shutdown();
    }

    #[test]
    fn a_disabled_log_emits_nothing_and_does_not_panic() {
        let events = EventLog::disabled();
        events.flow(&flow());
    }
}
