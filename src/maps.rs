use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use log::info;
use std::fs;
use std::net::Ipv4Addr;

use crate::metrics::proto::PacketMetric;
use crate::types::{PacketKey, PacketValue};
use crate::xxh64::xxh64_hash;

pub fn load_malware_domains(
    bpf: &mut Ebpf,
) -> Result<aya::maps::HashMap<&mut MapData, u64, u8>, anyhow::Error> {
    let malware_domains_map = bpf
        .map_mut("malware_domains")
        .ok_or_else(|| anyhow!("Map 'malware_domains' not found"))?;
    let mut malware_domains: HashMap<_, u64, u8> = HashMap::try_from(malware_domains_map)?;

    let domains = fs::read_to_string("malware_domains.txt").unwrap_or_default();
    for domain in domains.lines() {
        let domain = domain.trim();
        if !domain.is_empty() {
            let domain_hash = xxh64_hash(domain.as_bytes());
            malware_domains.insert(domain_hash, 1, 0)?;
            info!("Added malware domain: {} (hash: {})", domain, domain_hash);
        }
    }

    Ok(malware_domains)
}

pub fn collect_metrics(
    packet_counts: &HashMap<&MapData, PacketKey, PacketValue>,
) -> Result<Vec<PacketMetric>, anyhow::Error> {
    let mut metrics = vec![];
    for entry in packet_counts.iter().filter_map(|r| r.ok()) {
        let (key, value) = entry;
        metrics.push(PacketMetric {
            protocol: key.protocol,
            count: value.count,
            src_ip: Ipv4Addr::from(key.src_ip).to_string(),
            dst_ip: Ipv4Addr::from(key.dst_ip).to_string(),
            src_port: key.src_port as u32,
            dst_port: key.dst_port as u32,
            timestamp: value.timestamp,
            payload_size: value.payload_size,
        });
    }
    Ok(metrics)
}
