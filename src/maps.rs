use crate::metrics::proto::PacketMetric;
use crate::types::{PacketKey, PacketValue};
use crate::xxh64::xxh64_hash;
use anyhow::Result;
use aya::{
    Ebpf,
    maps::{HashMap, MapData},
};
use log::info;
use std::{collections::HashMap as StdHashMap, fs, net::Ipv4Addr, sync::Arc};
use tokio::sync::Mutex;

pub fn load_malware_domains(bpf: &mut Ebpf) -> Result<StdHashMap<String, u8>> {
    let malware_domains_map = bpf
        .map_mut("malware_domains")
        .ok_or_else(|| anyhow::anyhow!("Map 'malware_domains' not found"))?;
    let mut malware_domains: HashMap<_, u64, u8> = HashMap::try_from(malware_domains_map)?;
    let mut domains = StdHashMap::new();

    let file_domains = fs::read_to_string("malware_domains.txt").unwrap_or_default();
    for domain in file_domains.lines() {
        let domain = domain.trim();
        if !domain.is_empty() {
            let domain_hash = xxh64_hash(domain.as_bytes());
            malware_domains.insert(domain_hash, 1, 0)?;
            domains.insert(domain.to_string(), 1);
            info!("Added malware domain: {} (hash: {})", domain, domain_hash);
        }
    }

    Ok(domains)
}

pub async fn collect_metrics(
    packet_counts: &Arc<Mutex<HashMap<MapData, PacketKey, PacketValue>>>,
) -> Result<Vec<PacketMetric>> {
    let mut metrics = vec![];
    let packet_counts = packet_counts.lock().await;

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

pub fn update_malware_domain(
    malware_domains: &mut StdHashMap<String, u8>,
    domain: &str,
) -> Result<()> {
    let domain_hash = xxh64_hash(domain.as_bytes());
    malware_domains.insert(domain.to_string(), 1);
    info!(
        "Dynamically added malware domain: {} (hash: {})",
        domain, domain_hash
    );
    Ok(())
}
