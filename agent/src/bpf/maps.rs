use anyhow::{Result, anyhow};
use aya::{
    Ebpf,
    maps::{HashMap, MapData},
};
use common::{PacketKey, PacketValue};
use log::info;
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

use crate::config::malware_domains;
use crate::telemetry::PacketMetric;
use crate::utils::xxh64_hash;

pub fn load_malware_domains(bpf: &mut Ebpf) -> Result<usize> {
    let map = bpf
        .map_mut("malware_domains")
        .ok_or_else(|| anyhow!("Map 'malware_domains' not found in eBPF object"))?;

    let mut malware_map: HashMap<_, u64, u8> = HashMap::try_from(map)?;

    let path = malware_domains();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                "malware_domains.txt not found at {}, starting with empty map",
                path.display()
            );
            return Ok(0);
        }
        Err(e) => return Err(anyhow!("Failed to read {}: {e}", path.display())),
    };

    let mut loaded = 0;
    for line in content.lines() {
        let domain = line.trim();
        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }

        let hash = xxh64_hash(domain.as_bytes());

        if malware_map.insert(hash, 1, 0).is_ok() {
            info!("Loaded malware domain: {} (hash: 0x{:x})", domain, hash);
            loaded += 1;
        } else {
            info!("Skipped domain (insert failed): {}", domain);
        }
    }

    info!("Successfully loaded {loaded} malicious domains into BPF map");
    Ok(loaded)
}

pub async fn collect_metrics(
    packet_counts: &Arc<Mutex<HashMap<MapData, PacketKey, PacketValue>>>,
) -> Result<Vec<PacketMetric>> {
    let mut metrics = Vec::new();
    let mut keys_to_remove = Vec::new();

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    {
        let mut map = packet_counts.lock().await;

        for entry in map.iter().flatten() {
            let (key, value) = entry;

            metrics.push(PacketMetric {
                protocol: key.protocol,
                count: value.count,
                src_ip: Ipv4Addr::from(key.src_ip).to_string(),
                dst_ip: Ipv4Addr::from(key.dst_ip).to_string(),
                src_port: key.src_port as u32,
                dst_port: key.dst_port as u32,
                timestamp,
                payload_size: value.payload_size,
            });

            keys_to_remove.push(key);
        }

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
    }

    Ok(metrics)
}
