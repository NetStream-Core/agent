use anyhow::Result;
use log::{info, warn};
use regex::Regex;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    fs::File as TokioFile,
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
};

use crate::{maps, xxh64};

pub fn load_hashes(path: &str) -> Result<Arc<HashMap<String, u64>>> {
    let mut domain_hashes = HashMap::new();
    let domains = std::fs::read_to_string(path).unwrap_or_default();
    for domain in domains.lines() {
        let domain = domain.trim();
        if !domain.is_empty() {
            let domain_hash = xxh64::xxh64_hash(domain.as_bytes());
            domain_hashes.insert(domain.to_string(), domain_hash);
        }
    }
    Ok(Arc::new(domain_hashes))
}

pub fn spawn_trace_monitor(
    malware_domains: Arc<Mutex<HashMap<String, u8>>>,
    domain_hashes: Arc<HashMap<String, u64>>,
) {
    tokio::spawn(async move {
        let trace_file = match TokioFile::open("/sys/kernel/debug/tracing/trace_pipe").await {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open trace_pipe: {}", e);
                return;
            }
        };

        let hash_to_domain: HashMap<u64, String> = domain_hashes
            .iter()
            .map(|(domain, hash)| (*hash, domain.clone()))
            .collect();

        let mut trace_reader = BufReader::new(trace_file);
        let hash_regex = Regex::new(r"hash=(\d+)").unwrap();
        let mut line = String::new();

        while let Ok(bytes_read) = trace_reader.read_line(&mut line).await {
            if bytes_read == 0 {
                break;
            }

            if let Some(captures) = hash_regex.captures(&line) {
                if let Some(hash_str) = captures.get(1) {
                    if let Ok(hash) = hash_str.as_str().parse::<u64>() {
                        if let Some(domain) = hash_to_domain.get(&hash) {
                            info!("Matched domain in logs: {} (hash: {})", domain, hash);

                            {
                                let mut malware_domains = malware_domains.lock().await;
                                if let Err(e) =
                                    maps::update_malware_domain(&mut malware_domains, domain)
                                {
                                    warn!("Failed to update malware_domains: {}", e);
                                }
                            }
                        }
                    }
                }
            }

            line.clear();
        }
    });
}
