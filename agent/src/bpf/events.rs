use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use log::{info, warn};
use std::{collections::HashMap, net::Ipv4Addr, ptr, sync::Arc};
use tokio::io::{Interest, unix::AsyncFd};

use crate::utils::hash;
use common::MalwareEvent;

const SRC_IP_OFFSET: usize = 0;
const DOMAIN_HASH_OFFSET: usize = 4;

pub fn load_hashes(path: &str) -> Result<Arc<HashMap<String, u64>>> {
    let mut domain_hashes = HashMap::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            warn!("Malware domains file not found, starting with empty list");
            return Ok(Arc::new(domain_hashes));
        }
    };

    for line in content.lines() {
        let domain = line.trim();
        if domain.is_empty() {
            continue;
        }
        let h = hash::xxh64_hash(domain.as_bytes());
        domain_hashes.insert(domain.to_string(), h);
    }

    Ok(Arc::new(domain_hashes))
}

pub fn spawn_event_monitor(ring_buf: RingBuf<MapData>, domain_hashes: Arc<HashMap<String, u64>>) {
    tokio::spawn(async move {
        let hash_to_domain: HashMap<u64, String> = domain_hashes
            .iter()
            .map(|(domain, &hash)| (hash, domain.clone()))
            .collect();

        let mut async_fd = match AsyncFd::with_interest(ring_buf, Interest::READABLE) {
            Ok(fd) => fd,
            Err(e) => {
                warn!("Failed to create AsyncFd for RingBuf: {e}");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    warn!("RingBuf readable_mut error: {e}");
                    continue;
                }
            };

            {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    let ptr = item.as_ptr();
                    let size = std::mem::size_of::<MalwareEvent>();

                    if item.len() < size {
                        continue;
                    }

                    unsafe {
                        let src_ip_be = ptr::read_unaligned(ptr.add(SRC_IP_OFFSET) as *const u32);

                        let domain_hash =
                            ptr::read_unaligned(ptr.add(DOMAIN_HASH_OFFSET) as *const u64);

                        let src_ip = Ipv4Addr::from(u32::from_be(src_ip_be));

                        if let Some(domain) = hash_to_domain.get(&domain_hash) {
                            info!(
                                "MALWARE DETECTED via RingBuf! Domain: {} (IP: {})",
                                domain, src_ip
                            );
                        }
                    }
                }
            }

            guard.clear_ready();
        }
    });
}
