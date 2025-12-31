use aya::maps::{MapData, RingBuf};
use log::{info, warn};
use std::{net::Ipv4Addr, ptr, sync::Arc};
use tokio::io::{Interest, unix::AsyncFd};

use crate::domain_manager::DomainManager;
use common::MalwareEvent;

const SRC_IP_OFFSET: usize = 0;
const DOMAIN_HASH_OFFSET: usize = 4;

pub fn spawn_event_monitor(ring_buf: RingBuf<MapData>, domain_mgr: Arc<DomainManager>) {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::with_interest(ring_buf, Interest::READABLE) {
            Ok(fd) => fd,
            Err(e) => {
                warn!("Failed to create AsyncFd: {e}");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    warn!("RingBuf error: {e}");
                    continue;
                }
            };

            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if item.len() < std::mem::size_of::<MalwareEvent>() {
                    continue;
                }

                unsafe {
                    let ptr = item.as_ptr();
                    let src_ip_be = ptr::read_unaligned(ptr.add(SRC_IP_OFFSET) as *const u32);
                    let domain_hash =
                        ptr::read_unaligned(ptr.add(DOMAIN_HASH_OFFSET) as *const u64);

                    let src_ip = Ipv4Addr::from(u32::from_be(src_ip_be));

                    if let Some(domain) = domain_mgr.get_domain_name(domain_hash) {
                        info!("🔴 MALWARE DETECTED! Domain: {} (IP: {})", domain, src_ip);
                    } else {
                        info!(
                            "🔴 MALWARE DETECTED! Unknown hash: 0x{:x} (IP: {})",
                            domain_hash, src_ip
                        );
                    }
                }
            }
            guard.clear_ready();
        }
    });
}
