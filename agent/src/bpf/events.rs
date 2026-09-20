use aya::maps::{MapData, RingBuf};
use common::{ACTION_DROPPED, ACTION_OBSERVED, ACTION_QUARANTINED, MalwareEvent};
use log::{info, warn};
use opentelemetry::{KeyValue, global};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::io::{Interest, unix::AsyncFd};

use crate::domain_manager::DomainManager;

fn action_label(action: u32) -> &'static str {
    match action {
        ACTION_OBSERVED => "observed",
        ACTION_DROPPED => "dropped",
        ACTION_QUARANTINED => "quarantined",
        _ => "unknown",
    }
}

pub fn spawn_event_monitor(ring_buf: RingBuf<MapData>, domain_mgr: Arc<DomainManager>) {
    tokio::spawn(async move {
        let hits = global::meter("netstream_agent")
            .u64_counter("netstream_blocklist_hits_total")
            .with_description("Blocked domain detections by response action")
            .build();

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
                let Some(event) = MalwareEvent::parse(&item) else {
                    continue;
                };

                let src_ip = Ipv4Addr::from(u32::from_be(event.src_ip));
                let action = action_label(event.action);
                hits.add(1, &[KeyValue::new("action", action)]);

                if let Some(domain) = domain_mgr.get_domain_name(event.domain_hash) {
                    info!(
                        "🔴 MALWARE DETECTED! Domain: {} (IP: {}) action={}",
                        domain, src_ip, action
                    );
                } else {
                    info!(
                        "🔴 MALWARE DETECTED! Unknown hash: 0x{:x} (IP: {}) action={}",
                        event.domain_hash, src_ip, action
                    );
                }
            }
            guard.clear_ready();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_bytes(src_ip: u32, action: u32, domain_hash: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(src_ip.to_ne_bytes());
        bytes.extend(action.to_ne_bytes());
        bytes.extend(domain_hash.to_ne_bytes());
        bytes
    }

    #[test]
    fn event_is_parsed_from_ring_buffer_bytes() {
        let bytes = event_bytes(u32::from_ne_bytes([10, 0, 0, 7]), ACTION_QUARANTINED, 42);

        let event = MalwareEvent::parse(&bytes).expect("parsed");

        assert_eq!(event.src_ip, u32::from_ne_bytes([10, 0, 0, 7]));
        assert_eq!(event.action, ACTION_QUARANTINED);
        assert_eq!(event.domain_hash, 42);
    }

    #[test]
    fn trailing_bytes_are_ignored_and_short_buffers_rejected() {
        let mut bytes = event_bytes(1, ACTION_DROPPED, 2);
        bytes.push(0xff);
        assert!(MalwareEvent::parse(&bytes).is_some());
        assert!(MalwareEvent::parse(&bytes[..15]).is_none());
        assert!(MalwareEvent::parse(&[]).is_none());
    }

    #[test]
    fn actions_have_stable_labels() {
        assert_eq!(action_label(ACTION_OBSERVED), "observed");
        assert_eq!(action_label(ACTION_DROPPED), "dropped");
        assert_eq!(action_label(ACTION_QUARANTINED), "quarantined");
        assert_eq!(action_label(99), "unknown");
    }
}
