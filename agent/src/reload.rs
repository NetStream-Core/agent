use aya::Ebpf;
use aya::maps::HashMap as BpfHashMap;
use futures_util::StreamExt;
use log::{info, warn};
use signal_hook::consts::SIGHUP;
use signal_hook_tokio::Signals;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

use crate::domain_manager::DomainManager;

/// Watches `path` for changes (polling every `poll_interval`, or immediately
/// on `SIGHUP`) and pushes only the added and removed hashes into the
/// `malware_domains` eBPF map, so a reload neither drops blocking coverage
/// nor touches the hit counters of domains that stayed on the list.
pub fn spawn_blocklist_reload(
    bpf: Arc<Mutex<Ebpf>>,
    domain_mgr: Arc<RwLock<DomainManager>>,
    path: PathBuf,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        let mut signals = match Signals::new([SIGHUP]) {
            Ok(signals) => Some(signals.fuse()),
            Err(e) => {
                warn!("Failed to register SIGHUP handler for blocklist reload: {e}");
                None
            }
        };
        let mut tick = interval(poll_interval);
        tick.tick().await;

        loop {
            match &mut signals {
                Some(signals) => {
                    tokio::select! {
                        _ = tick.tick() => {}
                        signal = signals.next() => {
                            match signal {
                                Some(_) => info!("Blocklist reload triggered by SIGHUP"),
                                None => break,
                            }
                        }
                    }
                }
                None => {
                    tick.tick().await;
                }
            }

            let delta = {
                let mut mgr = domain_mgr.write().await;
                match mgr.reload_from_file(&path) {
                    Ok(delta) => delta,
                    Err(e) => {
                        warn!("Failed to reload blocklist from {}: {e}", path.display());
                        continue;
                    }
                }
            };

            if delta.is_empty() {
                continue;
            }

            let mut bpf = bpf.lock().await;
            let Some(map) = bpf.map_mut("malware_domains") else {
                warn!("Map 'malware_domains' not found while reloading the blocklist");
                continue;
            };
            let malware_map: Result<BpfHashMap<_, u64, u8>, _> = BpfHashMap::try_from(map);
            let Ok(mut malware_map) = malware_map else {
                warn!("Failed to access the 'malware_domains' map while reloading");
                continue;
            };

            for hash in &delta.added {
                let _ = malware_map.insert(hash, 1, 0);
            }
            for hash in &delta.removed {
                let _ = malware_map.remove(hash);
            }

            info!(
                "Blocklist reloaded from {}: {} added, {} removed",
                path.display(),
                delta.added.len(),
                delta.removed.len()
            );
        }
    });
}
