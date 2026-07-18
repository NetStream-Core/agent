use anyhow::{Result, anyhow};
use aya::programs::xdp::XdpLinkId;
use aya::{
    Ebpf,
    maps::{HashMap, RingBuf},
    programs::{Xdp, XdpFlags},
};
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::bpf_object;
use crate::utils::get_default_interface;
use common::{PacketKey, PacketValue};

pub async fn setup(
    hashes: &[u64],
) -> Result<(
    Arc<Mutex<Ebpf>>,
    Arc<Mutex<HashMap<aya::maps::MapData, PacketKey, PacketValue>>>,
    RingBuf<aya::maps::MapData>,
    XdpLinkId,
)> {
    let interface = get_default_interface()?;
    info!("Using network interface: {}", interface);

    let path = bpf_object();
    if !path.exists() {
        return Err(anyhow!("eBPF file not found: {}", path.display()));
    }

    let mut bpf = Ebpf::load_file(&path)?;

    let program = bpf
        .program_mut("xdp_monitor")
        .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?;
    let xdp: &mut Xdp = program.try_into()?;

    xdp.load()?;
    let link_id: XdpLinkId = xdp.attach(&interface, XdpFlags::default())?;

    info!("eBPF program attached to {}", interface);

    {
        let map = bpf
            .map_mut("malware_domains")
            .ok_or_else(|| anyhow!("Map 'malware_domains' not found"))?;
        let mut malware_map: HashMap<_, u64, u8> = HashMap::try_from(map)?;
        for &hash in hashes {
            let _ = malware_map.insert(hash, 1, 0);
        }
        info!("BPF: loaded {} malware hashes", hashes.len());
    }

    let ring_buf = {
        let map = bpf
            .take_map("events")
            .ok_or_else(|| anyhow!("Map 'events' not found"))?;
        RingBuf::try_from(map)?
    };

    let packet_counts = {
        let map = bpf
            .take_map("packet_counts")
            .ok_or_else(|| anyhow!("Map 'packet_counts' not found"))?;
        let hash = HashMap::<_, PacketKey, PacketValue>::try_from(map)?;
        Arc::new(Mutex::new(hash))
    };

    Ok((Arc::new(Mutex::new(bpf)), packet_counts, ring_buf, link_id))
}
