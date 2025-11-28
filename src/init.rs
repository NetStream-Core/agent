use anyhow::{Result, anyhow};
use aya::{
    Ebpf,
    maps::{HashMap, RingBuf},
    programs::{Xdp, XdpFlags},
};
use log::info;
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;

use crate::{maps, network, types};

pub async fn setup() -> Result<(
    Arc<Mutex<Ebpf>>,
    Arc<Mutex<HashMap<aya::maps::MapData, types::PacketKey, types::PacketValue>>>,
    RingBuf<aya::maps::MapData>,
)> {
    let interface = network::get_default_interface()?;
    info!("Using network interface: {}", interface);

    if !Path::new("bpf/prog.bpf.o").exists() {
        return Err(anyhow!("eBPF file not found: bpf/prog.bpf.o"));
    }

    let bpf = Arc::new(Mutex::new(Ebpf::load_file("bpf/prog.bpf.o")?));

    {
        let mut bpf_mut = bpf.lock().await;
        let program = bpf_mut
            .program_mut("xdp_monitor")
            .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?;
        let xdp_program: &mut Xdp = program.try_into()?;
        xdp_program.load()?;
        xdp_program.attach(&interface, XdpFlags::default())?;
    }

    info!("eBPF program attached to {}", interface);

    let mut bpf_guard = bpf.lock().await;
    let _ = maps::load_malware_domains(&mut bpf_guard)?;

    let ring_buf = {
        let map = bpf_guard
            .take_map("events")
            .ok_or_else(|| anyhow!("Map 'events' not found"))?;
        RingBuf::try_from(map)?
    };

    drop(bpf_guard);

    let packet_counts = {
        let mut bpf_guard = bpf.lock().await;
        let packet_counts_map = bpf_guard
            .take_map("packet_counts")
            .ok_or_else(|| anyhow!("Map 'packet_counts' not found"))?;
        let hash_map: HashMap<_, types::PacketKey, types::PacketValue> =
            HashMap::try_from(packet_counts_map)?;
        Arc::new(Mutex::new(hash_map))
    };

    Ok((bpf, packet_counts, ring_buf))
}
