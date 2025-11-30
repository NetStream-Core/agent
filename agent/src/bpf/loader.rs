use anyhow::{Result, anyhow};
use aya::{
    Ebpf,
    maps::{HashMap, RingBuf},
    programs::{Xdp, XdpFlags},
};
use log::info;
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;

use crate::bpf::maps;
use crate::utils::net;
use common::{PacketKey, PacketValue};

pub async fn setup() -> Result<(
    Arc<Mutex<Ebpf>>,
    Arc<Mutex<HashMap<aya::maps::MapData, PacketKey, PacketValue>>>,
    RingBuf<aya::maps::MapData>,
)> {
    let interface = net::get_default_interface()?;
    info!("Using network interface: {}", interface);

    if !Path::new("./bpf/prog.bpf.o").exists() {
        return Err(anyhow!("eBPF file not found: ./bpf/prog.bpf.o"));
    }

    let mut bpf = Ebpf::load_file("./bpf/prog.bpf.o")?;

    {
        let program = bpf
            .program_mut("xdp_monitor")
            .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?;
        let xdp_program: &mut Xdp = program.try_into()?;
        xdp_program.load()?;
        xdp_program.attach(&interface, XdpFlags::default())?;
    }
    info!("eBPF program attached to {}", interface);

    maps::load_malware_domains(&mut bpf)?;

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
        let hash: HashMap<_, PacketKey, PacketValue> = HashMap::try_from(map)?;
        Arc::new(Mutex::new(hash))
    };

    Ok((Arc::new(Mutex::new(bpf)), packet_counts, ring_buf))
}
