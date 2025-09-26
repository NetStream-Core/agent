use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use std::path::Path;
use tokio::main;

mod maps;
mod metrics;
mod network;
mod types;
mod xxh64;

#[main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Loading eBPF program...");

    let interface = network::get_default_interface()?;
    info!("Using network interface: {}", interface);

    if !Path::new("bpf/prog.bpf.o").exists() {
        return Err(anyhow!("eBPF file not found: bpf/prog.bpf.o"));
    }

    let mut bpf = Ebpf::load_file("bpf/prog.bpf.o")?;

    let program = bpf
        .program_mut("xdp_monitor")
        .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?;

    let xdp_program: &mut Xdp = program.try_into()?;

    xdp_program.load()?;
    xdp_program.attach(&interface, XdpFlags::default())?;

    info!("eBPF program attached to {}", interface);

    #[allow(unused_variables)]
    let malware_domains = maps::load_malware_domains(&mut bpf)?;

    let packet_counts_map = bpf
        .map("packet_counts")
        .ok_or_else(|| anyhow!("Map 'packet_counts' not found"))?;
    let packet_counts = aya::maps::HashMap::try_from(packet_counts_map)?;

    loop {
        let metrics = maps::collect_metrics(&packet_counts)?;
        let serialized = metrics::serialize_metrics(metrics)?;
        for buf in serialized {
            info!("Serialized metric (hex): {:x?}", buf);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
