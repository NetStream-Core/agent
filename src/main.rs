use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use std::path::Path;
use tokio::main;

mod metrics;
mod network;

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

    let packet_counts_map = bpf
        .map("packet_counts")
        .ok_or_else(|| anyhow!("Map 'packet_counts' not found"))?;
    let packet_counts: HashMap<_, u32, u64> = HashMap::try_from(packet_counts_map)?;

    loop {
        let mut metrics = vec![];
        for key in packet_counts.iter().filter_map(|r| r.ok()).map(|(k, _)| k) {
            if let Ok(count) = packet_counts.get(&key, 0) {
                info!("Protocol {}: {} packets", key, count);
                metrics.push(metrics::proto::PacketMetric {
                    protocol: key,
                    count,
                });
            }
        }

        let serialized = metrics::serialize_metrics(metrics)?;
        for buf in serialized {
            info!("Serialized metric (hex): {:x?}", buf);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
