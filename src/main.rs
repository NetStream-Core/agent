use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::main;

mod metrics;
mod network;

#[repr(C)]
#[derive(Copy, Clone)]
struct PacketKey {
    protocol: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PacketValue {
    count: u64,
    timestamp: u64,
    payload_size: u32,
}

unsafe impl aya::Pod for PacketKey {}
unsafe impl aya::Pod for PacketValue {}

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
    let packet_counts: HashMap<_, PacketKey, PacketValue> = HashMap::try_from(packet_counts_map)?;

    loop {
        let mut metrics = vec![];
        for entry in packet_counts.iter().filter_map(|r| r.ok()) {
            let (key, value) = entry;
            info!(
                "Protocol {}: src_ip={:?}, dst_ip={:?}, src_port={}, dst_port={}, count={}, timestamp={}, payload_size={}",
                key.protocol,
                Ipv4Addr::from(key.src_ip),
                Ipv4Addr::from(key.dst_ip),
                key.src_port,
                key.dst_port,
                value.count,
                value.timestamp,
                value.payload_size
            );
            metrics.push(metrics::proto::PacketMetric {
                protocol: key.protocol,
                count: value.count,
                src_ip: Ipv4Addr::from(key.src_ip).to_string(),
                dst_ip: Ipv4Addr::from(key.dst_ip).to_string(),
                src_port: key.src_port as u32,
                dst_port: key.dst_port as u32,
                timestamp: value.timestamp,
                payload_size: value.payload_size,
            });
        }

        let serialized = metrics::serialize_metrics(metrics)?;
        for buf in serialized {
            info!("Serialized metric (hex): {:x?}", buf);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
