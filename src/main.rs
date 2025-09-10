use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use std::path::Path;
use tokio::main;

#[main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Agent started. Hello from logger!");

    if !Path::new("bpf/prog.bpf.o").exists() {
        return Err(anyhow!("eBPF file not found: bpf/prog.bpf.o"));
    }

    let mut bpf = Ebpf::load_file("bpf/prog.bpf.o")?;

    let program = bpf
        .program_mut("xdp_monitor")
        .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?;

    let xdp_program: &mut Xdp = program.try_into()?;

    xdp_program.load()?;
    xdp_program.attach("wlan0", XdpFlags::default())?;

    info!("eBPF program attached");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Ok(())
}
