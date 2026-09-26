use anyhow::{Result, anyhow};
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::xdp::XdpLinkId;
use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    maps::{
        HashMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc},
};
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::response::ResponseConfig;
use common::{PacketKey, PacketValue};

static BPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/prog.bpf.o"));

fn is_l3_interface(iface: &str) -> bool {
    let path = format!("/sys/class/net/{iface}/addr_len");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|len| len == 0)
        .unwrap_or(false)
}

pub struct Loaded {
    pub bpf: Arc<Mutex<Ebpf>>,
    pub packet_counts: Arc<Mutex<PerCpuHashMap<MapData, PacketKey, PacketValue>>>,
    pub malware_events: RingBuf<MapData>,
    pub dns_queries: RingBuf<MapData>,
    pub dns_events_lost: PerCpuArray<MapData, u64>,
    pub xdp_link_id: XdpLinkId,
    pub tc_link_id: SchedClassifierLinkId,
}

pub struct LoadOptions<'a> {
    pub interface: &'a str,
    pub dns_events: bool,
    pub flow_table_entries: u32,
    pub new_flows_per_second: u32,
    pub collapse_ephemeral_ports: bool,
    pub ephemeral_range: (u16, u16),
}

pub async fn setup(
    options: &LoadOptions<'_>,
    hashes: &[u64],
    response: &ResponseConfig,
) -> Result<Loaded> {
    let interface = options.interface;
    info!("Using network interface: {}", interface);

    let is_l3 = is_l3_interface(interface);
    info!(
        "Interface link type: {}",
        if is_l3 {
            "L3/TUN (no Ethernet header)"
        } else {
            "L2/Ethernet"
        }
    );

    let (ephemeral_min, ephemeral_max) = options.ephemeral_range;
    info!(
        "Flow table: {} entries; ephemeral ports {}-{} are {}",
        options.flow_table_entries,
        ephemeral_min,
        ephemeral_max,
        if options.collapse_ephemeral_ports {
            "collapsed"
        } else {
            "kept"
        }
    );

    let new_flow_budget = (options.new_flows_per_second / 10).max(1);
    info!(
        "New flows admitted per CPU: {} per second, the rest is aggregated per host pair",
        options.new_flows_per_second
    );

    let mut bpf = EbpfLoader::new()
        .set_max_entries("packet_counts", options.flow_table_entries)
        .set_max_entries("flow_clock", options.flow_table_entries)
        .set_global("NEW_FLOW_BUDGET", &new_flow_budget, true)
        .set_global("IS_L3_INTERFACE", &(is_l3 as u8), true)
        .set_global(
            "COLLAPSE_EPHEMERAL",
            &(options.collapse_ephemeral_ports as u8),
            true,
        )
        .set_global("EPHEMERAL_MIN", &ephemeral_min, true)
        .set_global("EPHEMERAL_MAX", &ephemeral_max, true)
        .set_global("DNS_EVENTS", &(options.dns_events as u8), true)
        .set_global("RESPONSE_MODE", &response.mode.as_kernel_value(), true)
        .set_global(
            "QUARANTINE_TTL_NS",
            &(response.quarantine_ttl.as_nanos() as u64),
            true,
        )
        .load(BPF_OBJECT)?;

    let program = bpf
        .program_mut("xdp_monitor")
        .ok_or_else(|| anyhow!("Program 'xdp_monitor' not found"))?;
    let xdp: &mut Xdp = program.try_into()?;

    xdp.load()?;
    let link_id: XdpLinkId = xdp.attach(interface, XdpFlags::default())?;

    info!("eBPF program attached to {}", interface);

    match tc::qdisc_add_clsact(interface) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(anyhow!("Failed to add clsact qdisc on {interface}: {e}")),
    }

    let tc_program = bpf
        .program_mut("tc_dns_monitor")
        .ok_or_else(|| anyhow!("Program 'tc_dns_monitor' not found"))?;
    let tc_prog: &mut SchedClassifier = tc_program.try_into()?;

    tc_prog.load()?;
    let tc_link_id: SchedClassifierLinkId = tc_prog.attach(interface, TcAttachType::Egress)?;

    info!("TC egress program attached to {}", interface);

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

    {
        let map = bpf
            .map_mut("quarantine_allowlist")
            .ok_or_else(|| anyhow!("Map 'quarantine_allowlist' not found"))?;
        let mut allowlist: LpmTrie<_, u32, u8> = LpmTrie::try_from(map)?;
        for prefix in &response.allowlist {
            let key = Key::new(prefix.len as u32, u32::from_ne_bytes(prefix.addr.octets()));
            allowlist.insert(&key, 1, 0)?;
        }
        info!(
            "Response mode: {}; quarantine allowlist has {} entries",
            response.mode,
            response.allowlist.len()
        );
    }

    let malware_events = {
        let map = bpf
            .take_map("events")
            .ok_or_else(|| anyhow!("Map 'events' not found"))?;
        RingBuf::try_from(map)?
    };

    let dns_queries = {
        let map = bpf
            .take_map("dns_queries")
            .ok_or_else(|| anyhow!("Map 'dns_queries' not found"))?;
        RingBuf::try_from(map)?
    };

    let dns_events_lost = {
        let map = bpf
            .take_map("dns_events_lost")
            .ok_or_else(|| anyhow!("Map 'dns_events_lost' not found"))?;
        PerCpuArray::try_from(map)?
    };

    let packet_counts = {
        let map = bpf
            .take_map("packet_counts")
            .ok_or_else(|| anyhow!("Map 'packet_counts' not found"))?;
        let hash = PerCpuHashMap::<_, PacketKey, PacketValue>::try_from(map)?;
        Arc::new(Mutex::new(hash))
    };

    Ok(Loaded {
        bpf: Arc::new(Mutex::new(bpf)),
        packet_counts,
        malware_events,
        dns_queries,
        dns_events_lost,
        xdp_link_id: link_id,
        tc_link_id,
    })
}
