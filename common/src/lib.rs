#![no_std]

use aya::Pod;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PacketKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: u8,
    pub flags: u16,
}

pub const SIZE_BINS: usize = 6;

pub const KEY_FLAG_AGGREGATED: u16 = 1;
pub const KEY_FLAG_PORTS_MERGED: u16 = 2;

pub const DIRECTION_INGRESS: u8 = 0;
pub const DIRECTION_EGRESS: u8 = 1;

unsafe impl Pod for PacketKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PacketValue {
    pub count: u64,
    pub timestamp: u64,
    pub payload_size: u64,
    pub ip_bytes: u64,
    pub tcp_syn: u64,
    pub tcp_synack: u64,
    pub tcp_fin: u64,
    pub tcp_rst: u64,
    pub size_bins: [u64; SIZE_BINS],
    pub iat_count: u64,
    pub iat_sum_us: u64,
    pub iat_sumsq_us: u64,
}

unsafe impl Pod for PacketValue {}

const _: () = assert!(core::mem::size_of::<PacketKey>() == 16);
const _: () = assert!(core::mem::size_of::<PacketValue>() == 136);

#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct MalwareEvent {
    pub src_ip: u32,
    pub action: u32,
    pub domain_hash: u64,
}

impl MalwareEvent {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        bytes
            .get(..core::mem::size_of::<Self>())
            .map(bytemuck::pod_read_unaligned)
    }
}

pub const DNS_QNAME_CAPACITY: usize = 256;

#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DnsEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub qtype: u16,
    pub direction: u8,
    pub qname_len: u8,
    pub qname: [u8; DNS_QNAME_CAPACITY],
}

impl DnsEvent {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        bytes
            .get(..core::mem::size_of::<Self>())
            .map(bytemuck::pod_read_unaligned)
    }

    pub fn qname_wire(&self) -> &[u8] {
        &self.qname[..self.qname_len as usize]
    }
}

const _: () = assert!(core::mem::size_of::<DnsEvent>() == 268);

pub const ACTION_OBSERVED: u32 = 0;
pub const ACTION_DROPPED: u32 = 1;
pub const ACTION_QUARANTINED: u32 = 2;

pub const MODE_MONITOR: u8 = 0;
pub const MODE_ENFORCE: u8 = 1;
pub const MODE_GATEWAY: u8 = 2;

const _: () = assert!(core::mem::size_of::<MalwareEvent>() == 16);

unsafe impl Pod for MalwareEvent {}
