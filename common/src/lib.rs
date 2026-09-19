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
    pub _padding: u16,
}

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
}

unsafe impl Pod for PacketValue {}

const _: () = assert!(core::mem::size_of::<PacketKey>() == 16);
const _: () = assert!(core::mem::size_of::<PacketValue>() == 64);

#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct MalwareEvent {
    pub src_ip: u32,
    pub _padding: u32,
    pub domain_hash: u64,
}

unsafe impl Pod for MalwareEvent {}
