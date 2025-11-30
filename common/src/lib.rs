#![no_std]

use aya::Pod;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PacketKey {
    pub protocol: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

unsafe impl Pod for PacketKey {}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PacketValue {
    pub count: u64,
    pub timestamp: u64,
    pub payload_size: u32,
}

unsafe impl Pod for PacketValue {}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct MalwareEvent {
    pub src_ip: u32,
    pub domain_hash: u64,
}

unsafe impl Pod for MalwareEvent {}
