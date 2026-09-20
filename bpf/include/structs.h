#ifndef __STRUCTS_H__
#define __STRUCTS_H__

#include "budget.h"

struct packet_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  direction;
    __u16 flags;
};

struct packet_value {
    __u64 count;
    __u64 timestamp;
    __u64 payload_size;
    __u64 ip_bytes;
    __u64 tcp_syn;
    __u64 tcp_synack;
    __u64 tcp_fin;
    __u64 tcp_rst;
};

_Static_assert(sizeof(struct packet_key) == 16, "packet_key layout is shared with the agent");
_Static_assert(sizeof(struct packet_value) == 64, "packet_value layout is shared with the agent");

struct malware_event_t {
    __u32 src_ip;
    __u32 action;
    __u64 domain_hash;
};

struct block_entry {
    __u64 expires_ns;
    __u64 domain_hash;
};

struct allowlist_key {
    __u32 prefixlen;
    __u32 addr;
};

_Static_assert(sizeof(struct malware_event_t) == 16, "malware_event_t layout is shared with the agent");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct packet_key);
    __type(value, struct packet_value);
    __uint(max_entries, 10240);
} packet_counts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct budget_state);
} flow_budget SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 1024);
} malware_domains SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct block_entry);
    __uint(max_entries, 4096);
} blocked_ips SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct allowlist_key);
    __type(value, __u8);
    __uint(max_entries, 256);
} quarantine_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} dns_queries SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dns_events_lost SEC(".maps");

#endif /* __STRUCTS_H__ */
