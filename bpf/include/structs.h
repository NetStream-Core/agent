#ifndef __STRUCTS_H__
#define __STRUCTS_H__

struct packet_key
{
    __u32 protocol;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct packet_value
{
    __u64 count;
    __u64 timestamp;
    __u32 payload_size;
} __attribute__((packed));

struct malware_event_t {
    __u32 src_ip;
    __u64 domain_hash;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct packet_key);
    __type(value, struct packet_value);
    __uint(max_entries, 10240);
} packet_counts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 1024);
} malware_domains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} events SEC(".maps");

#endif /* __STRUCTS_H__ */
