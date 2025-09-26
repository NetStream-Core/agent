#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define BPF_NTOHS(x) (__builtin_bswap16(x))

struct packet_key {
    __u32 protocol;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct packet_value {
    __u64 count;
    __u64 timestamp;
    __u32 payload_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct packet_key);
    __type(value, struct packet_value);
    __uint(max_entries, 1024);
} packet_counts SEC(".maps");

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    struct packet_key key = {0};
    key.protocol = ip->protocol;
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;

    __u32 payload_size = BPF_NTOHS(ip->tot_len) - sizeof(*ip);

    if (ip->protocol == 6) {
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end) {
            return XDP_PASS;
        }
        key.src_port = BPF_NTOHS(tcp->source);
        key.dst_port = BPF_NTOHS(tcp->dest);
        payload_size -= sizeof(*tcp);
    } else if (ip->protocol == 17) {
        struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end) {
            return XDP_PASS;
        }
        key.src_port = BPF_NTOHS(udp->source);
        key.dst_port = BPF_NTOHS(udp->dest);
        payload_size -= sizeof(*udp);
    }

    struct packet_value *value = bpf_map_lookup_elem(&packet_counts, &key);
    if (!value) {
        struct packet_value new_value = {
            .count = 1,
            .timestamp = bpf_ktime_get_ns(),
            .payload_size = payload_size,
        };
        bpf_map_update_elem(&packet_counts, &key, &new_value, BPF_NOEXIST);
    } else {
        __sync_fetch_and_add(&value->count, 1);
        value->timestamp = bpf_ktime_get_ns();
        value->payload_size = payload_size;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
