#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Protocol (TCP/UDP)
    __type(value, __u64); // Count
    __uint(max_entries, 1024);
} packet_counts SEC(".maps");

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) {
        bpf_printk("Invalid Ethernet header");
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_printk("Not an IP packet: %x", eth->h_proto);
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        bpf_printk("Invalid IP header");
        return XDP_PASS;
    }

    __u32 proto = ip->protocol;
    if (proto != 6 && proto != 17) {
        bpf_printk("Unsupported protocol: %d", proto);
        return XDP_PASS;
    }

    __u64 zero = 0;
    if (!bpf_map_lookup_elem(&packet_counts, &proto)) {
        bpf_map_update_elem(&packet_counts, &proto, &zero, BPF_NOEXIST);
        bpf_printk("Initialized counter for protocol: %d", proto);
    }

    __u64 *count = bpf_map_lookup_elem(&packet_counts, &proto);
    if (count) {
        __sync_fetch_and_add(count, 1);
        bpf_printk("Packet counted for protocol %d: %lld", proto, *count);
    } else {
        bpf_printk("Failed to lookup count for protocol: %d", proto);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
