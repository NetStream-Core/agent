#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "include/common.h"
#include "include/dns.h"
#include "include/structs.h"

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx)
{
    void          *data_end = (void *)(long)ctx->data_end;
    void          *data     = (void *)(long)ctx->data;
    struct ethhdr *eth      = data;

    if (data + sizeof(*eth) > data_end) { return XDP_PASS; }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) { return XDP_PASS; }

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) { return XDP_PASS; }

    struct packet_key key = {0};
    key.protocol          = ip->protocol;
    key.src_ip            = ip->saddr;
    key.dst_ip            = ip->daddr;

    __u32 ip_header_len = (ip->ihl & 0x0f) * 4;
    if (ip_header_len < sizeof(*ip)) { return XDP_PASS; }

    if (data + sizeof(*eth) + ip_header_len > data_end) { return XDP_PASS; }

    __u32 payload_size = BPF_NTOHS(ip->tot_len) - ip_header_len;

    if (ip->protocol == 6) {
        struct tcphdr *tcp = data + sizeof(*eth) + ip_header_len;

        if ((void *)tcp + sizeof(*tcp) > data_end) { return XDP_PASS; }

        key.src_port = BPF_NTOHS(tcp->source);
        key.dst_port = BPF_NTOHS(tcp->dest);
        payload_size -= sizeof(*tcp);
    } else if (ip->protocol == 17) {
        struct udphdr *udp = data + sizeof(*eth) + ip_header_len;

        if ((void *)udp + sizeof(*udp) > data_end) { return XDP_PASS; }

        key.src_port = BPF_NTOHS(udp->source);
        key.dst_port = BPF_NTOHS(udp->dest);
        payload_size -= sizeof(*udp);

        if (key.dst_port == DNS_PORT) {
            void *dns_data = data + sizeof(*eth) + ip_header_len + sizeof(*udp);
            int   result   = handle_dns(ctx, dns_data, data_end);
            if (result != XDP_PASS) { return result; }
        }
    }

    struct packet_value *value = bpf_map_lookup_elem(&packet_counts, &key);
    if (!value) {
        struct packet_value new_value = {
            .count        = 1,
            .timestamp    = bpf_ktime_get_ns(),
            .payload_size = payload_size,
        };
        bpf_map_update_elem(&packet_counts, &key, &new_value, BPF_NOEXIST);
    } else {
        __sync_fetch_and_add(&value->count, 1);
        value->timestamp = bpf_ktime_get_ns();
        __sync_fetch_and_add(&value->payload_size, payload_size);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
