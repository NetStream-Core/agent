#ifndef __FLOW_H__
#define __FLOW_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "common.h"
#include "structs.h"

const volatile __u8 IS_L3_INTERFACE = 0;

struct flow_ctx
{
    struct packet_key key;
    __u32             ip_bytes;
    __u32             payload_size;
    __u8              is_dns;
    __u8              tcp_syn;
    __u8              tcp_ack;
    __u8              tcp_fin;
    __u8              tcp_rst;
};

static __always_inline struct iphdr *locate_ip(void *data, void *data_end)
{
    void *ip_start;

    if (IS_L3_INTERFACE) {
        ip_start = data;
    } else {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end) { return NULL; }
        if (eth->h_proto != __constant_htons(ETH_P_IP)) { return NULL; }
        ip_start = data + sizeof(*eth);
    }

    if (ip_start + sizeof(struct iphdr) > data_end) { return NULL; }
    return ip_start;
}

static __always_inline int is_blocked(__u32 addr)
{
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &addr);
    return blocked && *blocked == 1;
}

static __always_inline void *dns_payload(struct iphdr *ip)
{
    return (void *)ip + (ip->ihl & 0x0f) * 4 + sizeof(struct udphdr);
}

static __always_inline int parse_flow(struct iphdr *ip, void *data_end, __u8 direction, struct flow_ctx *fc)
{
    __u32 ip_header_len = (ip->ihl & 0x0f) * 4;
    if (ip_header_len < sizeof(*ip)) { return -1; }
    if ((void *)ip + ip_header_len > data_end) { return -1; }

    __u32 total_len = BPF_NTOHS(ip->tot_len);
    if (total_len < ip_header_len) { return -1; }

    fc->key.src_ip    = ip->saddr;
    fc->key.dst_ip    = ip->daddr;
    fc->key.protocol  = ip->protocol;
    fc->key.direction = direction;
    fc->ip_bytes      = total_len;
    fc->payload_size  = total_len - ip_header_len;

    void *l4 = (void *)ip + ip_header_len;

    if (ip->protocol == 6) {
        struct tcphdr *tcp = l4;
        if ((void *)tcp + sizeof(*tcp) > data_end) { return -1; }

        __u32 tcp_header_len = tcp->doff * 4;
        if (tcp_header_len < sizeof(*tcp) || tcp_header_len > fc->payload_size) { return -1; }

        fc->key.src_port = BPF_NTOHS(tcp->source);
        fc->key.dst_port = BPF_NTOHS(tcp->dest);
        fc->payload_size -= tcp_header_len;
        fc->tcp_syn = tcp->syn;
        fc->tcp_ack = tcp->ack;
        fc->tcp_fin = tcp->fin;
        fc->tcp_rst = tcp->rst;
    } else if (ip->protocol == 17) {
        struct udphdr *udp = l4;
        if ((void *)udp + sizeof(*udp) > data_end) { return -1; }
        if (fc->payload_size < sizeof(*udp)) { return -1; }

        fc->key.src_port = BPF_NTOHS(udp->source);
        fc->key.dst_port = BPF_NTOHS(udp->dest);
        fc->payload_size -= sizeof(*udp);
        fc->is_dns = fc->key.dst_port == DNS_PORT;
    }

    return 0;
}

static __always_inline void count_flow(struct flow_ctx *fc)
{
    struct packet_value *value = bpf_map_lookup_elem(&packet_counts, &fc->key);
    if (!value) {
        struct packet_value zero = {};
        bpf_map_update_elem(&packet_counts, &fc->key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&packet_counts, &fc->key);
    }
    if (!value) { return; }

    value->count += 1;
    value->ip_bytes += fc->ip_bytes;
    value->payload_size += fc->payload_size;
    value->timestamp = bpf_ktime_get_ns();

    if (fc->tcp_syn && fc->tcp_ack) {
        value->tcp_synack += 1;
    } else if (fc->tcp_syn) {
        value->tcp_syn += 1;
    }
    if (fc->tcp_fin) { value->tcp_fin += 1; }
    if (fc->tcp_rst) { value->tcp_rst += 1; }
}

#endif /* __FLOW_H__ */
