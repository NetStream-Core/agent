#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include "include/common.h"
#include "include/dns.h"
#include "include/structs.h"

const volatile __u8 IS_L3_INTERFACE = 0;

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    void *ip_start;

    if (IS_L3_INTERFACE) {
        ip_start = data;
    } else {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end) { return XDP_PASS; }
        if (eth->h_proto != __constant_htons(ETH_P_IP)) { return XDP_PASS; }
        ip_start = data + sizeof(*eth);
    }

    struct iphdr *ip = ip_start;
    if (ip_start + sizeof(*ip) > data_end) { return XDP_PASS; }

    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    if (blocked && *blocked == 1) { return XDP_DROP; }
    blocked = bpf_map_lookup_elem(&blocked_ips, &ip->daddr);
    if (blocked && *blocked == 1) { return XDP_DROP; }

    debug_printk("IP packet: proto=%d src=%x dst=%x\n", ip->protocol, ip->saddr, ip->daddr);

    struct packet_key key = {0};
    key.protocol          = ip->protocol;
    key.src_ip            = ip->saddr;
    key.dst_ip            = ip->daddr;

    __u32 ip_header_len = (ip->ihl & 0x0f) * 4;
    if (ip_header_len < sizeof(*ip)) { return XDP_PASS; }

    if (ip_start + ip_header_len > data_end) { return XDP_PASS; }

    __u32 payload_size = BPF_NTOHS(ip->tot_len) - ip_header_len;

    if (ip->protocol == 6) {
        struct tcphdr *tcp = ip_start + ip_header_len;

        if ((void *)tcp + sizeof(*tcp) > data_end) { return XDP_PASS; }

        key.src_port = BPF_NTOHS(tcp->source);
        key.dst_port = BPF_NTOHS(tcp->dest);
        payload_size -= sizeof(*tcp);
    } else if (ip->protocol == 17) {
        struct udphdr *udp = ip_start + ip_header_len;

        if ((void *)udp + sizeof(*udp) > data_end) { return XDP_PASS; }

        key.src_port = BPF_NTOHS(udp->source);
        key.dst_port = BPF_NTOHS(udp->dest);
        payload_size -= sizeof(*udp);

        if (key.dst_port == DNS_PORT) {
            void *dns_data = ip_start + ip_header_len + sizeof(*udp);
            int   result   = handle_dns(dns_data, data_end, key.src_ip);
            if (result != XDP_PASS) { return result; }
        }
    }

    debug_printk("Updating map: proto=%d src=%x dst=%x sport=%d dport=%d\n", key.protocol, key.src_ip, key.dst_ip,
                 key.src_port, key.dst_port);

    struct packet_value *value = bpf_map_lookup_elem(&packet_counts, &key);
    if (!value) {
        debug_printk("New entry\n");
        struct packet_value new_value = {
            .count        = 1,
            .timestamp    = bpf_ktime_get_ns(),
            .payload_size = payload_size,
        };
        bpf_map_update_elem(&packet_counts, &key, &new_value, BPF_ANY);
    } else {
        debug_printk("Existing entry, count=%d\n", value->count);
        __sync_fetch_and_add(&value->count, 1);
        value->timestamp = bpf_ktime_get_ns();
        __sync_fetch_and_add(&value->payload_size, payload_size);
    }

    debug_printk("Map updated\n");

    return XDP_PASS;
}

SEC("classifier")
int tc_dns_monitor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    void *ip_start;

    debug_printk("TC egress: packet seen, len=%d\n", skb->len);

    if (IS_L3_INTERFACE) {
        ip_start = data;
    } else {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end) { return TC_ACT_OK; }
        if (eth->h_proto != __constant_htons(ETH_P_IP)) { return TC_ACT_OK; }
        ip_start = data + sizeof(*eth);
    }

    struct iphdr *ip = ip_start;
    if (ip_start + sizeof(*ip) > data_end) {
        debug_printk("TC egress: truncated IP header\n");
        return TC_ACT_OK;
    }

    debug_printk("TC egress: IP proto=%d src=%x dst=%x\n", ip->protocol, ip->saddr, ip->daddr);

    if (ip->protocol != 17) { return TC_ACT_OK; } /* нас интересует только UDP/DNS здесь */

    __u32 ip_header_len = (ip->ihl & 0x0f) * 4;
    if (ip_header_len < sizeof(*ip)) { return TC_ACT_OK; }
    if (ip_start + ip_header_len > data_end) { return TC_ACT_OK; }

    struct udphdr *udp = ip_start + ip_header_len;
    if ((void *)udp + sizeof(*udp) > data_end) { return TC_ACT_OK; }

    debug_printk("TC egress: UDP sport=%d dport=%d\n", BPF_NTOHS(udp->source), BPF_NTOHS(udp->dest));

    if (BPF_NTOHS(udp->dest) != DNS_PORT) { return TC_ACT_OK; }

    debug_printk("TC egress: DNS query detected, calling handle_dns\n");

    void *dns_data = (void *)udp + sizeof(*udp);
    int   result   = handle_dns(dns_data, data_end, ip->saddr);

    /* ВАЖНО: коды возврата XDP и TC не совпадают числами (XDP_PASS == TC_ACT_SHOT == 2),
       поэтому транслируем явно, а не возвращаем result напрямую. */
    if (result == XDP_DROP) { return TC_ACT_SHOT; }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
