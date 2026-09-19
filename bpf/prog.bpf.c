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
#include "include/flow.h"

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct iphdr *ip = locate_ip(data, data_end);
    if (!ip) { return XDP_PASS; }

    if (is_blocked(ip->saddr) || is_blocked(ip->daddr)) { return XDP_DROP; }

    struct flow_ctx fc = {};
    if (parse_flow(ip, data_end, DIRECTION_INGRESS, &fc) < 0) { return XDP_PASS; }

    debug_printk("rx: proto=%d src=%x dst=%x\n", fc.key.protocol, fc.key.src_ip, fc.key.dst_ip);

    if (fc.is_dns) {
        int result = handle_dns(dns_payload(ip), data_end, fc.key.src_ip);
        if (result != XDP_PASS) { return result; }
    }

    count_flow(&fc);
    return XDP_PASS;
}

SEC("classifier")
int tc_dns_monitor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct iphdr *ip = locate_ip(data, data_end);
    if (!ip) { return TC_ACT_OK; }

    struct flow_ctx fc = {};
    if (parse_flow(ip, data_end, DIRECTION_EGRESS, &fc) < 0) { return TC_ACT_OK; }

    debug_printk("tx: proto=%d src=%x dst=%x\n", fc.key.protocol, fc.key.src_ip, fc.key.dst_ip);

    if (fc.is_dns) {
        int result = handle_dns(dns_payload(ip), data_end, fc.key.src_ip);
        if (result == XDP_DROP) { return TC_ACT_SHOT; }
    }

    count_flow(&fc);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
