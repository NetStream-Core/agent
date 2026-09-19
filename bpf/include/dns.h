#ifndef __DNS_H__
#define __DNS_H__

#include <bpf/bpf_helpers.h>
#include "common.h"
#include "structs.h"

static __always_inline int handle_dns(void *data, void *data_end, __u32 src_ip)
{
    void *dns_data = data;
    if (dns_data + DNS_HEADER_SIZE > data_end) { return XDP_PASS; }

    __u32 query_length = data_end - dns_data - DNS_HEADER_SIZE;
    if (query_length > MAX_QUERY_LENGTH) {
        return XDP_DROP;
    }
    if (query_length > SUSPICIOUS_QUERY_LENGTH) {
        return XDP_DROP;
    }

    char *query_name = dns_data + DNS_HEADER_SIZE;

    __u64 hash = 0x9e3779b97f4a7c15ULL;
    const __u64 prime = 0x100000001b3ULL;
    __u32 qname_len = 0;

    #pragma unroll
    for (__u32 i = 0; i < MAX_QUERY_LENGTH; i++) {
        if (query_name + i + 1 > data_end) { return XDP_PASS; }

        __u8 byte = query_name[i];
        if (byte == 0) {
            qname_len = i;
            break;
        }

        hash ^= (__u64)byte;
        hash *= prime;
        hash = (hash << 23) | (hash >> 41);
    }

    if (qname_len == 0) {
        return XDP_PASS;
    }

    hash ^= (hash >> 33);
    hash *= 0xc2b2ae35ULL;
    hash ^= (hash >> 29);

    __u64 domain_hash = hash;
    __u8 *is_malware  = bpf_map_lookup_elem(&malware_domains, &domain_hash);

    if (is_malware && *is_malware == 1) {
        __u8 blocked = 1;
        bpf_map_update_elem(&blocked_ips, &src_ip, &blocked, BPF_ANY);

        struct malware_event_t *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->src_ip = src_ip;
            e->domain_hash = domain_hash;
            bpf_ringbuf_submit(e, 0);
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif /* __DNS_H__ */
