#ifndef __DNS_H__
#define __DNS_H__

#include <bpf/bpf_helpers.h>
#include "common.h"
#include "structs.h"
#include "xxh64.h"

static __always_inline int handle_dns(struct xdp_md *ctx, void *data, void *data_end) {
    void *dns_data = data;
    if (dns_data + DNS_HEADER_SIZE > data_end) {
        return XDP_PASS;
    }

    __u32 query_length = data_end - dns_data - DNS_HEADER_SIZE;
    if (query_length > MAX_QUERY_LENGTH) {
        bpf_printk("DNS query too long: %u", query_length);
        return XDP_DROP;
    }

    if (query_length > SUSPICIOUS_QUERY_LENGTH) {
        bpf_printk("Suspicious DNS query length: %u", query_length);
        return XDP_DROP;
    }

    char *query_name = dns_data + DNS_HEADER_SIZE;
    __u32 qname_len = 0;
    for (__u32 i = 0; i < MAX_QUERY_LENGTH; i++) {
        if (query_name + i >= data_end) {
            return XDP_PASS;
        }
        if (query_name[i] == 0) {
            qname_len = i + 1;
            break;
        }
    }

    if (qname_len == 0) {
        bpf_printk("Invalid QNAME");
        return XDP_PASS;
    }

    __u64 domain_hash = xxh64_hash(query_name, qname_len);
    __u8 *is_malware = bpf_map_lookup_elem(&malware_domains, &domain_hash);
    if (is_malware && *is_malware == 1) {
        bpf_printk("Malware DNS domain detected: hash=%llu", domain_hash);
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif /* __DNS_H__ */
