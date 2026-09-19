#ifndef __DNS_H__
#define __DNS_H__

#include <bpf/bpf_helpers.h>
#include "common.h"
#include "structs.h"
#include "dnsname.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_scratch);
} dns_scratch_map SEC(".maps");

static __always_inline int handle_dns(void *data, void *data_end, __u32 src_ip)
{
    void *dns_data = data;
    if (dns_data + DNS_HEADER_SIZE > data_end) { return XDP_PASS; }

    __u32 scratch_key         = 0;
    struct dns_scratch *state = bpf_map_lookup_elem(&dns_scratch_map, &scratch_key);
    if (!state) { return XDP_PASS; }

    struct dns_suffixes suffixes = {};
    if (dns_suffix_hashes(dns_data + DNS_HEADER_SIZE, data_end, state, &suffixes) < 0) { return XDP_PASS; }

    #pragma unroll
    for (int k = 0; k < DNS_SUFFIX_MAX; k++) {
        if ((__u32)k >= suffixes.count) { break; }

        __u64 domain_hash = suffixes.hashes[k];
        __u8 *is_malware  = bpf_map_lookup_elem(&malware_domains, &domain_hash);
        if (!is_malware || *is_malware != 1) { continue; }

        __u8 blocked = 1;
        bpf_map_update_elem(&blocked_ips, &src_ip, &blocked, BPF_ANY);

        struct malware_event_t *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->src_ip      = src_ip;
            e->domain_hash = domain_hash;
            bpf_ringbuf_submit(e, 0);
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif /* __DNS_H__ */
