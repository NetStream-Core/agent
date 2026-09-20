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

const volatile __u8  DNS_EVENTS         = 1;
const volatile __u8  RESPONSE_MODE     = MODE_MONITOR;
const volatile __u64 QUARANTINE_TTL_NS = 60000000000ULL;

static __always_inline int is_allowlisted(__u32 addr)
{
    struct allowlist_key key = {.prefixlen = 32, .addr = addr};
    return bpf_map_lookup_elem(&quarantine_allowlist, &key) != NULL;
}

static __always_inline int handle_dns(void *data, void *data_end, __u32 src_ip, __u32 dst_ip, __u8 direction)
{
    void *dns_data = data;
    if (dns_data + DNS_HEADER_SIZE > data_end) { return XDP_PASS; }

    __u32 scratch_key         = 0;
    struct dns_scratch *state = bpf_map_lookup_elem(&dns_scratch_map, &scratch_key);
    if (!state) { return XDP_PASS; }

    struct dns_suffixes suffixes = {};
    if (dns_suffix_hashes(dns_data + DNS_HEADER_SIZE, data_end, state, &suffixes) < 0) { return XDP_PASS; }

    if (DNS_EVENTS) {
        state->event.src_ip    = src_ip;
        state->event.dst_ip    = dst_ip;
        state->event.direction = direction;
        if (bpf_ringbuf_output(&dns_queries, &state->event, sizeof(state->event), 0) != 0) {
            __u64 *lost = bpf_map_lookup_elem(&dns_events_lost, &scratch_key);
            if (lost) { *lost += 1; }
        }
    }

    #pragma unroll
    for (int k = 0; k < DNS_SUFFIX_MAX; k++) {
        if ((__u32)k >= suffixes.count) { break; }

        __u64 domain_hash = suffixes.hashes[k];
        __u8 *is_malware  = bpf_map_lookup_elem(&malware_domains, &domain_hash);
        if (!is_malware || *is_malware != 1) { continue; }

        __u32 action = RESPONSE_MODE == MODE_MONITOR ? ACTION_OBSERVED : ACTION_DROPPED;

        if (RESPONSE_MODE == MODE_GATEWAY && !is_allowlisted(src_ip)) {
            struct block_entry entry = {
                .expires_ns  = bpf_ktime_get_ns() + QUARANTINE_TTL_NS,
                .domain_hash = domain_hash,
            };
            bpf_map_update_elem(&blocked_ips, &src_ip, &entry, BPF_ANY);
            action = ACTION_QUARANTINED;
        }

        struct malware_event_t *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->src_ip      = src_ip;
            e->action      = action;
            e->domain_hash = domain_hash;
            bpf_ringbuf_submit(e, 0);
        }
        return RESPONSE_MODE == MODE_MONITOR ? XDP_PASS : XDP_DROP;
    }

    return XDP_PASS;
}

#endif /* __DNS_H__ */
