#ifndef __DNSNAME_H__
#define __DNSNAME_H__

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define DNS_HASH_BASE 0x9e3779b97f4a7c15ULL
#define DNS_NAME_MAX_LENGTH 255
#define DNS_LABEL_MAX_LENGTH 63
#define DNS_SUFFIX_MAX 8

#define DNS_BARRIER() __asm__ __volatile__("" ::: "memory")

struct dns_event
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 qtype;
    __u8  direction;
    __u8  qname_len;
    __u8  qname[DNS_NAME_MAX_LENGTH + 1];
};

_Static_assert(sizeof(struct dns_event) == 268, "dns_event layout is shared with the agent");

struct dns_suffixes
{
    __u64 hashes[DNS_SUFFIX_MAX];
    __u32 count;
};

struct dns_scratch
{
    __u64 label_hash[DNS_SUFFIX_MAX];
    __u32 label_len[DNS_SUFFIX_MAX];
    __u64 current_hash;
    __u32 current_len;
    __u32 remaining;
    __u32 label_count;
    __u32 _padding;
    struct dns_event event;
};

static __always_inline __u64 dns_hash_pow(__u32 exponent)
{
    __u64 result = 1;
    __u64 base   = DNS_HASH_BASE;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (exponent & 1) { result *= base; }
        base *= base;
        exponent >>= 1;
    }
    return result;
}

static __always_inline __u64 dns_hash_finalize(__u64 h)
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static __always_inline __u8 dns_lower(__u8 c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static __always_inline int dns_suffix_hashes(const __u8 *name, const __u8 *end, struct dns_scratch *st,
                                             struct dns_suffixes *out)
{
    st->label_count     = 0;
    st->remaining       = 0;
    st->current_hash    = 0;
    st->current_len     = 0;
    st->event.qtype     = 0;
    st->event.qname_len = 0;

    int terminated = 0;

    for (__u32 i = 0; i < DNS_NAME_MAX_LENGTH; i++) {
        DNS_BARRIER();
        if (name + i + 1 > end) { return -1; }
        __u8 byte = name[i];
        st->event.qname[i] = byte;

        if (st->remaining == 0) {
            if (st->current_len > 0) {
                #pragma unroll
                for (int j = DNS_SUFFIX_MAX - 1; j > 0; j--) {
                    st->label_hash[j] = st->label_hash[j - 1];
                    st->label_len[j]  = st->label_len[j - 1];
                }
                st->label_hash[0] = st->current_hash;
                st->label_len[0]  = st->current_len;
                st->label_count++;
                st->current_hash = 0;
                st->current_len  = 0;
            }
            if (byte == 0) {
                terminated          = 1;
                st->event.qname_len = i;
                if (name + i + 3 <= end) { st->event.qtype = (name[i + 1] << 8) | name[i + 2]; }
                break;
            }
            if (byte > DNS_LABEL_MAX_LENGTH) { return -1; }
            st->remaining    = byte;
            st->current_hash = byte;
            st->current_len  = 1;
        } else {
            st->current_hash = st->current_hash * DNS_HASH_BASE + dns_lower(byte);
            st->current_len++;
            st->remaining--;
        }
    }

    DNS_BARRIER();
    if (!terminated || st->label_count == 0) { return -1; }

    __u64 suffix_hash = 0;
    __u32 suffix_len  = 0;
    out->count        = 0;

    #pragma unroll
    for (int k = 0; k < DNS_SUFFIX_MAX; k++) {
        if ((__u32)k >= st->label_count) { break; }
        suffix_hash    = st->label_hash[k] * dns_hash_pow(suffix_len) + suffix_hash;
        suffix_len    += st->label_len[k];
        out->hashes[k] = dns_hash_finalize(suffix_hash);
        out->count     = k + 1;
    }

    return 0;
}

#endif /* __DNSNAME_H__ */
