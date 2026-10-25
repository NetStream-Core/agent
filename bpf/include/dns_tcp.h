#ifndef __DNS_TCP_H__
#define __DNS_TCP_H__

#include <bpf/bpf_helpers.h>
#include "common.h"
#include "dns.h"
#include "structs.h"

// A DNS-over-TCP message is a 2-byte big-endian length prefix followed by
// the message itself (RFC 7766 §8). Most queries fit in one TCP segment
// and need none of this — fast path stays a single bounds check, same as
// before. When a message is split across segments (a long tunnelling
// query over a link with a small MSS is the realistic case this project
// cares about, not large zone-transfer responses), each additional
// segment arrives as its own packet with no header of its own to key off
// — only the flow's 4-tuple identifies it as a continuation.
//
// DNS_HEADER_SIZE (12) + a full-length encoded name (DNS_NAME_MAX_LENGTH
// + 1 = 256) + qtype/qclass (4) = 272, so this would only need to be
// ~300 — but it's a power of 2 instead so every `buf[... & (SIZE-1)]`
// index below is unconditionally in range by construction, the standard
// way to satisfy the BPF verifier on a buffer index derived from two
// variables (a per-iteration loop counter and a map-value-sourced
// offset) instead of hoping it can prove the bound through the if-checks
// alone (confirmed against the real verifier: it couldn't). Nowhere near
// the full 65535-byte DNS-over-TCP maximum, which exists for large
// responses this project's suffix-hash check never needed anyway (see
// dns.h's handle_dns — it only ever looks at the question name).
#define DNS_TCP_REASSEMBLY_MAX 512

struct dns_tcp_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct dns_tcp_buffer
{
    __u16 expected_len; // from the first segment's 2-byte length prefix
    __u16 have_len;      // bytes buffered so far, excluding that prefix
    __u8  buf[DNS_TCP_REASSEMBLY_MAX];
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dns_tcp_key);
    __type(value, struct dns_tcp_buffer);
} dns_tcp_reassembly SEC(".maps");

// Scratch space for building a dns_tcp_buffer before bpf_map_update_elem
// — the struct is too big for the 512-byte BPF stack (same reason
// dns_scratch_map exists for struct dns_scratch in dns.h), so it's built
// in a single-entry per-CPU map value instead of a local variable.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_tcp_buffer);
} dns_tcp_scratch_map SEC(".maps");

// Appends up to `len` bytes starting at `src` into `*buf` (bounded by
// DNS_TCP_REASSEMBLY_MAX), bumping have_len. Returns the number of bytes
// actually copied — less than `len` once the buffer is full, which the
// caller treats as "can't reassemble this one", not an error.
// Clamped to both the buffer's remaining room and the message's own
// remaining length (expected_len is always set before this is called) —
// a segment can carry trailing bytes of the next pipelined DNS-over-TCP
// message after this one ends, which must not be read as if they were
// part of this message's qname.
static __always_inline __u16 dns_tcp_append(struct dns_tcp_buffer *buf, const __u8 *src, const void *data_end, __u16 len)
{
    // have_len/expected_len come from the map value, which the verifier
    // can't assume is bounded just because this code only ever writes
    // values <= DNS_TCP_REASSEMBLY_MAX into them — without this check it
    // rejects `buf->buf[start + i]` below as a potentially out-of-range
    // write (confirmed against the real verifier, not a guess).
    __u16 start = buf->have_len;
    if (start >= DNS_TCP_REASSEMBLY_MAX) { return 0; }

    __u16 room = DNS_TCP_REASSEMBLY_MAX - start;
    if (buf->expected_len > start) {
        __u16 need = buf->expected_len - start;
        if (need < room) { room = need; }
    }
    __u16 n = len < room ? len : room;

    #pragma unroll
    for (int i = 0; i < DNS_TCP_REASSEMBLY_MAX; i++) {
        if ((__u16)i >= n) { break; }
        if ((const void *)(src + i) + 1 > data_end) { break; }
        // `& (DNS_TCP_REASSEMBLY_MAX - 1)` (size is a power of 2): the
        // verifier can't otherwise prove `start + i` stays in range of
        // `buf` just from the if-checks above, since `start` comes from
        // the map value and `i` from a loop counter tracked separately
        // (confirmed — it rejected the unmasked version with "invalid
        // access to map value").
        buf->buf[(start + i) & (DNS_TCP_REASSEMBLY_MAX - 1)] = src[i];
    }

    buf->have_len = start + n;
    return n;
}

// Called once per TCP segment on port 53. Returns the XDP_PASS/XDP_DROP
// verdict from handle_dns if this segment completed a message (either
// the common single-segment case, or the segment that finished a
// reassembled one), or -1 if there's no verdict yet — nothing to do with
// this packet (buffered, waiting on more segments; or it couldn't be
// parsed as DNS-over-TCP at all).
//
// handle_dns is called from *inside* each of the two branches below,
// not once afterwards from a value this function returns by pointer.
// That's deliberate: the BPF verifier merges a stack slot's tracked type
// at the join point where two branches reconverge, and `dns_data` would
// hold either a packet pointer (the no-reassembly branch) or a
// map-value pointer (the reassembled branch) depending on which one ran
// — once merged, every later read of that slot is ambiguous between the
// two kinds, which blew the verifier's state exploration past its
// 1M-instruction limit on this exact program (confirmed; a later fix
// attempt that called handle_dns from two call sites *after* returning
// through flow_ctx still failed, for the same reason: the merge already
// happened before those two call sites existed). Calling handle_dns
// before either branch returns keeps each call's argument pointer a
// single, unambiguous kind for the whole of its inlined body.
static __always_inline int reassemble_dns_tcp(struct flow_ctx *fc, void *payload, void *data_end)
{
    struct dns_tcp_key key = {
        .src_ip   = fc->key.src_ip,
        .dst_ip   = fc->key.dst_ip,
        .src_port = fc->key.src_port,
        .dst_port = fc->key.dst_port,
    };

    struct dns_tcp_buffer *pending = bpf_map_lookup_elem(&dns_tcp_reassembly, &key);
    if (pending) {
        __u16 copied = dns_tcp_append(pending, payload, data_end, (__u16)fc->payload_size);
        if (copied == 0 && fc->payload_size > 0) {
            // buffer's full and this segment added nothing usable — give
            // up on this message rather than loop forever accepting
            // segments that can never complete it.
            bpf_map_delete_elem(&dns_tcp_reassembly, &key);
            return -1;
        }
        if (pending->have_len < pending->expected_len) { return -1; }

        void *msg_data     = pending->buf;
        void *msg_data_end = pending->buf + pending->have_len;
        bpf_map_delete_elem(&dns_tcp_reassembly, &key);
        return handle_dns(msg_data, msg_data_end, fc->key.src_ip, fc->key.dst_ip, fc->key.direction, fc->key.protocol);
    }

    // No pending entry: this segment is (the start of) a new message —
    // it must carry the 2-byte length prefix.
    if (fc->payload_size < 2) { return -1; }
    if ((void *)((__u8 *)payload + 2) > data_end) { return -1; }
    __u16 msg_len = ((const __u8 *)payload)[0] << 8 | ((const __u8 *)payload)[1];
    void *msg     = (__u8 *)payload + 2;
    __u16 avail   = (__u16)fc->payload_size - 2;

    if (avail >= msg_len) {
        // common case: the whole message is already here, no map
        // touched. Pass data_end (the real, verifier-trusted packet
        // boundary) rather than a `msg + msg_len` pointer built from
        // the attacker-controlled length prefix — the verifier can't
        // prove that one doesn't run past the packet, since it isn't
        // derived from data_end at all (confirmed: it rejected a read
        // bounds-checked against that derived pointer). handle_dns
        // already stops at DNS_NAME_MAX_LENGTH or a terminating byte
        // well before data_end in practice, exactly as it did for UDP
        // and for TCP before this reassembly code existed.
        return handle_dns(msg, data_end, fc->key.src_ip, fc->key.dst_ip, fc->key.direction, fc->key.protocol);
    }

    __u32 scratch_key          = 0;
    struct dns_tcp_buffer *tpl = bpf_map_lookup_elem(&dns_tcp_scratch_map, &scratch_key);
    if (!tpl) { return -1; }
    tpl->expected_len = msg_len;
    tpl->have_len     = 0;
    dns_tcp_append(tpl, msg, data_end, avail);
    bpf_map_update_elem(&dns_tcp_reassembly, &key, tpl, BPF_ANY);
    return -1;
}

#endif /* __DNS_TCP_H__ */
