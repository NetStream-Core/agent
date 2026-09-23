#ifndef __VALUES_H__
#define __VALUES_H__

#include <linux/types.h>

#define SIZE_BINS 6

struct packet_value {
    __u64 count;
    __u64 timestamp;
    __u64 payload_size;
    __u64 ip_bytes;
    __u64 tcp_syn;
    __u64 tcp_synack;
    __u64 tcp_fin;
    __u64 tcp_rst;
    __u64 size_bins[SIZE_BINS];
    __u64 iat_count;
    __u64 iat_sum_us;
    __u64 iat_sumsq_us;
};

_Static_assert(sizeof(struct packet_value) == 136, "packet_value layout is shared with the agent");

#endif /* __VALUES_H__ */
