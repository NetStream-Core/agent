#ifndef __SHAPE_H__
#define __SHAPE_H__

#include <linux/types.h>

#include "values.h"

#define IAT_CAP_US 10000000ULL

static __always_inline __u32 size_bin(__u32 ip_bytes)
{
    if (ip_bytes <= 64) { return 0; }
    if (ip_bytes <= 128) { return 1; }
    if (ip_bytes <= 256) { return 2; }
    if (ip_bytes <= 512) { return 3; }
    if (ip_bytes <= 1024) { return 4; }
    return 5;
}

static __always_inline void record_shape(struct packet_value *value, __u32 ip_bytes, __u64 previous, __u64 now)
{
    __u32 bin = size_bin(ip_bytes);
    if (bin < SIZE_BINS) { value->size_bins[bin] += 1; }

    if (previous == 0 || now <= previous) { return; }

    __u64 gap_us = (now - previous) / 1000;
    if (gap_us > IAT_CAP_US) { gap_us = IAT_CAP_US; }

    value->iat_count += 1;
    value->iat_sum_us += gap_us;
    value->iat_sumsq_us += gap_us * gap_us;
}

#endif /* __SHAPE_H__ */
