#ifndef __XXH64_H__
#define __XXH64_H__

#include "common.h"

static __always_inline __u64 xxh64_hash(const char *data, __u32 len) {
    __u64 hash = 0x9e3779b97f4a7c15ULL;
    __u64 prime = 0x100000001b3ULL;
    __u32 i;

    if (len > MAX_QUERY_LENGTH) {
        len = MAX_QUERY_LENGTH;
    }

    for (i = 0; i < len && data[i] != 0; i++) {
        hash ^= (__u64)data[i];
        hash *= prime;
        hash = (hash << 23) | (hash >> 41);
    }

    hash ^= (hash >> 33);
    hash *= 0xc2b2ae35ULL;
    hash ^= (hash >> 29);
    return hash;
}


#endif /* __XXH64_H__ */
