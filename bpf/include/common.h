#ifndef __COMMON_H__
#define __COMMON_H__

#define BPF_NTOHS(x) (__builtin_bswap16(x))
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define MAX_QUERY_LENGTH 255
#define SUSPICIOUS_QUERY_LENGTH 100

#endif /* __COMMON_H__ */
