#ifndef __COMMON_H__
#define __COMMON_H__

#define BPF_NTOHS(x) (__builtin_bswap16(x))
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define MAX_QUERY_LENGTH 255
#define SUSPICIOUS_QUERY_LENGTH 100

#ifdef DEBUG
#define debug_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_printk(fmt, ...) ((void)0)
#endif

#endif /* __COMMON_H__ */
