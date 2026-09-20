#ifndef __COMMON_H__
#define __COMMON_H__

#define BPF_NTOHS(x) (__builtin_bswap16(x))
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS 1

#define MODE_MONITOR 0
#define MODE_ENFORCE 1
#define MODE_GATEWAY 2

#define ACTION_OBSERVED 0
#define ACTION_DROPPED 1
#define ACTION_QUARANTINED 2

#ifdef DEBUG
#define debug_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_printk(fmt, ...) ((void)0)
#endif

#endif /* __COMMON_H__ */
