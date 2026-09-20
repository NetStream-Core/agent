#ifndef __PORTS_H__
#define __PORTS_H__

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static __always_inline int port_is_ephemeral(__u16 port, __u16 low, __u16 high)
{
    return port >= low && port <= high;
}

static __always_inline void collapse_ephemeral_port(__u16 *src_port, __u16 *dst_port, __u16 low, __u16 high)
{
    int src_ephemeral = port_is_ephemeral(*src_port, low, high);
    int dst_ephemeral = port_is_ephemeral(*dst_port, low, high);

    if (src_ephemeral && !dst_ephemeral) {
        *src_port = 0;
    } else if (dst_ephemeral && !src_ephemeral) {
        *dst_port = 0;
    }
}

#endif /* __PORTS_H__ */
