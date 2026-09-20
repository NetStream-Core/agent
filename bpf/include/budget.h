#ifndef __BUDGET_H__
#define __BUDGET_H__

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BUDGET_WINDOW_NS 100000000ULL
#define BUDGET_PARTIAL_FACTOR 10

struct budget_state
{
    __u64 window_start;
    __u32 full;
    __u32 partial;
};

static __always_inline void budget_refresh(struct budget_state *state, __u64 now)
{
    if (now - state->window_start >= BUDGET_WINDOW_NS) {
        state->window_start = now;
        state->full         = 0;
        state->partial      = 0;
    }
}

static __always_inline int budget_take_full(struct budget_state *state, __u64 now, __u32 budget)
{
    budget_refresh(state, now);
    if (state->full >= budget) { return 0; }

    state->full++;
    return 1;
}

static __always_inline int budget_take_partial(struct budget_state *state, __u64 now, __u32 budget)
{
    budget_refresh(state, now);
    if (state->partial >= budget * BUDGET_PARTIAL_FACTOR) { return 0; }

    state->partial++;
    return 1;
}

#endif /* __BUDGET_H__ */
