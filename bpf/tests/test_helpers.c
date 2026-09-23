#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "budget.h"
#include "dnsname.h"
#include "ports.h"
#include "shape.h"

#define GOOGLE_COM_HASH 4282548222659472292ULL
#define COM_HASH 17442394860103835407ULL

static void collapse(__u16 *src, __u16 *dst)
{
    collapse_ephemeral_port(src, dst, 32768, 60999);
}

static void test_ephemeral_source_is_collapsed(void)
{
    __u16 src = 44321, dst = 443;
    collapse(&src, &dst);
    assert(src == 0 && dst == 443);
}

static void test_ephemeral_destination_is_collapsed(void)
{
    __u16 src = 443, dst = 44321;
    collapse(&src, &dst);
    assert(src == 443 && dst == 0);
}

static void test_both_or_neither_ephemeral_are_kept(void)
{
    __u16 src = 40000, dst = 45000;
    collapse(&src, &dst);
    assert(src == 40000 && dst == 45000);

    src = 80;
    dst = 8080;
    collapse(&src, &dst);
    assert(src == 80 && dst == 8080);
}

static void test_range_boundaries_are_inclusive(void)
{
    __u16 src = 32768, dst = 22;
    collapse(&src, &dst);
    assert(src == 0 && dst == 22);

    src = 60999;
    dst = 22;
    collapse(&src, &dst);
    assert(src == 0);

    src = 32767;
    dst = 22;
    collapse(&src, &dst);
    assert(src == 32767);

    src = 61000;
    dst = 22;
    collapse(&src, &dst);
    assert(src == 61000);
}

static void test_scan_targets_in_the_ephemeral_range_keep_both_ports(void)
{
    __u16 src = 41000, dst = 50000;
    collapse(&src, &dst);
    assert(src == 41000 && dst == 50000);
}

static int hashes(const char *wire, int length, struct dns_suffixes *out, struct dns_scratch *state)
{
    __u8 packet[300];
    memcpy(packet, wire, length);
    packet[length]     = 0;
    packet[length + 1] = 0;
    packet[length + 2] = 16;
    packet[length + 3] = 0;
    packet[length + 4] = 1;
    return dns_suffix_hashes(packet, packet + length + 5, state, out);
}

static void test_suffix_hashes_and_case_insensitivity(void)
{
    struct dns_suffixes lower, upper;
    struct dns_scratch  state;

    assert(hashes("\x06google\x03"
                  "com",
                  11, &lower, &state) == 0);
    assert(lower.count == 2);
    assert(lower.hashes[0] == COM_HASH);
    assert(lower.hashes[1] == GOOGLE_COM_HASH);
    assert(state.event.qtype == 16);
    assert(state.event.qname_len == 11);

    assert(hashes("\x06GoOgLe\x03"
                  "COM",
                  11, &upper, &state) == 0);
    assert(upper.count == 2);
    assert(upper.hashes[0] == COM_HASH && upper.hashes[1] == GOOGLE_COM_HASH);
}

static void test_only_the_last_eight_labels_are_hashed(void)
{
    struct dns_suffixes out;
    struct dns_scratch  state;
    char                wire[64];
    int                 length = 0;

    for (int i = 0; i < 12; i++) {
        wire[length++] = 1;
        wire[length++] = 'a' + i;
    }
    assert(hashes(wire, length, &out, &state) == 0);
    assert(out.count == DNS_SUFFIX_MAX);
}

static void test_malformed_names_are_rejected(void)
{
    struct dns_suffixes out;
    struct dns_scratch  state;
    __u8                packet[8] = {3, 'a', 'b'};

    assert(hashes("\x40"
                  "abc",
                  4, &out, &state) == -1);
    assert(dns_suffix_hashes(packet, packet + 3, &state, &out) == -1);
    assert(hashes("", 0, &out, &state) == -1);
}

static void test_budget_admits_up_to_the_limit_per_window(void)
{
    struct budget_state state = {0};

    for (int i = 0; i < 5; i++) { assert(budget_take_full(&state, 1000 + i, 5)); }
    assert(!budget_take_full(&state, 2000, 5));
    assert(!budget_take_full(&state, 3000, 5));
}

static void test_partial_budget_is_a_multiple_of_the_full_one_and_independent(void)
{
    struct budget_state state = {0};

    for (int i = 0; i < 5; i++) { assert(budget_take_full(&state, 1000, 5)); }
    assert(!budget_take_full(&state, 1000, 5));

    for (int i = 0; i < 5 * BUDGET_PARTIAL_FACTOR; i++) { assert(budget_take_partial(&state, 1000, 5)); }
    assert(!budget_take_partial(&state, 1000, 5));
}

static void test_budgets_refill_when_the_window_ends(void)
{
    struct budget_state state = {0};
    __u64               start = 10ULL * BUDGET_WINDOW_NS;

    for (int i = 0; i < 3; i++) { assert(budget_take_full(&state, start, 3)); }
    assert(budget_take_partial(&state, start, 3));
    assert(!budget_take_full(&state, start + BUDGET_WINDOW_NS - 1, 3));

    assert(budget_take_full(&state, start + BUDGET_WINDOW_NS, 3));
    assert(state.full == 1);
    assert(state.partial == 0);
    assert(state.window_start == start + BUDGET_WINDOW_NS);
}

static void test_size_bins_are_disjoint_and_ordered(void)
{
    assert(size_bin(0) == 0 && size_bin(40) == 0 && size_bin(64) == 0);
    assert(size_bin(65) == 1 && size_bin(128) == 1);
    assert(size_bin(129) == 2 && size_bin(256) == 2);
    assert(size_bin(257) == 3 && size_bin(512) == 3);
    assert(size_bin(513) == 4 && size_bin(1024) == 4);
    assert(size_bin(1025) == 5 && size_bin(65535) == 5);
}

static void test_first_packet_has_no_inter_arrival_time(void)
{
    struct packet_value value = {0};
    record_shape(&value, 60, 0, 5000000);
    assert(value.size_bins[0] == 1);
    assert(value.iat_count == 0 && value.iat_sum_us == 0 && value.iat_sumsq_us == 0);
}

static void test_inter_arrival_moments_accumulate_in_microseconds(void)
{
    struct packet_value value = {0};
    record_shape(&value, 1500, 1000000, 1000000 + 2000000);
    record_shape(&value, 1500, 3000000, 3000000 + 4000000);

    assert(value.size_bins[5] == 2);
    assert(value.iat_count == 2);
    assert(value.iat_sum_us == 2000 + 4000);
    assert(value.iat_sumsq_us == 2000ULL * 2000 + 4000ULL * 4000);
}

static void test_inter_arrival_gaps_are_capped(void)
{
    struct packet_value value = {0};
    record_shape(&value, 100, 1, 1 + 60ULL * 1000000000ULL);
    assert(value.iat_sum_us == IAT_CAP_US);
    assert(value.iat_sumsq_us == IAT_CAP_US * IAT_CAP_US);
}

static void test_non_monotonic_clock_is_ignored(void)
{
    struct packet_value value = {0};
    record_shape(&value, 100, 9000, 8000);
    assert(value.iat_count == 0);
    assert(value.size_bins[1] == 1);
}

int main(void)
{
    test_ephemeral_source_is_collapsed();
    test_ephemeral_destination_is_collapsed();
    test_both_or_neither_ephemeral_are_kept();
    test_range_boundaries_are_inclusive();
    test_scan_targets_in_the_ephemeral_range_keep_both_ports();
    test_suffix_hashes_and_case_insensitivity();
    test_only_the_last_eight_labels_are_hashed();
    test_malformed_names_are_rejected();
    test_budget_admits_up_to_the_limit_per_window();
    test_partial_budget_is_a_multiple_of_the_full_one_and_independent();
    test_budgets_refill_when_the_window_ends();
    test_size_bins_are_disjoint_and_ordered();
    test_first_packet_has_no_inter_arrival_time();
    test_inter_arrival_moments_accumulate_in_microseconds();
    test_inter_arrival_gaps_are_capped();
    test_non_monotonic_clock_is_ignored();
    puts("bpf helper tests passed");
    return 0;
}
