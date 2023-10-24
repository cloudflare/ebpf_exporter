#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

// Loosely based on https://github.com/xdp-project/xdp-project/blob/master/areas/latency/softirq_net_latency.bt

// 20 buckets for latency, max range is 0.5s .. 1.0s
#define MAX_LATENCY_SLOT 21

#define check_net_rx(vec_nr)                                                                                           \
    if (vec_nr != NET_RX_SOFTIRQ) {                                                                                    \
        return 0;                                                                                                      \
    }

// We only use one index in the array for this
u32 net_rx_idx = 0;

struct softirq_latency_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirq_raised_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirq_serviced_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirq_raise_timestamp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirq_entry_timestamp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 2);
    __type(key, u32);
    __type(value, u64);
} softirq_entry_latency_seconds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 2);
    __type(key, u32);
    __type(value, u64);
} softirq_service_latency_seconds SEC(".maps");

SEC("tp_btf/softirq_raise")
int BPF_PROG(softirq_raise, unsigned int vec_nr)
{
    u64 *existing_ts_ptr, *raised_total_ptr, ts;

    check_net_rx(vec_nr);

    ts = bpf_ktime_get_ns();

    read_array_ptr(&softirq_raised_total, &net_rx_idx, raised_total_ptr);
    *raised_total_ptr += 1;

    read_array_ptr(&softirq_raise_timestamp, &net_rx_idx, existing_ts_ptr);

    // Set the timestamp only if it is not set, so that we always measure the oldest non-entered raise
    if (!*existing_ts_ptr) {
        *existing_ts_ptr = ts;
    }

    return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr)
{
    u64 delta_us, *raise_ts_ptr, *existing_entry_ts_ptr, *serviced_total_ptr, ts;
    struct softirq_latency_key_t key = {};

    check_net_rx(vec_nr);

    ts = bpf_ktime_get_ns();

    read_array_ptr(&softirq_serviced_total, &net_rx_idx, serviced_total_ptr);
    *serviced_total_ptr += 1;

    read_array_ptr(&softirq_raise_timestamp, &net_rx_idx, raise_ts_ptr);

    // Interrupt was re-rased after ts was obtained, resulting in negative duration
    if (*raise_ts_ptr > ts) {
        return 0;
    }

    // Interrupt entry started with no corresponding raise, resulting in large duration
    if (!*raise_ts_ptr) {
        return 0;
    }

    delta_us = (ts - *raise_ts_ptr) / 1000;

    increment_exp2_histogram_nosync(&softirq_entry_latency_seconds, key, delta_us, MAX_LATENCY_SLOT);

    // Allow raise timestamp to be set again
    *raise_ts_ptr = 0;

    read_array_ptr(&softirq_entry_timestamp, &net_rx_idx, existing_entry_ts_ptr);

    // There is some time from function start to here, so overall service time includes it
    *existing_entry_ts_ptr = ts;

    return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit, unsigned int vec_nr)
{
    u64 delta_us, *entry_ts_ptr, ts;
    struct softirq_latency_key_t key = {};

    check_net_rx(vec_nr);

    ts = bpf_ktime_get_ns();

    read_array_ptr(&softirq_entry_timestamp, &net_rx_idx, entry_ts_ptr);

    // Interrupt exited with no corresponding entry, resulting in large duration
    if (!*entry_ts_ptr) {
        return 0;
    }

    delta_us = (ts - *entry_ts_ptr) / 1000;

    increment_exp2_histogram_nosync(&softirq_service_latency_seconds, key, delta_us, MAX_LATENCY_SLOT);

    // Reset entry ts to prevent skipped entries to be counted at exit
    *entry_ts_ptr = 0;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
