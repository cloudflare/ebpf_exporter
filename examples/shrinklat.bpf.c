#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bits.bpf.h"

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 26

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, u32);
    __type(value, u64);
} shrink_node_latency SEC(".maps");

SEC("kprobe/shrink_node")
int shrink_node_enter(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/shrink_node")
int shrink_node_exit(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp, *count;
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) {
        return 0;
    }

    // Latency in microseconds
    u64 latency_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    u64 latency_slot = log2l(latency_us);

    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    count = bpf_map_lookup_elem(&shrink_node_latency, &latency_slot);
    if (!count) {
        bpf_map_update_elem(&shrink_node_latency, &latency_slot, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&shrink_node_latency, &latency_slot);
        if (!count) {
            goto cleanup;
        }
    }
    __sync_fetch_and_add(count, 1);

    latency_slot = MAX_LATENCY_SLOT + 1;
    count = bpf_map_lookup_elem(&shrink_node_latency, &latency_slot);
    if (!count) {
        bpf_map_update_elem(&shrink_node_latency, &latency_slot, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&shrink_node_latency, &latency_slot);
        if (!count) {
            goto cleanup;
        }
    }
    __sync_fetch_and_add(count, latency_us);

cleanup:
    bpf_map_delete_elem(&start, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
