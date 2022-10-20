#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 26

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
} shrink_node_latency_seconds SEC(".maps");

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
    u64 *tsp, latency_us, latency_slot;

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) {
        return 0;
    }

    // Latency in microseconds
    latency_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // Latency histogram key
    latency_slot = log2l(latency_us);

    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    increment_map(&shrink_node_latency_seconds, &latency_slot, 1);

    latency_slot = MAX_LATENCY_SLOT + 1;
    increment_map(&shrink_node_latency_seconds, &latency_slot, latency_us);

    bpf_map_delete_elem(&start, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
