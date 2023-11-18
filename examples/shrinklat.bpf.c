#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 26

struct key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, u32); // struct key_t in reality, but btf gets confused and logs a warning
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
    u64 *tsp, delta_us, ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct key_t key = {};

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) {
        return 0;
    }

    delta_us = (ts - *tsp) / 1000;

    increment_exp2_histogram(&shrink_node_latency_seconds, key, delta_us, MAX_LATENCY_SLOT);

    bpf_map_delete_elem(&start, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
