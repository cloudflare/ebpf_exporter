#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 10240

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 27

enum fs_file_op {
    F_READ,
    F_WRITE,
    F_OPEN,
    F_FSYNC,

    F_MAX
};

struct xfs_latency_key_t {
    u8 op;
    u8 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * F_MAX);
    __type(key, struct xfs_latency_key_t);
    __type(value, u64);
} xfs_latency_seconds SEC(".maps");

static int probe_entry()
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);

    return 0;
}

static int probe_return(enum fs_file_op op)
{
    u64 *tsp, delta_us, ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct xfs_latency_key_t key = { .op = (u8) op };

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) {
        return 0;
    }

    delta_us = (ts - *tsp) / 1000;

    increment_exp2_histogram(&xfs_latency_seconds, key, delta_us, MAX_LATENCY_SLOT);

    bpf_map_delete_elem(&start, &pid);

    return 0;
}

SEC("kprobe/xfs_file_read_iter")
int xfs_file_read_enter()
{
    return probe_entry();
}

SEC("kretprobe/xfs_file_read_iter")
int xfs_file_read_exit()
{
    return probe_return(F_READ);
}

SEC("kprobe/xfs_file_write_iter")
int xfs_file_write_enter()
{
    return probe_entry();
}

SEC("kretprobe/xfs_file_write_iter")
int xfs_file_write_exit()
{
    return probe_return(F_WRITE);
}

SEC("kprobe/xfs_file_open")
int xfs_file_open_enter()
{
    return probe_entry();
}

SEC("kretprobe/xfs_file_open")
int xfs_file_open_exit()
{
    return probe_return(F_OPEN);
}

SEC("kprobe/xfs_file_fsync")
int xfs_file_sync_enter()
{
    return probe_entry();
}

SEC("kretprobe/xfs_file_fsync")
int xfs_file_sync_exit()
{
    return probe_return(F_FSYNC);
}

char LICENSE[] SEC("license") = "GPL";
