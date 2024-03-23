#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 10240

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 27

struct ext4_latency_key_t {
    u8 op;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, struct ext4_latency_key_t);
    __type(value, u64);
} ext4_latency_seconds SEC(".maps");

enum fs_file_op {
    F_READ,
    F_WRITE,
    F_OPEN,
    F_FSYNC,
    F_GETATTR,
};
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
    struct ext4_latency_key_t key = {};

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) {
        return 0;
    }
    delta_us = (ts - *tsp) / 1000;
    key.op = op;

    increment_exp2_histogram(&ext4_latency_seconds, key, delta_us, MAX_LATENCY_SLOT);

    bpf_map_delete_elem(&start, &pid);
    return 0;
}

SEC("kprobe/ext4_file_read_iter")
int ext4_file_read_enter()
{
    return probe_entry();
}

SEC("kretprobe/ext4_file_read_iter")
int ext4_file_read_exit()
{
    return probe_return(F_READ);
}

SEC("kprobe/ext4_file_write_iter")
int ext4_file_write_enter()
{
    return probe_entry();
}

SEC("kretprobe/ext4_file_write_iter")
int ext4_file_write_exit()
{
    return probe_return(F_WRITE);
}

SEC("kprobe/ext4_file_open")
int ext4_file_open_enter()
{
    return probe_entry();
}

SEC("kretprobe/ext4_file_open")
int ext4_file_open_exit()
{
    return probe_return(F_OPEN);
}

SEC("kprobe/ext4_sync_file")
int ext4_file_sync_enter()
{
    return probe_entry();
}

SEC("kretprobe/ext4_sync_file")
int ext4_file_sync_exit()
{
    return probe_return(F_FSYNC);
}

SEC("kprobe/ext4_file_getattr")
int ext4_file_getattr_enter()
{
    return probe_entry();
}

SEC("kretprobe/ext4_file_getattr")
int ext4_file_getattr_exit()
{
    return probe_return(F_GETATTR);
}

char LICENSE[] SEC("license") = "GPL";
