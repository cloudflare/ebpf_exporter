#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} libc_malloc_calls_total SEC(".maps");

SEC("uprobe/libc.so.6:malloc")
int do_count(struct pt_regs *ctx)
{
    u64 cgroup_id = bpf_get_current_cgroup_id();

    increment_map(&libc_malloc_calls_total, &cgroup_id, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
