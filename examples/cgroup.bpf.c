#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} cgroup_sched_migrations_total SEC(".maps");

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(sched_migrate_task)
{
    u64 cgroup_id = bpf_get_current_cgroup_id();
    increment_map(&cgroup_sched_migrations_total, &cgroup_id, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
