#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} cgroup_sched_migrations_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} cgroup_sched_migrations_not_match_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} cgroup_id_map SEC(".maps");

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(sched_migrate_task)
{
    u64 *ok;
    u64 cgroup_id = bpf_get_current_cgroup_id();
    ok = bpf_map_lookup_elem(&cgroup_id_map, &cgroup_id);
    if (ok) {
        increment_map(&cgroup_sched_migrations_total, &cgroup_id, 1);
    } else {
        increment_map(&cgroup_sched_migrations_not_match_total, &cgroup_id, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
