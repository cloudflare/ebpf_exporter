#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} cgroup_cgrp_storage_sched_migrations_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} cgroup_cgrp_storage_sched_migrations_not_match_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, u64);
} cgroup_id_map_cgrp_storage SEC(".maps");

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(sched_migrate_task, struct task_struct *task, int dest_cpu)
{
    u64 *ok;
    struct cgroup *cgrp = task->cgroups->dfl_cgrp;
    ok = bpf_cgrp_storage_get(&cgroup_id_map_cgrp_storage, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ok) {
        return 1;
    }
    u64 cgroup_id = BPF_CORE_READ(cgrp, kn, id);
    if (*ok) {
        increment_map(&cgroup_cgrp_storage_sched_migrations_total, &cgroup_id, 1);
    } else {
        increment_map(&cgroup_cgrp_storage_sched_migrations_not_match_total, &cgroup_id, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
