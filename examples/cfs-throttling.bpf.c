#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

// 21 buckets for latency, max range is 0.5s .. 1.0s
#define MAX_LATENCY_SLOT 20

#define MAX_CGROUPS 1024

struct key_t {
    u32 cgroup;
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * MAX_CGROUPS);
    __type(key, struct key_t);
    __type(value, u64);
} cfs_throttling_seconds SEC(".maps");

SEC("fentry/unthrottle_cfs_rq")
int BPF_PROG(unthrottle_cfs_rq, struct cfs_rq *cfs_rq)
{
    u64 throttled_us = (cfs_rq->rq->clock - cfs_rq->throttled_clock) / 1000;
    struct key_t key = { .cgroup = cfs_rq->tg->css.cgroup->kn->id };

    increment_exp2_histogram(&cfs_throttling_seconds, key, throttled_us, MAX_LATENCY_SLOT);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
