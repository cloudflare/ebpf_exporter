#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "tracing.bpf.h"

// Skipping 3 frames off the top as they are just bpf trampoline
#define SKIP_FRAMES (3 & BPF_F_SKIP_FIELD_MASK)

#define MAX_STACK_DEPTH 20

struct cfs_throttle_span_t {
    struct span_base_t span_base;
    u64 kstack[MAX_STACK_DEPTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cfs_throttle_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, u32);
    __type(value, struct span_parent_t);
} traced_cgroups SEC(".maps");

SEC("usdt/./tracing/demos/cfs-throttling/demo:ebpf_exporter:cfs_set_parent_span")
int BPF_USDT(cfs_set_parent_span, u64 trace_id_hi, u64 trace_id_lo, u64 span_id)
{
    u32 cgroup = bpf_get_current_cgroup_id();
    struct span_parent_t parent = { .trace_id_hi = trace_id_hi, .trace_id_lo = trace_id_lo, .span_id = span_id };

    bpf_map_update_elem(&traced_cgroups, &cgroup, &parent, BPF_ANY);

    return 0;
}

SEC("usdt/./tracing/demos/cfs-throttling/demo:ebpf_exporter:cfs_clear_parent_span")
int BPF_USDT(cfs_clear_parent_span)
{
    u32 cgroup = bpf_get_current_cgroup_id();

    bpf_map_delete_elem(&traced_cgroups, &cgroup);

    return 0;
}

SEC("tp_btf/cgroup_release")
int BPF_PROG(cgroup_release, struct cgroup *cgrp)
{
    u32 cgroup = cgrp->kn->id;

    bpf_map_delete_elem(&traced_cgroups, &cgroup);

    return 0;
}

SEC("fentry/unthrottle_cfs_rq")
int BPF_PROG(unthrottle_cfs_rq, struct cfs_rq *cfs_rq)
{
    u32 cgroup = cfs_rq->tg->css.cgroup->kn->id;
    u64 throttled_ns = cfs_rq->rq->clock - cfs_rq->throttled_clock;
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_cgroups, &cgroup);

    if (!cfs_rq->throttled_clock) {
        return 0;
    }

    if (!parent) {
        return 0;
    }

    submit_span(&cfs_throttle_spans, struct cfs_throttle_span_t, parent, {
        span->span_base.span_monotonic_timestamp_ns -= throttled_ns;
        span->span_base.span_duration_ns = throttled_ns;

        bpf_get_stack(ctx, &span->kstack, sizeof(span->kstack), SKIP_FRAMES);
    });

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
