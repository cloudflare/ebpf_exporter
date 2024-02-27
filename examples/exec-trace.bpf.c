#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "tracing.bpf.h"

#define BASH_PATH "/bin/bash"

#define EXE_LENGTH 64

struct exec_span_t {
    struct span_base_t span_base;
    char exe[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, u32);
    __type(value, struct exec_span_t);
} traced_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_spans SEC(".maps");

// Clang 14 in Ubuntu 22.04 does not inline __builtin_memcmp, so we have to reimplement it.
static inline int memcmp_fallback(const void *str1, const void *str2, size_t count)
{
    const unsigned char *s1 = (const unsigned char *) str1;
    const unsigned char *s2 = (const unsigned char *) str2;

    while (count-- > 0) {
        if (*s1++ != *s2++)
            return s1[-1] < s2[-1] ? -1 : 1;
    }

    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    u64 ts = bpf_ktime_get_ns();
    u64 tgid = p->tgid, ptgid = p->real_parent->tgid;
    struct exec_span_t *parent;
    struct exec_span_t span = { 0 };
    bool start;

    if (!bprm) {
        return 0;
    }

    if (bpf_probe_read_kernel_str(span.exe, sizeof(span.exe), bprm->filename) < 0) {
        return 0;
    }

    parent = bpf_map_lookup_elem(&traced_tgids, &ptgid);
    start = memcmp_fallback(span.exe, BASH_PATH, sizeof(BASH_PATH)) == 0;

    if (parent) {
        span.span_base.parent.trace_id_hi = parent->span_base.parent.trace_id_hi;
        span.span_base.parent.trace_id_lo = parent->span_base.parent.trace_id_lo;
        span.span_base.parent.span_id = parent->span_base.span_id;
        span.span_base.span_id = ts;
    } else if (start) {
        span.span_base.parent.trace_id_lo = ts;
        span.span_base.span_id = ts;
    } else {
        return 0;
    }

    span.span_base.span_monotonic_timestamp_ns = ts;

    bpf_map_update_elem(&traced_tgids, &tgid, &span, BPF_ANY);

    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
    u64 ts = bpf_ktime_get_ns();
    u64 parent_tgid = parent->tgid, child_tgid = child->tgid;
    struct exec_span_t *span, fork;

    if (parent_tgid == child_tgid) {
        return 0;
    }

    span = bpf_map_lookup_elem(&traced_tgids, &parent_tgid);
    if (!span) {
        return 0;
    }

    fork = *span;
    fork.span_base.parent.span_id = fork.span_base.span_id;
    fork.span_base.span_id = ts;

    bpf_map_update_elem(&traced_tgids, &child_tgid, &fork, BPF_ANY);

    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p)
{
    u64 ts = bpf_ktime_get_ns();
    u64 tgid = p->tgid;
    struct exec_span_t *span = bpf_map_lookup_elem(&traced_tgids, &tgid);
    struct exec_span_t *submit;

    if (!span) {
        return 0;
    }

    span->span_base.span_duration_ns = ts - span->span_base.span_monotonic_timestamp_ns;

    submit = bpf_ringbuf_reserve(&exec_spans, sizeof(struct exec_span_t), 0);
    if (!submit) {
        goto exit;
    }

    *submit = *span;

    bpf_ringbuf_submit(submit, 0);

exit:
    bpf_map_delete_elem(&traced_tgids, &tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
