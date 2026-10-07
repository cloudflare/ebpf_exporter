#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "tracing.bpf.h"

// On Zen v4 this is the depth.
#define LBR_DEPTH 16

struct failure_span_t {
    struct span_base_t span_base;
    struct perf_branch_entry entries[LBR_DEPTH];
    u32 errno;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} failure_spans SEC(".maps");

SEC("fexit/do_sys_openat2")
int BPF_PROG(do_sys_openat2, int dfd, const char *filename, struct open_how *how, int retval)
{
    struct failure_span_t span = { 0 };
    struct failure_span_t *submit;
    u64 ts;

    if (retval >= 0) {
        return 0;
    }

    s64 snapshot_bytes = bpf_get_branch_snapshot(span.entries, sizeof(span.entries), 0);
    if (snapshot_bytes == 0) {
        return 0;
    }

    ts = bpf_ktime_get_ns();

    span.span_base.parent.trace_id_lo = ts;
    span.span_base.span_id = ts;
    span.span_base.span_monotonic_timestamp_ns = ts;
    span.errno = -retval;

    submit = bpf_ringbuf_reserve(&failure_spans, sizeof(struct failure_span_t), 0);
    if (!submit) {
        return 0;
    }

    *submit = span;

    bpf_ringbuf_submit(submit, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
