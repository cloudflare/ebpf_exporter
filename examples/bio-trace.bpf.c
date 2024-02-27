#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracing.bpf.h"

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

struct disk_span_t {
    struct span_base_t span_base;
    u32 dev;
    u8 op;
};

#define submit_bio_span(map, type, rq, fill)                                                                           \
    struct span_parent_t parent = {};                                                                                  \
    parent.trace_id_hi = BPF_CORE_READ(rq, start_time_ns);                                                             \
    parent.trace_id_lo = (u64) rq;                                                                                     \
                                                                                                                       \
    submit_span(map, type, &parent, fill);

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 64);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} block_rq_insert_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} block_rq_service_spans SEC(".maps");

SEC("raw_tp/block_rq_insert")
int block_rq_insert(struct bpf_raw_tracepoint_args *ctx)
{
    struct request *rq = (struct request *) ctx->args[0];
    struct gendisk *disk = BPF_CORE_READ(rq, q, disk);

    submit_bio_span(&block_rq_insert_spans, struct disk_span_t, rq, {
        span->dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
        span->op = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
    });

    return 0;
}

SEC("raw_tp/block_rq_issue")
int block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    struct request *rq = (struct request *) ctx->args[0];
    bpf_map_update_elem(&start, &rq, &ts, 0);
    return 0;
}

SEC("raw_tp/block_rq_complete")
int block_rq_complete(struct bpf_raw_tracepoint_args *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    struct request *rq = (struct request *) ctx->args[0];
    struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
    u64 *issue_ts_ptr;

    issue_ts_ptr = bpf_map_lookup_elem(&start, &rq);
    if (!issue_ts_ptr) {
        return 0;
    }

    submit_bio_span(&block_rq_service_spans, struct disk_span_t, rq, {
        span->span_base.span_duration_ns = ts - *issue_ts_ptr;
        span->dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
        span->op = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
    });

    bpf_map_delete_elem(&start, &rq);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
