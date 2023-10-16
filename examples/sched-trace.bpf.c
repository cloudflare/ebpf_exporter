#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracing.bpf.h"

// https://github.com/torvalds/linux/blob/v6.1/include/linux/sched.h#L84
#define TASK_INTERRUPTIBLE 0x00000001
#define TASK_UNINTERRUPTIBLE 0x00000002

enum task_state {
    STATE_TASK_PROBABLY_RUNNING,
    STATE_TASK_INTERRUPTIBLE,
    STATE_TASK_UNINTERRUPTIBLE,
};

struct sched_wakeup_span_t {
    struct span_base_t span_base;
    u32 tgid;
    u32 pid;
};

struct sched_migrate_span_t {
    struct span_base_t span_base;
    u32 tgid;
    u32 pid;
    u32 orig_cpu;
    u32 dest_cpu;
};

struct sched_switch_span_t {
    struct span_base_t span_base;
    u32 tgid;
    u32 pid;
    u32 prev_state;
    bool preempt;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sched_wakeup_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sched_migrate_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sched_switch_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, u32);
    __type(value, struct span_parent_t);
} traced_tgids SEC(".maps");

static int task_state(unsigned int state)
{
    if (state & TASK_INTERRUPTIBLE) {
        return STATE_TASK_INTERRUPTIBLE;
    } else if (state & TASK_UNINTERRUPTIBLE) {
        return STATE_TASK_UNINTERRUPTIBLE;
    }

    return STATE_TASK_PROBABLY_RUNNING;
}

SEC("uprobe/./tracing/demos/sched/demo:sched_set_parent_span")
int sock_set_parent_span(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 trace_id_hi = PT_REGS_PARM1(ctx);
    u64 trace_id_lo = PT_REGS_PARM2(ctx);
    u64 span_id = PT_REGS_PARM3(ctx);
    struct span_parent_t parent = { .trace_id_hi = trace_id_hi, .trace_id_lo = trace_id_lo, .span_id = span_id };

    bpf_map_update_elem(&traced_tgids, &tgid, &parent, BPF_ANY);

    return 0;
}

SEC("uprobe/./tracing/demos/sched/demo:sched_clear_parent_span")
int sched_clear_parent_span(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_delete_elem(&traced_tgids, &tgid);

    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p)
{
    u32 tgid = p->tgid;

    if (p->pid != p->tgid) {
        return 0;
    }

    bpf_map_delete_elem(&traced_tgids, &tgid);

    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 tgid = p->tgid, pid = p->pid;
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_tgids, &tgid);

    if (!parent) {
        return 0;
    }

    submit_span(&sched_wakeup_spans, struct sched_wakeup_span_t, parent, {
        span->tgid = tgid;
        span->pid = pid;
    });

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *p, struct task_struct *next, unsigned int prev_state)
{
    u32 tgid = p->tgid, pid = p->pid;
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_tgids, &tgid);

    if (!parent) {
        return 0;
    }

    submit_span(&sched_switch_spans, struct sched_switch_span_t, parent, {
        span->tgid = tgid;
        span->pid = pid;

        span->prev_state = task_state(prev_state);
        span->preempt = preempt;
    });

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
