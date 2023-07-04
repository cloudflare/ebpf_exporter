#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} raw_timer_starts_total SEC(".maps");

SEC("raw_tp/timer_start")
int do_count(struct bpf_raw_tracepoint_args *ctx)
{
    struct timer_list *timer = (struct timer_list *) ctx->args[0];
    u64 function = (u64) BPF_CORE_READ(timer, function);

    increment_map(&raw_timer_starts_total, &function, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
