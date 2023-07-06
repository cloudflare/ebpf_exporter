#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} timer_starts_total SEC(".maps");

SEC("tp_btf/timer_start")
int BPF_PROG(timer_start, struct timer_list *timer)
{
    u64 function = (u64) timer->function;
    increment_map(&timer_starts_total, &function, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
