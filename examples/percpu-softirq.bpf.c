#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, NR_SOFTIRQS);
    __type(key, u32);
    __type(value, u64);
} softirqs_total SEC(".maps");

SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr)
{
    increment_map(&softirqs_total, &vec_nr, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
