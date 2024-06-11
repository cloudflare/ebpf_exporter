#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define TASK_COMM_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, TASK_COMM_LEN);
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1024);
} mm_shrink_slab_events_total SEC(".maps");

SEC("tp_btf/mm_shrink_slab_end")
int BPF_PROG(mm_shrink_slab_end, struct pt_regs *regs, long id)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, TASK_COMM_LEN);

    increment_map(&mm_shrink_slab_events_total, comm, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
