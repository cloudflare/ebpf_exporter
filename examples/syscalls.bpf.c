#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} syscalls_total SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id)
{
    increment_map(&syscalls_total, &id, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
