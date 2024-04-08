#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} syscalls_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} syscall_errors_total SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id)
{
    increment_map(&syscalls_total, &id, 1);
    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit, struct pt_regs *regs, long ret)
{
    if (ret < 0) {
        ret = -ret; // negative return is errno
        increment_map(&syscall_errors_total, &ret, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
