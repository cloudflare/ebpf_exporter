#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} syscalls_total SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 syscall_id = (u64) ctx->id;
    increment_map(&syscalls_total, &syscall_id, 1);
    return 0;
}
