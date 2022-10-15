#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct key_t {
    u64 pid;
    u64 random;
    char command[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

SEC("kprobe/sys_getpid")
int kprobe__sys_getpid(struct pt_regs *ctx)
{
    u64 one = 1;
    u64 *count;

    struct key_t key = {};

    key.pid = bpf_get_current_pid_tgid();
    key.random = bpf_ktime_get_ns() % 1024;
    bpf_get_current_comm(&key.command, sizeof(key.command));

    count = (u64*) bpf_map_lookup_elem(&counts, &key);
    if (count) {
        *count += 1;
    } else {
        bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
