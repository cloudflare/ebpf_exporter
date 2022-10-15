#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} counts SEC(".maps");

SEC("kprobe/sys_getpid")
int kprobe__sys_getpid(struct pt_regs *ctx)
{
    u64 one = 1;
    u64 *count;
    u32 key = bpf_get_current_pid_tgid();

    count = (u64*) bpf_map_lookup_elem(&counts, &key);
    if (count) {
        *count += 1;
    } else {
        bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
