#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} counts SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(probe)
{
    u32 key = bpf_get_current_pid_tgid();
    u64 *count;

    count = bpf_map_lookup_elem(&counts, &key);
    if (!count) {
        bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&counts, &key);
        if (!count) {
            return 0;
        }
    }
    __sync_fetch_and_add(count, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
