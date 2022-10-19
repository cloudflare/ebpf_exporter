#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static u64 zero = 0;

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

#if defined(__TARGET_ARCH_x86)
SEC("fentry/__x64_sys_getpid")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_getpid")
#else
#error Unknown target for this architecture
#endif
int probe(struct pt_regs *ctx)
{
    u64 *count;
    struct key_t key = {};

    key.pid = bpf_get_current_pid_tgid();
    key.random = bpf_ktime_get_ns() % 1024;
    bpf_get_current_comm(&key.command, sizeof(key.command));

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
