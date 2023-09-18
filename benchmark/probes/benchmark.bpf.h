#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(__TARGET_ARCH_x86)
#define FENTRY_SEC() SEC("fentry/__do_sys_getpid")
#elif defined(__TARGET_ARCH_arm64)
#define FENTRY_SEC() SEC("fentry/__arm64_sys_getpid")
#else
#error Unknown target for this architecture
#endif

#if defined(__TARGET_ARCH_x86)
#define KPROBE_SEC() SEC("kprobe/__do_sys_getpid")
#elif defined(__TARGET_ARCH_arm64)
#define KPROBE_SEC() SEC("kprobe/__arm64_sys_getpid")
#else
#error Unknown target for this architecture
#endif

#define TRACEPOINT_SEC() SEC("tp_btf/sys_enter")

#define BENCHMARK_PROBE(sec, impl)                                                                                     \
    sec() int probe()                                                                                                  \
    {                                                                                                                  \
        return impl();                                                                                                 \
    }

static u64 zero = 0;

#ifdef BENCHMARK_NO_MAP
static inline int empty_probe()
{
    return 0;
}
#endif

#ifdef BENCHMARK_SIMPLE_MAP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} counts SEC(".maps");

static inline int simple_probe()
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
#endif

#ifdef BENCHMARK_COMPLEX_MAP
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

static inline int complex_probe()
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
#endif

char LICENSE[] SEC("license") = "GPL";
