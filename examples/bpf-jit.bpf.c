#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

const volatile u64 kaddr_bpf_jit_current = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} bpf_jit_pages_currently_allocated SEC(".maps");

SEC("kprobe/bpf_jit_binary_alloc")
int trace_change(struct pt_regs *ctx)
{
    u32 zero_key = 0;
    s64 current_value = 0;

    if (!kaddr_bpf_jit_current) {
        return 0;
    }

    bpf_probe_read_kernel(&current_value, sizeof(current_value), (const void*) kaddr_bpf_jit_current);
    bpf_map_update_elem(&bpf_jit_pages_currently_allocated, &zero_key, &current_value, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
