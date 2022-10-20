#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

const volatile u64 kaddr_bpf_jit_current = 0;

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} current SEC(".maps");

// Sometimes bpf_jit_charge_modmem / bpf_jit_uncharge_modmem get elided,
// so we're tracing the outer entrypoint here instead. It's common to see
// calls to bpf_jit_binary_free not being traced too, so we skip that.
SEC("kprobe/bpf_jit_binary_alloc")
int trace_change(struct pt_regs *ctx)
{
    s64 current_value = 0;

    if (!kaddr_bpf_jit_current) {
        return 0;
    }

    bpf_probe_read_kernel(&current_value, sizeof(current_value), (const void*) kaddr_bpf_jit_current);
    bpf_map_update_elem(&current, &zero, &current_value, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
