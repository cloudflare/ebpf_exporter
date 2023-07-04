#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

const volatile u64 kaddr_bpf_jit_current = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} bpf_jit_pages_currently_allocated SEC(".maps");

static int update_current()
{
    u32 zero_key = 0;
    s64 current_value = 0;

    if (!kaddr_bpf_jit_current) {
        return 0;
    }

    bpf_probe_read_kernel(&current_value, sizeof(current_value), (const void *) kaddr_bpf_jit_current);
    bpf_map_update_elem(&bpf_jit_pages_currently_allocated, &zero_key, &current_value, BPF_ANY);

    return 0;
}

// Sometimes bpf_jit_charge_modmem / bpf_jit_uncharge_modmem get elided,
// so we're tracing the outer entrypoint here instead. It's common to see
// calls to bpf_jit_binary_free not being traced too, so we skip that.
SEC("kprobe/bpf_jit_binary_alloc")
int trace_change()
{
    return update_current();
}

// This code runs right after program is attached, allowing initialization
// of the metric in the absence of any updates from bpf jit.
SEC("uprobe//proc/self/exe:post_attach_mark")
int do_init()
{
    return update_current();
}

char LICENSE[] SEC("license") = "GPL";
