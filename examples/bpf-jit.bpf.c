#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

static u64 zero = 0;

static u64 bpf_jit_current_kaddr_index = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, u32);
	__type(value, u64);
} kaddrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} current SEC(".maps");

SEC("kprobe/bpf_jit_binary_alloc")
int trace_change(struct pt_regs *ctx)
{
	s64 current_value = 0;
	u64* bpf_jit_current_kaddr_ptr;

	bpf_jit_current_kaddr_ptr = bpf_map_lookup_elem(&kaddrs, &bpf_jit_current_kaddr_index);
	if (!bpf_jit_current_kaddr_ptr) {
		return 0;
	}

	if (bpf_jit_current_kaddr_ptr) {
		bpf_probe_read_kernel(&current_value, sizeof(current_value), (const void*) *bpf_jit_current_kaddr_ptr);
	}

	bpf_map_update_elem(&current, &zero, &current_value, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
