#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bits.bpf.h"

static u64 zero = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} counts SEC(".maps");


SEC("tracepoint/sched/sched_migrate_task")
int do_count(struct pt_regs *ctx)
{
    u64* count;
    u64 cgroup_id = bpf_get_current_cgroup_id();

	count = bpf_map_lookup_elem(&counts, &cgroup_id);
	if (!count) {
		bpf_map_update_elem(&counts, &cgroup_id, &zero, BPF_NOEXIST);
		count = bpf_map_lookup_elem(&counts, &cgroup_id);
		if (!count) {
			return 0;
		}
	}
	__sync_fetch_and_add(count, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
