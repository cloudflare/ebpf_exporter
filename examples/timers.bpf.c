#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

static u64 zero = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} counts SEC(".maps");

SEC("tracepoint/timer/timer_start")
int do_count(struct trace_event_raw_timer_start* ctx)
{
    u64* count;
    u64 function = (u64) ctx->function;

	count = bpf_map_lookup_elem(&counts, &function);
	if (!count) {
		bpf_map_update_elem(&counts, &function, &zero, BPF_NOEXIST);
		count = bpf_map_lookup_elem(&counts, &function);
		if (!count) {
			return 0;
		}
	}
	__sync_fetch_and_add(count, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
