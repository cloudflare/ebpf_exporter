#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CPUS 512

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} references SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} misses SEC(".maps");

static int trace_event(void *map, u32 cpu, u64 sample_period)
{
    u64 *count;

    count = bpf_map_lookup_elem(map, &cpu);
    if (!count) {
        bpf_map_update_elem(map, &cpu, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(map, &cpu);
        if (!count) {
            return 0;
        }
    }
    __sync_fetch_and_add(count, sample_period);

	return 0;
}

SEC("perf_event")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
    return trace_event(&misses, bpf_get_smp_processor_id(), ctx->sample_period);
}

SEC("perf_event")
int on_cache_reference(struct bpf_perf_event_data *ctx)
{
    return trace_event(&references, bpf_get_smp_processor_id(), ctx->sample_period);
}

char LICENSE[] SEC("license") = "GPL";
