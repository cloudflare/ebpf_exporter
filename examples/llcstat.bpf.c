#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_CPUS 512

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} llc_references_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} llc_misses_total SEC(".maps");

static int trace_event(void *map, u32 cpu, u64 sample_period)
{
    increment_map(map, &cpu, sample_period);

    return 0;
}

SEC("perf_event/type=0,config=3,frequency=1")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
    return trace_event(&llc_misses_total, bpf_get_smp_processor_id(), ctx->sample_period);
}

SEC("perf_event/type=0,config=2,frequency=1")
int on_cache_reference(struct bpf_perf_event_data *ctx)
{
    return trace_event(&llc_references_total, bpf_get_smp_processor_id(), ctx->sample_period);
}

char LICENSE[] SEC("license") = "GPL";
