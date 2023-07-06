#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} oom_kills_total SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(kprobe__oom_kill_process, struct oom_control *oc, const char *message)
{
    u64 cgroup_id = 0;

    struct mem_cgroup *mcg = BPF_CORE_READ(oc, memcg);
    if (mcg) {
        cgroup_id = BPF_CORE_READ(mcg, css.cgroup, kn, id);
    }

    bpf_perf_event_output(ctx, &oom_kills_total, BPF_F_CURRENT_CPU, &cgroup_id, sizeof(cgroup_id));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
