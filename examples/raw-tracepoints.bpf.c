#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} counts SEC(".maps");


SEC("raw_tp/timer_start")
int do_count(struct bpf_raw_tracepoint_args *ctx)
{
    u64* count;
    struct timer_list *timer = (struct timer_list *) ctx->args[0];
    u64 function = (u64) BPF_CORE_READ(timer, function);

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
