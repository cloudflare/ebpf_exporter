#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

/* Minimum value for tp->rcv_ssthresh that is not considered a clamp */
#define MIN_CLAMP 32 * 1024

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} tcp_window_clamps_total SEC(".maps");

static int handle_tcp_sock(struct tcp_sock *tp)
{
    u32 zero = 0, rcv_ssthresh;

    if (!tp) {
        return 0;
    }

    rcv_ssthresh = BPF_CORE_READ(tp, rcv_ssthresh);

    if (rcv_ssthresh < MIN_CLAMP) {
        increment_map(&tcp_window_clamps_total, &zero, 1);
    }

    return 0;
}

#ifdef FENTRY_SUPPORT
// If fentry/fexit is supported, use it for simpler and faster probe.
// You need to pass -DFENTRY_SUPPORT in compiler flags to enable this.

SEC("fexit/tcp_try_rmem_schedule")
int BPF_PROG(tcp_try_rmem_schedule_exit, struct sock *sk)
{
    return handle_tcp_sock((struct tcp_sock *) sk);
}

#else
// Otherwise, fall back to good old kprobe.

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct sock *);
} tcp_rmem_schedule_enters SEC(".maps");

static u64 enter_key()
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid) {
        // If tgid is present, use it as high bits in the compound key.
        return ((u64) tgid) << 32;
    }

    // If tgid is zero, combine it with processor id to prevent tgid / cpu collisions.
    return ((u64) tgid << 32) | (u32) bpf_get_smp_processor_id();
}

SEC("kprobe/tcp_try_rmem_schedule")
int BPF_KPROBE(tcp_try_rmem_schedule, struct sock *sk)
{
    u64 key = enter_key();

    bpf_map_update_elem(&tcp_rmem_schedule_enters, &key, &sk, BPF_NOEXIST);

    return 0;
}

SEC("kretprobe/tcp_try_rmem_schedule")
int BPF_KRETPROBE(tcp_try_rmem_schedule_ret)
{
    u64 key = enter_key();
    struct sock **skp = bpf_map_lookup_elem(&tcp_rmem_schedule_enters, &key);

    if (!skp) {
        return 0;
    }

    bpf_map_delete_elem(&tcp_rmem_schedule_enters, &key);

    return handle_tcp_sock((struct tcp_sock *) *skp);
}

#endif

char LICENSE[] SEC("license") = "GPL";
