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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct sock *);
} tcp_rmem_schedule_enters SEC(".maps");

static int enter_key()
{
    u64 pid = bpf_get_current_pid_tgid();
    if (pid) {
        return pid;
    }

    return bpf_get_smp_processor_id();
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
    u32 rcv_ssthresh, zero = 0;
    u64 key = enter_key();
    struct sock **skp = bpf_map_lookup_elem(&tcp_rmem_schedule_enters, &key);
    struct tcp_sock *tp;

    if (!skp) {
        return 0;
    }

    tp = (struct tcp_sock *) *skp;

    if (!tp) {
        return 0;
    }

    rcv_ssthresh = BPF_CORE_READ(tp, rcv_ssthresh);

    if (rcv_ssthresh < MIN_CLAMP) {
        increment_map(&tcp_window_clamps_total, &zero, 1);
    }

    bpf_map_delete_elem(&tcp_rmem_schedule_enters, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
