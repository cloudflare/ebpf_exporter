#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define BUCKET_MULTIPLIER 50
#define BUCKET_COUNT 20

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BUCKET_COUNT + 2);
    __type(key, u64);
    __type(value, u64);
} tcp_syn_backlog SEC(".maps");

static int do_count(u64 backlog)
{
    u64 bucket = backlog / BUCKET_MULTIPLIER;

    increment_map(&tcp_syn_backlog, &bucket, 1);
    increment_map(&tcp_syn_backlog, &bucket, backlog);

    return 0;
}

SEC("kprobe/tcp_v4_syn_recv_sock")
int BPF_KPROBE(kprobe__tcp_v4_syn_recv_sock, struct sock *sk)
{
    return do_count(BPF_CORE_READ(sk, sk_ack_backlog) / 50);
}

SEC("kprobe/tcp_v6_syn_recv_sock")
int BPF_KPROBE(kprobe__tcp_v6_syn_recv_sock, struct sock *sk)
{
    return do_count(BPF_CORE_READ(sk, sk_ack_backlog) / 50);
}

char LICENSE[] SEC("license") = "GPL";
