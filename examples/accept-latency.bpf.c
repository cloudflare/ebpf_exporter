#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 26

// Max number of listening ports we expect to see on the host
#define MAX_PORTS 1024

struct socket_latency_key_t {
    u16 port;
    u64 slot;
};

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct request_sock *);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * MAX_PORTS);
    __type(key, struct socket_latency_key_t);
    __type(value, u64);
} accept_latency SEC(".maps");

SEC("kprobe/inet_csk_reqsk_queue_hash_add")
int BPF_KPROBE(kprobe__inet_csk_reqsk_queue_hash_add, struct sock *sk, struct request_sock *req)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &req, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(kprobe__inet_csk_accept, struct sock *sk)
{
    u64 *tsp, *count, delta_us;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *) sk;
    struct request_sock *req = BPF_CORE_READ(icsk, icsk_accept_queue).rskq_accept_head;

    tsp = bpf_map_lookup_elem(&start, &req);
    if (!tsp) {
        return 0;
    }

    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // Latency histogram key
    u64 latency_slot = log2l(delta_us);

    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    struct socket_latency_key_t latency_key = {};
    latency_key.port = BPF_CORE_READ(sk, __sk_common).skc_num;
    latency_key.slot = latency_slot;

    count = bpf_map_lookup_elem(&accept_latency, &latency_key);
    if (!count) {
        bpf_map_update_elem(&accept_latency, &latency_key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&accept_latency, &latency_key);
        if (!count) {
            goto cleanup;
        }
    }
    __sync_fetch_and_add(count, 1);

    latency_key.slot = MAX_LATENCY_SLOT + 1;

    count = bpf_map_lookup_elem(&accept_latency, &latency_key);
    if (!count) {
        bpf_map_update_elem(&accept_latency, &latency_key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&accept_latency, &latency_key);
        if (!count) {
            goto cleanup;
        }
    }
    __sync_fetch_and_add(count, delta_us);

cleanup:
    bpf_map_delete_elem(&start, &req);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
