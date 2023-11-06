#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192

// Type of tcp retransmits
#define RETRANSMIT 1
#define TLP 2

#define AF_INET 2
#define AF_INET6 10

#define UPPER_PORT_BOUND 32768

struct ipv4_key_t {
    u32 saddr;
    u32 daddr;
    u16 mainport;
    u32 type;
};

struct ipv6_key_t {
    u8 saddr[16];
    u8 daddr[16];
    u16 mainport;
    u32 type;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_key_t);
    __type(value, u64);
} tcp_retransmit_ipv4_packets_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_key_t);
    __type(value, u64);
} tcp_retransmit_ipv6_packets_total SEC(".maps");

static int trace_event(const struct sock *sk, u32 type)
{
    u32 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_key_t key;
        __builtin_memset(&key, 0, sizeof(key));

        key.saddr = sk->__sk_common.skc_rcv_saddr;
        key.daddr = sk->__sk_common.skc_daddr;

        u16 sport = sk->__sk_common.skc_num;
        u16 dport = sk->__sk_common.skc_dport;
        dport = __builtin_bswap16(dport);

        if (sport <= dport) {
            key.mainport = sport;
        } else {
            key.mainport = dport;
        }

        if (key.mainport >= UPPER_PORT_BOUND) {
            key.mainport = 0;
        }

        key.type = type;

        increment_map(&tcp_retransmit_ipv4_packets_total, &key, 1);

    } else if (family == AF_INET6) {
        struct ipv6_key_t key;
        __builtin_memset(&key, 0, sizeof(key));

        bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        u16 sport = sk->__sk_common.skc_num;
        u16 dport = sk->__sk_common.skc_dport;
        dport = __builtin_bswap16(dport);

        if (sport <= dport) {
            key.mainport = sport;
        } else {
            key.mainport = dport;
        }

        if (key.mainport >= UPPER_PORT_BOUND) {
            key.mainport = 0;
        }

        key.type = type;

        increment_map(&tcp_retransmit_ipv6_packets_total, &key, 1);
    }
    return 0;
}

SEC("fentry/tcp_send_loss_probe")
int BPF_PROG(tcp_send_loss_probe, struct sock *sk)
{
    return trace_event(sk, TLP);
}

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb, struct sock *sk)
{
    return trace_event(sk, RETRANSMIT);
}

char LICENSE[] SEC("license") = "GPL";
