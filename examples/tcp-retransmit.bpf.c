#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
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
    u16 main_port;
    u8 type;
};

struct ipv6_key_t {
    u8 saddr[16];
    u8 daddr[16];
    u16 main_port;
    u8 type;
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

static int extract_main_port(const struct sock *sk)
{
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = __builtin_bswap16(sk->__sk_common.skc_dport);

    if (sport > UPPER_PORT_BOUND && dport > UPPER_PORT_BOUND) {
        return 0;
    }

    if (sport < dport) {
        return sport;
    }

    return dport;
}

#define TRACE_PROTOCOL(key_type, map, ip_extractor)                                                                    \
    key_type key = {};                                                                                                 \
                                                                                                                       \
    key.type = type;                                                                                                   \
    key.main_port = extract_main_port(sk);                                                                             \
                                                                                                                       \
    ip_extractor;                                                                                                      \
                                                                                                                       \
    increment_map(map, &key, 1);                                                                                       \
                                                                                                                       \
    return 0;

static int trace_ipv4(const struct sock *sk, u8 type)
{
    TRACE_PROTOCOL(struct ipv4_key_t, &tcp_retransmit_ipv4_packets_total, {
        key.saddr = sk->__sk_common.skc_rcv_saddr;
        key.daddr = sk->__sk_common.skc_daddr;
    });
}

static int trace_ipv6(const struct sock *sk, u8 type)
{
    TRACE_PROTOCOL(struct ipv6_key_t, &tcp_retransmit_ipv6_packets_total, {
        bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    });
}

static int trace_event(const struct sock *sk, u8 type)
{
    switch (sk->__sk_common.skc_family) {
    case AF_INET:
        return trace_ipv4(sk, type);
    case AF_INET6:
        return trace_ipv6(sk, type);
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
