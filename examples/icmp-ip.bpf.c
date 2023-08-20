#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define IPHDR_ADDR(skb) BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header)

struct icmp4_key_t {
    u32 addr;
};

struct icmp6_key_t {
    u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct icmp4_key_t);
    __type(value, u64);
} icmp4_received_packets_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct icmp6_key_t);
    __type(value, u64);
} icmp6_received_packets_total SEC(".maps");

// kprobe for compatibility, please prefer fentry instead
SEC("kprobe/icmp_rcv")
int BPF_PROG(icmp_rcv, struct sk_buff *skb)
{
    struct iphdr ip_hdr;
    struct icmp4_key_t key;

    if (bpf_probe_read_kernel(&ip_hdr, sizeof(ip_hdr), IPHDR_ADDR(skb)) < 0) {
        return 0;
    }

    key.addr = ip_hdr.saddr;

    increment_map(&icmp4_received_packets_total, &key, 1);

    return 0;
}

// kprobe for compatibility, please prefer fentry instead
SEC("kprobe/icmpv6_rcv")
int BPF_PROG(icmpv6_rcv, struct sk_buff *skb)
{
    struct ipv6hdr ipv6_hdr;
    struct icmp6_key_t key;

    if (bpf_probe_read_kernel(&ipv6_hdr, sizeof(ipv6_hdr), IPHDR_ADDR(skb)) < 0) {
        return 0;
    }

    if (bpf_probe_read_kernel(&key.addr, sizeof(key.addr), ipv6_hdr.saddr.in6_u.u6_addr8) < 0) {
        return 0;
    }

    increment_map(&icmp6_received_packets_total, &key, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
