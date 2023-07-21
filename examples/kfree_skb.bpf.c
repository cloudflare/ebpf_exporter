#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "maps.bpf.h"

#define ETH_P_IPV6 0x86DD
#define ETH_P_IP 0x0800

struct kfree_skb_key_t {
    u16 eth_proto;
    u16 ip_proto;
    u16 port;
    u16 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct kfree_skb_key_t);
    __type(value, u64);
} kfree_skb_total SEC(".maps");

SEC("tp_btf/kfree_skb") int BPF_PROG(kfree_skb, struct sk_buff *skb, void *location, enum skb_drop_reason reason)
{
    struct kfree_skb_key_t key;
    struct ethhdr eth_hdr;
    struct iphdr ip_hdr;
    struct ipv6hdr ipv6_hdr;
    struct tcphdr tcp_hdr;
    struct udphdr udp_hdr;
    u16 ip_proto = 0;

    // Same as skb_mac_header_was_set:
    // * https://elixir.bootlin.com/linux/v6.5-rc1/source/include/linux/skbuff.h#L2899
    if (skb->mac_header == (typeof(skb->mac_header)) ~0U) {
        return 0;
    }

    if (bpf_probe_read_kernel(&eth_hdr, sizeof(eth_hdr), skb->head + skb->mac_header)) {
        return 0;
    }

    key.eth_proto = bpf_ntohs(eth_hdr.h_proto);

    if (!key.eth_proto && !bpf_ntohs(skb->protocol)) {
        return 0;
    }

    switch (key.eth_proto) {
    case ETH_P_IP:
        if (bpf_probe_read_kernel(&ip_hdr, sizeof(ip_hdr), skb->head + skb->network_header) < 0) {
            return 0;
        }
        ip_proto = ip_hdr.protocol;
        break;
    case ETH_P_IPV6:
        if (bpf_probe_read_kernel(&ipv6_hdr, sizeof(ipv6_hdr), skb->head + skb->network_header) < 0) {
            return 0;
        }
        ip_proto = ipv6_hdr.nexthdr;
        break;
    }

    key.ip_proto = ip_proto;

    // Same as skb_transport_header_was_set:
    // * https://elixir.bootlin.com/linux/v6.5-rc1/source/include/linux/skbuff.h#L2860
    if (skb->transport_header == (typeof(skb->transport_header)) ~0U) {
        return 0;
    }

    // Using key.ip_proto directly is not allowed for some reason:
    //
    // ; switch (key.ip_proto) {
    // 48: (54) w1 &= 65535
    // R1 32-bit pointer arithmetic prohibited
    switch (ip_proto) {
    case IPPROTO_TCP:
        if (bpf_probe_read_kernel(&tcp_hdr, sizeof(tcp_hdr), skb->head + skb->transport_header) < 0) {
            return 0;
        }
        key.port = bpf_ntohs(tcp_hdr.dest);
        break;
    case IPPROTO_UDP:
        if (bpf_probe_read_kernel(&udp_hdr, sizeof(udp_hdr), skb->head + skb->transport_header) < 0) {
            return 0;
        }
        key.port = bpf_ntohs(udp_hdr.dest);
        break;
    }

    key.reason = reason;

    increment_map(&kfree_skb_total, &key, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
