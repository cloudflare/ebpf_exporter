#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct inet_frags_key_t {
    u32 ifindex;
    u8 ip_version;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct inet_frags_key_t);
    __type(value, u64);
} inet_frags_total SEC(".maps");

static __always_inline void increment_map_for_skb(void *map, struct sk_buff *skb)
{
    void *skb_head = BPF_CORE_READ(skb, head);
    u16 skb_l3_off = BPF_CORE_READ(skb, network_header);

    struct iphdr *iph = (struct iphdr *) (skb_head + skb_l3_off);
    struct inet_frags_key_t key = { 0 };

    key.ip_version = BPF_CORE_READ_BITFIELD_PROBED(iph, version);
    key.ifindex = BPF_CORE_READ(skb, skb_iif);

    increment_map(map, &key, 1);
}

SEC("kprobe/inet_frag_queue_insert")
int BPF_KPROBE(inet_frag_queue_insert, struct inet_frag_queue *q, struct sk_buff *skb, int offset)
{
    increment_map_for_skb(&inet_frags_total, skb);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
