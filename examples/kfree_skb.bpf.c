#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u16);
    __type(value, u64);
} kfree_skb_total SEC(".maps");

SEC("tp_btf/kfree_skb")
int BPF_PROG(kfree_skb, struct sk_buff *skb, void *location, enum skb_drop_reason reason)
{
    u16 key = reason;
    increment_map(&kfree_skb_total, &key, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
