#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "regs-ip.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, u64);
    __type(value, u64);
} page_cache_ops_total SEC(".maps");

SEC("kprobe/add_to_page_cache_lru")
int add_to_page_cache_lru(struct pt_regs *ctx)
{
    u64 ip = KPROBE_REGS_IP_FIX(PT_REGS_IP_CORE(ctx));
    increment_map(&page_cache_ops_total, &ip, 1);
    return 0;
}

SEC("kprobe/mark_page_accessed")
int mark_page_accessed(struct pt_regs *ctx)
{
    u64 ip = KPROBE_REGS_IP_FIX(PT_REGS_IP_CORE(ctx));
    increment_map(&page_cache_ops_total, &ip, 1);
    return 0;
}

// This function is usually not visible.
SEC("kprobe/folio_account_dirtied")
int folio_account_dirtied(struct pt_regs *ctx)
{
    u64 ip = KPROBE_REGS_IP_FIX(PT_REGS_IP_CORE(ctx));
    increment_map(&page_cache_ops_total, &ip, 1);
    return 0;
}

SEC("kprobe/mark_buffer_dirty")
int mark_buffer_dirty(struct pt_regs *ctx)
{
    u64 ip = KPROBE_REGS_IP_FIX(PT_REGS_IP_CORE(ctx));
    increment_map(&page_cache_ops_total, &ip, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
