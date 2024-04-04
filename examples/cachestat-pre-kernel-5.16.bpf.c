// Use this version of cachestat when kernel version <= 5.15
// https://github.com/cloudflare/ebpf_exporter/issues/132

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

enum pache_cache_op {
    OP_CACHE_ACCESS,
    OP_CACHE_WRITES,
    OP_PAGE_ADD_LRU,
    OP_PAGE_MARK_DIRTIES,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, u8);
    __type(value, u64);
} page_cache_ops_total SEC(".maps");

static int trace_event(enum pache_cache_op op)
{
    increment_map(&page_cache_ops_total, &op, 1);
    return 0;
}

SEC("fentry/mark_page_accessed")
int mark_page_accessed()
{
    return trace_event(OP_CACHE_ACCESS);
}

SEC("fentry/mark_buffer_dirty")
int mark_buffer_dirty()
{
    return trace_event(OP_CACHE_WRITES);
}

SEC("fentry/add_to_page_cache_lru")
int add_to_page_cache_lru()
{
    return trace_event(OP_PAGE_ADD_LRU);
}

SEC("fentry/account_page_dirtied")
int account_page_dirtied()
{
    return trace_event(OP_PAGE_MARK_DIRTIES);
}

char LICENSE[] SEC("license") = "GPL";
