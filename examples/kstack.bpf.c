#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_STACK_DEPTH 20

// Skipping 3 frames off the top as they are just bpf trampoline
#define SKIP_FRAMES (3 & BPF_F_SKIP_FIELD_MASK)

struct key_t {
    u64 kstack[MAX_STACK_DEPTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128);
    __type(key, struct key_t);
    __type(value, u64);
} mark_page_accessed_total SEC(".maps");

SEC("fentry/mark_page_accessed")
int mark_page_accessed(struct pt_regs *ctx)
{
    struct key_t key = {};

    if (bpf_get_stack(ctx, &key.kstack, sizeof(key.kstack), SKIP_FRAMES) < 0) {
        return 0;
    }

    increment_map(&mark_page_accessed_total, &key, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
