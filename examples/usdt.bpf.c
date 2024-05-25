#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"

struct call_t {
    char module[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct call_t);
    __type(value, u64);
} python_module_imports_total SEC(".maps");

SEC("usdt/python3:python:import__find__load__start")
int BPF_USDT(do_count, void *arg0)
{
    struct call_t call = {};

    bpf_probe_read_user_str(&call.module, sizeof(call.module), arg0);

    increment_map(&python_module_imports_total, &call, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
