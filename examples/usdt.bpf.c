#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

struct call_t {
    char module[128];
    char function[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct call_t);
    __type(value, u64);
} python_function_entries_total SEC(".maps");

SEC("usdt/python3:python:function__entry")
int BPF_USDT(do_count, void *arg0, void *arg1, void *arg2)
{
    struct call_t call = {};

    // https://docs.python.org/3/howto/instrumentation.html#available-static-markers
    bpf_probe_read_user_str(&call.module, sizeof(call.module), arg0);
    bpf_probe_read_user_str(&call.function, sizeof(call.function), arg1);

    increment_map(&python_function_entries_total, &call, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
