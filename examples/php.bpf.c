#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"

struct call_t {
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct call_t);
    __type(value, u64);
} php_compile_file_total SEC(".maps");

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:compile__file__entry")
int BPF_USDT(do_count, char *arg0, char *arg1) 
{
    struct call_t call = {};

    bpf_probe_read_user_str(&call.filename, sizeof(call.filename), arg1);

    increment_map(&php_compile_file_total, &call, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
