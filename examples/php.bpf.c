#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"

#define MAX_STR_LEN 256

struct call_t {
    char filename[MAX_STR_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct call_t);
    __type(value, u64);
} php_compile_file_total SEC(".maps");


int truncate_string(char *str, int max_length) {
    int i;

    // 文字列を後ろからチェック
    for (i = max_length - 1; i >= 0; i--) {
        if (str[i] == '/') {
            return i; 
        } else {
            str[i] = '\0';
        }
    }

    return -1;
}

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:compile__file__entry")
int BPF_USDT(do_count, char *arg0, char *arg1) 
{
    struct call_t call = {};

    bpf_probe_read_user_str(&call.filename, sizeof(call.filename), arg1);

    truncate_string(call.filename, MAX_STR_LEN);

    increment_map(&php_compile_file_total, &call, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
