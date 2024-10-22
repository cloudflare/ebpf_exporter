#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"

struct call_t {
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 3
    );
    __type(key, struct call_t);
    __type(value, u64);
} php_compile_file_total SEC(".maps");

#define MAX_STR_LEN 128


int check_slash_reverse(const char *str) {
    int length = MAX_STR_LEN;
    int i;

    // 文字列を後ろからチェック
    for (i = length - 1; i >= 0; i--) {
        if (str[i] == '/') {
            // '/' が見つかったらその時点のlengthを返す
            return i; 
        }
    }

    // '/' が見つからない場合、-1 を返す
    return -1;
}

int truncate_string(char *str, int max_length) {
    int i;

    // 文字列をチェックして、最大長さを超えたら切り詰める
    for (i = 0; i < max_length; i++) {
        if (str[i] == '\0') {
            // 既にヌル終端されている場合はそのまま
            return 0;
        }
    }

    // ここに到達した場合、最大長さを超えているので切り詰める
    if (i >= max_length) {
        str[max_length] = '\0'; // 文字列を切り詰める
    }

    return 0;
}

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:compile__file__entry")
int BPF_USDT(do_count, char *arg0, char *arg1) 
{
    struct call_t call = {};

    bpf_probe_read_user_str(&call.filename, sizeof(call.filename), arg1);

    truncate_string(call.filename, check_slash_reverse(call.filename));

    increment_map(&php_compile_file_total, &call, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
