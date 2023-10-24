#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

// 17 buckets for backlog sizes, max range is 64k..128k
#define MAX_BUCKET_SLOT 17

// Address on which docker accepts connections
#define DOCKER_SOCK_ADDR_PATH "/var/run/docker.sock"

// Keep in sync with static_map in the config
enum unix_addr {
    DOCKER_SOCK_ADDR,
    MAX_PATHS // Max number of paths to track
};

struct key_t {
    enum unix_addr addr;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_BUCKET_SLOT + 2) * MAX_PATHS);
    __type(key, struct key_t);
    __type(value, u64);
} unix_socket_backlog SEC(".maps");

// https://elixir.bootlin.com/linux/v6.6-rc1/source/include/linux/skbuff.h#L2133
static inline __u32 skb_queue_len(const struct sk_buff_head *list_)
{
    return list_->qlen;
}

static int do_count(enum unix_addr addr, u64 backlog)
{
    struct key_t key = {};

    key.addr = addr;

    increment_exp2zero_histogram(&unix_socket_backlog, key, backlog, MAX_BUCKET_SLOT);

    return 0;
}

SEC("fexit/unix_find_other")
int BPF_PROG(unix_find_other, struct net *net, struct sockaddr_un *sunaddr, int addr_len, int type, struct sock *other)
{
    // Make sure to use clang-15, otherwise you might see:
    //   libbpf: failed to find BTF for extern 'memcmp': -2
    if (__builtin_memcmp(sunaddr->sun_path, DOCKER_SOCK_ADDR_PATH, sizeof(DOCKER_SOCK_ADDR_PATH)) == 0) {
        return do_count(DOCKER_SOCK_ADDR, skb_queue_len(&other->sk_receive_queue));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
