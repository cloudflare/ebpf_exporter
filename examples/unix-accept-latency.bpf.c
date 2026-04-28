// Measure connect-to-accept latency for monitored UNIX stream sockets.
//
// Stores an enqueue timestamp in sk_storage on the server-side socket
// at security_unix_stream_connect(), then reads it back at unix_accept()
// return to compute the time spent on the listener's accept queue.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

// 11 buckets for msec latency: <=1, 2, 3-4, 5-8, ..., 257-512, 513-1024.
// exp2 bucket k (k=0..10) holds observations with ceil(log2(delta)) == k;
// contract is that bucket k contains values <= 2^k ms. Observations
// above 1024 ms are clamped into the top bucket.
#define MAX_LATENCY_SLOT 10

// D-Bus system bus socket
#define DBUS_SOCK_ADDR_PATH "/run/dbus/system_bus_socket"

// systemd-journald stdout stream socket
#define JOURNAL_SOCK_ADDR_PATH "/run/systemd/journal/stdout"

// MySQL/MariaDB server socket
#define MYSQLD_SOCK_ADDR_PATH "/var/run/mysqld/mysqld.sock"

// Keep in sync with static_map in the config
enum unix_addr {
    DBUS_SOCK_ADDR,
    JOURNAL_SOCK_ADDR,
    MYSQLD_SOCK_ADDR,
    MAX_PATHS // Max number of paths to track
};

// Match a listener's sun_path against monitored paths.
// Returns the unix_addr enum or -1 if no match.
static __always_inline int match_unix_path(struct sock *listener)
{
    struct unix_sock *u;
    struct unix_address *addr;

    u = bpf_skc_to_unix_sock(listener);
    if (!u)
        return -1;

    addr = u->addr;
    if (!addr)
        return -1;

    if (__builtin_memcmp(addr->name[0].sun_path, DBUS_SOCK_ADDR_PATH, sizeof(DBUS_SOCK_ADDR_PATH)) == 0)
        return DBUS_SOCK_ADDR;
    if (__builtin_memcmp(addr->name[0].sun_path, JOURNAL_SOCK_ADDR_PATH, sizeof(JOURNAL_SOCK_ADDR_PATH)) == 0)
        return JOURNAL_SOCK_ADDR;
    if (__builtin_memcmp(addr->name[0].sun_path, MYSQLD_SOCK_ADDR_PATH, sizeof(MYSQLD_SOCK_ADDR_PATH)) == 0)
        return MYSQLD_SOCK_ADDR;

    return -1;
}

struct key_t {
    enum unix_addr addr;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // +2: one bucket per slot plus the sum slot at MAX_LATENCY_SLOT + 1
    __uint(max_entries, (MAX_LATENCY_SLOT + 2) * MAX_PATHS);
    __type(key, struct key_t);
    __type(value, u64);
} unix_accept_latency_seconds SEC(".maps");

// Per-newsk state captured at connect and consumed at accept. Storing
// the path index alongside the timestamp avoids re-matching the
// listener's sun_path on the accept side (sk_storage presence already
// proves it's a monitored socket).
struct enqueue_state {
    u64 ts;
    u8 path;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct enqueue_state);
} enqueue_ts SEC(".maps");

// security_unix_stream_connect(sock, other, newsk)
//
// Called inside unix_stream_connect() right before the connection is
// established.  'other' is the listener socket.  Only store the
// timestamp if the listener matches a monitored path.
SEC("fentry/security_unix_stream_connect")
int BPF_PROG(trace_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
    struct enqueue_state state;
    int path;

    path = match_unix_path(other);
    if (path < 0)
        return 0;

    state.ts = bpf_ktime_get_ns();
    state.path = path;
    bpf_sk_storage_get(&enqueue_ts, newsk, &state, BPF_SK_STORAGE_GET_F_CREATE);
    return 0;
}

// unix_accept(sock, newsock, arg) -> ret
//
// fexit: on success newsock->sk is the same newsk from connect,
// grafted via sock_graft().  sock->sk is the listener.
SEC("fexit/unix_accept")
int BPF_PROG(trace_accept, struct socket *sock, struct socket *newsock, struct proto_accept_arg *arg, int ret)
{
    struct key_t key = {};
    struct enqueue_state *state;
    struct sock *sk;
    s64 delta;

    if (ret != 0)
        return 0;

    sk = newsock->sk;
    if (!sk)
        return 0;

    state = bpf_sk_storage_get(&enqueue_ts, sk, 0, 0);
    if (!state)
        return 0;

    delta = (s64) (bpf_ktime_get_ns() - state->ts);
    if (delta < 0)
        goto cleanup;

    // Convert to milliseconds
    delta /= 1000000U;

    key.addr = state->path;
    increment_exp2_histogram(&unix_accept_latency_seconds, key, delta, MAX_LATENCY_SLOT);

cleanup:
    bpf_sk_storage_delete(&enqueue_ts, sk);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
