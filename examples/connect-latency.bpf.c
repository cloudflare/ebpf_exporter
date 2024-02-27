#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_LATENCY_SLOT 26

struct connect_start_key_t {
    u64 pid_tgid;
};

struct connect_start_val_t {
    u64 ts;
    int addrlen;
    u32 d_ip;    // Destination IPv4 address
    u16 d_port;  // Destination port number
};

struct connect_latency_key_t {
    u32 d_ip;    // Destination IPv4 address
    u16 d_port;  // Destination port number
    u64 slot;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connect_start_key_t);
    __type(value, struct connect_start_val_t);
} connect_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LATENCY_SLOT + 2);
    __type(key, struct connect_latency_key_t);
    __type(value, u64);
} connect_latency_seconds SEC(".maps");

static inline __u16 ntohs(__u16 value) {
    return ((value & 0x00FF) << 8) | ((value & 0xFF00) >> 8);
}

SEC("kprobe/__sys_connect")
int BPF_KPROBE(kprobe__sys_connect, int sockfd, const struct sockaddr *addr, int addrlen)
{
    struct sockaddr sa;
    struct connect_start_val_t start_val = {};

    bpf_probe_read(&sa, sizeof(sa), addr);

    if (sa.sa_family == 1) {
        return 0;  // Ignore UNIX domain sockets
    }

    if (addrlen == sizeof(struct sockaddr_in)) {
        struct sockaddr_in v4;
        bpf_probe_read(&v4, sizeof(v4), addr);
        start_val.d_ip = v4.sin_addr.s_addr;
        start_val.d_port = v4.sin_port;
    } else if (addrlen == sizeof(struct sockaddr_in6)) {
	const char debug_str[] = "This is ipv6!\n";
	bpf_trace_printk(debug_str, sizeof(debug_str));
        struct sockaddr_in6 v6;
        bpf_probe_read(&v6, sizeof(v6), addr);

        if (BPF_CORE_READ(&v6.sin6_addr.in6_u, u6_addr32[0]) == 0x00000000 &&
            BPF_CORE_READ(&v6.sin6_addr.in6_u, u6_addr32[1]) == 0x00000000 &&
            BPF_CORE_READ(&v6.sin6_addr.in6_u, u6_addr32[2]) == 0x0000FFFF) {

            start_val.d_ip = BPF_CORE_READ(&v6.sin6_addr.in6_u, u6_addr32[3]);
            start_val.d_port = v6.sin6_port;
        } else {
            const char debug_str[] = "This is native ipv6, I'm giving up!\n";
            bpf_trace_printk(debug_str, sizeof(debug_str));
            return 0;
        }
    } else {
        const char debug_str[] = "Unexpected addrlen: %d, address family: %d\n";
        bpf_trace_printk(debug_str, sizeof(debug_str), addrlen, sa.sa_family);
        return 0;
    }

    struct connect_start_key_t start_key = {};
    start_key.pid_tgid = bpf_get_current_pid_tgid();
    start_val.ts = bpf_ktime_get_ns();
    start_val.addrlen = addrlen;
    bpf_map_update_elem(&connect_start, &start_key, &start_val, BPF_ANY);

    return 0;
}

SEC("kretprobe/__sys_connect")
int BPF_KRETPROBE(kretprobe__sys_connect, int ret)
{
    u64 delta_us, latency_slot;
    struct connect_start_key_t start_key = {};
    start_key.pid_tgid = bpf_get_current_pid_tgid();
    struct connect_start_val_t *start_val;
    start_val = bpf_map_lookup_elem(&connect_start, &start_key);
    if (!start_val) {
        const char debug_str[] = "Did not find anything in the map!\n";
        bpf_trace_printk(debug_str, sizeof(debug_str));
        return 0;
    }
    if (ret != 0) {
        return 0; // Filter out non-blocking sockets and errors
    }
    const char debug_str[] = "Return code is: %d\n";
    bpf_trace_printk(debug_str, sizeof(debug_str), ret);
    struct connect_latency_key_t key = {};
    key.d_ip = start_val->d_ip;
    key.d_port = ntohs(start_val->d_port);

    delta_us = (bpf_ktime_get_ns() - start_val->ts) / 1000;
    latency_slot = log2l(delta_us);
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    key.slot = latency_slot;
    increment_map(&connect_latency_seconds, &key, 1);

    key.slot = MAX_LATENCY_SLOT + 1;
    increment_map(&connect_latency_seconds, &key, delta_us);

    bpf_map_delete_elem(&connect_start, &start_key);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
