#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define UPPER_PORT_BOUND 32768

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UPPER_PORT_BOUND);
    __type(key, u16);
    __type(value, u64);
} tcp_listen_drops_total SEC(".maps");

// This tracepoint requires a kernel patch:
// * https://github.com/bobrik/linux/commit/3470d9b7fcf4
SEC("raw_tp/tcp_listen_queue_drop")
int do_count(struct bpf_raw_tracepoint_args *ctx)
{
    struct inet_sock *inet = (struct inet_sock *) ctx->args[0];
    u16 lport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));

    // We are not interested in ephemeral ports for outbound connections.
    // There's a ton of them and they don't easily correlate with services.
    // To still have some visibility, we put all of the ephemeral ports into
    // the same local_port="0" label and defer to debugging with tracepoints
    // to find what port and service are having issues.
    if (lport >= UPPER_PORT_BOUND) {
        lport = 0;
    }

    increment_map(&tcp_listen_drops_total, &lport, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
