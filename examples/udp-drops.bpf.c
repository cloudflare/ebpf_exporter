#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

#define UPPER_PORT_BOUND 9024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UPPER_PORT_BOUND);
    __type(key, u16);
    __type(value, u64);
} udp_fail_queue_rcv_skbs_total SEC(".maps");

SEC("tracepoint/udp/udp_fail_queue_rcv_skb")
int do_count(struct trace_event_raw_udp_fail_queue_rcv_skb *ctx)
{
    u16 lport = ctx->lport;

    // We are not interested in ephemeral ports for outbound connections.
    // There's a ton of them and they don't easily correlate with services.
    // To still have some visibility, we put all of the ephemeral ports into
    // the same local_port="0" label and defer to debugging with tracepoints
    // to find what port and service are having issues.
    if (lport >= UPPER_PORT_BOUND) {
        lport = 0;
    }

    increment_map(&udp_fail_queue_rcv_skbs_total, &lport, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
