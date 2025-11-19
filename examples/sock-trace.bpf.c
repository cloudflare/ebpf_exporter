#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "tracing.bpf.h"

#define MAX_STACK_DEPTH 8

// Skipping 3 frames off the top as they are just bpf trampoline
#define SKIP_FRAMES (3 & BPF_F_SKIP_FIELD_MASK)

extern int LINUX_KERNEL_VERSION __kconfig;

struct stitch_span_t {
    struct span_base_t span_base;
    u64 socket_cookie;
};

struct sock_release_span_t {
    struct span_base_t span_base;
    u64 span_id;
};

struct sk_span_t {
    struct span_base_t span_base;
    u64 ksym;
};

struct sk_error_report_span_t {
    struct span_base_t span_base;
    u64 kstack[MAX_STACK_DEPTH];
    u32 sk_err;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} stitch_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sock_release_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sk_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sk_error_report_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, u64);
    __type(value, struct span_parent_t);
} traced_socket_cookies SEC(".maps");

SEC("usdt/./tracing/demos/sock/demo:ebpf_exporter:sock_set_parent_span")
int BPF_USDT(sock_set_parent_span, u64 socket_cookie, u64 trace_id_hi, u64 trace_id_lo, u64 span_id,
             u64 example_userspace_tag)
{
    struct span_parent_t parent = { .trace_id_hi = trace_id_hi,
                                    .trace_id_lo = trace_id_lo,
                                    .span_id = span_id,
                                    .example_userspace_tag = example_userspace_tag };

    bpf_map_update_elem(&traced_socket_cookies, &socket_cookie, &parent, BPF_ANY);

    submit_span(&stitch_spans, struct stitch_span_t, &parent, { span->socket_cookie = socket_cookie; });

    return 0;
}

SEC("fentry/__sock_release")
int BPF_PROG(__sock_release, struct socket *sock)
{
    u64 socket_cookie = bpf_get_socket_cookie(sock->sk);
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_socket_cookies, &socket_cookie);

    if (!parent) {
        return 0;
    }

    submit_span(&sock_release_spans, struct sock_release_span_t, parent, { span->span_id = 0xdead; });

    bpf_map_delete_elem(&traced_socket_cookies, &socket_cookie);

    return 0;
}

static int handle_sk(struct pt_regs *ctx, u64 socket_cookie)
{
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_socket_cookies, &socket_cookie);

    if (!parent) {
        return 0;
    }

    submit_span(&sk_spans, struct sk_span_t, parent, {
        // FIXME: PT_REGS_IP_CORE(ctx) does not work for fentry, so we abuse kstack
        bpf_get_stack(ctx, &span->ksym, sizeof(span->ksym), SKIP_FRAMES);
        span->ksym -= 8;
    });

    return 0;
}

SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb)
{
    return handle_sk((struct pt_regs *) ctx, bpf_get_socket_cookie(sk));
}

SEC("fentry/__ip_local_out")
int BPF_PROG(__ip_local_out, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return handle_sk((struct pt_regs *) ctx, bpf_get_socket_cookie(sk));
}

SEC("fentry/ip_finish_output")
int BPF_PROG(ip_finish_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return handle_sk((struct pt_regs *) ctx, bpf_get_socket_cookie(sk));
}

SEC("fentry/__tcp_retransmit_skb")
int BPF_PROG(__tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb)
{
    return handle_sk((struct pt_regs *) ctx, bpf_get_socket_cookie(sk));
}

// Older kernels are not happy with calls to bpf_get_socket_cookie(skb->sk):
//
// ; return handle_sk((struct pt_regs *) ctx, bpf_get_socket_cookie(skb->sk));
// 3: (85) call bpf_get_socket_cookie#46
// R1 type=untrusted_ptr_ expected=sock_common, sock, tcp_sock, xdp_sock, ptr_, trusted_ptr_
//
// I'm not sure which is the oldest available kernel, but I know it doesn't work on v6.5
// in Github Actions, but runs fine on v6.9-rc3 locally. I'm too lazy to bisect.
static int handle_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 9, 0)) {
        return 0;
    }

    return handle_sk(ctx, bpf_get_socket_cookie(skb->sk));
}

SEC("fentry/nf_hook_slow")
int BPF_PROG(nf_hook_slow, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, skb);
}

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, skb);
}

SEC("fentry/dev_hard_start_xmit")
int BPF_PROG(dev_hard_start_xmit, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, skb);
}

// bpf_get_socket_cookie is not available in raw_tp:
// * https://github.com/torvalds/linux/blob/v6.6/kernel/trace/bpf_trace.c#L1926-L1939
SEC("fentry/sk_error_report")
int BPF_PROG(sk_error_report, struct sock *sk)
{
    u64 socket_cookie = bpf_get_socket_cookie(sk);
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_socket_cookies, &socket_cookie);

    if (!parent) {
        return 0;
    }

    submit_span(&sk_error_report_spans, struct sk_error_report_span_t, parent, {
        bpf_get_stack(ctx, &span->kstack, sizeof(span->kstack), SKIP_FRAMES);
        span->sk_err = sk->sk_err;
    });

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
