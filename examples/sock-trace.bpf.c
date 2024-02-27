#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "tracing.bpf.h"

u32 yes = true;

struct stitch_span_t {
    struct span_base_t span_base;
    u32 fd;
    u64 addr;
};

struct sock_release_span_t {
    struct span_base_t span_base;
    u64 span_id;
};

struct skb_span_t {
    struct span_base_t span_base;
    u64 ksym;
};

struct file_key_t {
    u32 tgid;
    u32 fd;
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
} skb_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, u32);
    __type(value, bool);
} traced_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, struct sock *);
    __type(value, struct span_parent_t);
} traced_socks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, struct file_key_t);
    __type(value, struct sock *);
} fd_to_sock SEC(".maps");

SEC("fentry/fd_install")
int BPF_PROG(fd_install, unsigned int fd, struct file *file)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct file_key_t key = { .tgid = tgid, .fd = fd };
    bool *traced = bpf_map_lookup_elem(&traced_tgids, &tgid);
    struct sock *sk;

    if (!traced) {
        return 0;
    }

    sk = BPF_CORE_READ((struct socket *) file->private_data, sk);

    bpf_map_update_elem(&fd_to_sock, &key, &sk, BPF_ANY);

    return 0;
}

SEC("fentry/close_fd")
int BPF_PROG(close_fd, unsigned int fd)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct file_key_t key = { .tgid = tgid, .fd = fd };

    bpf_map_delete_elem(&traced_socks, &key);

    return 0;
}

SEC("usdt/./tracing/demos/sock/demo:ebpf_exporter:enable_kernel_tracing")
int BPF_USDT(enable_kernel_tracing)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&traced_tgids, &tgid, &yes, BPF_NOEXIST);

    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p)
{
    u32 tgid = p->tgid;

    if (p->pid != p->tgid) {
        return 0;
    }

    bpf_map_delete_elem(&traced_tgids, &tgid);

    return 0;
}

SEC("usdt/./tracing/demos/sock/demo:ebpf_exporter:sock_set_parent_span")
int BPF_USDT(sock_set_parent_span, int fd, u64 trace_id_hi, u64 trace_id_lo, u64 span_id)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct span_parent_t parent = { .trace_id_hi = trace_id_hi, .trace_id_lo = trace_id_lo, .span_id = span_id };
    struct file_key_t key = { .tgid = tgid, .fd = fd };
    struct sock **sk = bpf_map_lookup_elem(&fd_to_sock, &key);

    if (!sk) {
        return 0;
    }

    bpf_map_update_elem(&traced_socks, sk, &parent, BPF_ANY);

    submit_span(&stitch_spans, struct stitch_span_t, &parent, {
        span->fd = fd;
        span->addr = (u64) *sk;
    });

    return 0;
}

SEC("fentry/__sock_release")
int BPF_PROG(__sock_release, struct socket *sock)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_socks, &sk);

    if (!parent) {
        return 0;
    }

    submit_span(&sock_release_spans, struct sock_release_span_t, parent, { span->span_id = 0xdead; });

    bpf_map_delete_elem(&traced_socks, &sk);

    return 0;
}

static int handle_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct span_parent_t *parent = bpf_map_lookup_elem(&traced_socks, &sk);

    if (!parent) {
        return 0;
    }

    submit_span(&skb_spans, struct skb_span_t, parent, { span->ksym = PT_REGS_IP_CORE(ctx); });

    return 0;
}

SEC("kprobe/tcp_v4_do_rcv")
int BPF_PROG(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, sk, skb);
}

SEC("kprobe/nf_hook_slow")
int BPF_PROG(nf_hook_slow, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, BPF_CORE_READ(skb, sk), skb);
}

SEC("kprobe/__ip_local_out")
int BPF_PROG(__ip_local_out, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, sk, skb);
}

SEC("kprobe/ip_finish_output")
int BPF_PROG(ip_finish_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, sk, skb);
}

SEC("kprobe/__dev_queue_xmit")
int BPF_PROG(__dev_queue_xmit, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, BPF_CORE_READ(skb, sk), skb);
}

SEC("kprobe/dev_hard_start_xmit")
int BPF_PROG(dev_hard_start_xmit, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, BPF_CORE_READ(skb, sk), skb);
}

SEC("kprobe/__tcp_retransmit_skb")
int BPF_PROG(__tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb)
{
    return handle_skb((struct pt_regs *) ctx, sk, skb);
}

char LICENSE[] SEC("license") = "GPL";
