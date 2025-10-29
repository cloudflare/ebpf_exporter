/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This is an ebpf_exporter variant of the netstacklat tool
 *
 * Netstacklat - is a tool that "Monitor RX latency within the network stack"
 *  - https://github.com/xdp-project/bpf-examples/tree/main/netstacklat
 *  - Developed by Simon Sundberg <simon.sundberg@kau.se>
 *
 * This variant have been code optimized heavily towards Cloudflare's use-case.
 * Many hooks and features have been disabled, via constructs that lets both the
 * compiler and BPF verifier do dead-code elimination.
 */
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

// Mimic macros from /include/net/tcp.h
#define tcp_sk(ptr) container_of(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)
#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))

char LICENSE[] SEC("license") = "GPL";

/* The ebpf_exporter variant of netstacklat is not runtime configurable at
 * BPF-load time. Thus, below user_config isn't define as 'volatile', instead
 * the 'const' allows the compiler to do dead-code elimination.
 */
const __s64 TAI_OFFSET = (37LL * NS_PER_S);
const struct netstacklat_bpf_config user_config = {
	.network_ns = 0,
	.filter_min_sockqueue_len = 0, /* zero means filter is inactive */
	.filter_nth_packet = 0, /* reduce recorded event to every nth packet, use power-of-2 */
	.filter_pid = false,
	.filter_ifindex = true,
	.filter_cgroup = true,
	.groupby_ifindex = false, /* If true also define CONFIG_GROUPBY_IFINDEX */
	.groupby_cgroup = true,
	.include_hol_blocked = false,
};

/* This provide easy way compile-time to disable some hooks */
/* #define CONFIG_HOOKS_EARLY_RCV 1 */
#undef CONFIG_HOOKS_EARLY_RCV
/* #define CONFIG_HOOKS_ENQUEUE 1 */
#undef CONFIG_HOOKS_ENQUEUE
#define CONFIG_HOOKS_DEQUEUE 1
#define CONFIG_ENABLE_IP_HOOKS 1
#define CONFIG_ENABLE_TCP_HOOKS 1
/* #define CONFIG_ENABLE_UDP_HOOKS 1 */

/* Allows to compile-time disable ifindex map as YAML cannot conf this */
/* #define CONFIG_IFINDEX_FILTER_MAP 1 */
#undef CONFIG_IFINDEX_FILTER_MAP

/* Allows to compile-time disable PID filter map as it is very large */
/* #define CONFIG_PID_FILTER_MAP 1 */
#undef CONFIG_PID_FILTER_MAP

/*
 * Alternative definition of sk_buff to handle renaming of the field
 * mono_delivery_time to tstamp_type. See
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct sk_buff___old {
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	__u8 mono_delivery_time: 1;
} __attribute__((preserve_access_index));

/* NOTICE: max_entries need to be adjusted based on maximum
 *  number of cgroups and ifindex (that are "groupby" collecting)
 *  and "enabled" hooks.
 */
#define N_CGROUPS	2 /* depend on cgroup_id_map matches in YAML config*/
#ifdef CONFIG_GROUPBY_IFINDEX
#define N_IFACES	6 /* On prod only interested in ext0 and vlan100@ext0 */
#else
#define N_IFACES	1 /* With groupby_ifindex==false */
#endif
#define N_HOOKS	1

#if (CONFIG_HOOKS_EARLY_RCV || CONFIG_HOOKS_ENQUEUE || CONFIG_ENABLE_UDP_HOOKS)
#err "Please update N_HOOKS"
#endif

struct tcp_sock_ooo_range {
	u32 prev_n_ooopkts;
	u32 ooo_seq_end;
	/* indicates if ooo_seq_end is still valid (as 0 can be valid seq) */
	bool active;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HIST_NBUCKETS * N_HOOKS * N_CGROUPS * N_IFACES);
	__type(key, struct hist_key);
	__type(value, u64);
} netstack_latency_seconds SEC(".maps");

#ifdef CONFIG_PID_FILTER_MAP
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PID_MAX_LIMIT);
	__type(key, u32);
	__type(value, u64);
} netstack_pidfilter SEC(".maps");
#endif

#ifdef CONFIG_IFINDEX_FILTER_MAP
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, IFINDEX_MAX);
	__type(key, u32);
	__type(value, u64);
} netstack_ifindexfilter SEC(".maps");
#endif

/* Eval two different cgroup_id_map types*/
/* #define CONFIG_CGRP_STORAGE 1 */
#ifdef CONFIG_CGRP_STORAGE
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);  /* type: cgrp_storage */
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u32);
	__type(value, u64);
} netstack_cgroupfilter SEC(".maps");
#else
struct {
	__uint(type, BPF_MAP_TYPE_HASH); /* type: hash */
	__uint(max_entries, MAX_PARSED_CGROUPS);
	__type(key, u64);
	__type(value, u64);
} netstack_cgroupfilter SEC(".maps");
#endif

/* Per-CPU counter for down sampling the recorded events to every nth event */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NETSTACKLAT_N_HOOKS);
    __type(key, u32);
    __type(value, u64);
} netstack_nth_filter SEC(".maps");

static ktime_t time_since(ktime_t tstamp)
{
	ktime_t now;

	if (tstamp <= 0)
		return -1;

	now = bpf_ktime_get_tai_ns() - TAI_OFFSET;
	if (tstamp > now)
		return -1;

	return (now - tstamp) / LATENCY_SCALE;
}

/*
 * Is a < b considering u32 wrap around?
 * Based on the before() function in /include/net/tcp.h
 */
static bool u32_lt(u32 a, u32 b)
{
	return (s32)(a - b) < 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcp_sock_ooo_range);
} netstack_tcp_ooo_range SEC(".maps");

/* Determine if ebpf_exporter macro or local C implementation is used */
#define CONFIG_MAP_MACROS	1
#ifdef  CONFIG_MAP_MACROS
#include "maps.bpf.h"
#define _record_latency_since(tstamp, key)					\
	ktime_t latency = time_since(tstamp);					\
	if (latency >= 0)							\
		increment_exp2_histogram_nosync(&netstack_latency_seconds,	\
						key, latency,			\
						HIST_MAX_LATENCY_SLOT);
#else /* !CONFIG_MAP_MACROS */
#define _record_latency_since(tstamp, key)	\
	record_latency_since(tstamp, &key)

static u64 *lookup_or_zeroinit_histentry(void *map, const struct hist_key *key)
{
	u64 zero = 0;
	u64 *val;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	// Key not in map - try insert it and lookup again
	bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(map, key);
}

static u32 get_exp2_histogram_bucket_idx(u64 value, u32 max_bucket)
{
	u32 bucket = log2l(value);

	// Right-inclusive histogram, so "round up" the log value
	if (bucket > 0 && 1ULL << bucket < value)
		bucket++;

	if (bucket > max_bucket)
		bucket = max_bucket;

	return bucket;
}

/*
 * Same call signature as the increment_exp2_histogram_nosync macro from
 * https://github.com/cloudflare/ebpf_exporter/blob/master/examples/maps.bpf.h
 * but provided as a function.
 *
 * Unlike the macro, only works with keys of type struct hist_key. The hist_key
 * struct must be provided by value (rather than as a pointer) to keep the same
 * call signature as the ebpf-exporter macro, although this will get inefficent
 * if struct hist_key grows large.
 */
static void increment_exp2_histogram_nosync(void *map, struct hist_key key,
					    u64 value, u32 max_bucket)
{
	u64 *bucket_count;

	// Increment histogram
	key.bucket = get_exp2_histogram_bucket_idx(value, max_bucket);
	bucket_count = lookup_or_zeroinit_histentry(map, &key);
	if (bucket_count)
		(*bucket_count)++;

	// Increment sum at end of histogram
	if (value == 0)
		return;

	key.bucket = max_bucket + 1;
	bucket_count = lookup_or_zeroinit_histentry(map, &key);
	if (bucket_count)
		*bucket_count += value;
}

static void record_latency(ktime_t latency, const struct hist_key *key)
{
	increment_exp2_histogram_nosync(&netstack_latency_seconds, *key, latency,
					HIST_MAX_LATENCY_SLOT);
}
static void record_latency_since(ktime_t tstamp, const struct hist_key *key)
{
	ktime_t latency = time_since(tstamp);
	if (latency >= 0)
		record_latency(latency, key);
}
#endif /* !CONFIG_MAP_MACROS */

static inline bool filter_nth_packet(const enum netstacklat_hook hook)
{
	u32 key = hook;
	u64 pkt_cnt;
	u64 *nth;

	/* Zero and one means disabled */
	if (user_config.filter_nth_packet <= 1)
		return true;

	nth = bpf_map_lookup_elem(&netstack_nth_filter, &key);
	if (!nth)
		return false;

	/* The hooks (like tcp-socket-read) runs outside the socket lock in a
	 * preempt/migrate-able user context. Thus, atomic updates are needed
	 * for correctness, but keep PERCPU map to limit cache-line bouncing.
	 */
	pkt_cnt = __sync_fetch_and_add(nth, 1);
	if ((pkt_cnt % user_config.filter_nth_packet) == 0) {
		return true;
	}
	return false;
}

static bool filter_ifindex(u32 ifindex)
{
	if (!user_config.filter_ifindex)
		// No ifindex filter - all ok
		return true;

#ifdef CONFIG_IFINDEX_FILTER_MAP
	u64 *ifindex_ok;

	ifindex_ok = bpf_map_lookup_elem(&netstack_ifindexfilter, &ifindex);
	if (!ifindex_ok)
		return false;

	return *ifindex_ok > 0;
#else
	/* Hack for production:
	 * - We want to exclude 'lo' which have ifindex==1.
	 * - We want to filter on ext0 (ifindex 2) and vlan100@ext0 (ifindex 5)
	 *   unfortunately ifindex'es are not stable, some production metals have
	 *   ifindex==6 for vlan100@link0. Relax filter until adding YAML config.
	 */
	if (ifindex > 1 && ifindex < 12)
		return true;

	return false;
#endif
}

static __u64 get_network_ns(struct sk_buff *skb, struct sock *sk)
{
	/*
	 * Favor reading from sk due to less redirection (fewer probe reads)
	 * and skb->dev is not always set.
	 */
	if (sk)
		return BPF_CORE_READ(sk->__sk_common.skc_net.net, ns.inum);
	else if (skb)
		return BPF_CORE_READ(skb->dev, nd_net.net, ns.inum);
	return 0;
}

static bool filter_network_ns(struct sk_buff *skb, struct sock *sk)
{
	if (user_config.network_ns == 0)
		return true;

	return get_network_ns(skb, sk) == user_config.network_ns;
}

#if (CONFIG_HOOKS_EARLY_RCV || CONFIG_HOOKS_ENQUEUE)
static void record_skb_latency(struct sk_buff *skb, struct sock *sk, enum netstacklat_hook hook)
{
	struct hist_key key = { .hook = hook };
	u32 ifindex;

	if (bpf_core_field_exists(skb->tstamp_type)) {
		/*
		 * For kernels >= v6.11 the tstamp_type being non-zero
		 * (SKB_CLOCK_REALTIME) implies that skb->tstamp holds a
		 * preserved TX timestamp rather than a RX timestamp. See
		 * https://lore.kernel.org/all/20240509211834.3235191-2-quic_abchauha@quicinc.com/
		 */
		if (BPF_CORE_READ_BITFIELD(skb, tstamp_type) > 0)
			return;

	} else {
		/*
		 * For kernels < v6.11, the field was called mono_delivery_time
		 * instead, see https://lore.kernel.org/all/20220302195525.3480280-1-kafai@fb.com/
		 * Kernels < v5.18 do not have the mono_delivery_field either,
		 * but we do not support those anyways (as they lack the
		 * bpf_ktime_get_tai_ns helper)
		 */
		struct sk_buff___old *skb_old = (void *)skb;
		if (BPF_CORE_READ_BITFIELD(skb_old, mono_delivery_time) > 0)
			return;
	}

	ifindex = skb->skb_iif;
	if (!filter_ifindex(ifindex))
		return;

	if (!filter_network_ns(skb, sk))
		return;

	if (!filter_nth_packet(hook))
		return;

#ifdef CONFIG_GROUPBY_IFINDEX
	if (user_config.groupby_ifindex)
		key.ifindex = ifindex;
#endif

	_record_latency_since(skb->tstamp, key);
}
#endif

#ifdef CONFIG_PID_FILTER_MAP
static bool filter_pid(u32 pid)
{
	u64 *pid_ok;

	if (!user_config.filter_pid)
		// No PID filter - all PIDs ok
		return true;

	pid_ok = bpf_map_lookup_elem(&netstack_pidfilter, &pid);
	if (!pid_ok)
		return false;

	return *pid_ok > 0;
}
#endif /* CONFIG_PID_FILTER_MAP */

#ifdef CONFIG_CGRP_STORAGE
static bool filter_cgroup(u64 *cgroup_id)
{
	if (!user_config.filter_cgroup) {
		if (user_config.groupby_cgroup)
			*cgroup_id = bpf_get_current_cgroup_id();
		// No cgroup filter - all cgroups ok
		return true;
	}

	struct task_struct *task = bpf_get_current_task_btf();
	struct cgroup *cgrp = task->cgroups->dfl_cgrp;

	if (user_config.groupby_cgroup)
		/* no need to call bpf_get_current_cgroup_id() */
		*cgroup_id = BPF_CORE_READ(cgrp, kn, id);

	return bpf_cgrp_storage_get(&netstack_cgroupfilter, cgrp, 0, 0) != NULL;
}
#else /* !CONFIG_CGRP_STORAGE */
static bool filter_cgroup(u64 *cgroup_id)
{
	if (!user_config.filter_cgroup) {
		if (user_config.groupby_cgroup)
			*cgroup_id = bpf_get_current_cgroup_id();
		// No cgroup filter - all cgroups ok
		return true;
	}
	*cgroup_id = bpf_get_current_cgroup_id();

	return bpf_map_lookup_elem(&netstack_cgroupfilter, cgroup_id) != NULL;
}
#endif /* !CONFIG_CGRP_STORAGE */

static bool filter_current_task()
{
	bool ok = true;

#ifdef CONFIG_PID_FILTER_MAP
	__u32 tgid;

	if (user_config.filter_pid) {
		tgid = bpf_get_current_pid_tgid() >> 32;
		ok = ok && filter_pid(tgid);
	}
#endif
	return ok;
}

static inline bool sk_backlog_empty(const struct sock *sk)
{
	return READ_ONCE(sk->sk_backlog.tail) == NULL;
}

/* To lower runtime overhead, skip recording timestamps for sockets with very
 * few packets. Use sk_buff_head->qlen to see if e.g. queue have more than 2
 * elements
 */
static inline __u32 sk_queue_len(const struct sk_buff_head *list_)
{
	return READ_ONCE(list_->qlen);
}

static bool filter_min_sockqueue_len(struct sock *sk)
{
	const u32 min_qlen = user_config.filter_min_sockqueue_len;

	if (min_qlen == 0)
		return true;

	if (sk_queue_len(&sk->sk_receive_queue) >= min_qlen)
		return true;

	/* Packets can also be on the sk_backlog, but we don't know the number
	 * of SKBs on the queue, because sk_backlog.len is in bytes (based on
	 * skb->truesize).  Thus, if any backlog exists we don't filter.
	 */
	if (!sk_backlog_empty(sk))
		return true;

	return false;
}

#if (CONFIG_HOOKS_DEQUEUE || CONFIG_HOOKS_ENQUEUE)
static __always_inline bool filter_socket(struct sock *sk, struct sk_buff *skb,
					  u64 *cgroup_id, const enum netstacklat_hook hook)
{
	if (!filter_min_sockqueue_len(sk))
		return false;

	if (!filter_cgroup(cgroup_id))
		return false;

	if (!filter_nth_packet(hook))
		return false;

	return true;
}
#endif

static int current_max_possible_ooo_seq(struct tcp_sock *tp, u32 *seq)
{
	struct tcp_skb_cb cb;
	u32 max_seq = 0;
	int err = 0;

	if (BPF_CORE_READ(tp, out_of_order_queue.rb_node) == NULL) {
		/* No ooo-segments currently in ooo-queue
		 * Any ooo-segments must already have been merged to the
		 * receive queue. Current rcv_nxt must therefore be ahead
		 * of all ooo-segments that have arrived until now.
		 */
		err = bpf_core_read(&max_seq, sizeof(max_seq), &tp->rcv_nxt);
		if (err)
			bpf_printk("failed to read tcp_sock->rcv_nxt, err=%d",
				   err);
	} else {
		/*
		 * Some ooo-segments currently in ooo-queue
		 * Max out-of-order seq is given by the seq_end of the tail
		 * skb in the ooo-queue.
		 */
		err = BPF_CORE_READ_INTO(&cb, tp, ooo_last_skb, cb);
		if (err)
			bpf_printk(
				"failed to read tcp_sock->ooo_last_skb->cb, err=%d",
				err);
		max_seq = cb.end_seq;
	}

	*seq = max_seq;
	return err;
}

static bool tcp_read_in_ooo_range(struct tcp_sock *tp,
				  struct tcp_sock_ooo_range *ooo_range)
{
	u32 read_seq;
	int err;

	if (!ooo_range->active)
		return false;

	err = bpf_core_read(&read_seq, sizeof(read_seq), &tp->copied_seq);
	if (err) {
		bpf_printk("failed to read tcp_sock->copied_seq, err=%d", err);
		return true; // Assume we may be in ooo-range
	}

	if (u32_lt(ooo_range->ooo_seq_end, read_seq)) {
		ooo_range->active = false;
		return false;
	} else {
		return true;
	}
}

static bool tcp_read_maybe_holblocked(struct sock *sk)
{
	struct tcp_sock_ooo_range *ooo_range;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 n_ooopkts, nxt_seq;
	int err;

	err = bpf_core_read(&n_ooopkts, sizeof(n_ooopkts), &tp->rcv_ooopack);
	if (err) {
		bpf_printk("failed to read tcp_sock->rcv_ooopack, err=%d\n",
			   err);
		return true; // Assume we may be in ooo-range
	}

	if (n_ooopkts == 0)
		return false;

	ooo_range = bpf_sk_storage_get(&netstack_tcp_ooo_range, sk, NULL,
				       BPF_SK_STORAGE_GET_F_CREATE);
	if (!ooo_range) {
		bpf_printk(
			"failed getting ooo-range socket storage for tcp socket");
		return true; // Assume we may be in ooo-range
	}

	// Increase in ooo-packets since last - figure out next safe seq
	if (n_ooopkts > ooo_range->prev_n_ooopkts) {
		ooo_range->prev_n_ooopkts = n_ooopkts;
		err = current_max_possible_ooo_seq(tp, &nxt_seq);
		if (!err) {
			ooo_range->ooo_seq_end = nxt_seq;
			ooo_range->active = true;
		}
		return true;
	}

	return tcp_read_in_ooo_range(tp, ooo_range);
}

static void record_socket_latency(struct sock *sk, struct sk_buff *skb,
				  ktime_t tstamp, enum netstacklat_hook hook,
				  u64 cgroup_id)
{
	struct hist_key key = { .hook = hook };
	u32 ifindex;

	if (!filter_current_task())
		return;

	ifindex = skb ? skb->skb_iif : sk->sk_rx_dst_ifindex;
	if (!filter_ifindex(ifindex))
		return;

	if (!filter_network_ns(skb, sk))
		return;

#ifdef CONFIG_GROUPBY_IFINDEX
	if (user_config.groupby_ifindex)
		key.ifindex = ifindex;
#endif
	if (user_config.groupby_cgroup)
		key.cgroup = cgroup_id;

	_record_latency_since(tstamp, key);
}

#ifdef CONFIG_HOOKS_EARLY_RCV
# ifdef CONFIG_ENABLE_IP_HOOKS
SEC("fentry/ip_rcv_core")
int BPF_PROG(netstacklat_ip_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/ip6_rcv_core")
int BPF_PROG(netstacklat_ip6_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}
# endif /* CONFIG_ENABLE_IP_HOOKS */

# ifdef CONFIG_ENABLE_TCP_HOOKS
SEC("fentry/tcp_v4_rcv")
int BPF_PROG(netstacklat_tcp_v4_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/tcp_v6_rcv")
int BPF_PROG(netstacklat_tcp_v6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}
# endif /* CONFIG_ENABLE_TCP_HOOKS */

# ifdef CONFIG_ENABLE_UDP_HOOKS
SEC("fentry/udp_rcv")
int BPF_PROG(netstacklat_udp_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fentry/udpv6_rcv")
int BPF_PROG(netstacklat_udpv6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}
# endif /* CONFIG_ENABLE_UDP_HOOKS */
#endif /* CONFIG_HOOKS_EARLY_RCV */

#ifdef CONFIG_HOOKS_ENQUEUE
# ifdef CONFIG_ENABLE_TCP_HOOKS
SEC("fexit/tcp_queue_rcv")
int BPF_PROG(netstacklat_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_skb_latency(skb, sk, NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED);
	return 0;
}
# endif /* CONFIG_ENABLE_TCP_HOOKS */

# ifdef CONFIG_ENABLE_UDP_HOOKS
SEC("fexit/__udp_enqueue_schedule_skb")
int BPF_PROG(netstacklat_udp_enqueue_schedule_skb, struct sock *sk,
	     struct sk_buff *skb, int retval)
{
	if (retval == 0)
		record_skb_latency(skb, sk, NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED);
	return 0;
}
# endif /* CONFIG_ENABLE_UDP_HOOKS */
#endif /* CONFIG_HOOKS_ENQUEUE */

#ifdef CONFIG_HOOKS_DEQUEUE
# ifdef CONFIG_ENABLE_TCP_HOOKS
SEC("fentry/tcp_recv_timestamp")
int BPF_PROG(netstacklat_tcp_recv_timestamp, void *msg, struct sock *sk,
	     struct scm_timestamping_internal *tss)
{
	const enum netstacklat_hook hook = NETSTACKLAT_HOOK_TCP_SOCK_READ;
	u64 cgroup_id = 0;

	if (!filter_socket(sk, NULL, &cgroup_id, hook))
		return 0;

	struct timespec64 *ts = &tss->ts[0];

	if (!user_config.include_hol_blocked && tcp_read_maybe_holblocked(sk))
		return 0;

	record_socket_latency(sk, NULL,
			      (ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
			      hook, cgroup_id);
	return 0;
}
# endif /* CONFIG_ENABLE_TCP_HOOKS */

# ifdef CONFIG_ENABLE_UDP_HOOKS
SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	const enum netstacklat_hook hook = NETSTACKLAT_HOOK_UDP_SOCK_READ;
	u64 cgroup_id = 0;

	if (!filter_socket(sk, skb, &cgroup_id, hook))
		return 0;

	record_socket_latency(sk, skb, skb->tstamp, hook, cgroup_id);
	return 0;
}
# endif /* CONFIG_ENABLE_UDP_HOOKS */
#endif /* CONFIG_HOOKS_DEQUEUE */
