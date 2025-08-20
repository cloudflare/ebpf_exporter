/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux_local.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"

char LICENSE[] SEC("license") = "GPL";


volatile const __s64 TAI_OFFSET = (37LL * NS_PER_S);
volatile const struct netstacklat_bpf_config user_config = {
	.network_ns = 0,
	.filter_pid = false,
	.filter_ifindex = false,
	.filter_cgroup = false,
	.filter_nonempty_sockqueue = false,
	.groupby_ifindex = false,
	.groupby_cgroup = false,
};

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HIST_NBUCKETS * NETSTACKLAT_N_HOOKS * 64);
	__type(key, struct hist_key);
	__type(value, u64);
} netstack_latency_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PID_MAX_LIMIT);
	__type(key, u32);
	__type(value, u64);
} netstack_pidfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, IFINDEX_MAX);
	__type(key, u32);
	__type(value, u64);
} netstack_ifindexfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_CGROUPS);
	__type(key, u64);
	__type(value, u64);
} netstack_cgroupfilter SEC(".maps");

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

static ktime_t time_since(ktime_t tstamp)
{
	ktime_t now;

	if (tstamp <= 0)
		return -1;

	now = bpf_ktime_get_tai_ns() - TAI_OFFSET;
	if (tstamp > now)
		return -1;

	return now - tstamp;
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

static bool filter_ifindex(u32 ifindex)
{
	u64 *ifindex_ok;

	if (!user_config.filter_ifindex)
		// No ifindex filter - all ok
		return true;

	ifindex_ok = bpf_map_lookup_elem(&netstack_ifindexfilter, &ifindex);
	if (!ifindex_ok)
		return false;

	return *ifindex_ok > 0;
}

static bool filter_network_ns(u32 ns)
{
	if (user_config.network_ns == 0)
		return true;

	return ns == user_config.network_ns;
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

	if (!filter_network_ns(get_network_ns(skb, sk)))
		return;

	if (user_config.groupby_ifindex)
		key.ifindex = ifindex;

	record_latency_since(skb->tstamp, &key);
}

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

static bool filter_cgroup(u64 cgroup_id)
{
	if (!user_config.filter_cgroup)
		// No cgroup filter - all cgroups ok
		return true;

	return bpf_map_lookup_elem(&netstack_cgroupfilter, &cgroup_id) != NULL;
}

static bool filter_current_task(u64 cgroup)
{
	bool ok = true;
	__u32 tgid;

	if (user_config.filter_pid) {
		tgid = bpf_get_current_pid_tgid() >> 32;
		ok = ok && filter_pid(tgid);
	}

	if (user_config.filter_cgroup)
		ok = ok && filter_cgroup(cgroup);

	return ok;
}

/**
 * skb_queue_empty - check if a queue is empty
 * @list: queue head
 *
 * Returns true if the queue is empty, false otherwise.
 *
 * Copied from /include/linux/skbuff.h
 */
static inline int skb_queue_empty(const struct sk_buff_head *list)
{
	return list->next == (const struct sk_buff *)list;
}

static bool filter_nonempty_sockqueue(struct sock *sk)
{
	if (!user_config.filter_nonempty_sockqueue)
		return true;

	return !skb_queue_empty(&sk->sk_receive_queue);
}

static void record_socket_latency(struct sock *sk, struct sk_buff *skb,
				  ktime_t tstamp, enum netstacklat_hook hook)
{
	struct hist_key key = { .hook = hook };
	u64 cgroup = 0;
	u32 ifindex;

	if (!filter_nonempty_sockqueue(sk))
		return;

	if (user_config.filter_cgroup || user_config.groupby_cgroup)
		cgroup = bpf_get_current_cgroup_id();

	if (!filter_current_task(cgroup))
		return;

	ifindex = skb ? skb->skb_iif : sk->sk_rx_dst_ifindex;
	if (!filter_ifindex(ifindex))
		return;

	if (!filter_network_ns(get_network_ns(skb, sk)))
		return;

	if (user_config.groupby_ifindex)
		key.ifindex = ifindex;
	if (user_config.groupby_cgroup)
		key.cgroup = cgroup;

	record_latency_since(tstamp, &key);
}

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

SEC("fexit/tcp_queue_rcv")
int BPF_PROG(netstacklat_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_skb_latency(skb, sk, NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED);
	return 0;
}

SEC("fexit/__udp_enqueue_schedule_skb")
int BPF_PROG(netstacklat_udp_enqueue_schedule_skb, struct sock *sk,
	     struct sk_buff *skb, int retval)
{
	if (retval == 0)
		record_skb_latency(skb, sk, NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED);
	return 0;
}

SEC("fentry/tcp_recv_timestamp")
int BPF_PROG(netstacklat_tcp_recv_timestamp, void *msg, struct sock *sk,
	     struct scm_timestamping_internal *tss)
{
	struct timespec64 *ts = &tss->ts[0];
	record_socket_latency(sk, NULL,
			      (ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
			      NETSTACKLAT_HOOK_TCP_SOCK_READ);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_socket_latency(sk, skb, skb->tstamp,
			      NETSTACKLAT_HOOK_UDP_SOCK_READ);
	return 0;
}
