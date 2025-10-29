/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NETSTACKLAT_H
#define NETSTACKLAT_H

/* To reduce Prometheus buckets metric reduce/scale latency time resolution.
 * This LATENCY_SCALE is connected to the YAML bucket_multiplier config.
 */
#define LATENCY_SCALE 1000UL

#define HIST_MAX_LATENCY_SLOT 24 // ( 2^24 ns / 1000) usecs -> ~16.7s
/*
 * MAX_LATENCY_SLOT + 1 buckets for hist, + 1 "bucket" for the "sum key"
 * (https://github.com/cloudflare/ebpf_exporter?tab=readme-ov-file#sum-keys)
 * that ebpf_exporter expects for exp2 hists (see how it's used in the
 * increment_exp2_histogram_nosync() function)
 */
#define HIST_NBUCKETS (HIST_MAX_LATENCY_SLOT + 2)

#define NS_PER_S 1000000000

// The highest possible PID on a Linux system (from /include/linux/threads.h)
#define PID_MAX_LIMIT (4 * 1024 * 1024)
// The highest ifindex we expect to encounter
#define IFINDEX_MAX 16384
// The maximum number of different cgroups we can filter for
#define MAX_PARSED_CGROUPS 4096

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#ifndef max
#define max(a, b)                   \
	({                          \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a > _b ? _a : _b;  \
	})
#endif

#ifndef min
#define min(a, b)                   \
	({                          \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a < _b ? _a : _b;  \
	})
#endif

enum netstacklat_hook {
	NETSTACKLAT_HOOK_INVALID = 0,
	NETSTACKLAT_HOOK_IP_RCV,
	NETSTACKLAT_HOOK_TCP_START,
	NETSTACKLAT_HOOK_UDP_START,
	NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED,
	NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED,
	NETSTACKLAT_HOOK_TCP_SOCK_READ,
	NETSTACKLAT_HOOK_UDP_SOCK_READ,
	NETSTACKLAT_N_HOOKS,
};

/* Disabling user_config.groupby_ifindex requires modifying hist_key and YAML
 */
/* #define CONFIG_GROUPBY_IFINDEX 1 */
#undef CONFIG_GROUPBY_IFINDEX

/*
 * Key used for the histogram map
 * To be compatible with ebpf-exporter, all histograms need a key struct whose final
 * member is named "bucket" and is the histogram bucket index.
 */
struct hist_key {
	__u64 cgroup;
#ifdef CONFIG_GROUPBY_IFINDEX
	__u32 ifindex;
#endif
	__u16 hook; // need well defined size for ebpf-exporter to decode
	__u16 bucket; // needs to be last to be compatible with ebpf-exporter
} __attribute__((packed));

struct netstacklat_bpf_config {
	__u32 network_ns;
	__u32 filter_min_sockqueue_len;
	__u64 filter_nth_packet;
	bool filter_pid;
	bool filter_ifindex;
	bool filter_cgroup;
	bool groupby_ifindex;
	bool groupby_cgroup;
	bool include_hol_blocked;
};

#endif
