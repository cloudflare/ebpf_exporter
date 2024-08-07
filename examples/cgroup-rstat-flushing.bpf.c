/*
 * Measure cgroup rstat (recursive stats) flushing overhead and latency.
 *
 * Loosely based on bpftrace script cgroup_rstat_tracepoint.bt
 *  - https://github.com/xdp-project/xdp-project/blob/master/areas/latency/cgroup_rstat_tracepoint.bt
 *
 * Depends on tracepoints added in kernel v6.10
 */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_CGROUP_LEVELS	5

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_CGROUP_LEVELS + 1);
	__type(key, u32);
	__type(value, u64);
} cgroup_rstat_flush_total SEC(".maps");

// 24 buckets for latency, max range is 0.83s .. 1.67s
#define MAX_LATENCY_SLOT 24

struct hist_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, struct hist_key_t);
    __type(value, u64);
} cgroup_rstat_lock_wait_seconds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 128);
    __type(key, u64);
    __type(value, u64);
} start_wait SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, struct hist_key_t);
    __type(value, u64);
} cgroup_rstat_lock_hold_seconds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 128);
    __type(key, u64);
    __type(value, u64);
} start_hold SEC(".maps");

/* Complex key for encoding lock properties */
struct lock_key_t {
	u8  contended;
	u8  yield;
	u16 level;
};
#define MAX_LOCK_KEY_ENTRIES	128

/* Total counter for obtaining lock together with state (prometheus labels)
 *
 * State for cgroup level, contended and yield case.
 *
 * The problematic/interesting case is when the lock was contended (prior to
 * obtaining the lock).  This "contended" label is key in analyzing locking
 * issues.
 *
 * Kernel can yield the rstat lock when walking individial CPU stats.  This
 * leads to "interresting" concurrency issues.  Thus, having a label "yield"
 * can help diagnose.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_LOCK_KEY_ENTRIES);
	__type(key, struct lock_key_t);
	__type(value, u64);
} cgroup_rstat_locked_total SEC(".maps");

/** Measurement#1: lock rates
 *  =========================
 For locks, the problematic/interesting case is when the lock was contended.

 Simply counting the lock+unlock is complicated by yielding the lock in the main
 flushing loop (in cgroup_rstat_flush_locked()). The tracepoints "cpu" argument
 will be (minus) -1 when the lock is not a yielded lock.

 Concern: The lock rates will vary (a lot) and aggregating this as an average
 will not capture spikes. Especially given Prometheus capture intervals only
 happens every 53 seconds.

*/
SEC("tp_btf/cgroup_rstat_locked")
int BPF_PROG(rstat_locked, struct cgroup *cgrp, int cpu, bool contended)
{
	u64 now = bpf_ktime_get_ns();
	u64 pid = bpf_get_current_pid_tgid();
	struct lock_key_t lock_key = { 0 };
	u32 level = cgrp->level;

	if (level > MAX_CGROUP_LEVELS)
		level = MAX_CGROUP_LEVELS;

	if (cpu >= 0)
		lock_key.yield = 1;

	lock_key.contended = contended;
	lock_key.level = (level & 0xFF);

	increment_map_nosync(&cgroup_rstat_locked_total, &lock_key, 1);

	/* Lock hold time start */
	bpf_map_update_elem(&start_hold, &pid, &now, BPF_ANY);
	// TODO: Should we ignore yield and measure flush time instead?

	/* Lock contended event happened prior to obtaining this lock.
	 * Get back start "wait" timestamp that was recorded.
	 */
	if (contended) {
		u64 *start_wait_ts;
		struct hist_key_t key;
		u64 delta;

		read_array_ptr(&start_wait, &pid, start_wait_ts);
		// TODO: validate LRU lookup success
		delta = (now - *start_wait_ts) / 100; /* 0.1 usec */

		increment_exp2_histogram_nosync(&cgroup_rstat_lock_wait_seconds,
						key, delta, MAX_LATENCY_SLOT);
		// Should we reset timestamp?
		*start_wait_ts = 0;
	}

	return 0;
}

SEC("tp_btf/cgroup_rstat_unlock")
int BPF_PROG(rstat_unlock, struct cgroup *cgrp, int cpu, bool contended)
{
    u64 now = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    u64 *start_hold_ts;
    struct hist_key_t key;
    u64 delta;

    /* Lock hold time */
    read_array_ptr(&start_hold, &pid, start_hold_ts);
    // TODO: validate LRU lookup success
    delta = (now - *start_hold_ts) / 100; /* 0.1 usec */

    increment_exp2_histogram_nosync(&cgroup_rstat_lock_hold_seconds, key, delta, MAX_LATENCY_SLOT);
    // Should we reset timestamp?
    *start_hold_ts = 0;

    return 0;
}

/** Measurement#2: latency/delay caused by flush
 *  ============================================
 Measure both time waiting for the lock, and time spend holding the lock.

 This should be a histogram (for later latency heatmap).
 */

SEC("tp_btf/cgroup_rstat_lock_contended")
int BPF_PROG(rstat_lock_contended, struct cgroup *cgrp, int cpu, bool contended)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();

    /* TODO: Do more validation here.
     * In patchset V8+V9, two contended events can happen due to races.
     * Could add code that handles this and does some validation.
     */
    bpf_map_update_elem(&start_wait, &pid, &ts, BPF_ANY);
    return 0;
}

/** Measurement#3: flush rate
 *  =========================
 Simply count invocations of cgroup_rstat_flush_locked().

 Concern: The flush rates will vary (a lot), e.g. then cadvisor collects stats
 for all cgroups in the system, or when kswapd does concurrent flushing (of root
 cgroup). Averaging this (over approx 1 minute) gives the wrong impression.

 Mitigation workaround: Store counters per cgroup "level" (level=0 is root).
 This will allow us to separate root-cgroup flushes from cadvisor walking all
 cgroup levels.

 */
SEC("fentry/cgroup_rstat_flush_locked")
int BPF_PROG(cgroup_rstat_flush_locked, struct cgroup *cgrp)
{
	u32 level_key = cgrp->level;

	if (level_key > MAX_CGROUP_LEVELS)
		level_key = MAX_CGROUP_LEVELS;

	increment_map_nosync(&cgroup_rstat_flush_total, &level_key, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
