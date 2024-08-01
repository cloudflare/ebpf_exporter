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

#define MAX_CGRP_LEVELS	5

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_CGRP_LEVELS + 1);
	__type(key, u32);
	__type(value, u64);
} cgroup_rstat_flush_total SEC(".maps");

/* Total counter for obtaining lock together with contended state */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2); /* contended state used as key */
	__type(key, u32);
	__type(value, u64);
} cgroup_rstat_locked_state SEC(".maps");

/** Measurement#1: lock rates
 *  =========================
 For locks, the problematic/interesting case is when the lock was contended.

 Simply counting the lock+unlock is complicated by yielding the lock in the main
 flushing loop (in cgroup_rstat_flush_locked()). The tracepoints "cpu" argument
 will be (minus) -1 when the lock is not a yielded lock.

 Concern: The lock rates will vary (a lot) and aggregating this as an average
 will not capture spikes. Especially given Prometheus capture intervals only
 happens every 53 seconds.

 Q: will lock "type=yield" be a good idea?

*/

SEC("tp_btf/cgroup_rstat_locked")
int BPF_PROG(rstat_locked, struct cgroup *cgrp, int cpu, bool contended)
{
	u32 key = contended;
	u64 *cnt;

	read_array_ptr(&cgroup_rstat_locked_state, &key, cnt);
	(*cnt)++;

	return 0;
}


/** Measurement#2: latency/delay caused by flush
 *  ============================================
 Measure both time waiting for the lock, and time spend holding the lock.

 This should be a histogram (for later latency heatmap).

 */


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
	u64 level_key = cgrp->level;

	if (level_key > MAX_CGRP_LEVELS)
		level_key = MAX_CGRP_LEVELS;

	increment_map_nosync(&cgroup_rstat_flush_total, &level_key, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
