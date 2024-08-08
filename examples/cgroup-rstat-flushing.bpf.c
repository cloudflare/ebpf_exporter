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

#define MAX_CGROUP_LEVELS 5

/* From: linux/include/linux/cgroup.h */
static inline u64 cgroup_id(const struct cgroup *cgrp)
{
    return cgrp->kn->id;
}

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, struct hist_key_t);
    __type(value, u64);
} cgroup_rstat_flush_latency_seconds SEC(".maps");

struct start_time_key_t {
    u64 pid_tgid;
    u64 cgrp_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 128);
    __type(key, struct start_time_key_t);
    __type(value, u64);
} start_flush SEC(".maps");

struct flush_key_t {
    u64 cgrp_id;
    u32 level;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flush_key_t);
    __type(value, u64);
} cgroup_rstat_flush_seconds_sum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flush_key_t);
    __type(value, u64);
} cgroup_rstat_flush_seconds_count SEC(".maps");

/* Complex key for encoding lock properties */
struct lock_key_t {
    u8 contended;
    u8 yield;
    u16 level;
};
#define MAX_LOCK_KEY_ENTRIES 128

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

    /* Lock contended event happened prior to obtaining this lock.
     * Get back start "wait" timestamp that was recorded.
     */
    if (contended) {
        u64 *start_wait_ts;
        struct hist_key_t key;
        u64 delta;

        read_array_ptr(&start_wait, &pid, start_wait_ts);
        // TODO: validate LRU lookup success
        /* Lock wait time */
        delta = (now - *start_wait_ts) / 100; /* 0.1 usec */

        increment_exp2_histogram_nosync(&cgroup_rstat_lock_wait_seconds, key, delta, MAX_LATENCY_SLOT);
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

    read_array_ptr(&start_hold, &pid, start_hold_ts);
    // TODO: validate LRU lookup success
    /* Lock hold time */
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
    /* Lock wait time start */
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
    u64 now = bpf_ktime_get_ns();
    u32 level_key = cgrp->level;

    if (level_key > MAX_CGROUP_LEVELS)
        level_key = MAX_CGROUP_LEVELS;

    increment_map_nosync(&cgroup_rstat_flush_total, &level_key, 1);

    /* Flush time latency start */
    struct start_time_key_t key_ts;
    key_ts.pid_tgid = bpf_get_current_pid_tgid();
    key_ts.cgrp_id = cgroup_id(cgrp);
    bpf_map_update_elem(&start_flush, &key_ts, &now, BPF_ANY);

    return 0;
}

SEC("fexit/cgroup_rstat_flush_locked")
int BPF_PROG(cgroup_rstat_flush_locked_exit, struct cgroup *cgrp)
{
    u64 now = bpf_ktime_get_ns();
    struct start_time_key_t key_ts;
    u64 *start_flush_ts;
    u64 delta;

    key_ts.pid_tgid = bpf_get_current_pid_tgid();
    key_ts.cgrp_id = cgroup_id(cgrp);
    read_array_ptr(&start_flush, &key_ts, start_flush_ts);
    // TODO: validate LRU lookup success
    /* Flush time latency */
    delta = (now - *start_flush_ts) / 100; /* 0.1 usec */
    *start_flush_ts = 0;

    struct hist_key_t key;
    increment_exp2_histogram_nosync(&cgroup_rstat_flush_latency_seconds, key, delta, MAX_LATENCY_SLOT);
    /*
     * ebpf_exporter will also have:
     *  ebpf_exporter_cgroup_rstat_flush_latency_seconds_sum and
     *  ebpf_exporter_cgroup_rstat_flush_latency_seconds_count
     *
     * Unfortunately _sum isn't getting updated.
     *
     * The Prometheus idea behind having _seconds_count and _seconds_sum
     * =================================================================
     * The _seconds_count is number of observed flush calls that have been made, so
     * rate(_seconds_count[1m]) in query returns per-second rate of flushes.
     *
     * The _seconds_sum is the sum of the delta values, so rate(flush_seconds_sum[1m])
     * is the amount of time spent for flushes per second.
     *
     * Divide these two expressions to get the average latency over the last minute.
     * The full expression for average latency would be:
     *   rate(_seconds_sum[1m]) / rate(_seconds_count[1m])
     */

    /* Per cgroup record average latency via _seconds_count and _seconds_sum */
    struct flush_key_t flush_key;
    flush_key.cgrp_id = cgroup_id(cgrp);
    flush_key.level = cgrp->level;
    increment_map_nosync(&cgroup_rstat_flush_seconds_sum, &flush_key, delta);
    increment_map_nosync(&cgroup_rstat_flush_seconds_count, &flush_key, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
