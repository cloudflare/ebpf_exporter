/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "biolatency.h"

extern int LINUX_KERNEL_VERSION __kconfig;

static struct hist initial_io_latency_hist;
static struct hist initial_io_size_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} io_latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} io_size SEC(".maps");


static __always_inline int trace_rq_start(struct request *rq)
{
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &rq, &ts, 0);
	return 0;
}


SEC("raw_tp/block_rq_insert")
int rawtracepoint__block_rq_insert(struct bpf_raw_tracepoint_args *ctx)
{
	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */

	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0))
		return trace_rq_start((void *)ctx->args[1]);
	else
		return trace_rq_start((void *)ctx->args[0]);
}

SEC("raw_tp/block_rq_issue")
int rawtracepoint__block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0))
		return trace_rq_start((void *)ctx->args[1]);
	else
		return trace_rq_start((void *)ctx->args[0]);
}

SEC("raw_tp/block_rq_complete")
int rawtracepoint__block_rq_complete(struct bpf_raw_tracepoint_args *ctx)
{
	struct request *rq = (struct request *)ctx->args[0];
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist *histl = NULL;
	struct hist *hists = NULL;
	u32 i = 0;
	s64 delta;
	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp) {
		return 0;
	}

	delta = (s64)(ts - *tsp);
	if (delta < 0) {
		goto cleanup;
	}

	struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);

	hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;

	u32 cmd_flags = BPF_CORE_READ(rq, cmd_flags);

	hkey.flags = 0;
	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		if (cmd_flags & flags[i].bit) {
			hkey.flags = flags[i].bit;
		}
	}
	if (!hkey.flags)
		goto cleanup;

	if ((cmd_flags & REQ_OP_MASK) < ARRAY_SIZE(ops)) {
		hkey.ops = (cmd_flags & REQ_OP_MASK);
	} else {
		goto cleanup;
	}

	delta /= 1000U; //use us
	slot = log2l(delta);
	if (slot >= max_latency_slot)
		slot = max_latency_slot;

	hkey.slot = slot;
	histl = bpf_map_lookup_elem(&io_latency, &hkey);
	if (!histl) {
		bpf_map_update_elem(&io_latency, &hkey, &initial_io_latency_hist, 0);
		histl = bpf_map_lookup_elem(&io_latency, &hkey);
		if (!histl) {
			goto cleanup;
		}
	}
	__sync_fetch_and_add(&histl->counters, 1);

	hkey.slot = max_latency_slot + 1;
	histl = bpf_map_lookup_elem(&io_latency, &hkey);
	if (!histl) {
		bpf_map_update_elem(&io_latency, &hkey, &initial_io_latency_hist, 0);
		histl = bpf_map_lookup_elem(&io_latency, &hkey);
		if (!histl) {
			goto cleanup;
		}
	}
	__sync_fetch_and_add(&histl->counters, delta);

	// Size in kibibytes
	u32 data_len = BPF_CORE_READ(rq, __data_len);
	u64 size_kib = data_len / 1024;

	slot = log2l(size_kib);
	if (slot >= max_size_slot)
		slot = max_size_slot;
	hkey.slot = slot;
	hists = bpf_map_lookup_elem(&io_size, &hkey);
	if (!hists){
		bpf_map_update_elem(&io_size, &hkey, &initial_io_size_hist, 0);
		hists = bpf_map_lookup_elem(&io_size, &hkey);
		if (!hists) {
			goto cleanup;
		}
	}
	__sync_fetch_and_add(&hists->counters, 1);

	hkey.slot = max_size_slot + 1;
	hists = bpf_map_lookup_elem(&io_size, &hkey);
	if (!hists){
		bpf_map_update_elem(&io_size, &hkey, &initial_io_size_hist, 0);
		hists = bpf_map_lookup_elem(&io_size, &hkey);
		if (!hists) {
			goto cleanup;
		}
	}
	__sync_fetch_and_add(&hists->counters, size_kib);

	cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
