/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "mm.h"

extern int LINUX_KERNEL_VERSION __kconfig;

static struct hist kcompactd_count_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} kcompactd_counts SEC(".maps");


SEC("tracepoint/compaction/mm_compaction_kcompactd_wake")
int tracepoint__compaction__mm_compaction_kcompactd_wake(struct trace_event_raw_kcompactd_wake_template *ctx)
{
	struct hist_key hkey;
	hkey.numa_node = ctx->nid;
	hkey.numa_zone = ctx->classzone_idx;
	struct hist *histc = NULL;
	histc = bpf_map_lookup_elem(&kcompactd_counts, &hkey);
	if (!histc) {
		bpf_map_update_elem(&kcompactd_counts, &hkey, &kcompactd_count_hist, 0);
		histc = bpf_map_lookup_elem(&kcompactd_counts, &hkey);
		if (!histc) {
			return 0;
		}
	}
	__sync_fetch_and_add(&histc->counters, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
