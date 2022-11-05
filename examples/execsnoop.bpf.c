// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	u8 comm[TASK_COMM_LEN];
	u8 filename[MAX_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} process_exec_total SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned fname_off;
	struct event *e;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&process_exec_total, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
