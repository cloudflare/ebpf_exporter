/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SHRINKLAT_H
#define __SHRINKLAT_H

#define MAX_SLOTS	32
#define MAX_ENTRIES	10240

// 27 buckets for latency, max range is 33.6s .. 67.1s
const u8 max_latency_slot = 26;
const u32 shrink_latency_slot = ((max_latency_slot + 2) );

struct hist_key {
	u32  slot;
};

struct hist {
	u64 counters;
};
#endif /* __SHRINKLAT_H */
