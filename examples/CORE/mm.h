/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __DIRECTRECLAIM_H
#define __DIRECTRECLAIM_H

#define MAX_SLOTS	32
#define MAX_ENTRIES	10240

struct hist_key {
	u32  numa_node;
	u32  numa_zone;
};

struct hist {
	u64 counters;
};
#endif /* __DIRECTRECLAIM_H */
