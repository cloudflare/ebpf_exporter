/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BIOLATENCY_H
#define __BIOLATENCY_H

#define DISK_NAME_LEN	32
#define MAX_SLOTS	27
#define MAX_ENTRIES	10240

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

// Max number of disks we expect to see on the host
const u8 max_disks = 255;

// 27 buckets for latency, max range is 33.6s .. 67.1s
const u8 max_latency_slot = 26;

// 16 buckets per disk in kib, max range is 16mib .. 32mib
const u8 max_size_slot = 15;

const u32 io_latency_slot = ((max_latency_slot + 2) * max_disks);
const u32 io_size_slot = ((max_size_slot + 2) * max_disks);

struct hist_key {
	u32  dev;
	u32  flags;
	u32  ops;
	u32  slot;
};

struct hist {
	u64 counters;
};

#define REQ_OP_BITS 8
#define REQ_OP_MASK  ((1 << REQ_OP_BITS) - 1)
#define REQ_SYNC  (1 << (REQ_OP_BITS + 3))
#define REQ_META  (1 << (REQ_OP_BITS + 4))
#define REQ_PRIO  (1 << (REQ_OP_BITS + 5))
#define REQ_NOMERGE  (1 << (REQ_OP_BITS + 6))
#define REQ_IDLE  (1 << (REQ_OP_BITS + 7))
#define REQ_INTEGRITY  (1 << (REQ_OP_BITS + 8))
#define REQ_FUA  (1 << (REQ_OP_BITS + 9))
#define REQ_PREFLUSH (1 << (REQ_OP_BITS + 10))
#define REQ_RAHEAD  (1 << (REQ_OP_BITS + 11))
#define REQ_BACKGROUND  (1 << (REQ_OP_BITS + 12))
#define REQ_NOWAIT (1 << (REQ_OP_BITS + 13))


static struct { int bit; const char *str; } flags[] = {
	{ REQ_NOWAIT, "NoWait" },
	{ REQ_BACKGROUND, "Background" },
	{ REQ_RAHEAD, "ReadAhead" },
	{ REQ_PREFLUSH, "PreFlush" },
	{ REQ_FUA, "FUA" },
	{ REQ_INTEGRITY, "Integrity" },
	{ REQ_IDLE, "Idle" },
	{ REQ_NOMERGE, "NoMerge" },
	{ REQ_PRIO, "Priority" },
	{ REQ_META, "Metadata" },
	{ REQ_SYNC, "Sync" },
};

static const char *ops[] = {
	[REQ_OP_READ] = "Read",
	[REQ_OP_WRITE] = "Write",
	[REQ_OP_FLUSH] = "Flush",
	[REQ_OP_DISCARD] = "Discard",
	[REQ_OP_SECURE_ERASE] = "SecureErase",
	[REQ_OP_ZONE_RESET] = "ZoneReset",
	[REQ_OP_WRITE_SAME] = "WriteSame",
	[REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
	[REQ_OP_WRITE_ZEROES] = "WriteZeroes",
	[REQ_OP_ZONE_OPEN] = "ZoneOpen",
	[REQ_OP_ZONE_CLOSE] = "ZoneClose",
	[REQ_OP_ZONE_FINISH] = "ZoneFinish",
	[REQ_OP_SCSI_IN] = "SCSIIn",
	[REQ_OP_SCSI_OUT] = "SCSIOut",
	[REQ_OP_DRV_IN] = "DrvIn",
	[REQ_OP_DRV_OUT] = "DrvOut",
};

#endif /* __BIOLATENCY_H */
