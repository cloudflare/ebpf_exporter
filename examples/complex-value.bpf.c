#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

/**
 * commit d152c682f03c ("block: add an explicit ->disk backpointer to the
 * request_queue") and commit f3fa33acca9f ("block: remove the ->rq_disk
 * field in struct request") make some changes to `struct request` and
 * `struct request_queue`. Now, to get the `struct gendisk *` field in a CO-RE
 * way, we need both `struct request` and `struct request_queue`.
 * see:
 *     https://github.com/torvalds/linux/commit/d152c682f03c
 *     https://github.com/torvalds/linux/commit/f3fa33acca9f
 */
struct request_queue___x {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
    struct request_queue___x *q;
    struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

struct key_t {
    u32 dev;
};

struct value_t {
    u64 count;
    u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, struct value_t);
} block_rq_completions SEC(".maps");

static __always_inline struct gendisk *get_disk(void *request)
{
    struct request___x *r = request;

    if (bpf_core_field_exists(r->rq_disk))
        return r->rq_disk;
    return r->q->disk;
}

static struct value_t *get_value(void *map, struct key_t *key)

{
    struct value_t *value = bpf_map_lookup_elem(map, key);
    if (!value) {
        struct value_t zero = { .count = 0, .bytes = 0 };
        bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(map, key);
        if (!value) {
            return NULL;
        }
    }

    return value;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
    struct gendisk *disk = get_disk(rq);
    struct key_t key = { .dev = disk ? MKDEV(disk->major, disk->first_minor) : 0 };
    struct value_t *value = get_value(&block_rq_completions, &key);

    if (!value) {
        return 0;
    }

    __sync_fetch_and_add(&value->count, 1);
    __sync_fetch_and_add(&value->bytes, nr_bytes);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
