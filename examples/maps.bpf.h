#include "bits.bpf.h"

#define lookup_or_zero_init_key(map, key, into)                                                                        \
    u64 zero = 0;                                                                                                      \
                                                                                                                       \
    into = bpf_map_lookup_elem(map, key);                                                                              \
    if (!into) {                                                                                                       \
        bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);                                                             \
        into = bpf_map_lookup_elem(map, key);                                                                          \
        if (!into) {                                                                                                   \
            return 0;                                                                                                  \
        }                                                                                                              \
    }

#define increment_variant(map, key, increment, variant)                                                                \
    u64 *count;                                                                                                        \
                                                                                                                       \
    lookup_or_zero_init_key(map, key, count);                                                                          \
                                                                                                                       \
    variant;                                                                                                           \
                                                                                                                       \
    return *count;

static inline int increment_map(void *map, void *key, u64 increment)
{
    increment_variant(map, key, increment, __sync_fetch_and_add(count, increment));
}

static inline int increment_map_nosync(void *map, void *key, u64 increment)
{
    increment_variant(map, key, increment, *count += increment);
}

// Arrays are always preallocated, so this only fails if the key is missing
#define read_array_ptr(map, key, into)                                                                                 \
    into = bpf_map_lookup_elem(map, key);                                                                              \
    if (!into) {                                                                                                       \
        return 0;                                                                                                      \
    }

#define _increment_histogram(map, key, increment, max_bucket, increment_fn)                                            \
    if (key.bucket > max_bucket) {                                                                                     \
        key.bucket = max_bucket;                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    increment_fn(map, &key, 1);                                                                                        \
                                                                                                                       \
    if (increment > 0) {                                                                                               \
        key.bucket = max_bucket + 1;                                                                                   \
        increment_fn(map, &key, increment);                                                                            \
    }

#define _increment_ex2_histogram(map, key, increment, max_bucket, increment_fn)                                        \
    key.bucket = log2l(increment);                                                                                     \
                                                                                                                       \
    if (key.bucket > max_bucket) {                                                                                     \
        key.bucket = max_bucket;                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    _increment_histogram(map, key, increment, max_bucket, increment_fn);

#define increment_exp2_histogram(map, key, increment, max_bucket)                                                      \
    _increment_ex2_histogram(map, key, increment, max_bucket, increment_map)

#define increment_exp2_histogram_nosync(map, key, increment, max_bucket)                                               \
    _increment_ex2_histogram(map, key, increment, max_bucket, increment_map_nosync)

#define _increment_exp2zero_histogram(map, key, increment, max_bucket, increment_fn)                                   \
    if (increment == 0) {                                                                                              \
        key.bucket = 0;                                                                                                \
    } else {                                                                                                           \
        key.bucket = log2l(increment) + 1;                                                                             \
    }                                                                                                                  \
                                                                                                                       \
    _increment_histogram(map, key, increment, max_bucket, increment_fn);

#define increment_exp2zero_histogram(map, key, increment, max_bucket)                                                  \
    _increment_exp2zero_histogram(map, key, increment, max_bucket, increment_map)

#define increment_exp2zero_histogram_nosync(map, key, increment, max_bucket)                                           \
    _increment_exp2zero_histogram(map, key, increment, max_bucket, increment_map_nosync)
