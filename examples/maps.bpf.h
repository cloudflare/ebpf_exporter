static int increment_map(void *map, void *key, u64 increment)
{
    u64 zero = 0, *count = bpf_map_lookup_elem(map, key);
    if (!count) {
        bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(map, key);
        if (!count) {
            return 0;
        }
    }

    __sync_fetch_and_add(count, increment);

    return *count;
}

// Arrays are always preallocated, so this only fails if the key is missing
#define read_array_ptr(map, key, into)                                                                                 \
    into = bpf_map_lookup_elem(map, key);                                                                              \
    if (!into) {                                                                                                       \
        return 0;                                                                                                      \
    }

#define _increment_histogram(map, key, increment, max_bucket)                                                          \
    if (key.bucket > max_bucket) {                                                                                     \
        key.bucket = max_bucket;                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    increment_map(map, &key, 1);                                                                                       \
                                                                                                                       \
    if (increment > 0) {                                                                                               \
        key.bucket = max_bucket + 1;                                                                                   \
        increment_map(map, &key, increment);                                                                           \
    }

#define increment_exp2_histogram(map, key, increment, max_bucket)                                                      \
    key.bucket = log2l(increment);                                                                                     \
                                                                                                                       \
    if (key.bucket > max_bucket) {                                                                                     \
        key.bucket = max_bucket;                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    _increment_histogram(map, key, increment, max_bucket);

#define increment_exp2zero_histogram(map, key, increment, max_bucket)                                                  \
    if (increment == 0) {                                                                                              \
        key.bucket = 0;                                                                                                \
    } else {                                                                                                           \
        key.bucket = log2l(increment) + 1;                                                                             \
    }                                                                                                                  \
                                                                                                                       \
    _increment_histogram(map, key, increment, max_bucket);
