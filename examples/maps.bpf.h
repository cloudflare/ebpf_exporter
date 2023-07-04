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
