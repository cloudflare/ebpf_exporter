struct span_parent_t {
    u64 trace_id_hi;
    u64 trace_id_lo;
    u64 span_id;
    u64 example_userspace_tag;
};

struct span_base_t {
    struct span_parent_t parent;
    u64 span_id;
    u64 span_monotonic_timestamp_ns;
    u64 span_duration_ns;
};

static inline void fill_span_base(struct span_base_t *span, struct span_parent_t *parent)
{
    span->parent = *parent;
    span->span_monotonic_timestamp_ns = bpf_ktime_get_ns();
    span->span_duration_ns = 0;
}

#define submit_span(map, type, parent, fill)                                                                           \
    type *span = bpf_ringbuf_reserve(map, sizeof(type), 0);                                                            \
    if (!span) {                                                                                                       \
        return 0;                                                                                                      \
    }                                                                                                                  \
                                                                                                                       \
    fill_span_base(&span->span_base, parent);                                                                          \
                                                                                                                       \
    fill;                                                                                                              \
                                                                                                                       \
    bpf_ringbuf_submit(span, 0);
