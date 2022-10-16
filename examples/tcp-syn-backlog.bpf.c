#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BUCKET_MULTIPLIER 50
#define BUCKET_COUNT 20

static u64 zero = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BUCKET_COUNT + 2);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
} buckets SEC(".maps");

static int do_count(u64 backlog)
{
	u64 *count, bucket = backlog / BUCKET_MULTIPLIER;

	count = bpf_map_lookup_elem(&buckets, &bucket);
	if (!count) {
		bpf_map_update_elem(&buckets, &bucket, &zero, BPF_NOEXIST);
		count = bpf_map_lookup_elem(&buckets, &bucket);
		if (!count) {
			goto cleanup;
		}
	}
	__sync_fetch_and_add(count, 1);

	bucket = BUCKET_COUNT + 1;

	count = bpf_map_lookup_elem(&buckets, &bucket);
	if (!count) {
		bpf_map_update_elem(&buckets, &bucket, &zero, BPF_NOEXIST);
		count = bpf_map_lookup_elem(&buckets, &bucket);
		if (!count) {
			goto cleanup;
		}
	}
	__sync_fetch_and_add(count, backlog);

cleanup:
	return 0;
}

SEC("kprobe/tcp_v4_syn_recv_sock")
int BPF_KPROBE(kprobe__tcp_v4_syn_recv_sock, struct sock *sk)
{
	return do_count(BPF_CORE_READ(sk, sk_ack_backlog) / 50);
}

SEC("kprobe/tcp_v6_syn_recv_sock")
int BPF_KPROBE(kprobe__tcp_v6_syn_recv_sock, struct sock *sk)
{
	return do_count(BPF_CORE_READ(sk, sk_ack_backlog) / 50);
}

char LICENSE[] SEC("license") = "GPL";
