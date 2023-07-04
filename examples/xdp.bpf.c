#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.bpf.h"

#define ETH_P_IPV6 0x86DD
#define ETH_P_IP 0x0800

struct packet_key_t {
    u16 eth_type;
    u16 proto;
    u16 port;
};

struct hdr_cursor {
    void *pos;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct packet_key_t);
    __type(value, u64);
} xdp_incoming_packets_total SEC(".maps");

// Primitive header extraction macros. See xdp-tutorial repo for more robust parsers:
// * https://github.com/xdp-project/xdp-tutorial/blob/master/common/parsing_helpers.h
#define parse_args struct hdr_cursor *cursor, void *data_end, struct
#define parse_header(type)                                                                                             \
    static bool parse_##type(parse_args type **hdr)                                                                    \
    {                                                                                                                  \
        size_t offset = sizeof(**hdr);                                                                                 \
                                                                                                                       \
        if (cursor->pos + offset > data_end) {                                                                         \
            return false;                                                                                              \
        }                                                                                                              \
                                                                                                                       \
        *hdr = cursor->pos;                                                                                            \
        cursor->pos += offset;                                                                                         \
                                                                                                                       \
        return true;                                                                                                   \
    }

parse_header(ethhdr);
parse_header(iphdr);
parse_header(ipv6hdr);
parse_header(tcphdr);
parse_header(udphdr);

static int xdp_trace(struct xdp_md *ctx)
{
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct packet_key_t key = {};
    struct hdr_cursor cursor = { .pos = data };
    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct ipv6hdr *ipv6_hdr;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;

    if (!parse_ethhdr(&cursor, data_end, &eth_hdr)) {
        return XDP_PASS;
    }

    key.eth_type = bpf_ntohs(eth_hdr->h_proto);

    switch (eth_hdr->h_proto) {
    case bpf_htons(ETH_P_IP):
        if (!parse_iphdr(&cursor, data_end, &ip_hdr)) {
            return XDP_PASS;
        }

        key.proto = ip_hdr->protocol;
        break;
    case bpf_htons(ETH_P_IPV6):
        if (!parse_ipv6hdr(&cursor, data_end, &ipv6_hdr)) {
            return XDP_PASS;
        }

        key.proto = ipv6_hdr->nexthdr;
        break;
    }

    switch (key.proto) {
    case IPPROTO_TCP:
        if (!parse_tcphdr(&cursor, data_end, &tcp_hdr)) {
            return XDP_PASS;
        }

        key.port = bpf_ntohs(tcp_hdr->dest);
        break;
    case IPPROTO_UDP:
        if (!parse_udphdr(&cursor, data_end, &udp_hdr)) {
            return XDP_PASS;
        }

        key.port = bpf_ntohs(udp_hdr->dest);
        break;
    }

    // Skip ephemeral port range to keep metrics tidy
    if (key.port >= 32768) {
        return XDP_PASS;
    }

    increment_map(&xdp_incoming_packets_total, &key, 1);

    return XDP_PASS;
}

SEC("xdp/lo")
int trace_lo(struct xdp_md *ctx)
{
    return xdp_trace(ctx);
}

char LICENSE[] SEC("license") = "GPL";
