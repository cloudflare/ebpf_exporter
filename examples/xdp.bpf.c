#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IPV6 0x86DD
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806

struct tcp_udp_out
{
  u32 src_ip;
  u32 dst_ip;
  u32 src_port;
  u32 dst_port;
  u32 protocol;
};

struct icmp_out
{
  u32 src_ip;
  u32 dst_ip;
  u32 type;
  u32 code;
  u32 protocol;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct tcp_udp_out);
  __type(value, u64);
} xdp_tcp_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct tcp_udp_out);
  __type(value, u64);
} xdp_udp_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct icmp_out);
  __type(value, u64);
} xdp_icmp_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, u32);
  __type(value, u64);
} xdp_total_packets_map SEC(".maps");

SEC("xdp/enp8s0,lo")
int xdp_trace(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = (struct ethhdr *)(data);
  if (eth + 1 > (struct ethhdr *)data_end)
    return XDP_PASS;
  u32 c = 0;
  increment_map(&xdp_total_packets_map, &c, 1);
  if (eth->h_proto == bpf_htons(ETH_P_IP))
  {
    struct iphdr *iph = data + sizeof(*eth);
    if (iph + 1 > (struct iphdr *)data_end)
      return XDP_PASS;
    if (iph->protocol == IPPROTO_UDP)
    {
      struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);
      if (udph + 1 > (struct udphdr *)data_end)
        return XDP_PASS;
      struct tcp_udp_out output = {
          .src_ip = iph->saddr,
          .dst_ip = iph->daddr,
          .src_port = bpf_ntohs(udph->source),
          .dst_port = bpf_ntohs(udph->dest),
          .protocol = IPPROTO_UDP,
      };
      increment_map(&xdp_udp_map, &output, 1);
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
      struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
      if (tcph + 1 > (struct tcphdr *)data_end)
        return XDP_PASS;
      struct tcp_udp_out output = {
          .src_ip = iph->saddr,
          .dst_ip = iph->daddr,
          .src_port = bpf_ntohs(tcph->source),
          .dst_port = bpf_ntohs(tcph->dest),
          .protocol = IPPROTO_TCP,
      };
      increment_map(&xdp_tcp_map, &output, 1);
    }
    else if (iph->protocol == IPPROTO_ICMP)
    {
      struct icmphdr *icmph = data + sizeof(*eth) + sizeof(*iph);
      if (icmph + 1 > (struct icmphdr *)data_end)
        return XDP_PASS;
      struct icmp_out output = {
          .src_ip = iph->saddr,
          .dst_ip = iph->daddr,
          .type = icmph->type,
          .code = icmph->code,
          .protocol = IPPROTO_ICMP,
      };
      increment_map(&xdp_icmp_map, &output, 1);
    }
  }
  return XDP_PASS;
}