#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf_helpers.h"

#ifndef __section
#define __section(x) __attribute__((section(x), used))
#endif

#define DEBUG 1


// bpf_trace_printk() is a helper function to print debug messages to path /sys/kernel/debug/tracing/trace_pipe
#ifdef DEBUG
#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })
#endif


struct ipv6hdr
{
    // __u8 ihl : 4;
    __u32 top;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u64 saddr1;
    __u64 saddr2;
    __u64 daddr1;
    __u64 daddr2;
    __u16 eh;
};

__section("classifier") int cls_main(struct __sk_buff *skb)
{
    struct icmphdr *icmph, icmp6h = {0};
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct ethhdr eth_copy;
    struct iphdr *iph;
    struct ipv6hdr *ipv6_cast;

    // These checks are needed for verifier
    if (data + sizeof(*eth) > data_end)
    {
        bpf_debug("Check 1");
        return TC_ACT_OK;
    }

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    {
        bpf_debug("Check 2");
        return TC_ACT_OK;
    }

    // Drop IPv6 packets
    if (ntohs(eth->h_proto) == ETH_P_IPV6)
    {
        bpf_debug("Dropping IPv6 packet");
        return TC_ACT_SHOT;
    }

    // TODO: Drop IPv6 packets to a specific address

    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";