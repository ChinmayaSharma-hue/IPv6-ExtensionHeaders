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
    __u16 saddr[8];
    __u16 daddr[8];
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
    // if (ntohs(eth->h_proto) == ETH_P_IPV6)
    // {
    //     bpf_debug("Dropping IPv6 packet");
    //     return TC_ACT_SHOT;
    // }

    // Drop packets to 2001:19f0:5:3ce7:5400:04ff:fe31:1527
    // Splitting into two parts and writing as 64 bit hex number: 0x200119F0 00053CE7 & 0x540004FF FE311527
    // In reverse byte order 0x3CE7000519F02001 & 0x1527FE3104FF5400
    if (ntohs(eth->h_proto) == ETH_P_IPV6)
    {
        // ipv6_cast = (struct ipv6hdr *)(data + sizeof(*eth));
        struct ipv6hdr ipv6_cast;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ipv6_cast, sizeof(struct ipv6hdr));
        __u16 daddr[8] = {0x2001, 0x19F0, 0x0005, 0x3CE7, 0x5400, 0x04FF, 0xFE31, 0x1527};
        int same_addr = 1;
        for(int i = 0; i<8; i++){
            if(ntohs(ipv6_cast.daddr[i]) != daddr[i])same_addr=0;
        }
        if (same_addr)
        {
            bpf_debug("Dropping IPv6 packet");
            return TC_ACT_SHOT;
        }
    }


    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";