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

#define default_action TC_ACT_SHOT

#define DEBUG 1

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
    __u32 top;
    __u16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u64 saddr1;
    __u64 saddr2;
    __u64 daddr1;
    __u64 daddr2;
};

    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |  Option Type  | Option Length |    ScaleDTLR  |     ScaleDTLS |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |   PSN This Packet             |  PSN Last Received            |
    //   |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |   Delta Time Last Received    |  Delta Time Last Sent         |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct ipv6_destopt_pdm
{
    __u8 type;      /* 0x0F */
    __u8 length;    /* 10 bytes */
    __u8 scaleDTLR; /* Scale Delta Time Last Recieved */
    __u8 scaleDTLS; /* Scale Delta Time Last Sent */
    __u16 PSNTP;    /* Packet Sequence Number This Packet */
    __u16 PSNLR;    /* Packet Sequence Number Last Received */
    __u16 DTLR;     /* Delta Time Last Received */
    __u16 DTLS;     /* Delta Time Last Sent */
    __u8 padn_opt;  /* PADN for Alignment: set to 1 */
    __u8 padn_len;  /* PADN for Alignment: set to 0; signifies 2 bytes of padding */
};



struct dest_opt_header
{
    __u8 nexthdr;
    __u8 hdrlen;
};

struct _5tuple
{
    __u64 saddr1;
    __u64 saddr2;
    __u64 daddr1;
    __u64 daddr2;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct pdm_flow_details
{
    __u16 PSNLS; /* Packet Sequence Number Last Sent */
    __u16 PSNLR; /* Packet Sequence Number Last Received */
    __u64 TLR;   /* Time Last Received */
    __u64 TLS;   /* Time Last Sent */
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct _5tuple);
    __type(value, struct pdm_flow_details);
    __uint(max_entries, 1024);
    __uint(pinning, 1);
} pdm_state_1 SEC(".maps");

static __always_inline long int log_2(long int x)
{
    long int length = 64;
    while (length > 0)
    {
        if (x & (1 << (length - 1)))
        {
            return length - 1;
        }
        length--;
    }
    return 0;
}

static __always_inline long int sdiv(long int x, long int y)
{
    bool xneg = x < 0;
    bool yneg = y < 0;

    uint64_t xdiv = xneg ? -x : x;
    uint64_t ydiv = yneg ? -y : y;
    uint32_t out = xdiv / ydiv;

    return xneg != yneg ? -out : out;
}

// pdm time delta scale function
static __always_inline void pdm_time_delta_scale(long int time_diff, u16 *delta, u8 *scale)
{
    int index = 0;
    long int base = time_diff;
    if (time_diff > 65535)
    {
        index = roundup(log_2(sdiv(base, 65535)), 1);
        base = base >> index;
    }
    *scale = index + 14;
    base *= 61035;
    if (base > 65535)
    {
        index = roundup(log_2(sdiv(base, 65535)), 1);
        base = base >> index;
    }
    *scale += index;
    *delta = base;
}


__section("pdm_ingress") int pdm_ingress_func(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;
    struct ipv6_destopt_pdm ingress_pdm_read;

    // Checking if eth headers are incomplete
    if (data + sizeof(*eth) > data_end)
    {
        bpf_debug("Eth headers incomplete");
        return default_action;
    }

    // Allowing IPV4 packets to passthrough without modification
    if (ntohs(eth->h_proto) != ETH_P_IPV6)
    {
        return TC_ACT_OK;
    }

    // Checking if IP headers are incomplete
    if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
    {
        bpf_debug("IP headers incomplete");
        return default_action;
    }

    // Deriving 5 tuple struct for identification of flow
    struct _5tuple key = {0};
    // Reading Source address into Destination address of 5tuple struct
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct ipv6hdr, saddr1), &key.daddr1, sizeof(key.daddr1) + sizeof(key.daddr2));
    // Reading Destination address into Source address of 5tuple struct
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct ipv6hdr, daddr1), &key.saddr1, sizeof(key.saddr1) + sizeof(key.saddr2));

    // bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(struct ipv6hdr) + sizeof(struct dest_opt_header) + sizeof(struct ipv6_destopt_pdm), &key.sport, sizeof(key.sport));
    // bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(struct ipv6hdr) + sizeof(struct dest_opt_header) + sizeof(struct ipv6_destopt_pdm) + sizeof(key.sport), &key.dport, sizeof(key.dport));
    
    bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(struct ipv6hdr), &key.protocol, sizeof(key.protocol)); // To Do: Find a helper function to get the protocol

    // Reading the PDM header
    bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(struct ipv6hdr) + sizeof(struct dest_opt_header), &ingress_pdm_read, sizeof(ingress_pdm_read));

    struct pdm_flow_details *pdm_flow_details_current = (struct pdm_flow_details *)bpf_map_lookup_elem(&pdm_state_1, &key);

    struct pdm_flow_details pdm_flow_details_update = {0};

    // TODO: Updating the BPF map with the new values
    //              --- your code here ---
    // 

    return TC_ACT_OK;
}









__section("pdm_egress") int pdm_egress_func(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;

    // TODO: Perform basic checks on the packet
    //              --- your code here ---
    // 

    __u8 nexthdr = 60; // Dest options

    bpf_skb_adjust_room(skb, sizeof(struct dest_opt_header) + sizeof(struct ipv6_destopt_pdm), BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET);

    // Set next header
    __u32 nexthdr_location = sizeof(*eth) + offsetof(struct ipv6hdr, nexthdr);
    __u8 old_nexthdr;
    bpf_skb_load_bytes(skb, nexthdr_location, &old_nexthdr, sizeof(old_nexthdr));

    // Load Payload Size and increment it by size of PDM extension header
    __u32 payload_location = sizeof(*eth) + offsetof(struct ipv6hdr, payload_len);
    __u16 payload_len;
    bpf_skb_load_bytes(skb, payload_location, &payload_len, sizeof(payload_len));
    payload_len = ntohs(payload_len);
    payload_len += sizeof(struct ipv6_destopt_pdm) + sizeof(struct dest_opt_header);
    payload_len = htons(payload_len);

    // Setting New Payload length
    // bpf_skb_store_bytes(skb, payload_location, &payload_len, sizeof(payload_len), BPF_F_RECOMPUTE_CSUM);

    // Setting nexthdr to 60
    bpf_skb_store_bytes(skb, nexthdr_location, &nexthdr, sizeof(nexthdr), BPF_F_RECOMPUTE_CSUM);

    // Setting Destination Options
    struct dest_opt_header dest_opt_header = {0};
    dest_opt_header.nexthdr = old_nexthdr; // Keep the old next header value
    dest_opt_header.hdrlen = 1;            // 16 Bytes

    // Deriving 5 tuple struct for flow identification
    struct _5tuple key = {0};
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct ipv6hdr, saddr1), &key.saddr1, sizeof(key.saddr1) + sizeof(key.saddr2));
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct ipv6hdr, daddr1), &key.daddr1, sizeof(key.daddr1) + sizeof(key.daddr2));

    // bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(struct ipv6hdr) + sizeof(struct dest_opt_header) + sizeof(struct ipv6_destopt_pdm), &key.sport, sizeof(key.sport));
    // bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(struct ipv6hdr) + sizeof(struct dest_opt_header) + sizeof(struct ipv6_destopt_pdm) + sizeof(key.sport), &key.dport, sizeof(key.dport));
    
    key.protocol = dest_opt_header.nexthdr; // To do: find a helper function to find the protocol

    struct pdm_flow_details *pdm_flow_details_current = (struct pdm_flow_details *)bpf_map_lookup_elem(&pdm_state_1, &key);

    struct pdm_flow_details pdm_flow_details_update = {0};

    if (pdm_flow_details_current == NULL)
    {
        // If flow doesnt exist, create a new flow
        struct pdm_flow_details pdm_flow_details_init = {0};
        pdm_flow_details_init.PSNLS = bpf_get_prandom_u32() >> 16;
        bpf_map_update_elem(&pdm_state_1, &key, &pdm_flow_details_init, BPF_NOEXIST);
        pdm_flow_details_current = &pdm_flow_details_init;
    }

    if (pdm_flow_details_current == NULL)
    {
        return default_action;
    }

    // Updating BPF map
    pdm_flow_details_update.PSNLS = pdm_flow_details_current->PSNLS + 1;
    pdm_flow_details_update.PSNLR = pdm_flow_details_current->PSNLR;
    pdm_flow_details_update.TLR = pdm_flow_details_current->TLR;
    pdm_flow_details_update.TLS = bpf_ktime_get_ns();
    bpf_map_update_elem(&pdm_state_1, &key, &pdm_flow_details_update, BPF_EXIST);

    // Defining PDM - RFC 8250
    struct ipv6_destopt_pdm pdm = {0};
    pdm.type = 0x0F;
    pdm.length = 10;
    pdm.padn_opt = 1;
    pdm.padn_len = 0;
    pdm.PSNTP = htons(pdm_flow_details_update.PSNLS);
    pdm.PSNLR = htons(pdm_flow_details_update.PSNLR);
    if (pdm_flow_details_update.TLR != 0)
    {
        pdm_time_delta_scale(pdm_flow_details_update.TLS - pdm_flow_details_update.TLR, &pdm.DTLR, &pdm.scaleDTLR);
        pdm.DTLR = htons(pdm.DTLR);
        pdm_time_delta_scale(pdm_flow_details_update.TLR - pdm_flow_details_current->TLS, &pdm.DTLS, &pdm.scaleDTLS); // Logic error, map is already updated and pointer is pointing to the updated map
        pdm.DTLS = htons(pdm.DTLS);
    }

    // TODO: Add PDM to the packet
    //     --- your code here ---
    // 

    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";