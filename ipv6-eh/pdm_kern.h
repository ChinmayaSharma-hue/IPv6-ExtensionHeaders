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