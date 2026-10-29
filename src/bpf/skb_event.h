#ifndef __SKB_EVENT_H
#define __SKB_EVENT_H

#if !defined(__VMLINUX_H__)
typedef unsigned long long __u64;
typedef unsigned int       __u32;
typedef unsigned short     __u16;
typedef unsigned char      __u8;
#endif

enum skb_op {
    SKB_OP_ALLOC        = 1,
    SKB_OP_GRO_MERGE    = 2,
    SKB_OP_TCP_COALESCE = 3,
    SKB_OP_GSO_SEGMENT  = 4,
    SKB_OP_EXPAND_HEAD  = 5,
    SKB_OP_CONSUME      = 6,
    SKB_OP_DROP         = 7,
};

struct skb_lifecycle_event {
    __u64 timestamp_ns;      // bpf_ktime_get_ns()
    __u64 skb_addr;          // Primary SKB pointer
    __u64 peer_skb_addr;     // Parent or Child pointer (for Merge/Split cases)
    __u32 len;               // skb->len
    __u32 data_len;          // skb->data_len
    __u32 truesize;          // skb->truesize
    __u32 drop_reason;       // enum skb_drop_reason for DROP events
    __u32 saddr;             // IPv4 Source Address (network byte order)
    __u32 daddr;             // IPv4 Destination Address (network byte order)
    __u16 sport;             // Source Port (host byte order)
    __u16 dport;             // Destination Port (host byte order)
    __u16 gso_size;          // From skb_shared_info
    __u16 gso_segs;          // From skb_shared_info
    __u8  nr_frags;          // From skb_shared_info
    __u8  op;                // enum skb_op
    __u8  protocol;          // IPPROTO_TCP (6), IPPROTO_UDP (17), etc.
    __u8  pad[5];            // Explicit padding to keep 8-byte alignment (total exactly 64 bytes)
};

#endif /* __SKB_EVENT_H */
