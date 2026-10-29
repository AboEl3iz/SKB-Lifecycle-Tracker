// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "skb_event.h"
#include "skb_filter.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 16MB Ring Buffer for high-throughput zero-copy event transport */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

/* Filter configuration map populated from user-space */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} config_map SEC(".maps");

/* Per-CPU Array Map for ring buffer overflow monitoring */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

/* Hash map for storing TCP coalesce metadata between fentry and fexit (UAF prevention) */
struct skb_meta_storage {
    struct skb_lifecycle_event event;
    __u64 tail_skb_addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct skb_meta_storage);
} tcp_coalesce_inflight SEC(".maps");

static __always_inline void inc_ringbuf_drop(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&ringbuf_drops, &key);
    if (cnt)
        (*cnt)++;
}

/* Safely decode non-linear metadata from skb_shared_info */
static __always_inline void
read_shinfo(struct sk_buff *skb, struct skb_lifecycle_event *e)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    unsigned int end    = BPF_CORE_READ(skb, end);
    if (!head)
        return;

    /* Reconstruct skb_shinfo(skb) pointer: head + end */
    struct skb_shared_info *shinfo = (struct skb_shared_info *)(head + end);
    e->nr_frags = BPF_CORE_READ(shinfo, nr_frags);
    e->gso_size = BPF_CORE_READ(shinfo, gso_size);
    e->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
}

/* Helper to populate common SKB fields into an event */
static __always_inline void
populate_skb_common(struct sk_buff *skb, struct skb_lifecycle_event *e)
{
    e->timestamp_ns = bpf_ktime_get_ns();
    e->skb_addr = (__u64)skb;
    e->len = BPF_CORE_READ(skb, len);
    e->data_len = BPF_CORE_READ(skb, data_len);
    e->truesize = BPF_CORE_READ(skb, truesize);
    read_shinfo(skb, e);
    extract_skb_flow(skb, e);
}

/* =========================================================================
 * SKB Allocation: Lifespan origin probe
 * ========================================================================= */

SEC("fexit/__alloc_skb")
int BPF_PROG(fexit___alloc_skb, unsigned int size, gfp_t gfp_mask, int flags, int node, struct sk_buff *ret)
{
    if (!ret)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(ret, cfg))
        return 0;

    struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_ringbuf_drop();
        return 0;
    }

    populate_skb_common(ret, e);
    e->peer_skb_addr = 0;
    e->drop_reason = 0;
    e->op = SKB_OP_ALLOC;
    for (int i = 0; i < 5; i++)
        e->pad[i] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* =========================================================================
 * Tracepoints: Lifecycle endpoints (Consume & Drop)
 * ========================================================================= */

SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(skb, cfg))
        return 0;

    struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_ringbuf_drop();
        return 0;
    }

    populate_skb_common(skb, e);
    e->peer_skb_addr = 0;
    e->op = SKB_OP_DROP;

    /* Drop reason with CO-RE fallback for older kernels */
    if (bpf_core_field_exists(ctx->reason)) {
        e->drop_reason = ctx->reason;
    } else {
        e->drop_reason = 0;
    }

    for (int i = 0; i < 5; i++)
        e->pad[i] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/skb/consume_skb")
int trace_consume_skb(struct trace_event_raw_consume_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(skb, cfg))
        return 0;

    struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_ringbuf_drop();
        return 0;
    }

    populate_skb_common(skb, e);
    e->peer_skb_addr = 0;
    e->drop_reason = 0;
    e->op = SKB_OP_CONSUME;
    for (int i = 0; i < 5; i++)
        e->pad[i] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* =========================================================================
 * fentry/fexit: Mutations (GRO merge, TCP coalesce, GSO, Headroom Expansion)
 * ========================================================================= */

SEC("fentry/skb_gro_receive")
int BPF_PROG(fentry_skb_gro_receive, struct sk_buff *p, struct sk_buff *skb)
{
    if (!p || !skb)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(p, cfg) && !should_trace_skb(skb, cfg))
        return 0;

    struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_ringbuf_drop();
        return 0;
    }

    /* skb is being merged into parent p */
    populate_skb_common(skb, e);
    e->peer_skb_addr = (__u64)p;
    e->drop_reason = 0;
    e->op = SKB_OP_GRO_MERGE;
    for (int i = 0; i < 5; i++)
        e->pad[i] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* UAF-Safe TCP Coalesce Tracking:
 * Capture skb and tail metadata in fentry BEFORE tcp_queue_rcv potentially eats/frees skb.
 * In fexit, if ret == 1, emit event from stored metadata without accessing freed skb memory.
 */
SEC("fentry/tcp_queue_rcv")
int BPF_PROG(fentry_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb, bool *fragstolen)
{
    if (!sk || !skb)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(skb, cfg))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct skb_meta_storage meta = {};
    populate_skb_common(skb, &meta.event);

    struct sk_buff *tail = BPF_CORE_READ(sk, sk_receive_queue.prev);
    meta.tail_skb_addr = (__u64)tail;

    bpf_map_update_elem(&tcp_coalesce_inflight, &tid, &meta, BPF_ANY);
    return 0;
}

SEC("fexit/tcp_queue_rcv")
int BPF_PROG(fexit_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb,
             bool *fragstolen, int ret)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct skb_meta_storage *meta = bpf_map_lookup_elem(&tcp_coalesce_inflight, &tid);
    if (!meta)
        return 0;

    /* ret == 1 indicates skb was absorbed/coalesced into socket receive queue tail */
    if (ret == 1) {
        struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            *e = meta->event;
            e->timestamp_ns = bpf_ktime_get_ns();
            e->peer_skb_addr = meta->tail_skb_addr;
            e->drop_reason = 0;
            e->op = SKB_OP_TCP_COALESCE;
            for (int i = 0; i < 5; i++)
                e->pad[i] = 0;
            bpf_ringbuf_submit(e, 0);
        } else {
            inc_ringbuf_drop();
        }
    }

    bpf_map_delete_elem(&tcp_coalesce_inflight, &tid);
    return 0;
}

SEC("fentry/__skb_gso_segment")
int BPF_PROG(fentry___skb_gso_segment, struct sk_buff *skb, netdev_features_t features, bool tx_path)
{
    if (!skb)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(skb, cfg))
        return 0;

    struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_ringbuf_drop();
        return 0;
    }

    populate_skb_common(skb, e);
    e->peer_skb_addr = 0;
    e->drop_reason = 0;
    e->op = SKB_OP_GSO_SEGMENT;
    for (int i = 0; i < 5; i++)
        e->pad[i] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/pskb_expand_head")
int BPF_PROG(fentry_pskb_expand_head, struct sk_buff *skb, int nhead, int ntail, gfp_t gfp_mask)
{
    if (!skb)
        return 0;

    __u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_skb(skb, cfg))
        return 0;

    struct skb_lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        inc_ringbuf_drop();
        return 0;
    }

    populate_skb_common(skb, e);
    e->peer_skb_addr = 0;
    e->drop_reason = 0;
    e->op = SKB_OP_EXPAND_HEAD;
    for (int i = 0; i < 5; i++)
        e->pad[i] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
