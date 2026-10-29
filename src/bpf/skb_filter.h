#ifndef __SKB_FILTER_H
#define __SKB_FILTER_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "skb_event.h"

struct filter_config {
    __u32 target_port;      // 0 = match all (host byte order)
    __u32 target_ifindex;   // 0 = match all
    __u64 target_netns_ino; // 0 = match all
};

/* Safely extract 5-tuple (IPv4 saddr, daddr, sport, dport, protocol) into event */
static __always_inline void
extract_skb_flow(struct sk_buff *skb, struct skb_lifecycle_event *e)
{
    e->saddr = 0;
    e->daddr = 0;
    e->sport = 0;
    e->dport = 0;
    e->protocol = 0;

    if (!skb)
        return;

    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 nh_off = BPF_CORE_READ(skb, network_header);

    // Attempt 1: Parse from packet network_header
    if (head && nh_off < 0x7fff) {
        unsigned char *ip_ptr = head + nh_off;
        __u8 ver_ihl = 0;
        if (bpf_probe_read_kernel(&ver_ihl, 1, ip_ptr) == 0) {
            __u8 ver = (ver_ihl >> 4) & 0x0f;
            if (ver == 4) {
                struct iphdr ip;
                if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_ptr) == 0) {
                    e->saddr = ip.saddr;
                    e->daddr = ip.daddr;
                    e->protocol = ip.protocol;

                    __u16 ihl = (ver_ihl & 0x0f) * 4;
                    if (ihl < 20)
                        ihl = 20;

                    __u16 th_off = BPF_CORE_READ(skb, transport_header);
                    unsigned char *l4_ptr = (th_off > nh_off && th_off < 0x7fff) ? (head + th_off) : (ip_ptr + ihl);

                    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
                        __be16 ports[2] = {0, 0};
                        if (bpf_probe_read_kernel(ports, sizeof(ports), l4_ptr) == 0) {
                            e->sport = bpf_ntohs(ports[0]);
                            e->dport = bpf_ntohs(ports[1]);
                        }
                    }
                    return;
                }
            }
        }
    }

    // Attempt 2: Fallback to socket context if network header not available
    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (sk) {
        short unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (family == 2 /* AF_INET */) {
            e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
            __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
            e->dport = bpf_ntohs(dport);
            e->protocol = BPF_CORE_READ(sk, sk_protocol);
        }
    }
}

/* Fast inline filter check. Returns true if packet matches configured filters. */
static __always_inline bool
should_trace_skb(struct sk_buff *skb, struct filter_config *cfg)
{
    if (!cfg)
        return true;

    // If no filters are set, trace everything
    if (cfg->target_port == 0 && cfg->target_ifindex == 0 && cfg->target_netns_ino == 0)
        return true;

    if (!skb)
        return false;

    // Check interface index if configured
    if (cfg->target_ifindex != 0) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);
        int ifindex = 0;
        if (dev) {
            ifindex = BPF_CORE_READ(dev, ifindex);
        } else {
            ifindex = BPF_CORE_READ(skb, skb_iif);
        }
        // If interface is known and does not match target, filter it out
        if (ifindex != 0 && (__u32)ifindex != cfg->target_ifindex)
            return false;
    }

    // Check network namespace inode if configured
    if (cfg->target_netns_ino != 0) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);
        struct net *net = NULL;
        if (dev) {
            net = BPF_CORE_READ(dev, nd_net.net);
        } else {
            struct sock *sk = BPF_CORE_READ(skb, sk);
            if (sk) {
                net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
            }
        }
        if (net) {
            __u32 inum = BPF_CORE_READ(net, ns.inum);
            if ((__u64)inum != cfg->target_netns_ino)
                return false;
        }
    }

    // Check L4 target port if configured (TCP or UDP, source or destination)
    if (cfg->target_port != 0) {
        __u16 sport = 0, dport = 0;
        bool found = false;

        unsigned char *head = BPF_CORE_READ(skb, head);
        __u16 nh_off = BPF_CORE_READ(skb, network_header);
        if (head && nh_off < 0x7fff) {
            unsigned char *ip_ptr = head + nh_off;
            __u8 ver_ihl = 0;
            if (bpf_probe_read_kernel(&ver_ihl, 1, ip_ptr) == 0 && ((ver_ihl >> 4) & 0x0f) == 4) {
                struct iphdr ip;
                if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_ptr) == 0) {
                    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
                        __u16 ihl = (ver_ihl & 0x0f) * 4;
                        if (ihl < 20)
                            ihl = 20;

                        __u16 th_off = BPF_CORE_READ(skb, transport_header);
                        unsigned char *l4_ptr = (th_off > nh_off && th_off < 0x7fff) ? (head + th_off) : (ip_ptr + ihl);
                        __be16 ports[2] = {0, 0};
                        if (bpf_probe_read_kernel(ports, sizeof(ports), l4_ptr) == 0) {
                            sport = bpf_ntohs(ports[0]);
                            dport = bpf_ntohs(ports[1]);
                            found = true;
                        }
                    }
                }
            }
        }

        // Socket fallback
        if (!found) {
            struct sock *sk = BPF_CORE_READ(skb, sk);
            if (sk) {
                short unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
                if (family == 2 /* AF_INET */) {
                    sport = BPF_CORE_READ(sk, __sk_common.skc_num);
                    __be16 dp = BPF_CORE_READ(sk, __sk_common.skc_dport);
                    dport = bpf_ntohs(dp);
                    found = true;
                }
            }
        }

        if (!found)
            return false;

        if (sport != cfg->target_port && dport != cfg->target_port)
            return false;
    }

    return true;
}

#endif /* __SKB_FILTER_H */
