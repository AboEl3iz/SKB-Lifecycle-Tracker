# Isolated Network Testing Environment (`netns` + `veth`)

This directory contains automated scripts and traffic generation tools for testing `skb-tracer` across full kernel networking paths (NAPI, GRO, GSO, Qdisc, and Sockets).

Because the Linux Loopback (`lo`) interface bypasses most of the kernel driver, NAPI, GRO, and GSO paths, this test harness uses **two isolated Network Namespaces** (`ns_client` and `ns_server`) connected by a virtual Ethernet wire (`veth_client` <-> `veth_server`).

---

## Network Architecture

```text
+------------------------+                     +------------------------+
| Namespace: ns_client   |                     | Namespace: ns_server   |
| IP: 10.0.0.1/24        |                     | IP: 10.0.0.2/24        |
|                        |                     |                        |
|     [ veth_client ]    |                     |     [ veth_server ]    |
+-----------│------------+                     +-----------▲------------+
            │                                              │
            └────────────── Kernel Virtual Wire ───────────┘
                       (Full Stack Traversal)
```

---

## Quick Start

### 1. Terminal 1: Run `skb-tracer`

```bash
# Recommended: Run directly inside ns_server attached to veth_server:
make run-server
# (which executes: sudo ip netns exec ns_server ./target/debug/skb-tracer -i veth_server)

# Or trace system-wide (all interfaces across all namespaces):
make run

# Or filter from the host by specific test port:
sudo ./target/debug/skb-tracer --port 5201
```

### 2. Terminal 2: Run Mutation Scenarios
```bash
# Setup the isolated network environment
make env-setup

# Option A: Run all 5 scenarios automatically
make test-all

# Option B: Run individual scenarios:
make test-gso       # Scenario 1: Force GSO Segmentation (skb_gso_segment)
make test-coalesce  # Scenario 2: Force TCP Coalesce (tcp_try_coalesce)
make test-gro       # Scenario 3: Force GRO Aggregation (skb_gro_receive)
make test-drops     # Scenario 4: Force Drops via Netfilter & tc netem
make test-flood     # Scenario 5: Maximum throughput UDP flood

# Clean up namespaces when finished
make env-teardown
```

---

## Scenarios Explained

| Scenario | Command | Mechanism | Expected eBPF Event |
| :--- | :--- | :--- | :--- |
| **1. GSO Segmentation** | `make test-gso` | Disables TSO/GSO with `ethtool -K veth_client tso off gso off` and sends 64KB TCP buffers. | `SKB_OP_GSO_SEGMENT` branching 64KB SKB into ~1448B child SKBs. |
| **2. TCP Coalescing** | `make test-coalesce` | Disables client offloads (`MTU 1500`), runs `slow_server` (100ms read delay), and blasts data to accumulate in socket queue. Traced via `fexit/tcp_queue_rcv`. | `SKB_OP_TCP_COALESCE` with incoming SKBs merged into parent socket queue tail. |
| **3. GRO Aggregation** | `make test-gro` | Forces client to send 1500-byte wire packets (`tso/gso/gro off`), enabling `veth_server` GRO (`gro_flush_timeout 20000`). | `SKB_OP_GRO_MERGE` with `nr_frags` increasing on the master SKB. |
| **4. Packet Drops** | `make test-drops` | Drops traffic via iptables (`-j DROP`) and tc netem (`netem drop 50%`). | `SKB_OP_DROP` with `SKB_DROP_REASON_NETFILTER_DROP` and `SKB_DROP_REASON_QDISC_DROP`. |
| **5. Throughput Stress** | `make test-flood` | Floods high-rate UDP datagrams to benchmark ring buffer throughput. | High throughput event streaming without ring buffer overflow. |

---

## Technical Implementation Details

### 1. Forcing Wire Packets to Trigger GRO & Coalescing
When testing over `veth` interfaces with standard settings, the Linux TCP stack uses GSO to pass 64KB contiguous memory blocks without segmenting. When the receiver gets already-giant buffers:
- GRO is bypassed because packets are already at maximum size.
- Socket buffers don't coalesce because there are few, large packets rather than a stream of contiguous segments.

By disabling client offloads (`ethtool -K veth_client tso off gso off gro off`) and enforcing `MTU 1500`, the kernel client is forced to slice data into 1500-byte wire packets. When `veth_server` receives the rapid sequence of 1500-byte packets, NAPI GRO aggregates them, and the socket receive queue merges them.

### 2. Solving `tcp_try_coalesce` Inlining (`fexit/tcp_queue_rcv`)
In modern kernels, `tcp_try_coalesce` is marked `static` and frequently inlined by the compiler into `tcp_queue_rcv()`, preventing `fentry` probes from attaching or firing. 

Furthermore, `tcp_try_coalesce` can be evaluated and return `false` (e.g. sequence gap or memory limit), which would produce false positives if probed at entry.

We solve this by hooking **`fexit/tcp_queue_rcv`**:
```c
SEC("fexit/tcp_queue_rcv")
int BPF_PROG(fexit_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb,
             bool *fragstolen, int ret)
```
- In `tcp_queue_rcv()`, the return value `ret` is `eaten`:
  - `ret == 1`: The incoming `skb` was successfully coalesced into `sk->sk_receive_queue.prev`.
  - `ret <= 0`: The `skb` was appended as a new queue entry (not coalesced).
- Hooking `fexit/tcp_queue_rcv` guarantees that we only emit `SKB_OP_TCP_COALESCE` when coalescing actually succeeds, and works reliably regardless of whether `tcp_try_coalesce` was inlined.
