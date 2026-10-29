# skb-tracer

Production-grade eBPF SKB Lifecycle and Mutation Tracker for Linux.

`skb-tracer` is a low-overhead, zero-copy kernel networking telemetry tool designed for SREs, network engineers, and Linux kernel developers. It tracks the complete lifecycle of Linux socket buffers (`struct sk_buff`), from allocation to socket consumption or drop, capturing complex in-kernel mutations such as Generic Receive Offload (GRO) merging, TCP socket coalescing, Generic Segmentation Offload (GSO) software splitting, and headroom expansions.

---

## Key Capabilities

- **Complete SKB Lifecycle Tracking:**
  - Allocation birth tracking via `fexit/__alloc_skb`.
  - Termination tracking via tracepoints `skb:consume_skb` and `skb:kfree_skb`.
  - Accurate calculation of packet lifespan latency:
    $$\text{Latency} = \text{Timestamp}_{\text{terminal}} - \text{Timestamp}_{\text{alloc}}$$
- **Mutation & Aggregation Visibility:**
  - **GRO Merge (`skb_gro_receive`):** Detects hardware and software NAPI packet aggregation into fragmented super-packets.
  - **TCP Coalescing (`tcp_queue_rcv`):** Tracks absorption of incoming packets into socket receive queue tails with full Use-After-Free (UAF) safety.
  - **GSO Segmentation (`__skb_gso_segment`):** Identifies CPU-intensive software segmentation when NIC offloads (TSO) are missing or disabled.
  - **Headroom Expansion (`pskb_expand_head`):** Exposes micro-latencies caused by buffer reallocations in overlay networks (VXLAN, Geneve, Calico, Cilium).
- **5-Tuple Flow Identification:**
  - Parses IPv4 source and destination addresses, transport protocol (TCP/UDP), and source/destination ports directly in BPF.
  - Identifies which connection or service is impacted whenever drops or mutations occur.
- **Drop Reason Attribution:**
  - Decodes kernel drop reason enums (e.g. `NETFILTER_DROP`, `NO_SOCKET`, `TCP_CSUM`, `PKT_TOO_SMALL`) via CO-RE.
- **Latency Distribution Profile:**
  - Calculates p50, p95, p99, average, minimum, and maximum lifespan latencies in microseconds.
- **Interactive Terminal UI (TUI):**
  - High-performance dashboard powered by `ratatui` with 10 Hz refresh, KPI rate cards, latency histograms, and live scrolling event stream.
- **Production Performance Guardrails:**
  - 16 MB kernel ring buffer with Per-CPU overflow loss tracking (`ringbuf_drops`).
  - Active LRU timer eviction preventing memory leaks under high packet volume.
  - Configurable sampling rate for normal consume events to eliminate standard output locking overhead.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------------------+
|                                  KERNEL SPACE                                     |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ alloc_skb ] ────► fexit:__alloc_skb (SKB_OP_ALLOC)                             |
|         │                                                                         |
|         ▼                                                                         |
|  [ Ingress / NAPI ] ─► fentry:skb_gro_receive (SKB_OP_GRO_MERGE)                  |
|         │                                                                         |
|         ▼                                                                         |
|  [ Routing / Overlay ] ─► fentry:pskb_expand_head (SKB_OP_EXPAND_HEAD)            |
|         │                                                                         |
|         ▼                                                                         |
|  [ Egress / Qdisc ] ─► fentry:__skb_gso_segment (SKB_OP_GSO_SEGMENT)              |
|         │                                                                         |
|         ▼                                                                         |
|  [ TCP Socket Queue ] ─► fentry/fexit:tcp_queue_rcv (SKB_OP_TCP_COALESCE)         |
|         │                                                                         |
|         ├──► Consumed ──► tracepoint:skb:consume_skb (SKB_OP_CONSUME)             |
|         └──► Dropped  ──► tracepoint:skb:kfree_skb (SKB_OP_DROP + reason)         |
|                                                                                   |
|                                         │                                         |
|                                         ▼                                         |
|                       16 MB Zero-Copy BPF Ring Buffer                             |
|                   (Plus Per-CPU Map for Overflow Monitoring)                      |
+-----------------------------------------------------------------------------------+
                                          │
                                          │ Userspace Polling (epoll / libbpf-rs)
                                          ▼
+-----------------------------------------------------------------------------------+
|                                USER SPACE (RUST)                                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ RingBufferConsumer ] ──► Crossbeam Channel ──► [ SkbLifespanEngine (DAG) ]     |
|                                                            │                      |
|                                                            ├── Generational SLAB  |
|                                                            │   Address Tracker    |
|                                                            ├── Active 500ms LRU   |
|                                                            │   Eviction Timer     |
|                                                            └── Latency Calculator |
|                                                                                   |
|                                         │                                         |
|               ┌─────────────────────────┼─────────────────────────┐               |
|               ▼                         ▼                         ▼               |
|      Interactive TUI             CLI Table Output            JSON Stream          |
|      (10 Hz ratatui)             (Sampled / Formatted)       (ndjson for logging) |
+-----------------------------------------------------------------------------------+
```

---

## System Requirements

- **Linux Kernel:** 5.8 or higher recommended (requires `CONFIG_DEBUG_INFO_BTF=y` and BPF ring buffer support).
- **Architecture:** x86_64, aarch64.
- **Privileges:** Root (`sudo`) or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`.
- **Build Dependencies:**
  - Rust 1.75+ (Cargo)
  - Clang / LLVM (supporting `-target bpf`)
  - `bpftool`
  - `libelf` and `zlib`

---

## Building

### Standard Build (Debug)
```bash
cargo build
```

### Production Release Build
```bash
cargo build --release
```
The optimized executable will be located at `./target/release/skb-tracer`.

---

## Usage and CLI Options

```text
Usage: skb-tracer [OPTIONS]

Options:
  -p, --port <PORT>                Target port to trace (0 = all ports) [default: 0]
  -i, --iface <IFACE>              Target network interface name (e.g. eth0, wlan0)
      --netns <NETNS>              Target network namespace inode (0 = all) [default: 0]
      --json                       Output events as newline-delimited JSON
  -s, --sample-rate <SAMPLE_RATE>  Sample rate: print 1 out of every N normal Consume events [default: 1]
      --summary-only               Suppress live event stream; display only summary upon exit
      --tui                        Interactive Terminal UI (TUI) dashboard with 10 Hz live metrics
  -v, --verbose                    Verbose debug logging
  -h, --help                       Print help
  -V, --version                    Print version
```

---

## Operational Modes

### 1. Interactive Terminal UI (TUI) Mode

Launches a full-screen, 10 Hz refresh dashboard providing real-time throughput metrics, drop counters, latency histograms, and a live scrolling event table:

```bash
sudo ./target/debug/skb-tracer --tui
```

Filter by interface or port:
```bash
sudo ./target/debug/skb-tracer -i eth0 -p 443 --tui
```

Keyboard Controls:
- `q` or `Ctrl+C`: Exit cleanly and restore terminal.
- `c`: Clear live event table.

### 2. High-Performance Filtered Tracing

Trace traffic exclusively on port 443 with sampled stdout printing (prints 1 out of every 50 normal consumes, while always printing all mutations and drops):

```bash
sudo ./target/debug/skb-tracer -p 443 -s 50
```

### 3. Pure Benchmarking Mode (Zero I/O Overhead)

Runs at line rate without writing events to stdout. Updates counters internally and prints a complete summary upon exit:

```bash
sudo ./target/debug/skb-tracer -i eth0 --summary-only
```

### 4. Machine-Readable JSON Streaming

Emits newline-delimited JSON for integration with Vector, Fluentd, Grafana Loki, or custom analysis scripts:

```bash
sudo ./target/debug/skb-tracer -p 8080 --json
```

---

## Example Outputs

### CLI Stream Output
```text
TIMESTAMP    OP             FLOW (SRC -> DST)              SKB_ADDR           LEN      FRAGS    TRUESIZE   DETAIL            
--------------------------------------------------------------------------------------------------------------------------------
1730198.102  GRO_MERGE      10.0.0.1:45322 -> 10.0.0.2:80  0xffff888102a3b000 1448     1        2048       absorbed into parent
1730198.103  TCP_COALESCE   10.0.0.1:45322 -> 10.0.0.2:80  0xffff888102a3b100 1448     0        1024       absorbed into socket queue
1730198.104  CONSUME        10.0.0.1:45322 -> 10.0.0.2:80  0xffff888102a3b000 2896     1        3072       delivered/consumed
1730198.150  DROP           10.0.0.1:58432 -> 10.0.0.2:99  0xffff888103c84000 64       0        1024       reason=NETFILTER_DROP
```

### Session Summary Report
```text
================================================================
SKB Lifecycle Tracker — Session Summary
================================================================
Total Events Processed:   84520
  - Allocations:          12400
  - Consumed SKBs:        71800
  - Dropped SKBs:         150
  - GRO Merges:           82
  - TCP Coalesces:        74
  - GSO Segments:         14
  - Headroom Expansions:  0
Ring Buffer Drops (Lost): 0
Average SKB Truesize:     1842 bytes
Frags (0 / 1-4 / 5+):     72300 / 12150 / 70

Packet Lifespan Latency Profile (Samples: 12400):
  - p50:                  16 µs
  - p95:                  38 µs
  - p99:                  54 µs
  - Average:              19 µs
  - Min / Max:            6 µs / 84 µs

Drop Reasons Breakdown:
  - NETFILTER_DROP: 140
  - NO_SOCKET: 10
================================================================
```

---

## Technical Implementations and Guarantees

### 1. In-Kernel L4 Port Filtering & Flow Extraction
In early kernel paths or socket delivery, `skb->transport_header` can be unset or equal to `network_header`. The BPF filter in `skb_filter.h` implements a two-stage extraction:
1. **Packet Header Parsing:** Decodes IPv4 header length (`ihl * 4`) to compute the exact transport header offset, reading source and destination ports for both TCP and UDP.
2. **Socket Context Fallback:** If packet headers are stripped or uninitialized (e.g. socket queue absorption in `tcp_queue_rcv`), it falls back to `struct sock_common` (`skc_num` and `skc_dport`).
3. **Target Port Check:** If `--port` is specified, packets are discarded in BPF unless source or destination port matches the target.

### 2. Use-After-Free Prevention in TCP Coalescing
When `tcp_queue_rcv()` returns `ret == 1`, the incoming SKB is eaten into the tail and freed via `kfree_skb_partial()`. Accessing `skb` in `fexit` creates a kernel Use-After-Free risk.

`skb-tracer` eliminates this by utilizing an inflight metadata hash map:
- In `fentry/tcp_queue_rcv`: Extracts SKB metadata and target queue tail address while memory is valid, keyed by `tid = bpf_get_current_pid_tgid()`.
- In `fexit/tcp_queue_rcv`: If `ret == 1`, emits the event using the captured metadata without touching the freed `skb`. Deletes the map entry immediately.

### 3. Active Memory Management
To prevent unbounded memory consumption under continuous 30,000+ packets/second traffic:
- **Timer-Driven Eviction:** LRU eviction runs on an active 500 ms timer (`Instant::elapsed() >= 500ms`) both inside the event loop and on timeout.
- **Generational GC:** When `address_generations` exceeds 65,536 entries, retired addresses not present in `active_skbs` are pruned.

### 4. Ring Buffer Overflow Protection
When the 16 MB ring buffer fills under extreme load, `bpf_ringbuf_reserve()` returns null. Rather than silently dropping events, `skb-tracer` atomically increments a `BPF_MAP_TYPE_PERCPU_ARRAY` counter (`ringbuf_drops`), which is polled and displayed in both the TUI and final summary.

---

## Testing Environment Harness

Because the Linux Loopback (`lo`) interface bypasses driver NAPI, GRO, and GSO paths, the repository includes an automated testing environment using **two isolated Network Namespaces** (`ns_client` <-> `ns_server`) connected by a virtual Ethernet wire (`veth_client` <-> `veth_server`).

### Setup Testing Environment
```bash
make env-setup
```

### Run All 5 Mutation Scenarios
```bash
make test-all
```

### Individual Scenarios
| Target | Scenario | Kernel Path Exercised |
| :--- | :--- | :--- |
| `make test-gso` | GSO Software Segmentation | Sends 64KB TCP super-packets with client offloads disabled |
| `make test-coalesce` | TCP Queue Coalescing | Runs slow reader server (100ms delay) to force queue accumulation |
| `make test-gro` | GRO Ingress Merging | Sends wire-rate 1500-byte packets to trigger receiver NAPI aggregation |
| `make test-drops` | Packet Drops & Reasons | Injects Netfilter drop rules and tc netem drop rate |
| `make test-flood` | Stress & Ring Buffer Load | Pushes 50,000 UDP datagrams to verify zero-loss buffer performance |

### Teardown Testing Environment
```bash
make env-teardown
```

---

## Repository Structure

```text
.
├── Cargo.toml                  # Rust dependencies (libbpf-rs, ratatui, clap, etc.)
├── Makefile                    # Build, test, and environment automation targets
├── TESTING.md                  # Deep dive on network namespace test scenarios
├── build.rs                    # Compiles BPF C code and generates Rust skeleton
├── scripts/
│   ├── netns_setup.sh          # Creates ns_client & ns_server with veth pair
│   ├── netns_teardown.sh       # Deletes namespaces and interfaces
│   ├── run_all_tests.sh        # Runs all 5 mutation scenarios sequentially
│   ├── test_coalesce.sh        # Coalesce test scenario
│   ├── test_drops.sh           # Packet drop test scenario
│   ├── test_flood.sh           # UDP flood throughput scenario
│   ├── test_gro.sh             # GRO aggregation test scenario
│   ├── test_gso.sh             # GSO software segmentation scenario
│   └── traffic_generator.py    # Python raw socket and traffic generation engine
└── src/
    ├── main.rs                 # CLI entry point, event loop, and summary reporting
    ├── lib.rs                  # Module exports
    ├── cli.rs                  # Command line definitions
    ├── compat.rs               # Kernel version parsing and BTF checks
    ├── consumer.rs             # Multi-threaded BPF ring buffer consumer
    ├── filter.rs               # Interface resolution and BPF filter configuration
    ├── stats.rs                # Aggregated counters, rolling rates, and latency profile
    ├── tracker.rs              # DAG state machine and generational SLAB reuse engine
    ├── tui.rs                  # Interactive ratatui dashboard
    ├── types.rs                # 64-byte SkbLifecycleEvent and FilterConfig definitions
    └── bpf/
        ├── skb_tracer.bpf.c    # Main eBPF program (probes, tracepoints, maps)
        ├── skb_event.h         # C event structure definitions
        ├── skb_filter.h        # In-kernel L4 port and netns filter logic
        └── vmlinux.h           # Kernel BTF type definitions
```

---

## License

Licensed under either of:
- GPL-2.0-only
- BSD-2-Clause / BSD-3-Clause
