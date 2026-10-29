use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::bounded;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::MapCore;
use skb_tracer::bpf::skel::SkbTracerSkelBuilder;
use skb_tracer::compat::check_system_requirements;
use skb_tracer::consumer::RingBufferConsumer;
use skb_tracer::filter::FilterManager;
use skb_tracer::stats::{AggregatedStats, RollingRateCalculator};
use skb_tracer::tracker::SkbLifespanEngine;
use skb_tracer::tui::{TuiRunner, TuiState};
use skb_tracer::types::{FilterConfig, SkbLifecycleEvent, SkbOp};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(
    name = "skb-tracer",
    author = "Karim",
    version = "0.1.0",
    about = "Production-grade eBPF SKB Lifecycle and Mutation Tracker"
)]
struct Cli {
    /// Target port to trace (0 = all ports)
    #[arg(short, long, default_value_t = 0)]
    port: u32,

    /// Target network interface name (e.g. eth0, wlan0)
    #[arg(short, long)]
    iface: Option<String>,

    /// Target network namespace inode (0 = all)
    #[arg(long, default_value_t = 0)]
    netns: u64,

    /// Output events as newline-delimited JSON
    #[arg(long)]
    json: bool,

    /// Sample rate: print 1 out of every N normal Consume events (default: 1 = 100%)
    #[arg(short = 's', long, default_value_t = 1)]
    sample_rate: u64,

    /// Suppress live event stream; display only summary upon exit
    #[arg(long)]
    summary_only: bool,

    /// Interactive Terminal UI (TUI) dashboard with 10 Hz live metrics
    #[arg(long)]
    tui: bool,

    /// Verbose debug logging
    #[arg(short, long)]
    verbose: bool,
}

fn read_ringbuf_drops(map: &libbpf_rs::Map) -> u64 {
    let key = 0u32.to_ne_bytes();
    if let Ok(Some(per_cpu_vals)) = map.lookup_percpu(&key, libbpf_rs::MapFlags::empty()) {
        per_cpu_vals
            .iter()
            .map(|slice| {
                if slice.len() >= 8 {
                    u64::from_ne_bytes(slice[0..8].try_into().unwrap_or([0; 8]))
                } else {
                    0
                }
            })
            .sum()
    } else {
        0
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.tui {
        let log_level = if cli.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        };
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_target(false)
            .init();
    }

    info!("Starting skb-tracer v0.1.0...");

    // 1. Verify system prerequisites and BTF
    let sys = check_system_requirements().context("System check failed")?;
    if !sys.is_root {
        info!("Note: If loading fails, re-run with sudo or check CAP_BPF / CAP_PERFMON.");
    }

    // 2. Open and load eBPF skeleton
    info!("Loading eBPF programs via CO-RE...");
    let skel_builder = SkbTracerSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("Failed to open BPF skeleton")?;
    let mut loaded_skel = open_skel.load().context("Failed to load BPF programs")?;

    // 3. Configure in-kernel filter
    let ifindex = if let Some(ref ifname) = cli.iface {
        FilterManager::ifname_to_index(ifname)?
    } else {
        0
    };

    let filter = FilterConfig {
        target_port: cli.port,
        target_ifindex: ifindex,
        target_netns_ino: cli.netns,
    };
    FilterManager::apply_to_bpf_map(&loaded_skel.maps.config_map, &filter)?;

    // 4. Attach tracepoints and fentry/fexit probes
    info!("Attaching eBPF probes...");
    loaded_skel
        .attach()
        .context("Failed to attach BPF probes")?;
    info!("All eBPF probes attached successfully!");

    // 5. Setup stop signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    ctrlc_handler(r)?;

    // 6. Setup Ring Buffer consumer thread
    let (tx, rx) = bounded::<SkbLifecycleEvent>(65536);
    let consumer = RingBufferConsumer::new(Arc::clone(&running));
    let consumer_handle = consumer.spawn(&loaded_skel.maps.events, tx)?;

    // 7. Initialize DAG Lifespan Engine, Stats, and TUI State
    let mut engine = SkbLifespanEngine::new(Duration::from_millis(500));
    let mut stats = AggregatedStats::new();
    let mut rates = RollingRateCalculator::new();

    let mut tui_runner = if cli.tui {
        Some(TuiRunner::init()?)
    } else {
        None
    };

    let mut tui_state = TuiState::new(filter, cli.iface.clone(), sys.kernel_release.clone());

    if !cli.json && !cli.summary_only && !cli.tui {
        println!(
            "\n{:<12} {:<14} {:<32} {:<18} {:<8} {:<8} {:<10} {:<18}",
            "TIMESTAMP", "OP", "FLOW (SRC -> DST)", "SKB_ADDR", "LEN", "FRAGS", "TRUESIZE", "DETAIL"
        );
        println!("{}", "-".repeat(128));
    }

    let mut last_evict = Instant::now();
    let mut last_rate_tick = Instant::now();
    let mut last_tui_render = Instant::now();
    let mut consume_display_counter = 0u64;

    // 8. Event loop
    while running.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(event) => {
                stats.record_event(&event);

                // Update DAG state machine
                let completed_node = engine.process_event(&event);
                if let Some(ref node) = completed_node {
                    if let Some(latency_us) = node.lifespan_us() {
                        stats.record_latency(latency_us);
                    }
                }

                // Periodic eviction (Fix 1.B: NEVER starve LRU eviction under heavy continuous load)
                if last_evict.elapsed() >= Duration::from_millis(500) {
                    let _ = engine.evict_lru();
                    last_evict = Instant::now();
                }

                if last_rate_tick.elapsed() >= Duration::from_millis(500) {
                    rates.tick(stats.total_events, stats.total_drops);
                    stats.ringbuf_overflow_drops = read_ringbuf_drops(&loaded_skel.maps.ringbuf_drops);
                    tui_state.kernel_ringbuf_drops = stats.ringbuf_overflow_drops;
                    tui_state.active_skbs_count = engine.active_skbs.len();
                    last_rate_tick = Instant::now();
                }

                if let Some(ref mut tui) = tui_runner {
                    tui_state.push_event(event);
                    if last_tui_render.elapsed() >= Duration::from_millis(100) {
                        tui.poll_input(Arc::clone(&running), &mut tui_state)?;
                        tui.draw(&tui_state, &stats, &rates)?;
                        last_tui_render = Instant::now();
                    }
                } else if cli.json {
                    println!("{}", serde_json::to_string(&event)?);
                    if let Some(ref node) = completed_node {
                        println!("{}", serde_json::to_string(node)?);
                    }
                } else if !cli.summary_only {
                    let is_mutation_or_drop = event.operation() != SkbOp::Consume;
                    let should_print = if is_mutation_or_drop {
                        true
                    } else {
                        consume_display_counter += 1;
                        cli.sample_rate <= 1 || (consume_display_counter % cli.sample_rate == 0)
                    };

                    if should_print {
                        let ts_sec = (event.timestamp_ns as f64) / 1_000_000_000.0;
                        let detail = match event.operation() {
                            SkbOp::Drop => format!("reason={}", event.drop_reason_str()),
                            SkbOp::GroMerge => "absorbed into parent".into(),
                            SkbOp::TcpCoalesce => "absorbed into socket queue".into(),
                            SkbOp::Consume => "delivered/consumed".into(),
                            SkbOp::GsoSegment => format!("gso_segs={}", event.gso_segs),
                            SkbOp::ExpandHead => "headroom expanded".into(),
                            SkbOp::Alloc => "allocated".into(),
                            _ => String::new(),
                        };

                        println!(
                            "{:<12.6} {:<14} {:<32} 0x{:<16x} {:<8} {:<8} {:<10} {:<18}",
                            ts_sec,
                            event.operation().to_string(),
                            event.flow_str(),
                            event.skb_addr,
                            event.len,
                            event.nr_frags,
                            event.truesize,
                            detail
                        );
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if last_evict.elapsed() >= Duration::from_millis(500) {
                    let _ = engine.evict_lru();
                    last_evict = Instant::now();
                }
                rates.tick(stats.total_events, stats.total_drops);
                stats.ringbuf_overflow_drops = read_ringbuf_drops(&loaded_skel.maps.ringbuf_drops);
                tui_state.kernel_ringbuf_drops = stats.ringbuf_overflow_drops;
                tui_state.active_skbs_count = engine.active_skbs.len();

                if let Some(ref mut tui) = tui_runner {
                    tui.poll_input(Arc::clone(&running), &mut tui_state)?;
                    if last_tui_render.elapsed() >= Duration::from_millis(100) {
                        tui.draw(&tui_state, &stats, &rates)?;
                        last_tui_render = Instant::now();
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Drop TUI to restore normal terminal state before summary
    drop(tui_runner);

    info!("Shutting down cleanly...");
    running.store(false, Ordering::Relaxed);
    let _ = consumer_handle.join();

    // Final read of ring buffer overflow drops
    stats.ringbuf_overflow_drops = read_ringbuf_drops(&loaded_skel.maps.ringbuf_drops);

    if !cli.json {
        println!("\n{}", "=".repeat(64));
        println!("SKB Lifecycle Tracker — Session Summary");
        println!("{}", "=".repeat(64));
        println!("Total Events Processed:   {}", stats.total_events);
        println!("  - Allocations:          {}", stats.total_allocs);
        println!("  - Consumed SKBs:        {}", stats.total_consumes);
        println!("  - Dropped SKBs:         {}", stats.total_drops);
        println!("  - GRO Merges:           {}", stats.total_gro_merges);
        println!("  - TCP Coalesces:        {}", stats.total_tcp_coalesces);
        println!("  - GSO Segments:         {}", stats.total_gso_segments);
        println!("  - Headroom Expansions:  {}", stats.total_expand_heads);
        println!("Ring Buffer Drops (Lost): {}", stats.ringbuf_overflow_drops);
        println!("Average SKB Truesize:     {} bytes", stats.average_truesize());
        println!(
            "Frags (0 / 1-4 / 5+):     {} / {} / {}",
            stats.frag_zero_count, stats.frag_one_to_four_count, stats.frag_five_plus_count
        );

        let (p50, p95, p99) = stats.latency.percentiles();
        println!("\nPacket Lifespan Latency Profile (Samples: {}):", stats.latency.count);
        println!("  - p50:                  {} µs", p50);
        println!("  - p95:                  {} µs", p95);
        println!("  - p99:                  {} µs", p99);
        println!("  - Average:              {} µs", stats.latency.average_us());
        println!(
            "  - Min / Max:            {} µs / {} µs",
            if stats.latency.min_us == u64::MAX { 0 } else { stats.latency.min_us },
            stats.latency.max_us
        );

        if !stats.drop_reasons.is_empty() {
            println!("\nDrop Reasons Breakdown:");
            for (reason, count) in &stats.drop_reasons {
                println!("  - {}: {}", reason, count);
            }
        }
        println!("{}", "=".repeat(64));
    }

    Ok(())
}

fn ctrlc_handler(running: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || {
        running.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C handler")?;
    Ok(())
}
