use crate::stats::{AggregatedStats, RollingRateCalculator};
use crate::types::{FilterConfig, SkbLifecycleEvent, SkbOp};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::collections::VecDeque;
use std::io::{stdout, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct TuiState {
    pub start_time: Instant,
    pub filter: FilterConfig,
    pub ifname: Option<String>,
    pub kernel_release: String,
    pub events_log: VecDeque<SkbLifecycleEvent>,
    pub max_log_size: usize,
    pub active_skbs_count: usize,
    pub kernel_ringbuf_drops: u64,
}

impl TuiState {
    pub fn new(filter: FilterConfig, ifname: Option<String>, kernel_release: String) -> Self {
        Self {
            start_time: Instant::now(),
            filter,
            ifname,
            kernel_release,
            events_log: VecDeque::with_capacity(100),
            max_log_size: 100,
            active_skbs_count: 0,
            kernel_ringbuf_drops: 0,
        }
    }

    pub fn push_event(&mut self, event: SkbLifecycleEvent) {
        if self.events_log.len() >= self.max_log_size {
            self.events_log.pop_front();
        }
        self.events_log.push_back(event);
    }
}

pub struct TuiRunner {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TuiRunner {
    pub fn init() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn draw(
        &mut self,
        state: &TuiState,
        stats: &AggregatedStats,
        rates: &RollingRateCalculator,
    ) -> Result<()> {
        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),  // Header / Title
                    Constraint::Length(3),  // KPI Rate Cards
                    Constraint::Length(10), // Metrics & Latency split
                    Constraint::Min(8),     // Live Event Log
                    Constraint::Length(1),  // Footer / Keybindings
                ])
                .split(f.area());

            // 1. Header
            let uptime = state.start_time.elapsed().as_secs();
            let iface_str = state.ifname.as_deref().unwrap_or("ALL");
            let port_str = if state.filter.target_port == 0 {
                "ALL".to_string()
            } else {
                state.filter.target_port.to_string()
            };

            let header_text = vec![Line::from(vec![
                Span::styled(
                    " SKB LIFECYCLE TRACKER ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" | "),
                Span::styled("Kernel: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&state.kernel_release, Style::default().fg(Color::White)),
                Span::raw(" | "),
                Span::styled("Interface: ", Style::default().fg(Color::DarkGray)),
                Span::styled(iface_str, Style::default().fg(Color::Yellow)),
                Span::raw(" | "),
                Span::styled("Port: ", Style::default().fg(Color::DarkGray)),
                Span::styled(port_str, Style::default().fg(Color::Yellow)),
                Span::raw(" | "),
                Span::styled("Uptime: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}s", uptime), Style::default().fg(Color::Green)),
            ])];
            let header_p = Paragraph::new(header_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("System Status")
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(header_p, chunks[0]);

            // 2. Rates / KPI Cards
            let rate_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                    Constraint::Percentage(34),
                ])
                .split(chunks[1]);

            let pps_card = Paragraph::new(format!("{:.1} pkts/s", rates.packets_per_sec)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Event Throughput")
                    .border_style(Style::default().fg(Color::Green)),
            );
            f.render_widget(pps_card, rate_chunks[0]);

            let drop_color = if rates.drops_per_sec > 0.0 {
                Color::Red
            } else {
                Color::Green
            };
            let drop_card = Paragraph::new(format!("{:.1} drops/s", rates.drops_per_sec)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Drop Rate")
                    .border_style(Style::default().fg(drop_color)),
            );
            f.render_widget(drop_card, rate_chunks[1]);

            let ringbuf_color = if state.kernel_ringbuf_drops > 0 {
                Color::Red
            } else {
                Color::DarkGray
            };
            let ringbuf_card = Paragraph::new(format!(
                "{} dropped (Buffer: 16 MB)",
                state.kernel_ringbuf_drops
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Ring Buffer Overflow")
                    .border_style(Style::default().fg(ringbuf_color)),
            );
            f.render_widget(ringbuf_card, rate_chunks[2]);

            // 3. Metrics & Latency Split
            let mid_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[2]);

            // Left: Lifecycle Counts
            let counts_lines = vec![
                Line::from(vec![
                    Span::raw("Total Processed: "),
                    Span::styled(
                        stats.total_events.to_string(),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" | Consumes: "),
                    Span::styled(
                        stats.total_consumes.to_string(),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(" | Drops: "),
                    Span::styled(
                        stats.total_drops.to_string(),
                        Style::default().fg(Color::Red),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("GRO Merges: "),
                    Span::styled(
                        stats.total_gro_merges.to_string(),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(" | TCP Coalesces: "),
                    Span::styled(
                        stats.total_tcp_coalesces.to_string(),
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("GSO Segments: "),
                    Span::styled(
                        stats.total_gso_segments.to_string(),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" | Head Expansions: "),
                    Span::styled(
                        stats.total_expand_heads.to_string(),
                        Style::default().fg(Color::Cyan),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("Allocations: "),
                    Span::styled(
                        stats.total_allocs.to_string(),
                        Style::default().fg(Color::Magenta),
                    ),
                    Span::raw(" | In-flight SKBs: "),
                    Span::styled(
                        state.active_skbs_count.to_string(),
                        Style::default().fg(Color::LightBlue),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("Avg Truesize: "),
                    Span::styled(
                        format!("{} B", stats.average_truesize()),
                        Style::default().fg(Color::White),
                    ),
                    Span::raw(" | Frags (0/1-4/5+): "),
                    Span::styled(
                        format!(
                            "{}/{}/{}",
                            stats.frag_zero_count,
                            stats.frag_one_to_four_count,
                            stats.frag_five_plus_count
                        ),
                        Style::default().fg(Color::White),
                    ),
                ]),
            ];
            let counts_widget = Paragraph::new(counts_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("SKB Lifecycle Operations")
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(counts_widget, mid_chunks[0]);

            // Right: Latency Profile & Percentiles
            let (p50, p95, p99) = stats.latency.percentiles();
            let latency_lines = vec![
                Line::from(vec![
                    Span::styled("Latency Profile", Style::default().fg(Color::Cyan)),
                    Span::raw(format!(" (Samples: {})", stats.latency.count)),
                ]),
                Line::from(vec![
                    Span::raw("  p50:     "),
                    Span::styled(
                        format!("{:>6} µs", p50),
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("   | Average: "),
                    Span::styled(
                        format!("{:>6} µs", stats.latency.average_us()),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  p95:     "),
                    Span::styled(
                        format!("{:>6} µs", p95),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("   | Min:     "),
                    Span::styled(
                        format!(
                            "{:>6} µs",
                            if stats.latency.min_us == u64::MAX {
                                0
                            } else {
                                stats.latency.min_us
                            }
                        ),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  p99:     "),
                    Span::styled(
                        format!("{:>6} µs", p99),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("   | Max:     "),
                    Span::styled(
                        format!("{:>6} µs", stats.latency.max_us),
                        Style::default().fg(Color::White),
                    ),
                ]),
            ];
            let latency_widget = Paragraph::new(latency_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Lifespan Latency Distribution")
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(latency_widget, mid_chunks[1]);

            // 4. Live Event Log Table
            let rows: Vec<Row> = state
                .events_log
                .iter()
                .rev()
                .take(15)
                .map(|e| {
                    let ts_sec = (e.timestamp_ns as f64) / 1_000_000_000.0;
                    let op_style = match e.operation() {
                        SkbOp::Drop => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        SkbOp::Consume => Style::default().fg(Color::Green),
                        SkbOp::GroMerge | SkbOp::TcpCoalesce => {
                            Style::default().fg(Color::Yellow)
                        }
                        SkbOp::GsoSegment | SkbOp::ExpandHead => Style::default().fg(Color::Cyan),
                        SkbOp::Alloc => Style::default().fg(Color::Magenta),
                        _ => Style::default().fg(Color::White),
                    };

                    let detail = match e.operation() {
                        SkbOp::Drop => format!("reason={}", e.drop_reason_str()),
                        SkbOp::GroMerge => "absorbed into parent".into(),
                        SkbOp::TcpCoalesce => "absorbed into socket queue".into(),
                        SkbOp::Consume => "consumed/delivered".into(),
                        SkbOp::GsoSegment => format!("gso_segs={}", e.gso_segs),
                        SkbOp::ExpandHead => "headroom expanded".into(),
                        SkbOp::Alloc => "allocated".into(),
                        _ => String::new(),
                    };

                    Row::new(vec![
                        Cell::from(format!("{:.4}", ts_sec)),
                        Cell::from(e.operation().to_string()).style(op_style),
                        Cell::from(e.flow_str()),
                        Cell::from(format!("0x{:x}", e.skb_addr)),
                        Cell::from(e.len.to_string()),
                        Cell::from(e.truesize.to_string()),
                        Cell::from(detail),
                    ])
                })
                .collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Length(10), // Timestamp
                    Constraint::Length(14), // Operation
                    Constraint::Length(32), // Flow (5-Tuple)
                    Constraint::Length(18), // SKB Addr
                    Constraint::Length(7),  // Len
                    Constraint::Length(9),  // Truesize
                    Constraint::Min(20),    // Detail
                ],
            )
            .header(
                Row::new(vec![
                    "TIME", "OP", "FLOW (SRC -> DST)", "SKB_ADDR", "LEN", "TRUESIZE", "DETAIL",
                ])
                .style(
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Live SKB Event Stream (Latest 15)")
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(table, chunks[3]);

            // 5. Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" [q] ", Style::default().fg(Color::Yellow)),
                Span::raw("Quit | "),
                Span::styled("[c] ", Style::default().fg(Color::Yellow)),
                Span::raw("Clear Log | "),
                Span::styled("Refresh: ", Style::default().fg(Color::DarkGray)),
                Span::styled("10 Hz (100ms)", Style::default().fg(Color::White)),
            ]));
            f.render_widget(footer, chunks[4]);
        })?;

        Ok(())
    }

    pub fn poll_input(&self, running: Arc<AtomicBool>, state: &mut TuiState) -> Result<()> {
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    running.store(false, Ordering::Relaxed);
                } else if key.code == KeyCode::Char('c') {
                    state.events_log.clear();
                }
            }
        }
        Ok(())
    }
}

impl Drop for TuiRunner {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
    }
}
