use crate::types::{SkbLifecycleEvent, SkbOp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub count: u64,
    pub total_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    #[serde(skip)]
    samples: Vec<u64>,
}

impl Default for LatencyStats {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyStats {
    pub fn new() -> Self {
        Self {
            count: 0,
            total_us: 0,
            min_us: u64::MAX,
            max_us: 0,
            samples: Vec::with_capacity(1024),
        }
    }

    pub fn record(&mut self, lat_us: u64) {
        self.count += 1;
        self.total_us += lat_us;
        if lat_us < self.min_us {
            self.min_us = lat_us;
        }
        if lat_us > self.max_us {
            self.max_us = lat_us;
        }

        // Retain up to 50,000 samples for high-accuracy percentile calculations
        if self.samples.len() < 50_000 {
            self.samples.push(lat_us);
        } else {
            let idx = (self.count as usize) % self.samples.len();
            self.samples[idx] = lat_us;
        }
    }

    pub fn average_us(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_us / self.count
        }
    }

    pub fn percentiles(&self) -> (u64, u64, u64) {
        if self.samples.is_empty() {
            return (0, 0, 0);
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let len = sorted.len();

        let p50 = sorted[(len * 50) / 100];
        let p95 = sorted[((len * 95) / 100).min(len - 1)];
        let p99 = sorted[((len * 99) / 100).min(len - 1)];

        (p50, p95, p99)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedStats {
    pub total_events: u64,
    pub total_allocs: u64,
    pub total_consumes: u64,
    pub total_drops: u64,
    pub total_gro_merges: u64,
    pub total_tcp_coalesces: u64,
    pub total_gso_segments: u64,
    pub total_expand_heads: u64,
    pub ringbuf_overflow_drops: u64,
    pub drop_reasons: HashMap<String, u64>,
    pub frag_zero_count: u64,
    pub frag_one_to_four_count: u64,
    pub frag_five_plus_count: u64,
    pub total_truesize_bytes: u64,
    pub latency: LatencyStats,
}

impl Default for AggregatedStats {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregatedStats {
    pub fn new() -> Self {
        Self {
            total_events: 0,
            total_allocs: 0,
            total_consumes: 0,
            total_drops: 0,
            total_gro_merges: 0,
            total_tcp_coalesces: 0,
            total_gso_segments: 0,
            total_expand_heads: 0,
            ringbuf_overflow_drops: 0,
            drop_reasons: HashMap::new(),
            frag_zero_count: 0,
            frag_one_to_four_count: 0,
            frag_five_plus_count: 0,
            total_truesize_bytes: 0,
            latency: LatencyStats::new(),
        }
    }

    pub fn record_event(&mut self, e: &SkbLifecycleEvent) {
        self.total_events += 1;
        self.total_truesize_bytes += e.truesize as u64;

        if e.nr_frags == 0 {
            self.frag_zero_count += 1;
        } else if e.nr_frags <= 4 {
            self.frag_one_to_four_count += 1;
        } else {
            self.frag_five_plus_count += 1;
        }

        match e.operation() {
            SkbOp::Alloc => self.total_allocs += 1,
            SkbOp::Consume => self.total_consumes += 1,
            SkbOp::Drop => {
                self.total_drops += 1;
                let reason = e.drop_reason_str().to_string();
                *self.drop_reasons.entry(reason).or_insert(0) += 1;
            }
            SkbOp::GroMerge => self.total_gro_merges += 1,
            SkbOp::TcpCoalesce => self.total_tcp_coalesces += 1,
            SkbOp::GsoSegment => self.total_gso_segments += 1,
            SkbOp::ExpandHead => self.total_expand_heads += 1,
            _ => {}
        }
    }

    pub fn record_latency(&mut self, lat_us: u64) {
        self.latency.record(lat_us);
    }

    pub fn average_truesize(&self) -> u64 {
        if self.total_events == 0 {
            0
        } else {
            self.total_truesize_bytes / self.total_events
        }
    }
}

pub struct RollingRateCalculator {
    last_tick: Instant,
    last_packet_count: u64,
    last_drop_count: u64,
    pub packets_per_sec: f64,
    pub drops_per_sec: f64,
}

impl Default for RollingRateCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl RollingRateCalculator {
    pub fn new() -> Self {
        Self {
            last_tick: Instant::now(),
            last_packet_count: 0,
            last_drop_count: 0,
            packets_per_sec: 0.0,
            drops_per_sec: 0.0,
        }
    }

    pub fn tick(&mut self, total_packets: u64, total_drops: u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick).as_secs_f64();
        if elapsed >= 0.5 {
            let pkt_delta = total_packets.saturating_sub(self.last_packet_count);
            let drop_delta = total_drops.saturating_sub(self.last_drop_count);

            self.packets_per_sec = (pkt_delta as f64) / elapsed;
            self.drops_per_sec = (drop_delta as f64) / elapsed;

            self.last_tick = now;
            self.last_packet_count = total_packets;
            self.last_drop_count = total_drops;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_stats_percentiles() {
        let mut stats = LatencyStats::new();
        for i in 1..=100 {
            stats.record(i);
        }
        assert_eq!(stats.count, 100);
        assert_eq!(stats.min_us, 1);
        assert_eq!(stats.max_us, 100);
        assert_eq!(stats.average_us(), 50);

        let (p50, p95, p99) = stats.percentiles();
        assert_eq!(p50, 51);
        assert_eq!(p95, 96);
        assert_eq!(p99, 100);
    }
}
