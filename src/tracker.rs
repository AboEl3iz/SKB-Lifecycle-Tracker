use crate::types::{SkbLifecycleEvent, SkbOp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkbNode {
    pub skb_addr: u64,
    pub generation: u64,
    pub initial_len: u32,
    pub current_len: u32,
    pub truesize: u32,
    pub nr_frags: u8,
    pub gso_segs: u16,
    pub gso_size: u16,
    pub parent: Option<(u64, u64)>,      // (addr, generation)
    pub children: Vec<(u64, u64)>,      // list of (addr, generation)
    pub events: Vec<SkbLifecycleEvent>,
    #[serde(skip, default = "Instant::now")]
    pub created_at: Instant,
    #[serde(skip, default = "Instant::now")]
    pub last_updated_at: Instant,
    pub drop_reason: Option<u32>,
    pub is_retired: bool,
}

impl SkbNode {
    pub fn new(addr: u64, gen: u64, event: &SkbLifecycleEvent) -> Self {
        let now = Instant::now();
        Self {
            skb_addr: addr,
            generation: gen,
            initial_len: event.len,
            current_len: event.len,
            truesize: event.truesize,
            nr_frags: event.nr_frags,
            gso_segs: event.gso_segs,
            gso_size: event.gso_size,
            parent: None,
            children: Vec::new(),
            events: vec![*event],
            created_at: now,
            last_updated_at: now,
            drop_reason: if event.operation() == SkbOp::Drop {
                Some(event.drop_reason)
            } else {
                None
            },
            is_retired: false,
        }
    }
    pub fn lifespan_us(&self) -> Option<u64> {
        if self.events.len() < 2 {
            return None;
        }
        let first_ts = self.events.first()?.timestamp_ns;
        let last_ts = self.events.last()?.timestamp_ns;
        if last_ts >= first_ts {
            Some((last_ts - first_ts) / 1_000)
        } else {
            None
        }
    }
}

pub struct SkbLifespanEngine {
    pub active_skbs: HashMap<u64, SkbNode>,
    pub address_generations: HashMap<u64, u64>,
    pub lru_timeout: Duration,
    pub total_retired: u64,
}

impl Default for SkbLifespanEngine {
    fn default() -> Self {
        Self::new(Duration::from_millis(500))
    }
}

impl SkbLifespanEngine {
    pub fn new(lru_timeout: Duration) -> Self {
        Self {
            active_skbs: HashMap::new(),
            address_generations: HashMap::new(),
            lru_timeout,
            total_retired: 0,
        }
    }

    /// Retrieves an existing active node, or initializes a new generation if previously retired or unseen.
    pub fn get_or_create_node(&mut self, addr: u64, event: &SkbLifecycleEvent) -> &mut SkbNode {
        if !self.active_skbs.contains_key(&addr) {
            let gen = self
                .address_generations
                .entry(addr)
                .and_modify(|g| *g += 1)
                .or_insert(0);
            let generation = *gen;
            self.active_skbs
                .insert(addr, SkbNode::new(addr, generation, event));
        }

        let node = self.active_skbs.get_mut(&addr).unwrap();
        node.last_updated_at = Instant::now();
        node
    }

    /// Process a lifecycle event and advance the state machine.
    /// Returns Some(SkbNode) when an SKB reaches terminal state (CONSUME or DROP).
    pub fn process_event(&mut self, e: &SkbLifecycleEvent) -> Option<SkbNode> {
        let op = e.operation();

        match op {
            SkbOp::GroMerge => {
                // peer_skb_addr = Parent (p), skb_addr = Child (skb) being merged
                let parent_addr = e.peer_skb_addr;
                let child_addr = e.skb_addr;

                let parent_gen = self
                    .address_generations
                    .get(&parent_addr)
                    .copied()
                    .unwrap_or(0);
                let child_gen = self
                    .address_generations
                    .get(&child_addr)
                    .copied()
                    .unwrap_or(0);

                // Update child
                let child_node = self.get_or_create_node(child_addr, e);
                child_node.parent = Some((parent_addr, parent_gen));
                child_node.events.push(*e);

                // Update parent
                let parent_node = self.get_or_create_node(parent_addr, e);
                parent_node.children.push((child_addr, child_gen));
                parent_node.current_len += e.len;
                parent_node.truesize += e.truesize;
                parent_node.events.push(*e);

                None
            }

            SkbOp::TcpCoalesce => {
                // peer_skb_addr = Target SKB on socket queue, skb_addr = Incoming SKB absorbed
                let target_addr = e.peer_skb_addr;
                let source_addr = e.skb_addr;

                let target_gen = self
                    .address_generations
                    .get(&target_addr)
                    .copied()
                    .unwrap_or(0);
                let source_gen = self
                    .address_generations
                    .get(&source_addr)
                    .copied()
                    .unwrap_or(0);

                // Update source
                let src_node = self.get_or_create_node(source_addr, e);
                src_node.parent = Some((target_addr, target_gen));
                src_node.events.push(*e);

                // Update target
                let target_node = self.get_or_create_node(target_addr, e);
                target_node.children.push((source_addr, source_gen));
                target_node.current_len += e.len;
                target_node.events.push(*e);

                None
            }

            SkbOp::Consume | SkbOp::Drop => {
                // Terminal state for this SKB address
                let node = if let Some(mut existing) = self.active_skbs.remove(&e.skb_addr) {
                    existing.events.push(*e);
                    existing.last_updated_at = Instant::now();
                    existing.current_len = e.len;
                    existing.truesize = e.truesize;
                    existing.nr_frags = e.nr_frags;
                    if op == SkbOp::Drop {
                        existing.drop_reason = Some(e.drop_reason);
                    }
                    existing.is_retired = true;
                    existing
                } else {
                    let gen = self
                        .address_generations
                        .entry(e.skb_addr)
                        .and_modify(|g| *g += 1)
                        .or_insert(0);
                    let mut new_node = SkbNode::new(e.skb_addr, *gen, e);
                    new_node.is_retired = true;
                    new_node
                };

                self.total_retired += 1;
                Some(node)
            }

            _ => {
                let node = self.get_or_create_node(e.skb_addr, e);
                node.events.push(*e);
                node.current_len = e.len;
                node.truesize = e.truesize;
                None
            }
        }
    }

    /// Garbage-collect inactive nodes that have exceeded lru_timeout
    pub fn evict_lru(&mut self) -> Vec<SkbNode> {
        let now = Instant::now();
        let timeout = self.lru_timeout;
        let mut evicted = Vec::new();

        let expired_addrs: Vec<u64> = self
            .active_skbs
            .iter()
            .filter(|(_, node)| now.duration_since(node.last_updated_at) > timeout)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired_addrs {
            if let Some(mut node) = self.active_skbs.remove(&addr) {
                node.is_retired = true;
                evicted.push(node);
                self.total_retired += 1;
            }
        }

        // Prevent memory leak in address_generations on high traffic runs
        if self.address_generations.len() > 65536 {
            let active_keys: std::collections::HashSet<u64> =
                self.active_skbs.keys().copied().collect();
            self.address_generations.retain(|addr, _| active_keys.contains(addr));
        }

        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slab_reuse_generation_bump() {
        let mut engine = SkbLifespanEngine::default();
        let addr = 0xffff888100200000;

        let event1 = SkbLifecycleEvent {
            timestamp_ns: 1000,
            skb_addr: addr,
            peer_skb_addr: 0,
            len: 1500,
            data_len: 0,
            truesize: 2048,
            drop_reason: 0,
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
            gso_size: 0,
            gso_segs: 0,
            nr_frags: 0,
            op: SkbOp::Consume as u8,
            protocol: 0,
            _pad: [0; 5],
        };

        let node1 = engine.process_event(&event1).unwrap();
        assert_eq!(node1.generation, 0);
        assert_eq!(node1.skb_addr, addr);

        // Subsequent event for the same address after retirement (SLAB reuse)
        let event2 = SkbLifecycleEvent {
            timestamp_ns: 2000,
            skb_addr: addr,
            peer_skb_addr: 0,
            len: 64,
            data_len: 0,
            truesize: 1024,
            drop_reason: 3, // TCP_CSUM
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
            gso_size: 0,
            gso_segs: 0,
            nr_frags: 0,
            op: SkbOp::Drop as u8,
            protocol: 0,
            _pad: [0; 5],
        };

        let node2 = engine.process_event(&event2).unwrap();
        assert_eq!(node2.generation, 1);
        assert_eq!(node2.drop_reason, Some(3));
    }
}
