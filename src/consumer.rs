use crate::types::SkbLifecycleEvent;
use crossbeam_channel::Sender;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

pub struct ConsumerStats {
    pub events_received: Arc<AtomicU64>,
    pub events_dropped: Arc<AtomicU64>,
}

pub struct RingBufferConsumer {
    is_running: Arc<AtomicBool>,
    pub stats: ConsumerStats,
}

impl RingBufferConsumer {
    pub fn new(is_running: Arc<AtomicBool>) -> Self {
        Self {
            is_running,
            stats: ConsumerStats {
                events_received: Arc::new(AtomicU64::new(0)),
                events_dropped: Arc::new(AtomicU64::new(0)),
            },
        }
    }

    /// Spawns the dedicated ring buffer consumer thread.
    pub fn spawn(
        &self,
        map: &libbpf_rs::Map,
        tx: Sender<SkbLifecycleEvent>,
    ) -> anyhow::Result<std::thread::JoinHandle<()>> {
        let is_running = Arc::clone(&self.is_running);
        let rx_counter = Arc::clone(&self.stats.events_received);
        let drop_counter = Arc::clone(&self.stats.events_dropped);

        let mut builder = libbpf_rs::RingBufferBuilder::new();

        builder.add(map, move |data: &[u8]| {
            match plain::from_bytes::<SkbLifecycleEvent>(data) {
                Ok(event) => {
                    rx_counter.fetch_add(1, Ordering::Relaxed);
                    if tx.try_send(*event).is_err() {
                        drop_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(err) => {
                    error!("Corrupted event from ring buffer: {:?}", err);
                }
            }
            0
        })?;

        let ring_buffer = builder.build()?;

        let handle = std::thread::Builder::new()
            .name("ring-consumer".into())
            .spawn(move || {
                debug!("Ring buffer consumer thread started");
                while is_running.load(Ordering::Relaxed) {
                    if let Err(err) = ring_buffer.poll(Duration::from_millis(50)) {
                        if is_running.load(Ordering::Relaxed) {
                            error!("Ring buffer poll error: {:?}", err);
                        }
                        break;
                    }
                }
                debug!("Ring buffer consumer thread exiting");
            })?;

        Ok(handle)
    }
}
