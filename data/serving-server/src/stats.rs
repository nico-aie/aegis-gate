//! Lock-free runtime statistics collected during serving.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

pub struct Stats {
    pub total_requests: AtomicU64,
    pub total_batches:  AtomicU64,
    /// Sum of all batch sizes (= total_requests when no errors).
    total_batch_items:  AtomicU64,
    /// Sum of per-batch ONNX latency in microseconds.
    total_infer_us:     AtomicU64,
    pub total_attacks:  AtomicU64,
    pub max_batch:      AtomicU32,
    pub started_at:     Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            total_batches:  AtomicU64::new(0),
            total_batch_items: AtomicU64::new(0),
            total_infer_us: AtomicU64::new(0),
            total_attacks:  AtomicU64::new(0),
            max_batch:      AtomicU32::new(0),
            started_at:     Instant::now(),
        }
    }
}

impl Stats {
    /// Called once when a batch finishes inference.
    pub fn record_batch(&self, batch_size: usize, infer_us: u32, attacks: usize) {
        self.total_batches.fetch_add(1, Relaxed);
        self.total_batch_items.fetch_add(batch_size as u64, Relaxed);
        self.total_requests.fetch_add(batch_size as u64, Relaxed);
        self.total_infer_us.fetch_add(infer_us as u64, Relaxed);
        self.total_attacks.fetch_add(attacks as u64, Relaxed);

        // Update max_batch atomically (best-effort, may not capture the true
        // maximum under concurrent updates — acceptable for monitoring).
        let cur = self.max_batch.load(Relaxed);
        if batch_size as u32 > cur {
            self.max_batch.store(batch_size as u32, Relaxed);
        }
    }

    pub fn avg_batch_size(&self) -> f64 {
        let batches = self.total_batches.load(Relaxed);
        if batches == 0 { return 0.0; }
        self.total_batch_items.load(Relaxed) as f64 / batches as f64
    }

    pub fn avg_infer_us(&self) -> f64 {
        let batches = self.total_batches.load(Relaxed);
        if batches == 0 { return 0.0; }
        self.total_infer_us.load(Relaxed) as f64 / batches as f64
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
