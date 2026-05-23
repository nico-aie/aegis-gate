//! Batch accumulator — the heart of the serving server.
//!
//! ## Design
//!
//! ```text
//! Client gRPC call
//!   │  ClassifyRequest
//!   ▼
//! [InferReq tx] ──► BatchCollector task
//!                       │  flush when:
//!                       │    • delay_ms elapsed since first item
//!                       │    • OR batch_size >= max_batch
//!                       ▼
//!                   WorkBatch ──► async-channel ──► Worker tasks (N)
//!                                                       │
//!                                             spawn_blocking(model.predict_batch)
//!                                                       │
//!                                           Prediction ──► oneshot reply to caller
//! ```
//!
//! ## Concurrency model
//!
//! - **One** `BatchCollector` Tokio task: collects `InferReq` items from the
//!   shared `mpsc` channel and forms `WorkBatch` objects.
//! - **N** `Worker` Tokio tasks: each holds one `Arc<Model>` (one ORT session).
//!   Workers pull batches from an `async_channel::bounded` MPMC queue, run
//!   inference in `spawn_blocking` (so ORT doesn't block the Tokio reactor),
//!   and fan results back to callers via `oneshot` channels.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep_until;

use crate::features::{extract_features, NUM_FEATURES};
use crate::model::{Model, Prediction};
use crate::stats::Stats;

// ── Public types ─────────────────────────────────────────────────────────────

/// Result sent back to the gRPC handler via oneshot.
#[derive(Debug)]
pub struct BatchResult {
    pub prediction: Prediction,
    pub batch_size: usize,
    pub infer_us:   u32,
    pub queue_ms:   f32,
}

/// Error returned to the gRPC handler if inference fails.
pub type InferError = String;

/// A single classify request queued for batching.
pub struct InferReq {
    /// Pre-extracted 27-float feature vector.
    pub features:    [f32; NUM_FEATURES],
    /// Oneshot sender — the gRPC handler awaits this.
    pub reply_tx:    oneshot::Sender<Result<BatchResult, InferError>>,
    /// When the request entered the queue (for queue_ms metric).
    pub received_at: Instant,
}

// ── Internal batch type ───────────────────────────────────────────────────────

struct WorkBatch {
    items: Vec<InferReq>,
}

// ── BatchService (public handle) ─────────────────────────────────────────────

/// Clone-cheap handle to the batch accumulator.
/// The gRPC service clones this to send requests.
#[derive(Clone)]
pub struct BatchService {
    tx: mpsc::Sender<InferReq>,
}

impl BatchService {
    /// Enqueue a classify request and await the result.
    /// Returns `Err` if the server is shutting down or inference fails.
    pub async fn classify(
        &self,
        features: [f32; NUM_FEATURES],
    ) -> Result<BatchResult, InferError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let req = InferReq {
            features,
            reply_tx,
            received_at: Instant::now(),
        };
        self.tx
            .send(req)
            .await
            .map_err(|_| "batch service shut down".to_string())?;
        reply_rx.await.map_err(|_| "reply channel dropped".to_string())?
    }

    /// Convenience: extract features from a raw request string then classify.
    #[allow(dead_code)]
    pub async fn classify_raw(
        &self,
        raw_request: &str,
    ) -> Result<BatchResult, InferError> {
        let features = extract_features(raw_request);
        self.classify(features).await
    }
}

// ── Spawn the collector + N workers ──────────────────────────────────────────

/// Spin up the batch service.
///
/// # Arguments
/// * `models`    — one `Arc<Model>` per worker (each has its own ORT session)
/// * `max_batch` — flush when this many items are queued
/// * `delay`     — flush after this duration since the first item arrived
/// * `queue_cap` — `mpsc` channel capacity (backpressure)
/// * `stats`     — shared stats collector
///
/// Returns a `BatchService` handle that gRPC handlers use to submit requests.
pub fn spawn(
    models:    Vec<Arc<Model>>,
    max_batch: usize,
    delay:     Duration,
    queue_cap: usize,
    stats:     Arc<Stats>,
) -> BatchService {
    let workers = models.len();
    assert!(workers > 0, "need at least one model/worker");

    // ── Shared request queue (gRPC handlers → collector) ──────────────────
    let (req_tx, req_rx) = mpsc::channel::<InferReq>(queue_cap);

    // ── Work queue (collector → workers) — MPMC so all workers compete ───
    // Capacity = workers * 2 so the collector doesn't stall while workers run.
    let (work_tx, work_rx) = async_channel::bounded::<WorkBatch>(workers * 2);

    // ── Spawn N worker tasks ───────────────────────────────────────────────
    for model in models {
        let work_rx  = work_rx.clone();
        let stats    = Arc::clone(&stats);
        tokio::spawn(worker_loop(model, work_rx, stats));
    }

    // ── Spawn 1 collector task ─────────────────────────────────────────────
    tokio::spawn(collector_loop(req_rx, work_tx, max_batch, delay));

    BatchService { tx: req_tx }
}

// ── Collector loop ────────────────────────────────────────────────────────────

async fn collector_loop(
    mut req_rx:  mpsc::Receiver<InferReq>,
    work_tx:     async_channel::Sender<WorkBatch>,
    max_batch:   usize,
    delay:       Duration,
) {
    tracing::debug!(max_batch, delay_ms = delay.as_millis(), "batch collector started");

    loop {
        // Wait for the first item of a new batch (no timeout — idle = no work).
        let first = match req_rx.recv().await {
            Some(r) => r,
            None    => { tracing::info!("request channel closed — collector exiting"); return; }
        };

        let mut items = Vec::with_capacity(max_batch);
        items.push(first);

        // Set a deadline from when the first item arrived.
        let deadline = tokio::time::Instant::now() + delay;

        // Drain more items until deadline or max_batch.
        loop {
            if items.len() >= max_batch { break; }
            tokio::select! {
                biased; // prefer checking channel over sleeping
                maybe = req_rx.recv() => {
                    match maybe {
                        Some(r) => items.push(r),
                        None    => {
                            // Channel closed mid-batch — flush what we have.
                            tracing::info!("request channel closed — flushing last batch");
                            break;
                        }
                    }
                }
                _ = sleep_until(deadline) => break,
            }
        }

        let batch = WorkBatch { items };

        tracing::debug!(batch_size = batch.items.len(), "batch formed, sending to worker");

        if work_tx.send(batch).await.is_err() {
            tracing::warn!("work queue closed — collector exiting");
            return;
        }
    }
}

// ── Worker loop ───────────────────────────────────────────────────────────────

async fn worker_loop(
    model:   Arc<Model>,
    work_rx: async_channel::Receiver<WorkBatch>,
    stats:   Arc<Stats>,
) {
    tracing::debug!(mode = model.mode(), "inference worker started");

    while let Ok(batch) = work_rx.recv().await {
        let n = batch.items.len();

        // Collect feature vectors into a contiguous slice for batch inference.
        let features: Vec<[f32; NUM_FEATURES]> =
            batch.items.iter().map(|r| r.features).collect();

        let infer_start = Instant::now();

        // Run ORT in a blocking thread — keeps Tokio reactor free.
        let model_ref = Arc::clone(&model);
        let results   = tokio::task::spawn_blocking(move || {
            model_ref.predict_batch(&features)
        }).await;

        let infer_us = infer_start.elapsed().as_micros() as u32;

        match results {
            Ok(Ok(preds)) => {
                let attacks = preds.iter().filter(|p| p.is_attack).count();
                stats.record_batch(n, infer_us, attacks);

                for (req, pred) in batch.items.into_iter().zip(preds) {
                    let queue_ms = req.received_at.elapsed().as_secs_f32() * 1_000.0;
                    let result = BatchResult {
                        prediction: pred,
                        batch_size: n,
                        infer_us,
                        queue_ms,
                    };
                    // Ignore if caller dropped the oneshot receiver.
                    let _ = req.reply_tx.send(Ok(result));
                }
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, batch_size = n, "inference error");
                let msg = e.to_string();
                for req in batch.items {
                    let _ = req.reply_tx.send(Err(msg.clone()));
                }
            }
            Err(e) => {
                // spawn_blocking panicked.
                tracing::error!(error = %e, "spawn_blocking panic in worker");
                let msg = format!("internal panic: {e}");
                for req in batch.items {
                    let _ = req.reply_tx.send(Err(msg.clone()));
                }
            }
        }
    }

    tracing::info!("inference worker exiting");
}
