//! In-process batch accumulator for the AI detector — NVIDIA Triton-style
//! dynamic batching, *same process, no IPC*. Replaces the per-request
//! `Mutex<Session>::run([1, 27])` bottleneck (which serialised all
//! inference to batch=1) with a `[N, 27]` forward pass amortised across
//! the requests that arrive within a small time window.
//!
//! ```text
//! inspect() ──features──► [mpsc] ──► collector task
//!                                       │  flush when delay_ms elapsed
//!                                       │  OR max_batch reached
//!                                       ▼
//!                                  WorkBatch ──► [async-channel MPMC] ──► N worker tasks
//!                                                                            │ spawn_blocking(predict_batch)
//!                                                                Prediction ──► oneshot back to caller
//! ```
//!
//! ## Concurrency model
//! - **One** collector task forms batches from the shared `mpsc` queue.
//! - **N** worker tasks, each owning one `Arc<Model>` (one ORT session),
//!   pull batches from an MPMC `async-channel` and run ORT inside
//!   `spawn_blocking` so the Tokio reactor stays free. N independent
//!   sessions ⇒ true parallel inference.
//!
//! ## Load safety (learned the hard way from the gRPC client)
//! The sync `Detector::inspect` bridges to this async path via
//! `block_in_place`, which parks a worker thread for the round-trip. To
//! keep a traffic burst from parking unbounded threads and wedging the
//! runtime, [`BatchService::classify`]:
//!   - uses `try_send` so a full queue **sheds** (fail-open) instead of
//!     blocking the caller, and
//!   - bounds the reply wait with [`CLASSIFY_TIMEOUT`].
//!
//! Batching keeps per-call latency low (≈ `delay_ms` + inference), so the
//! in-flight count — and thus parked threads — stays small in practice;
//! the shed + timeout are the hard ceilings for the overload case.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep_until;

use super::features::NUM_FEATURES;
use super::model::{Model, ModelError, Prediction};

/// How long a caller waits on the reply before giving up (fail-open).
/// Bounds how long `block_in_place` can park a worker thread — a stuck
/// or overloaded inference worker can never pin a caller indefinitely.
const CLASSIFY_TIMEOUT: Duration = Duration::from_millis(50);

/// Why a classify couldn't produce a verdict. Every variant is treated
/// as fail-open by the detector (no signal — request flows through).
#[derive(Debug)]
pub enum BatchError {
    /// Queue full — shedding under overload (back-pressure).
    Overloaded,
    /// Reply dropped (inference error / worker panic) or timed out.
    Unavailable,
}

/// A single classify request queued for batching.
struct InferReq {
    features: [f32; NUM_FEATURES],
    /// The caller awaits this; the worker sends the prediction, or drops
    /// the sender on failure (→ caller sees `RecvError` → fail-open).
    reply_tx: oneshot::Sender<Prediction>,
}

/// A batch handed from the collector to a worker.
struct WorkBatch {
    items: Vec<InferReq>,
}

/// Clone-cheap handle to the batch accumulator. The detector holds one.
#[derive(Clone)]
pub struct BatchService {
    tx: mpsc::Sender<InferReq>,
}

impl BatchService {
    /// Enqueue a feature vector and await its prediction.
    ///
    /// Load-safe by construction: `try_send` means a full queue returns
    /// [`BatchError::Overloaded`] immediately rather than blocking — the
    /// caller is inside `block_in_place`, so blocking here would park a
    /// worker thread and, under a burst, wedge the runtime. The reply
    /// wait is bounded by [`CLASSIFY_TIMEOUT`].
    pub async fn classify(
        &self,
        features: [f32; NUM_FEATURES],
    ) -> Result<Prediction, BatchError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .try_send(InferReq { features, reply_tx })
            .map_err(|_| BatchError::Overloaded)?;
        match tokio::time::timeout(CLASSIFY_TIMEOUT, reply_rx).await {
            Ok(Ok(pred)) => Ok(pred),
            // worker dropped the sender (inference error/panic) or timed out
            _ => Err(BatchError::Unavailable),
        }
    }
}

/// Load `workers` independent ONNX sessions and spawn the collector + N
/// worker tasks. Returns a clone-cheap [`BatchService`]. Must be called
/// from within a Tokio runtime (it calls `tokio::spawn`).
///
/// `Model::load` is run synchronously here (boot-time, one-shot); a bad
/// model path surfaces as `Err` so the boot path can fall back.
pub fn batch_spawn(
    model_path: &Path,
    normal_class_idx: i64,
    workers: usize,
    max_batch: usize,
    delay_ms: u64,
) -> Result<BatchService, ModelError> {
    let workers = workers.max(1);
    let max_batch = max_batch.max(1);

    // One independent session per worker — no shared lock, true parallel
    // inference across workers.
    let mut models = Vec::with_capacity(workers);
    for _ in 0..workers {
        models.push(Arc::new(Model::load(model_path, normal_class_idx)?));
    }

    // Back-pressure: cap queued requests so a burst sheds (fail-open) at
    // `classify` rather than growing unboundedly. Generous headroom over
    // the steady-state batch pipeline.
    let queue_cap = (workers * max_batch * 4).max(1024);
    let (req_tx, req_rx) = mpsc::channel::<InferReq>(queue_cap);
    // MPMC collector→workers queue; small bound so the collector doesn't
    // race far ahead of the workers.
    let (work_tx, work_rx) = async_channel::bounded::<WorkBatch>(workers * 2);

    for model in models {
        tokio::spawn(worker_loop(model, work_rx.clone()));
    }
    tokio::spawn(collector_loop(
        req_rx,
        work_tx,
        max_batch,
        Duration::from_millis(delay_ms),
    ));

    tracing::info!(
        workers,
        max_batch,
        delay_ms,
        queue_cap,
        "ai batch accumulator started"
    );
    Ok(BatchService { tx: req_tx })
}

/// Forms batches: waits for a first item, then drains until `max_batch`
/// or `delay` elapses, whichever comes first.
async fn collector_loop(
    mut req_rx: mpsc::Receiver<InferReq>,
    work_tx: async_channel::Sender<WorkBatch>,
    max_batch: usize,
    delay: Duration,
) {
    loop {
        // Idle until the first item of a new batch (no timeout = no spin).
        let first = match req_rx.recv().await {
            Some(r) => r,
            None => return, // service dropped
        };

        let mut items = Vec::with_capacity(max_batch);
        items.push(first);
        let deadline = tokio::time::Instant::now() + delay;

        while items.len() < max_batch {
            tokio::select! {
                biased; // prefer draining the queue over firing the timer
                maybe = req_rx.recv() => match maybe {
                    Some(r) => items.push(r),
                    None => break, // service dropped mid-batch — flush what we have
                },
                _ = sleep_until(deadline) => break,
            }
        }

        if work_tx.send(WorkBatch { items }).await.is_err() {
            return; // all workers gone
        }
    }
}

/// Pulls batches, runs ORT inference in `spawn_blocking`, and fans
/// predictions back to callers. On any failure it drops the reply
/// senders so callers fail open.
async fn worker_loop(model: Arc<Model>, work_rx: async_channel::Receiver<WorkBatch>) {
    while let Ok(batch) = work_rx.recv().await {
        let n = batch.items.len();
        let features: Vec<[f32; NUM_FEATURES]> =
            batch.items.iter().map(|r| r.features).collect();

        let infer_start = Instant::now();
        let model_ref = Arc::clone(&model);
        let result =
            tokio::task::spawn_blocking(move || model_ref.predict_batch(&features)).await;
        // Observability: batch_size > 1 confirms dynamic batching is
        // working (debug-level — silent at the default info filter).
        tracing::debug!(
            batch_size = n,
            infer_us = infer_start.elapsed().as_micros() as u64,
            "ai batch processed"
        );

        match result {
            Ok(Ok(preds)) if preds.len() == batch.items.len() => {
                for (req, pred) in batch.items.into_iter().zip(preds) {
                    // Ignore send error — caller may have already given up.
                    let _ = req.reply_tx.send(pred);
                }
            }
            Ok(Ok(_)) => {
                tracing::trace!("ai batch: prediction/batch length mismatch — fail-open");
                // batch.items dropped here → reply senders drop → callers fail open
            }
            Ok(Err(e)) => {
                tracing::trace!(error = %e, "ai batch inference error — fail-open");
            }
            Err(e) => {
                tracing::trace!(error = %e, "ai batch worker panicked — fail-open");
            }
        }
    }
}
