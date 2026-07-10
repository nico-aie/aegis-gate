#![cfg(feature = "ai")]
//! Gate-free micro-bench proving the synchronous session pool
//! parallelises inference (N sessions ⇒ ~N× throughput, flat p99) vs the
//! single serialized session. Ignored by default — needs a real model.
//!
//! Run:
//!   AEGIS_AI_MODEL=data/ai_model/waf_model.onnx \
//!     cargo test -p aegis-security --features ai --test ai_pool_bench \
//!     -- --ignored --nocapture

use std::sync::Arc;
use std::time::Instant;

use aegis_security::detectors::ai::features::NUM_FEATURES;
use aegis_security::detectors::ai::Model;

fn bench(model_path: &str, n_sessions: usize, threads: usize, per_thread: usize) {
    let model = Arc::new(
        Model::load_pool(std::path::Path::new(model_path), 0, n_sessions)
            .expect("load model pool"),
    );
    let feats = [0.2f32; NUM_FEATURES];

    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let m = Arc::clone(&model);
            std::thread::spawn(move || {
                let mut lat = Vec::with_capacity(per_thread);
                for _ in 0..per_thread {
                    let t = Instant::now();
                    let _ = m.predict(&feats);
                    lat.push(t.elapsed().as_secs_f64() * 1000.0);
                }
                lat
            })
        })
        .collect();

    let mut all: Vec<f64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let elapsed = start.elapsed().as_secs_f64();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let total = all.len();
    let p50 = all[total / 2];
    let p99 = all[total * 99 / 100];
    println!(
        "sessions={n_sessions:<2} threads={threads}: {:>7.0} infer/s   p50={p50:6.2}ms  p99={p99:6.2}ms",
        total as f64 / elapsed
    );
}

#[test]
#[ignore]
fn pool_scaling() {
    let model =
        std::env::var("AEGIS_AI_MODEL").unwrap_or_else(|_| "data/ai_model/waf_model.onnx".into());
    if !std::path::Path::new(&model).exists() {
        eprintln!("AEGIS_AI_MODEL not found ({model}) — skipping pool bench");
        return;
    }
    let (threads, per_thread) = (16, 500);
    println!("\n=== session-pool scaling ({threads} concurrent callers) ===");
    for n in [1usize, 2, 4, 8] {
        bench(&model, n, threads, per_thread);
    }
}
