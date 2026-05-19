mod features;

use features::{NUM_FEATURES, extract_features};
use ndarray::Array2;
use ort::{inputs, session::Session};
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;

// ─── CLI helpers ──────────────────────────────────────────────────────────────

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            return args.get(i + 1).cloned();
        }
        if let Some(val) = a.strip_prefix(&format!("{flag}=")) {
            return Some(val.to_string());
        }
    }
    None
}

// ─── Data loading ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Row {
    text: String,
    category: String,
}

/// Extended row for dataset_unified.csv (includes `source` column).
#[derive(Deserialize)]
struct UnifiedRow {
    text: String,
    category: String,
    source: String,
}

fn load_csv(path: &str) -> Vec<Row> {
    match csv::Reader::from_path(path) {
        Ok(mut rdr) => rdr.deserialize().filter_map(|r| r.ok()).collect(),
        Err(e) => {
            eprintln!("  [WARN] cannot open {path}: {e}");
            vec![]
        }
    }
}

fn load_unified_csv(path: &str) -> Vec<UnifiedRow> {
    match csv::Reader::from_path(path) {
        Ok(mut rdr) => rdr.deserialize().filter_map(|r| r.ok()).collect(),
        Err(e) => {
            eprintln!("  [WARN] cannot open {path}: {e}");
            vec![]
        }
    }
}

// ─── Feature extraction ───────────────────────────────────────────────────────

/// Threshold below which rayon thread-pool wakeup overhead exceeds the benefit
/// of parallelism. Tune down if CPU count is high, up if requests are very long.
const PAR_THRESHOLD: usize = 64;

fn build_feature_matrix(requests: &[&str]) -> Array2<f32> {
    let n = requests.len();
    let mut mat = Array2::<f32>::zeros((n, NUM_FEATURES));
    if n >= PAR_THRESHOLD {
        // Parallel path: collect into a temp vec then copy to avoid rayon + ndarray
        // borrow conflicts.
        let feats: Vec<[f32; NUM_FEATURES]> =
            requests.par_iter().map(|req| extract_features(req)).collect();
        for (i, feat) in feats.iter().enumerate() {
            for (j, &v) in feat.iter().enumerate() {
                mat[[i, j]] = v;
            }
        }
    } else {
        // Sequential path: avoids rayon thread-pool wakeup for small batches.
        for (i, req) in requests.iter().enumerate() {
            let feat = extract_features(req);
            for (j, &v) in feat.iter().enumerate() {
                mat[[i, j]] = v;
            }
        }
    }
    mat
}

// ─── Inference ────────────────────────────────────────────────────────────────

/// Returns (labels, prob_attack_scores).
/// ONNX binary model:
///   "label"         → int64  (N,)    — 0=Normal, 1=Attack
///   "probabilities" → float32 (N, 2) — [P(Normal), P(Attack)]
fn predict_batch(session: &mut Session, requests: &[&str]) -> (Vec<i64>, Vec<f32>) {
    if requests.is_empty() {
        return (vec![], vec![]);
    }
    let n = requests.len();
    let mat = build_feature_matrix(requests);
    let input = ort::value::Tensor::from_array(mat).expect("tensor creation failed");
    let outputs = session.run(inputs!["X" => input]).expect("inference failed");

    let (_, labels) = outputs["label"]
        .try_extract_tensor::<i64>()
        .expect("extract label tensor");
    let label_vec = labels.to_vec();

    let (_, probs) = outputs["probabilities"]
        .try_extract_tensor::<f32>()
        .expect("extract probabilities tensor");

    // Supports (N, 2) flat layout [p_normal_0, p_attack_0, p_normal_1, p_attack_1, ...]
    let n_cols = probs.len() / n.max(1);
    let scores: Vec<f32> = if n_cols >= 2 {
        (0..n).map(|i| probs[i * n_cols + 1]).collect()
    } else {
        // (N,) — single attack probability output
        (0..n).map(|i| probs[i]).collect()
    };

    (label_vec, scores)
}

fn predict_all(
    session: &mut Session,
    requests: &[&str],
    batch_size: usize,
) -> (Vec<i64>, Vec<f32>) {
    let mut labels = Vec::with_capacity(requests.len());
    let mut scores = Vec::with_capacity(requests.len());
    for chunk in requests.chunks(batch_size) {
        let (l, s) = predict_batch(session, chunk);
        labels.extend(l);
        scores.extend(s);
    }
    (labels, scores)
}

// ─── Metrics ──────────────────────────────────────────────────────────────────

struct BinaryMetrics {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
}

impl BinaryMetrics {
    fn accuracy(&self) -> f64 {
        let total = self.tp + self.fp + self.fn_ + self.tn;
        if total == 0 { 0.0 } else { (self.tp + self.tn) as f64 / total as f64 }
    }
    fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 { 0.0 } else { self.tp as f64 / d as f64 }
    }
    fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 { 0.0 } else { self.tp as f64 / d as f64 }
    }
    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
    }
    fn total(&self) -> usize {
        self.tp + self.fp + self.fn_ + self.tn
    }
}

fn compute_binary(
    y_true: &[i64],   // 0=Normal, 1=Attack
    y_pred: &[i64],
) -> BinaryMetrics {
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_ = 0usize;
    let mut tn = 0usize;
    for (&t, &p) in y_true.iter().zip(y_pred.iter()) {
        match (t, p) {
            (1, 1) => tp += 1,
            (0, 1) => fp += 1,
            (1, 0) => fn_ += 1,
            _      => tn += 1,
        }
    }
    BinaryMetrics { tp, fp, fn_, tn }
}

fn score_stats(scores: &[f32]) -> (f32, f32, f32) {
    if scores.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mean = scores.iter().sum::<f32>() / scores.len() as f32;
    let mut sorted = scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[(sorted.len() as f32 * 0.95) as usize];
    (mean, p50, p95)
}

// ─── Per-source evaluation ────────────────────────────────────────────────────

struct SourceResult {
    name: String,
    samples: usize,
    accuracy: f64,
    precision: f64,
    recall: f64,
    f1: f64,
    fn_count: usize,
    fp_count: usize,
}

fn evaluate_source(
    session: &mut Session,
    name: &str,
    rows: &[Row],
    batch_size: usize,
) -> Option<SourceResult> {
    if rows.is_empty() {
        println!("  [{name}] EMPTY — run: python export_sources.py");
        return None;
    }

    let sep = "=".repeat(68);
    println!("\n{sep}");
    println!(" Source : {name}  ({} samples)", rows.len());
    println!("{sep}");

    // Class distribution
    let mut dist: HashMap<&str, usize> = HashMap::new();
    for r in rows {
        *dist.entry(r.category.as_str()).or_insert(0) += 1;
    }
    let mut dist_vec: Vec<_> = dist.into_iter().collect();
    dist_vec.sort_by(|a, b| b.1.cmp(&a.1));
    println!(" Class distribution:");
    for (cat, n) in &dist_vec {
        println!("   {:<44} {:>7}", cat, n);
    }

    let t0 = Instant::now();
    let requests: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
    let (preds, scores) = predict_all(session, &requests, batch_size);
    let elapsed = t0.elapsed().as_secs_f64();

    // Map category string → binary label (0=Normal, 1=Attack)
    let y_true: Vec<i64> = rows
        .iter()
        .map(|r| if r.category == "Normal" { 0 } else { 1 })
        .collect();

    let m = compute_binary(&y_true, &preds);
    let total = m.total();

    println!(
        "\n Elapsed  : {elapsed:.2}s  ({:.0} req/s)",
        total as f64 / elapsed
    );

    println!("\n Binary classification (Normal=0 / Attack=1)");
    println!("   Accuracy  : {:.4}", m.accuracy());
    println!("   Precision : {:.4}   Recall : {:.4}   F1 : {:.4}", m.precision(), m.recall(), m.f1());
    println!("   TP={:<7} FP={:<7} FN={:<7} TN={}", m.tp, m.fp, m.fn_, m.tn);

    // Score stats split by true class
    let atk_scores: Vec<f32> = y_true.iter().zip(scores.iter())
        .filter(|(&t, _)| t == 1)
        .map(|(_, &s)| s)
        .collect();
    let norm_scores: Vec<f32> = y_true.iter().zip(scores.iter())
        .filter(|(&t, _)| t == 0)
        .map(|(_, &s)| s)
        .collect();

    if !atk_scores.is_empty() {
        let (m, p50, p95) = score_stats(&atk_scores);
        println!("\n P(Attack) for TRUE attacks  : mean={m:.4}  p50={p50:.4}  p95={p95:.4}");
    }
    if !norm_scores.is_empty() {
        let (m, p50, p95) = score_stats(&norm_scores);
        println!(" P(Attack) for TRUE normal   : mean={m:.4}  p50={p50:.4}  p95={p95:.4}");
    }

    // False negatives sample — most dangerous misses
    let fn_samples: Vec<_> = y_true.iter().zip(preds.iter()).zip(scores.iter())
        .zip(rows.iter())
        .filter(|(((&t, &p), _), _)| t == 1 && p == 0)
        .map(|(((_, _), &s), r)| (s, r.text.as_str()))
        .collect();
    if !fn_samples.is_empty() {
        let show_n = fn_samples.len().min(3);
        println!("\n False Negatives (attack missed, showing {show_n}/{}):", fn_samples.len());
        let mut sorted = fn_samples;
        sorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        for (score, text) in sorted.iter().take(show_n) {
            let first_line = text.lines().next().unwrap_or("");
            println!("   score={score:.4}  {}", &first_line[..first_line.len().min(100)]);
        }
    }

    // False positives sample — legitimate traffic blocked
    let fp_samples: Vec<_> = y_true.iter().zip(preds.iter()).zip(scores.iter())
        .zip(rows.iter())
        .filter(|(((&t, &p), _), _)| t == 0 && p == 1)
        .map(|(((_, _), &s), r)| (s, r.text.as_str()))
        .collect();
    if !fp_samples.is_empty() {
        let show_n = fp_samples.len().min(3);
        println!("\n False Positives (legitimate blocked, showing {show_n}/{}):", fp_samples.len());
        let mut sorted = fp_samples;
        sorted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        for (score, text) in sorted.iter().take(show_n) {
            let first_line = text.lines().next().unwrap_or("");
            println!("   score={score:.4}  {}", &first_line[..first_line.len().min(100)]);
        }
    }

    Some(SourceResult {
        name: name.to_string(),
        samples: total,
        accuracy: m.accuracy(),
        precision: m.precision(),
        recall: m.recall(),
        f1: m.f1(),
        fn_count: m.fn_,
        fp_count: m.fp,
    })
}

// ─── Save predictions CSV ─────────────────────────────────────────────────────

/// Write per-row predictions to a CSV file.
/// Columns: source, true_label, predicted, score, text_preview (first 120 chars of first line)
fn save_predictions(
    path: &str,
    source: &str,
    rows: &[Row],
    y_true: &[i64],
    y_pred: &[i64],
    scores: &[f32],
) {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path);
    let mut f = match file {
        Ok(f) => std::io::BufWriter::new(f),
        Err(e) => {
            eprintln!("  [WARN] cannot open {path}: {e}");
            return;
        }
    };
    for (((row, &yt), &yp), &s) in rows.iter().zip(y_true).zip(y_pred).zip(scores) {
        let true_label  = if yt == 1 { "Attack" } else { "Normal" };
        let pred_label  = if yp == 1 { "Attack" } else { "Normal" };
        let first_line  = row.text.lines().next().unwrap_or("").replace(',', " ");
        let preview     = &first_line[..first_line.len().min(120)];
        writeln!(f, "{source},{true_label},{pred_label},{s:.4},{preview}").ok();
    }
}

// ─── Benchmark ────────────────────────────────────────────────────────────────

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn benchmark(session: &mut Session, requests: &[String]) {
    println!("\n{}", "=".repeat(80));
    println!(" Rust inference benchmark  (latency = per-request, amortised)");
    println!("{}", "=".repeat(80));
    println!(
        "  {:>6}  {:>10}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}",
        "batch", "req/s", "mean", "p50", "p95", "p99", "max"
    );
    println!("  {}", "-".repeat(73));

    let strs: Vec<&str> = requests.iter().map(|s| s.as_str()).collect();
    let n = strs.len();

    for &batch in &[1usize, 10, 100, 1_000, 10_000] {
        if batch > n { continue; }
        let chunk: Vec<&str> = (0..batch).map(|i| strs[(i * n / batch) % n]).collect();

        for _ in 0..5 { predict_batch(session, &chunk); }

        let reps = match batch { 1 => 2_000, 10 => 1_000, 100 => 500, 1_000 => 100, _ => 20 };
        let mut latencies: Vec<f64> = Vec::with_capacity(reps);
        for _ in 0..reps {
            let t = Instant::now();
            predict_batch(session, &chunk);
            latencies.push(t.elapsed().as_secs_f64() * 1_000.0 / batch as f64);
        }

        let mean_ms = latencies.iter().sum::<f64>() / reps as f64;
        let rps = 1_000.0 / mean_ms;
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let f = |v: f64| format!("{:.3}ms", v);
        println!(
            "  {:>6}  {:>10.0}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}",
            batch, rps, f(mean_ms),
            f(percentile(&latencies, 50.0)),
            f(percentile(&latencies, 95.0)),
            f(percentile(&latencies, 99.0)),
            f(*latencies.last().unwrap_or(&0.0)),
        );
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Support running from either ml_waf/ or ml_waf/waf_infer/
    let root = if std::path::Path::new("waf_model.onnx").exists() {
        "."
    } else {
        ".."
    };
    let model_path  = format!("{root}/waf_model.onnx");
    let eval_dir    = format!("{root}/eval_data");
    let unified_csv = format!("{root}/dataset_unified.csv");
    let model_path  = model_path.as_str();
    let eval_dir    = eval_dir.as_str();
    let unified_csv = unified_csv.as_str();

    let batch_size: usize = get_flag(&args, "--batch-size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8192);
    let do_bench    = args.iter().any(|a| a == "--bench");
    let bench_only  = args.iter().any(|a| a == "--bench-only");
    let do_unified  = args.iter().any(|a| a == "--unified");
    let save_preds  = get_flag(&args, "--save-preds");

    let all_sources     = ["legitimate", "malicious", "srbh", "csic", "huggingface", "modern"];
    let default_sources = ["legitimate", "malicious", "modern"];
    let sources: Vec<String> = match get_flag(&args, "--source").as_deref() {
        Some("all") => all_sources.iter().map(|s| s.to_string()).collect(),
        Some(s)     => s.split(',').map(|x| x.trim().to_string()).collect(),
        None        => default_sources.iter().map(|s| s.to_string()).collect(),
    };

    println!("Loading ONNX model : {model_path}");
    let mut session = Session::builder()
        .expect("ORT session builder failed")
        .commit_from_file(model_path)
        .expect("failed to load ONNX model — run train.py first");

    println!("Classifier         : binary  (Normal=0 | Attack=1)");
    println!("Batch size         : {batch_size}");
    println!("Score              : P(Attack) — higher = more likely attack");

    // ── Evaluation ────────────────────────────────────────────────────────────
    let mut results: Vec<SourceResult> = vec![];

    // Initialise predictions CSV (write header once, append per source below).
    if let Some(ref p) = save_preds {
        match std::fs::write(p, "source,true_label,predicted,score,text_preview\n") {
            Ok(_)  => println!("Saving per-row predictions -> {p}"),
            Err(e) => eprintln!("  [WARN] cannot create {p}: {e}"),
        }
    }

    if do_unified && !bench_only {
        // Evaluate the full dataset_unified.csv, broken down by source column.
        println!("\nLoading unified CSV: {unified_csv} ...");
        let unified_rows = load_unified_csv(unified_csv);
        if unified_rows.is_empty() {
            eprintln!("  [WARN] unified CSV empty or not found — run build_clean_dataset.py first");
        } else {
            println!("  Loaded {} rows — grouping by source ...", unified_rows.len());
            let mut by_source: HashMap<String, Vec<Row>> = HashMap::new();
            for r in unified_rows {
                by_source.entry(r.source).or_default().push(Row {
                    text: r.text,
                    category: r.category,
                });
            }
            let mut sorted_sources: Vec<String> = by_source.keys().cloned().collect();
            sorted_sources.sort();
            for src in &sorted_sources {
                let rows = &by_source[src];
                if let Some(r) = evaluate_source(&mut session, src, rows, batch_size) {
                    results.push(r);
                }
                if let Some(ref p) = save_preds {
                    let reqs: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
                    let (preds, scores) = predict_all(&mut session, &reqs, batch_size);
                    let y_true: Vec<i64> = rows.iter()
                        .map(|r| if r.category == "Normal" { 0 } else { 1 })
                        .collect();
                    save_predictions(p, src, rows, &y_true, &preds, &scores);
                }
            }
        }
    } else if !bench_only {
        for src in &sources {
            let csv_path = format!("{eval_dir}/{src}.csv");
            println!("\nLoading {src} from {csv_path} ...");
            let rows = load_csv(&csv_path);
            if let Some(r) = evaluate_source(&mut session, src, &rows, batch_size) {
                results.push(r);
            }
            if let Some(ref p) = save_preds {
                let reqs: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
                let (preds, scores) = predict_all(&mut session, &reqs, batch_size);
                let y_true: Vec<i64> = rows.iter()
                    .map(|r| if r.category == "Normal" { 0 } else { 1 })
                    .collect();
                save_predictions(p, src, &rows, &y_true, &preds, &scores);
            }
        }
    }

    // ── Summary table ─────────────────────────────────────────────────────────
    if results.len() > 1 {
        println!("\n{}", "=".repeat(80));
        println!(" SUMMARY  (binary: Normal=0 / Attack=1)");
        println!("{}", "=".repeat(80));
        println!(
            "  {:<14} {:>8}  {:>8}  {:>9}  {:>7}  {:>7}  {:>5}  {:>5}",
            "Source", "Samples", "Accuracy", "Precision", "Recall", "F1", "FN", "FP"
        );
        println!("  {}", "-".repeat(76));
        for r in &results {
            println!(
                "  {:<14} {:>8}  {:>8.4}  {:>9.4}  {:>7.4}  {:>7.4}  {:>5}  {:>5}",
                r.name, r.samples, r.accuracy, r.precision, r.recall, r.f1,
                r.fn_count, r.fp_count
            );
        }
        println!();
        println!("  FN = False Negative (attack that slipped through)");
        println!("  FP = False Positive (legitimate request blocked)");
    }

    // ── Benchmark ─────────────────────────────────────────────────────────────
    if do_bench || bench_only {
        println!("\nLoading {unified_csv} for benchmark ...");
        let rows = load_csv(unified_csv);
        if rows.is_empty() {
            eprintln!("  [WARN] unified CSV empty — skipping benchmark");
        } else {
            let reqs: Vec<String> = rows.into_iter().map(|r| r.text).collect();
            benchmark(&mut session, &reqs);
        }
    }
}
