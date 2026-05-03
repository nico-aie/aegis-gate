mod features;

use features::{NUM_FEATURES, extract_features};
use ndarray::Array2;
use ort::{inputs, session::Session};
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
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

fn load_csv(path: &str) -> Vec<Row> {
    match csv::Reader::from_path(path) {
        Ok(mut rdr) => rdr.deserialize().filter_map(|r| r.ok()).collect(),
        Err(e) => {
            eprintln!("  [WARN] cannot open {path}: {e}");
            vec![]
        }
    }
}

fn load_label_map(path: &str) -> (HashMap<i64, String>, HashMap<String, i64>) {
    let raw: HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("cannot read label_map.json"))
            .expect("invalid JSON");
    let idx2name: HashMap<i64, String> =
        raw.iter().map(|(k, v)| (k.parse::<i64>().unwrap(), v.clone())).collect();
    let name2idx: HashMap<String, i64> =
        idx2name.iter().map(|(&i, n)| (n.clone(), i)).collect();
    (idx2name, name2idx)
}

// ─── Feature extraction (parallel via rayon) ──────────────────────────────────

fn build_feature_matrix(requests: &[&str]) -> Array2<f32> {
    // Each thread computes its own [f32; 26] row; matrix is filled sequentially.
    let feats: Vec<[f32; NUM_FEATURES]> =
        requests.par_iter().map(|req| extract_features(req)).collect();
    let n = feats.len();
    let mut mat = Array2::<f32>::zeros((n, NUM_FEATURES));
    for (i, feat) in feats.iter().enumerate() {
        for (j, &v) in feat.iter().enumerate() {
            mat[[i, j]] = v;
        }
    }
    mat
}

// ─── Inference ────────────────────────────────────────────────────────────────

fn predict_batch(session: &mut Session, requests: &[&str]) -> Vec<i64> {
    if requests.is_empty() {
        return vec![];
    }
    let mat = build_feature_matrix(requests);
    let input = ort::value::Tensor::from_array(mat).expect("tensor creation failed");
    let outputs = session.run(inputs!["X" => input]).expect("inference failed");
    let (_, labels) = outputs["label"]
        .try_extract_tensor::<i64>()
        .expect("extract label tensor failed");
    labels.to_vec()
}

fn predict_all(session: &mut Session, requests: &[&str], batch_size: usize) -> Vec<i64> {
    let mut preds = Vec::with_capacity(requests.len());
    for chunk in requests.chunks(batch_size) {
        preds.extend(predict_batch(session, chunk));
    }
    preds
}

// ─── Metrics ──────────────────────────────────────────────────────────────────

struct ClassReport {
    name: String,
    support: usize,
    tp: usize,
    fp: usize,
    fn_: usize,
}

impl ClassReport {
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
}

fn compute_metrics(
    y_true: &[i64],
    y_pred: &[i64],
    idx2name: &HashMap<i64, String>,
) -> Vec<ClassReport> {
    let mut tp: HashMap<i64, usize> = HashMap::new();
    let mut fp: HashMap<i64, usize> = HashMap::new();
    let mut fn_: HashMap<i64, usize> = HashMap::new();
    let mut support: HashMap<i64, usize> = HashMap::new();

    for (&t, &p) in y_true.iter().zip(y_pred.iter()) {
        *support.entry(t).or_insert(0) += 1;
        if t == p {
            *tp.entry(t).or_insert(0) += 1;
        } else {
            *fn_.entry(t).or_insert(0) += 1;
            *fp.entry(p).or_insert(0) += 1;
        }
    }

    let mut classes: Vec<i64> = support.keys().copied().collect();
    classes.sort();
    classes
        .into_iter()
        .map(|idx| ClassReport {
            name: idx2name.get(&idx).cloned().unwrap_or_else(|| idx.to_string()),
            support: *support.get(&idx).unwrap_or(&0),
            tp: *tp.get(&idx).unwrap_or(&0),
            fp: *fp.get(&idx).unwrap_or(&0),
            fn_: *fn_.get(&idx).unwrap_or(&0),
        })
        .collect()
}

fn print_class_report(reports: &[ClassReport]) {
    println!(
        "\n  {:<44} {:>9} {:>9} {:>9} {:>9}",
        "Class", "Prec", "Recall", "F1", "Support"
    );
    println!("  {}", "-".repeat(84));
    for r in reports {
        println!(
            "  {:<44} {:>9.4} {:>9.4} {:>9.4} {:>9}",
            r.name,
            r.precision(),
            r.recall(),
            r.f1(),
            r.support
        );
    }
    let n = reports.len() as f64;
    if n > 0.0 {
        let (sp, sr, sf) = reports
            .iter()
            .fold((0.0_f64, 0.0_f64, 0.0_f64), |a, r| {
                (a.0 + r.precision(), a.1 + r.recall(), a.2 + r.f1())
            });
        println!("  {}", "-".repeat(84));
        println!(
            "  {:<44} {:>9.4} {:>9.4} {:>9.4}",
            "macro avg",
            sp / n,
            sr / n,
            sf / n
        );
    }
}

// ─── Per-source evaluation ────────────────────────────────────────────────────

struct SourceResult {
    name: String,
    samples: usize,
    multi_acc: f64,
    binary_acc: f64,
    attack_prec: f64,
    attack_rec: f64,
    attack_f1: f64,
}

fn evaluate_source(
    session: &mut Session,
    name: &str,
    rows: &[Row],
    idx2name: &HashMap<i64, String>,
    name2idx: &HashMap<String, i64>,
    normal_idx: i64,
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

    let mut dist_map: HashMap<&str, usize> = HashMap::new();
    for r in rows {
        *dist_map.entry(r.category.as_str()).or_insert(0) += 1;
    }
    let mut dist: Vec<_> = dist_map.into_iter().collect();
    dist.sort_by(|a, b| b.1.cmp(&a.1));
    println!(" Class distribution:");
    for (cat, n) in &dist {
        println!("   {:<44} {:>7}", cat, n);
    }

    let t0 = Instant::now();
    let requests: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
    let preds = predict_all(session, &requests, batch_size);
    let elapsed = t0.elapsed().as_secs_f64();

    // Drop rows whose category is unknown to the model
    let mut y_true: Vec<i64> = Vec::with_capacity(rows.len());
    let mut y_pred: Vec<i64> = Vec::with_capacity(rows.len());
    for (row, &pred) in rows.iter().zip(preds.iter()) {
        if let Some(&tidx) = name2idx.get(row.category.as_str()) {
            y_true.push(tidx);
            y_pred.push(pred);
        }
    }
    let total = y_true.len();
    let correct = y_true.iter().zip(y_pred.iter()).filter(|(t, p)| t == p).count();
    let multi_acc = correct as f64 / total as f64;

    println!(
        "\n Elapsed : {elapsed:.2}s  ({:.0} req/s)",
        total as f64 / elapsed
    );
    println!(" Multi-class accuracy : {multi_acc:.4}");

    let reports = compute_metrics(&y_true, &y_pred, idx2name);
    print_class_report(&reports);

    // Binary: Normal=0 vs Attack=1
    let bin_true: Vec<u8> = y_true.iter().map(|&x| if x == normal_idx { 0 } else { 1 }).collect();
    let bin_pred: Vec<u8> = y_pred.iter().map(|&x| if x == normal_idx { 0 } else { 1 }).collect();

    let tp = bin_true.iter().zip(bin_pred.iter()).filter(|(&t, &p)| t == 1 && p == 1).count();
    let fp = bin_true.iter().zip(bin_pred.iter()).filter(|(&t, &p)| t == 0 && p == 1).count();
    let fn_ = bin_true.iter().zip(bin_pred.iter()).filter(|(&t, &p)| t == 1 && p == 0).count();
    let tn = bin_true.iter().zip(bin_pred.iter()).filter(|(&t, &p)| t == 0 && p == 0).count();
    let bin_acc = (tp + tn) as f64 / total as f64;
    let atk_p = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
    let atk_r = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 0.0 };
    let atk_f1 = if atk_p + atk_r > 0.0 { 2.0 * atk_p * atk_r / (atk_p + atk_r) } else { 0.0 };

    println!("\n Binary (Normal vs Attack)");
    println!(
        "   accuracy={bin_acc:.4}  attack  prec={atk_p:.4}  recall={atk_r:.4}  f1={atk_f1:.4}"
    );
    println!("   TP={tp}  FP={fp}  FN={fn_}  TN={tn}");

    // Top confusion pairs
    let n_errors = y_true.iter().zip(y_pred.iter()).filter(|(t, p)| t != p).count();
    if n_errors > 0 {
        let mut pairs: HashMap<(i64, i64), usize> = HashMap::new();
        for (&t, &p) in y_true.iter().zip(y_pred.iter()) {
            if t != p {
                *pairs.entry((t, p)).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<_> = pairs.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        println!("\n Top confusion pairs ({n_errors} errors / {total}):");
        for ((t, p), cnt) in sorted.iter().take(8) {
            let tn = idx2name.get(t).map(|s| s.as_str()).unwrap_or("?");
            let pn = idx2name.get(p).map(|s| s.as_str()).unwrap_or("?");
            println!("   {tn:<44} -> {pn:<44} {cnt:>5}");
        }
    }

    Some(SourceResult {
        name: name.to_string(),
        samples: total,
        multi_acc,
        binary_acc: bin_acc,
        attack_prec: atk_p,
        attack_rec: atk_r,
        attack_f1: atk_f1,
    })
}

// ─── Benchmark ────────────────────────────────────────────────────────────────

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
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
        if batch > n {
            continue;
        }
        let chunk: Vec<&str> = (0..batch).map(|i| strs[(i * n / batch) % n]).collect();

        for _ in 0..5 {
            predict_batch(session, &chunk);
        }
        let reps = match batch {
            1 => 2_000,
            10 => 1_000,
            100 => 500,
            1_000 => 100,
            _ => 20,
        };
        let mut latencies: Vec<f64> = Vec::with_capacity(reps);
        for _ in 0..reps {
            let t = Instant::now();
            predict_batch(session, &chunk);
            latencies.push(t.elapsed().as_secs_f64() * 1_000.0 / batch as f64);
        }

        let mean_ms = latencies.iter().sum::<f64>() / reps as f64;
        let rps = 1_000.0 / mean_ms;
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (p50, p95, p99, max) = (
            percentile(&latencies, 50.0),
            percentile(&latencies, 95.0),
            percentile(&latencies, 99.0),
            *latencies.last().unwrap_or(&0.0),
        );
        let f = |v: f64| format!("{:.3}ms", v);
        println!(
            "  {:>6}  {:>10.0}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}",
            batch,
            rps,
            f(mean_ms),
            f(p50),
            f(p95),
            f(p99),
            f(max)
        );
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let model_path = "waf_model.onnx";
    let label_map_path = "label_map.json";
    let eval_dir = "eval_data";
    let unified_csv = "dataset_unified.csv";

    let batch_size: usize = get_flag(&args, "--batch-size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8192);
    let do_bench = args.iter().any(|a| a == "--bench");
    let bench_only = args.iter().any(|a| a == "--bench-only");

    let all_sources = ["legitimate", "malicious", "srbh", "csic", "huggingface", "modern"];
    let default_sources = ["legitimate", "malicious", "modern"];
    let sources: Vec<String> = match get_flag(&args, "--source").as_deref() {
        Some("all") => all_sources.iter().map(|s| s.to_string()).collect(),
        Some(s) => s.split(',').map(|x| x.trim().to_string()).collect(),
        None => default_sources.iter().map(|s| s.to_string()).collect(),
    };

    println!("Loading ONNX model : {model_path}");
    let mut session = Session::builder()
        .expect("ORT session builder failed")
        .commit_from_file(model_path)
        .expect("failed to load ONNX model — run train.py first");

    let (idx2name, name2idx) = load_label_map(label_map_path);
    let normal_idx = *name2idx.get("Normal").expect("Normal not in label_map");

    let mut class_list: Vec<_> = idx2name.iter().collect();
    class_list.sort_by_key(|(&k, _)| k);
    println!(
        "Classes ({})        : [{}]",
        idx2name.len(),
        class_list.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>().join(", ")
    );
    println!("Batch size         : {batch_size}");

    // ── Evaluation ────────────────────────────────────────────────────────────
    let mut results: Vec<SourceResult> = vec![];

    if !bench_only {
        for src in &sources {
            let csv_path = format!("{eval_dir}/{src}.csv");
            println!("\nLoading {src} from {csv_path} ...");
            let rows = load_csv(&csv_path);
            if let Some(r) = evaluate_source(
                &mut session,
                src,
                &rows,
                &idx2name,
                &name2idx,
                normal_idx,
                batch_size,
            ) {
                results.push(r);
            }
        }
    }

    // ── Summary table ─────────────────────────────────────────────────────────
    if results.len() > 1 {
        println!("\n{}", "=".repeat(80));
        println!(" SUMMARY");
        println!("{}", "=".repeat(80));
        println!(
            "  {:<14} {:>8}  {:>9}  {:>7}  {:>6}  {:>6}  {:>7}",
            "Source", "Samples", "Multi-Acc", "Bin-Acc", "Atk-P", "Atk-R", "Atk-F1"
        );
        println!("  {}", "-".repeat(72));
        for r in &results {
            println!(
                "  {:<14} {:>8}  {:>9.4}  {:>7.4}  {:>6.4}  {:>6.4}  {:>7.4}",
                r.name, r.samples, r.multi_acc, r.binary_acc,
                r.attack_prec, r.attack_rec, r.attack_f1
            );
        }
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
