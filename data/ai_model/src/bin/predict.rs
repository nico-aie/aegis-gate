/// Single-request WAF inference tool.
///
/// Usage:
///   cargo run --bin predict                        # run hardcoded examples
///   cargo run --bin predict -- "GET /login?user=admin' OR 1=1--"
///   cargo run --bin predict -- "POST /api/upload" "username=test&pass=hello"
///
/// Request format: METHOD /path?query [body]
/// All three parts are space-separated, matching how extract_features() parses them.

#[path = "../features.rs"]
mod features;

use features::{FEATURE_NAMES, NUM_FEATURES, extract_features};
use ndarray::Array2;
use ort::{inputs, session::Session};
use std::collections::HashMap;

fn load_label_map(path: &str) -> HashMap<i64, String> {
    let raw: HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("cannot read label_map.json"))
            .expect("invalid JSON");
    raw.iter().map(|(k, v)| (k.parse::<i64>().unwrap(), v.clone())).collect()
}

fn predict_one(session: &mut Session, request: &str) -> i64 {
    let feat = extract_features(request);
    let mut mat = Array2::<f32>::zeros((1, NUM_FEATURES));
    for (j, &v) in feat.iter().enumerate() {
        mat[[0, j]] = v;
    }
    let input = ort::value::Tensor::from_array(mat).expect("tensor creation failed");
    let outputs = session.run(inputs!["X" => input]).expect("inference failed");
    let (_, labels) = outputs["label"]
        .try_extract_tensor::<i64>()
        .expect("extract label tensor failed");
    labels[0]
}

fn print_features(request: &str) {
    let feat = extract_features(request);
    println!("  Features:");
    for (name, &val) in FEATURE_NAMES.iter().zip(feat.iter()) {
        if val != 0.0 {
            println!("    {:<28} = {}", name, val);
        }
    }
}

fn run(session: &mut Session, idx2name: &HashMap<i64, String>, request: &str) {
    println!("\nRequest : {:?}", request);
    let label_idx = predict_one(session, request);
    let label = idx2name.get(&label_idx).map(|s| s.as_str()).unwrap_or("Unknown");
    println!("Result  : {} (class {})", label, label_idx);
    print_features(request);
}

fn main() {
    let model_path = "waf_model.onnx";
    let label_map_path = "label_map.json";

    println!("Loading model: {model_path}");
    let mut session = Session::builder()
        .expect("ORT session builder failed")
        .commit_from_file(model_path)
        .expect("failed to load ONNX model");

    let idx2name = load_label_map(label_map_path);
    println!(
        "Classes: {}",
        {
            let mut v: Vec<_> = idx2name.iter().collect();
            v.sort_by_key(|(&k, _)| k);
            v.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>().join(", ")
        }
    );
    println!("{}", "=".repeat(72));

    // ── CLI mode: use argument(s) as the request string ───────────────────────
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if !cli_args.is_empty() {
        let request = cli_args.join(" ");
        run(&mut session, &idx2name, &request);
        return;
    }

    // ── Hardcoded examples ────────────────────────────────────────────────────
    let examples: &[(&str, &str)] = &[
        // (label hint, request string)
        ("Normal",         "GET /index.html HTTP/1.1"),
        ("Normal",         "POST /api/login HTTP/1.1 username=alice&password=secret123"),
        ("SQLi",           "GET /search?q=1'+OR+'1'='1 HTTP/1.1"),
        ("SQLi",           "GET /user?id=1 UNION SELECT username,password FROM users-- HTTP/1.1"),
        ("XSS",            "GET /page?name=<script>alert(document.cookie)</script> HTTP/1.1"),
        ("XSS",            "POST /comment HTTP/1.1 body=<img src=x onerror=alert(1)>"),
        ("Path Traversal", "GET /files?path=../../../../etc/passwd HTTP/1.1"),
        ("Command Inj",    "GET /ping?host=127.0.0.1;cat /etc/shadow HTTP/1.1"),
        ("SSRF",           "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1"),
        ("Scanner",        "GET /admin HTTP/1.1 User-Agent: sqlmap/1.7"),
    ];

    for (hint, req) in examples {
        println!("\n[Expected: {}]", hint);
        run(&mut session, &idx2name, req);
    }
}
