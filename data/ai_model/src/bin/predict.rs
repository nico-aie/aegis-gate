//! Single-request WAF inference — binary classifier (Normal / Attack) with score.
//!
//! Usage:
//!   cargo run --bin predict                         # run built-in examples
//!   cargo run --bin predict -- "GET /path?q=test"   # single-line request
//!   cargo run --bin predict -- $'GET /path\nUser-Agent: sqlmap\nCookie: id=1'
//!
//! Multi-line requests: use \n to separate the request line from headers.
//! Output: verdict (Normal / Attack) + P(Attack) score + non-zero features.

#[path = "../features.rs"]
mod features;

use features::{FEATURE_NAMES, NUM_FEATURES, extract_features};
use ndarray::Array2;
use ort::{inputs, session::Session};

// ─── Inference ────────────────────────────────────────────────────────────────

/// Returns (prob_attack, verdict_str).
///
/// ONNX binary model outputs:
///   "label"         → int64  (N,)    — 0=Normal, 1=Attack
///   "probabilities" → float32 (N, 2) — [P(Normal), P(Attack)]
fn predict(session: &mut Session, request: &str) -> (f32, &'static str) {
    let feat = extract_features(request);
    let mut mat = Array2::<f32>::zeros((1, NUM_FEATURES));
    for (j, &v) in feat.iter().enumerate() {
        mat[[0, j]] = v;
    }
    let input = ort::value::Tensor::from_array(mat).expect("tensor");
    let outputs = session.run(inputs!["X" => input]).expect("inference");

    // probabilities shape is (1, 2): [P(Normal), P(Attack)]
    let (_, probs) = outputs["probabilities"]
        .try_extract_tensor::<f32>()
        .expect("extract probabilities");

    // Handle both (1,2) and (1,1) output shapes defensively.
    let prob_attack = if probs.len() >= 2 { probs[1] } else { probs[0] };
    let verdict = if prob_attack >= 0.5 { "Attack" } else { "Normal" };
    (prob_attack, verdict)
}

// ─── Display ──────────────────────────────────────────────────────────────────

fn show(session: &mut Session, hint: &str, request: &str) {
    let divider = "─".repeat(68);
    println!();
    println!("┌─ [{hint}]");

    // Print request lines
    let lines: Vec<&str> = request.lines().collect();
    println!("│  Request  : {}", lines[0]);
    for hdr in &lines[1..] {
        println!("│             {hdr}");
    }
    println!("│  {divider}");

    let (prob_attack, verdict) = predict(session, request);
    let prob_normal = 1.0 - prob_attack;

    // Visual risk bar  ████░░░░░░
    let filled = (prob_attack * 20.0).round() as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(20 - filled);

    let risk_label = match (prob_attack * 100.0) as u32 {
        0..=19   => "LOW",
        20..=49  => "MEDIUM-LOW",
        50..=74  => "MEDIUM-HIGH",
        75..=89  => "HIGH",
        _        => "CRITICAL",
    };

    println!("│  Result   : {verdict}");
    println!("│  P(Attack): {prob_attack:.4}   P(Normal): {prob_normal:.4}");
    println!("│  Risk     : [{bar}] {risk_label}");

    // Non-zero features
    let feat = extract_features(request);
    let nonzero: Vec<_> = FEATURE_NAMES
        .iter()
        .zip(feat.iter())
        .filter(|(_, &v)| v != 0.0)
        .collect();
    if !nonzero.is_empty() {
        println!("│  Features :");
        for (name, val) in &nonzero {
            println!("│    {:<28} = {val}", name);
        }
    }
    println!("└─");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    // When running from the waf_infer directory, model sits one level up.
    let model_path = if std::path::Path::new("waf_model.onnx").exists() {
        "waf_model.onnx"
    } else {
        "../waf_model.onnx"
    };

    println!("Loading model : {model_path}");
    let mut session = Session::builder()
        .expect("ORT session builder failed")
        .commit_from_file(model_path)
        .expect("failed to load ONNX model — run: python train.py");

    println!("Classifier    : binary  (Normal = 0 | Attack = 1)");
    println!("Score         : P(Attack) — higher means more likely an attack");
    println!("{}", "═".repeat(70));

    // ── CLI mode ─────────────────────────────────────────────────────────────
    let cli: Vec<String> = std::env::args().skip(1).collect();
    if !cli.is_empty() {
        // Allow \n literal to embed headers: "GET /path\nUser-Agent: sqlmap"
        let request = cli.join(" ").replace("\\n", "\n");
        show(&mut session, "CLI", &request);
        return;
    }

    // ── Built-in examples ────────────────────────────────────────────────────
    let examples: &[(&str, &str)] = &[
        // ── Legitimate traffic ──────────────────────────────────────────────
        (
            "Normal — static file",
            "GET /static/css/main.min.css\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0\n\
             Referer: https://example.com/",
        ),
        (
            "Normal — JSON API",
            "POST /api/v1/login {\"username\":\"alice\",\"password\":\"s3cr3t!\"}\n\
             Content-Type: application/json\n\
             User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0",
        ),
        (
            "Normal — search with query params",
            "GET /search?q=laptop+bag&category=electronics&page=2\n\
             User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0\n\
             Referer: https://shop.example.com/",
        ),
        (
            "Normal — authenticated REST call",
            "PUT /api/v2/users/42 {\"name\":\"Bob\",\"email\":\"bob@example.com\"}\n\
             Content-Type: application/json\n\
             Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIn0.sig\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // ── SQL Injection ───────────────────────────────────────────────────
        (
            "SQLi — UNION SELECT",
            "GET /user?id=1'+UNION+SELECT+username,password+FROM+users--\n\
             User-Agent: Mozilla/5.0 Firefox/115.0",
        ),
        (
            "SQLi — scanner User-Agent",
            "GET /index.php?id=1\n\
             User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)\n\
             Cookie: session=abc123",
        ),
        (
            "SQLi — injection in Cookie",
            "GET /profile\n\
             User-Agent: Mozilla/5.0 Chrome/126.0\n\
             Cookie: user_id=1'; DROP TABLE users; --",
        ),

        // ── XSS ─────────────────────────────────────────────────────────────
        (
            "XSS — script tag in query",
            "GET /page?name=<script>alert(document.cookie)</script>\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),
        (
            "XSS — event handler in JSON body",
            "POST /comment {\"text\":\"<img src=x onerror=alert(1)>\"}\n\
             Content-Type: application/json\n\
             User-Agent: Mozilla/5.0 Firefox/115.0",
        ),

        // ── Path Traversal ───────────────────────────────────────────────────
        (
            "Path Traversal — /etc/passwd",
            "GET /download?file=../../../../etc/passwd\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // ── Command Injection ────────────────────────────────────────────────
        (
            "Command Injection — shell pipe",
            "GET /ping?host=127.0.0.1;cat+/etc/shadow\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // ── SSRF ─────────────────────────────────────────────────────────────
        (
            "SSRF — AWS metadata",
            "GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // ── Scanner ──────────────────────────────────────────────────────────
        (
            "Scanner — Nikto User-Agent",
            "GET /admin/config.php\n\
             User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)",
        ),
    ];

    for (hint, req) in examples {
        show(&mut session, hint, req);
    }
}
