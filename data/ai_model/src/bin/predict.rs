//! Single-request WAF inference — binary classifier (Normal / Attack) with score.
//!
//! Usage:
//!   cargo run --bin predict                                        # built-in examples
//!   cargo run --bin predict -- "GET /path?q=test"                  # single-line request
//!   cargo run --bin predict -- "GET /path\nUser-Agent: sqlmap"     # with headers (\n literal)
//!
//! Output: verdict (Normal / Attack), P(Attack) score, risk bar, non-zero features.

#[path = "../features.rs"]
mod features;

use features::{FEATURE_NAMES, NUM_FEATURES, extract_features};
use ndarray::Array2;
use ort::{inputs, session::Session};

// ─── Inference ────────────────────────────────────────────────────────────────

struct Prediction {
    label:       i64,   // 0 = Normal, 1 = Attack  (from ONNX "label" output)
    prob_attack: f32,   // P(Attack) ∈ [0, 1]      (from ONNX "probabilities" output)
    feat:        [f32; NUM_FEATURES],
}

impl Prediction {
    fn verdict(&self) -> &'static str {
        if self.label == 1 { "Attack" } else { "Normal" }
    }
    fn prob_normal(&self) -> f32 {
        1.0 - self.prob_attack
    }
}

/// Extract features once, run ONNX session, return label + scores + feat array.
/// Mirrors the tensor layout handling in main.rs `predict_batch`.
fn infer(session: &mut Session, request: &str) -> Prediction {
    let feat = extract_features(request);

    let mut mat = Array2::<f32>::zeros((1, NUM_FEATURES));
    for (j, &v) in feat.iter().enumerate() {
        mat[[0, j]] = v;
    }

    let input   = ort::value::Tensor::from_array(mat).expect("tensor creation failed");
    let outputs = session.run(inputs!["X" => input]).expect("inference failed");

    // "label" → int64 (1,) — 0=Normal, 1=Attack
    let (_, labels) = outputs["label"]
        .try_extract_tensor::<i64>()
        .expect("extract label tensor");
    let label = labels[0];

    // "probabilities" → float32 (1, 2) — [P(Normal), P(Attack)]
    let (_, probs) = outputs["probabilities"]
        .try_extract_tensor::<f32>()
        .expect("extract probabilities tensor");

    // Handle both (1, 2) flat layout and (1,) single-score layout.
    let n_cols      = probs.len().max(1);
    let prob_attack = if n_cols >= 2 { probs[1] } else { probs[0] };

    Prediction { label, prob_attack, feat }
}

// ─── Display ──────────────────────────────────────────────────────────────────

fn show(session: &mut Session, hint: &str, request: &str) {
    let divider = "─".repeat(68);
    println!();
    println!("┌─ [{hint}]");

    let lines: Vec<&str> = request.lines().collect();
    println!("│  Request  : {}", lines[0]);
    for hdr in &lines[1..] {
        println!("│             {hdr}");
    }
    println!("│  {divider}");

    // Single extract_features + session call — features reused for display below.
    let p = infer(session, request);

    let filled    = (p.prob_attack * 20.0).round() as usize;
    let bar       = "█".repeat(filled) + &"░".repeat(20 - filled);
    let risk_label = match (p.prob_attack * 100.0) as u32 {
        0..=19  => "LOW",
        20..=49 => "MEDIUM-LOW",
        50..=74 => "MEDIUM-HIGH",
        75..=89 => "HIGH",
        _       => "CRITICAL",
    };

    println!("│  Result   : {}", p.verdict());
    println!("│  P(Attack): {:.4}   P(Normal): {:.4}", p.prob_attack, p.prob_normal());
    println!("│  Risk     : [{bar}] {risk_label}");

    let nonzero: Vec<_> = FEATURE_NAMES
        .iter()
        .zip(p.feat.iter())
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
    // Support running from either ml_waf/ or ml_waf/waf_infer/
    let model_path = if std::path::Path::new("waf_model.onnx").exists() {
        "waf_model.onnx"
    } else {
        "../waf_model.onnx"
    };

    println!("Loading model : {model_path}");
    let mut session = Session::builder()
        .expect("ORT session builder failed")
        .commit_from_file(model_path)
        .expect("failed to load ONNX model — run train.py first");

    println!("Classifier    : binary  (Normal = 0 | Attack = 1)");
    println!("Score         : P(Attack) — higher means more likely an attack");
    println!("{}", "=".repeat(70));

    // ── CLI mode ──────────────────────────────────────────────────────────────
    let cli: Vec<String> = std::env::args().skip(1).collect();
    if !cli.is_empty() {
        // Allow \n literal to embed headers: "GET /path\nUser-Agent: sqlmap"
        let request = cli.join(" ").replace("\\n", "\n");
        show(&mut session, "CLI", &request);
        return;
    }

    // ── Built-in examples ─────────────────────────────────────────────────────
    let examples: &[(&str, &str)] = &[
        // Normal traffic
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

        // SQL Injection
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

        // XSS
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

        // Path Traversal
        (
            "Path Traversal — /etc/passwd",
            "GET /download?file=../../../../etc/passwd\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // Command Injection
        (
            "Command Injection — shell pipe",
            "GET /ping?host=127.0.0.1;cat+/etc/shadow\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // SSRF
        (
            "SSRF — AWS metadata",
            "GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/\n\
             User-Agent: Mozilla/5.0 Chrome/126.0",
        ),

        // Scanner
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
