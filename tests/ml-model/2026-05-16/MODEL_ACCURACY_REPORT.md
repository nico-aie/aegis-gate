# Aegis-Gate AI Model — Accuracy Report

| | |
|---|---|
| **Date** | 2026-05-16 |
| **Model** | `data/ai_model/waf_model.onnx` (37 MB, binary classifier) |
| **Attack dataset** | `tests/security/dataset/attacks_v4.ndjson` — 200,000 samples, 21 classes, 13 obfuscation techniques |
| **Clean dataset** | `tests/security/dataset/clean_baselines_v4.ndjson` — 10,000 samples |
| **Total evaluated** | **210,000 samples** |
| **Feature extractor** | Python port of `crates/aegis-security/src/detectors/ai/features.rs` (27 features) |
| **Overall grade** | 🔴 **POOR — does not meet production thresholds** |

---

## 1. Executive Summary

`waf_model.onnx` is a pure binary classifier: class `0 = Normal`, class `1 = Attack`. Evaluated against the full v4 adversarial corpus, the model **detects roughly 70% of attacks** while simultaneously **false-positiving on 38% of legitimate traffic** — far outside acceptable production margins on both dimensions.

Two issues must be addressed in priority order:

1. **FP rate 38%** — will cause widespread service disruption if deployed live; production target is ≤ 0.5%
2. **Attack recall 69.8%** — below the 95% target; critically low for `websocket` (22.8%), `header_injection` (24.3%), and `recon` (34.2%)

---

## 2. Binary Detection Metrics

| Metric | Value | Production target |
|---|---:|---:|
| **Attack recall** | **69.83%** | ≥ 95% ❌ |
| **False positive rate (clean traffic)** | **38.07%** | ≤ 0.5% ❌ |
| Precision | 97.35% | — |
| F1 score | 0.8133 | — |
| Overall accuracy | 69.46% | — |

**Confusion matrix — 210,000 samples:**

| | Predicted Attack | Predicted Normal |
|---|---:|---:|
| **Actual Attack** (200,000) | TP = 139,664 | FN = 60,336 |
| **Actual Normal** (10,000) | FP = 3,807 | TN = 6,193 |

**Model output distribution across full corpus:**

| Predicted label | Count | Share |
|---|---:|---:|
| Attack (class 1) | 143,471 | 68.32% |
| Normal (class 0) | 66,529 | 31.68% |

---

## 3. Per-Class Attack Recall

Sorted worst → best. Each bar segment represents 5%.

| Attack Class | Total | Detected | Missed | Recall |
|---|---:|---:|---:|---|
| `websocket` | 2,000 | 455 | 1,545 | **22.8%** `████░░░░░░░░░░░░░░░░` |
| `header_injection` | 6,000 | 1,459 | 4,541 | **24.3%** `████░░░░░░░░░░░░░░░░` |
| `recon` | 22,000 | 7,519 | 14,481 | **34.2%** `██████░░░░░░░░░░░░░░` |
| `jwt_abuse` | 3,000 | 1,199 | 1,801 | **40.0%** `███████░░░░░░░░░░░░░` |
| `open_redirect` | 6,000 | 3,041 | 2,959 | **50.7%** `██████████░░░░░░░░░░` |
| `xss` | 18,000 | 10,876 | 7,124 | **60.4%** `████████████░░░░░░░░` |
| `path_traversal` | 14,000 | 8,475 | 5,525 | **60.5%** `████████████░░░░░░░░` |
| `prototype_pollution` | 4,000 | 2,651 | 1,349 | **66.3%** `█████████████░░░░░░░` |
| `ssti` | 10,000 | 6,789 | 3,211 | **67.9%** `█████████████░░░░░░░` |
| `ldap_injection` | 6,000 | 4,148 | 1,852 | **69.1%** `█████████████░░░░░░░` |
| `nosql_injection` | 6,000 | 4,436 | 1,564 | **73.9%** `██████████████░░░░░░` |
| `rce_deserialization` | 4,000 | 2,990 | 1,010 | **74.8%** `██████████████░░░░░░` |
| `command_injection` | 14,000 | 10,588 | 3,412 | **75.6%** `███████████████░░░░░` |
| `log4shell` | 4,000 | 3,222 | 778 | **80.5%** `████████████████░░░░` |
| `evasion_chain` | 18,000 | 14,846 | 3,154 | **82.5%** `████████████████░░░░` |
| `sqli` | 18,000 | 15,237 | 2,763 | **84.7%** `████████████████░░░░` |
| `xxe` | 8,000 | 6,888 | 1,112 | **86.1%** `█████████████████░░░` |
| `ssrf` | 14,000 | 12,251 | 1,749 | **87.5%** `█████████████████░░░` |
| `graphql_abuse` | 4,000 | 3,890 | 110 | **97.2%** `███████████████████░` |
| `polyglot` | 16,000 | 15,704 | 296 | **98.2%** `███████████████████░` |
| `http_smuggling` | 3,000 | 3,000 | 0 | **100.0%** `████████████████████` |

**Key observations:**

- 10 out of 21 classes fall below 70% recall. These account for a large share of real-world traffic volume (`recon` 22k, `xss` 18k, `path_traversal` 14k, `command_injection` 14k).
- `websocket` and `header_injection` are near-blind-spots — the 27 features carry no signals specific to WebSocket upgrade patterns or CRLF injection in arbitrary headers.
- `http_smuggling`, `polyglot`, and `graphql_abuse` score well because their payloads happen to overlap strongly with the SQL/cmd/entropy features the extractor already measures.

**Top false negatives by class:**

| Class | Missed |
|---|---:|
| `recon` | 14,481 |
| `xss` | 7,124 |
| `path_traversal` | 5,525 |
| `header_injection` | 4,541 |
| `command_injection` | 3,412 |
| `ssti` | 3,211 |
| `evasion_chain` | 3,154 |
| `open_redirect` | 2,959 |
| `sqli` | 2,763 |
| `ldap_injection` | 1,852 |

---

## 4. Recall by Obfuscation Technique

| Technique | Description | Total | Detected | Recall |
|---|---|---:|---:|---|
| `html_dec` | HTML decimal entity `&#60;` | 5,825 | 580 | **10.0%** `█░░░░░░░░░░░░░░░░░░░` |
| `html_hex` | HTML hex entity `&#x3C;` | 2,655 | 345 | **13.0%** `██░░░░░░░░░░░░░░░░░░` |
| `uniesc` | Unicode escape `<` | 4,890 | 1,482 | **30.3%** `██████░░░░░░░░░░░░░░` |
| `urlenc3x` | Triple URL-encode `%252527` | 2,310 | 1,080 | **46.8%** `█████████░░░░░░░░░░░` |
| `case` | Alternating case `SeLeCt` | 20,788 | 11,396 | **54.8%** `██████████░░░░░░░░░░` |
| `tab` | Tab substitution for spaces | 2,826 | 1,865 | **66.0%** `█████████████░░░░░░░` |
| `urlenc2x` | Double URL-encode `%2527` | 15,562 | 11,178 | **71.8%** `██████████████░░░░░░` |
| `none` | No obfuscation | 94,100 | 69,909 | **74.3%** `██████████████░░░░░░` |
| `urlenc` | Single URL-encode `%27` | 36,967 | 29,328 | **79.3%** `███████████████░░░░░` |
| `sqlcomment` | SQL comment insertion `UN/**/ION` | 2,258 | 1,842 | **81.6%** `████████████████░░░░` |
| `ws` | Whitespace replacement `/**/` | 2,273 | 1,855 | **81.6%** `████████████████░░░░` |
| `hex` | Full hex encoding `%XX` per byte | 4,450 | 3,977 | **89.4%** `█████████████████░░░` |
| `newline` | Newline substitution `%0a` | 5,096 | 4,827 | **94.7%** `██████████████████░░` |

**Key observations:**

- `html_dec` and `html_hex` (10–13%) — the feature extractor has **no HTML entity pattern**. `url_decode()` only handles `%XX`; `&#XX;` and `&#xXX;` pass through undecoded, rendering all decoded-feature regexes ineffective against HTML-encoded payloads.
- The `none` baseline is only 74.3%, meaning roughly 1 in 4 unobfuscated payloads is missed outright — a fundamental coverage gap independent of obfuscation.
- `case` at 54.8% despite all regexes using `(?i)` suggests the model relies heavily on case-sensitive structural features (entropy, character ratios) that alternating-case obfuscation disrupts.

---

## 5. Inference Latency

Benchmark: 1,000 single-request inferences on CPU.

| Metric | Value |
|---|---|
| Mean | 0.045 ms |
| p50 | 0.043 ms |
| p95 | 0.064 ms |
| p99 | 0.102 ms |
| Max | 0.345 ms |
| **Throughput (batch 4,096)** | **9,256 req/s** |

Latency is well within budget — sub-0.1ms at p99. Throughput of 9k+ req/s on a single CPU core is sufficient for the WAF hot path.

---

## 6. Root Cause Analysis

### 6-A  Why is the FP rate 38%?

The feature extractor measures signals such as `sql_keyword_count`, `special_char_count`, and Shannon entropy on the raw request string. Many legitimate URLs naturally contain SQL keywords (`from`, `where`, `order`, `select` appearing in field names or path segments), high special-character density (`&`, `=`, `+` in query strings), or high entropy (base64 tokens, UUIDs, session IDs). The model learned a decision boundary from a training corpus that lacked sufficient clean-traffic diversity, causing it to classify too many benign patterns as attacks.

A compounding factor: `extract_confidence()` in `model.rs` is currently a **stub that always returns `None`**, which forces `confidence = 1.0`. This makes the confidence threshold gate a no-op — there is no way to tune precision/recall at inference time without fixing the stub first.

### 6-B  Why is recall low for specific classes?

- **`websocket`** — WebSocket-specific patterns (Upgrade header, frame opcodes, masking keys) are absent from all 27 features; the model has no signal to work with.
- **`header_injection`** — CRLF injection typically lives in non-standard header values. `build_request_string` only folds in `User-Agent`, `Cookie`, and `Referer`; all other headers are discarded before feature extraction.
- **`recon`** — Reconnaissance paths like `/.env`, `/.git/config`, `/actuator/health` have low entropy and few special characters, making them indistinguishable from normal requests at the feature level.
- **`jwt_abuse`** — A JWT is a valid base64 string; `alg=none` manipulation is buried inside a JSON payload. None of the 27 features have JWT structural patterns.
- **`open_redirect`** — Redirect payloads (`//evil.com`, `@confusion`) often look like ordinary URLs with slightly unusual path structure; feature signals are weak.

### 6-C  Why does HTML entity obfuscation achieve 10–13% bypass?

`url_decode()` in `features.rs` decodes only `%XX` percent-encoding. HTML entities (`&#60;`, `&#x3C;`) are passed through unchanged. All decoded-feature regex patterns (`sql_keyword_count`, `xss_pattern_count`, etc.) then run against the still-encoded string, producing zero matches on the attack payload. This is a complete blind spot.

---

## 7. Recommendations

### 🔴 P1 — Fix `extract_confidence()` to enable threshold tuning

The probabilities output already exposes `[batch, 2]` softmax values. The stub simply needs to read them:

```rust
// crates/aegis-security/src/detectors/ai/model.rs
fn extract_confidence(outputs: &SessionOutputs, class_idx: i64) -> Option<f32> {
    let entry = outputs.get("probabilities")?;
    let (_shape, data) = entry.try_extract_tensor::<f32>().ok()?;
    data.get(class_idx as usize).filter(|p| p.is_finite()).copied()
}
```

Once confidence values are real, sweep thresholds from 0.5 to 0.95 on a held-out validation set. A threshold around 0.75–0.85 is likely to bring FP rate below 1% while retaining most of the attack recall.

### 🔴 P2 — Add HTML entity decoding to the feature extractor

```rust
// After url_decode(), add a second decode pass:
fn html_entity_decode(s: &str) -> String {
    // Replace &#DD; (decimal) and &#xHH; (hex) with the corresponding char
}
// Then run decoded-feature regexes against html_entity_decode(url_decode(full))
```

This single change is expected to lift `html_dec` recall from 10% to well above 60%.

### 🟡 P3 — Expand header coverage in `build_request_string`

Currently only `User-Agent`, `Cookie`, and `Referer` are folded into the feature string. Adding security-relevant headers will meaningfully improve `header_injection` recall:

```rust
for hdr in ["user-agent", "cookie", "referer",
            "x-forwarded-for", "x-real-ip",
            "content-type", "authorization",
            "x-forwarded-host", "x-original-url"] {
    // ... existing fold-in logic
}
```

### 🟡 P4 — Retrain on v4 binary corpus

The v4 generator at `tests/security/dataset/generator/generate_v4.py` produces a balanced, reproducible corpus. Collapse all 21 attack classes into label `1` and the clean baseline into label `0`, then retrain `waf_model.onnx`. Oversample the lowest-recall classes (`websocket`, `header_injection`, `recon`, `jwt_abuse`) to at least 5,000 examples each. Re-evaluate with this script after training.

### ℹ️ Notes

- `AiDetector` is currently **not wired into `pipeline.inbound()`** (finding SEC-07 from the Run-6 audit). These numbers reflect offline batch evaluation only; live WAF behavior will differ.
- The Python feature extractor is a manual port and may have minor floating-point deviations from the Rust implementation for edge cases near classification boundaries.

---

## 8. Evaluation Design

`waf_model.onnx` is a pure binary classifier. `label_map.json` maps `{"0": "Normal", "1": "Attack"}`; the `probabilities` output has shape `[batch, 2]`. All 21 v4 attack classes are treated as ground-truth `Attack = 1`; the clean baseline is ground-truth `Normal = 0`. Per-class recall measures how well the model's binary `Attack` decision generalises across distinct attack families and obfuscation layers without any per-class fine-tuning.

Feature extraction uses a 27-feature Python port of `crates/aegis-security/src/detectors/ai/features.rs`. Inference runs via ONNX Runtime 1.23.2 with batch size 4,096.

---

*Generated by `tests/ml-model/eval_v4.py` — 2026-05-16*  
*Model: `data/ai_model/waf_model.onnx` | Dataset: v4 adversarial corpus (200k attacks + 10k clean)*
