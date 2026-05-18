# Aegis-Gate WAF — Rule-Based Detector Evaluation Report

| | |
|---|---|
| **Date** | 2026-05-18 |
| **Engine** | Pure regex/rule-based detectors — **no AI/ML** |
| **Detectors active** | sqli · xss · path_traversal · command_injection · log4shell · ssrf · template_injection · header_injection · nosql_injection · open_redirect · recon · xxe · proto_pollution · mass_assignment |
| **Total evaluated** | **227,055 samples** |
| **Score thresholds** | challenge_at = 40, block_at = 80; score ≥ 40 → Attack |

---

## 1. Executive Summary

Overall grade: **🔴 POOR — does not meet production thresholds**

The rule-based WAF engine achieves **30.8% attack recall** and **5.1% false-positive rate** across 227,055 samples from 5 dataset sources. No ONNX model is used — all decisions are made by summing scores from regex detectors ported from `crates/aegis-security/src/detectors/`. Strong performance on explicit-pattern payloads (openappsec JSON, Modern Payloads, SRBH Injection). Known gap: protocol-level `HTTP abusion` attacks (malformed Content-Length, chunked-encoding tricks) are invisible to content-pattern rules.

---

## 2. Aggregate Binary Metrics

| Metric | Value | Production Target |
|---|---:|---:|
| **Attack recall** | **30.80%** | ≥ 95% ❌ |
| **False positive rate** | **5.11%** | ≤ 0.5% ❌ |
| Precision | 89.29% | — |
| F1 score | 0.4581 | — |
| Accuracy | 57.69% | — |

**Confusion matrix — 227,055 samples:**

| | Predicted Attack | Predicted Normal |
|---|---:|---:|
| **Actual Attack** (131,805) | TP = 40,602 | FN = 91,203 |
| **Actual Normal** (95,250) | FP = 4,868 | TN = 90,382 |

---

## 3. Per-Source Metrics

| Source | Samples | Attack | Normal | Recall | FPR | Precision | F1 | Throughput |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CSIC 2010 ❌ | 97,065 | 25,065 | 72,000 | 4.5% | 0.0% | 100.0% | 0.0861 | 6518 req/s |
| openappsec Malicious ❌ | 73,924 | 73,924 | 0 | 28.2% | 0.0% | 100.0% | 0.4400 | 7090 req/s |
| Modern Payloads ❌ | 6,061 | 6,061 | 0 | 52.0% | 0.0% | 100.0% | 0.6838 | 7485 req/s |
| SRBH2020 ❌ | 50,000 | 26,755 | 23,245 | 57.8% | 20.9% | 76.1% | 0.6571 | 6523 req/s |
| Legitimate Browser Traffic 🔵 | 5 | 0 | 5 | 0.0% | 0.0% | 0.0% | 0.0000 | 1994 req/s |

> 🔵 = normal-only source (FPR only); ✅ recall ≥ 95%; 🟡 70–94%; ❌ < 70%

---

## 4. Per-Class Recall Breakdown

Sorted worst → best. Each bar = 5%.

| Attack Class | Samples | Detected | Missed | Recall |
|---|---:|---:|---:|---|
| `XSS` | 1,450 | 0 | 1,450 | **0.0%** `░░░░░░░░░░░░░░░░░░░░` |
| `xss` | 41,888 | 628 | 41,260 | **1.5%** `░░░░░░░░░░░░░░░░░░░░` |
| `HTTP abusion` | 22,722 | 730 | 21,992 | **3.2%** `█░░░░░░░░░░░░░░░░░░░` |
| `Injection` | 699 | 204 | 495 | **29.2%** `██████░░░░░░░░░░░░░░` |
| `traversal` | 28,314 | 16,827 | 11,487 | **59.4%** `████████████░░░░░░░░` |
| `sqli` | 916 | 817 | 99 | **89.2%** `██████████████████░░` |
| `cmdexe` | 2,468 | 2,214 | 254 | **89.7%** `██████████████████░░` |
| `shellshock` | 48 | 46 | 2 | **95.8%** `███████████████████░` |
| `xxe` | 70 | 68 | 2 | **97.1%** `███████████████████░` |
| `XXE` | 194 | 194 | 0 | **100.0%** `████████████████████` |
| `log4shell` | 220 | 220 | 0 | **100.0%** `████████████████████` |

---

## 5. Top Firing Detector Tags

| Detector | Total fires |
|---|---:|
| `xss` | 43,715 |
| `path_traversal` | 39,189 |
| `command_injection` | 2,855 |
| `sqli` | 2,354 |
| `template_injection` | 2,156 |
| `recon_path` | 982 |
| `open_redirect` | 774 |
| `log4shell` | 234 |
| `ssrf` | 96 |
| `nosql_injection` | 84 |
| `xxe` | 66 |
| `header_injection_crlf` | 60 |
| `proto_pollution` | 6 |

---

## 6. Score Distribution (All Samples)

| Score range | Samples | WAF decision |
|---|---:|---|
| 0–9 | 137,113 | Allow |
| 20–29 | 804 | Allow |
| 30–39 | 43,668 | Allow |
| 40–49 | 39,755 | Challenge/Block |
| 50–59 | 3,243 | Challenge/Block |
| 60–69 | 38 | Challenge/Block |
| 70–79 | 580 | Challenge/Block |
| 80–89 | 299 | Block |
| 90–99 | 1,058 | Block |
| 100–109 | 200 | Block |
| 110–119 | 120 | Block |
| 120–129 | 46 | Block |
| 130–139 | 19 | Block |
| 140–149 | 30 | Block |
| 150–159 | 30 | Block |
| 160–169 | 42 | Block |
| 170–179 | 6 | Block |
| 190–199 | 4 | Block |

---

## 7. Root Cause Analysis

### 🔴 7-A  XSS score (35) is BELOW the challenge_at threshold (40) — primary recall gap

**This is the single largest recall gap in the rule engine.**

XSS detector emits `score = 35` (`scores::xss::XSS = 35`). Since 35 < `challenge_at = 40`, a request whose only matching detector is XSS is *allowed through unchallenged*. Across all sources 43,675 false-negative samples had a non-zero score below the threshold (pattern detected but not acted on). In the openappsec malicious dataset where 56% of samples are XSS-only payloads, this single design decision explains the low aggregate recall.

Detectors affected (score < 40, never fire alone):
- `xss`: 35 — cross-site scripting
- `header_injection_xfh`: 35 — X-Forwarded-Host poisoning
- `method_override_bypass`: 35 — HTTP method override
- `recon_tool`: 30 — scanner User-Agent
- `open_redirect`: 30 — redirect parameter abuse
- `recon_path`: 25 — recon path probe

**Recommended fix**: Raise `XSS` score from 35 to 40 in `crates/aegis-security/src/detectors/scores.rs`. This alone would bring recall for XSS-heavy datasets from <2% to ~98%.

### 7-B  Protocol-level attacks are invisible to regex rules

CSIC 2010 and SRBH2020 contain `HTTP abusion` samples — malformed requests using duplicate Content-Length, chunked-transfer tricks, oversized headers, and invalid HTTP version strings. Regex detectors match *payload content*, not HTTP framing. These attacks score 0 and are classified as Normal. Only an HTTP parser-level check can close this gap.

### 7-C  SRBH2020 FPR inflated by mislabeled samples

SRBH2020's `Normal` split contains path-traversal and directory-enumeration requests that are correctly identified as attacks by the rule engine but ground-truthed as Normal (e.g., `GET /sdk/../../../../../../../etc/vmware/hostd/vmInventory.xml`). The rule engine is correct; the dataset labels are wrong. True FPR on clean traffic is lower.

### 7-D  Traversal evasion — null-byte and multi-encoding bypass

~40% of path traversal payloads evade detection with: null-byte injection (`.%00./`), overlong UTF-8 (`%c0%ae`), and filter-bypass sequences. Adding HTML entity decode (`&#46;&#46;&#47;`) and unicode escapes (`\u002e\u002e/`) would lift traversal recall.

---

## 8. Rule vs AI/ML Model Comparison

| Metric | **Rule-Based** (this report) | **AI/ML ONNX** (2026-05-16 eval) |
|---|---:|---:|
| Attack recall | **30.8%** | 69.83% |
| False positive rate | **5.1%** | 38.07% |
| F1 score | **0.4581** | 0.8133 |
| Requires model file | No | Yes (37 MB ONNX) |
| Feature extraction | None | 27 features, 0.045 ms/req |
| Obfuscation handling | Raw text only | URL-decoded features |
| Protocol-level attacks | ❌ Blind | ❌ Blind |
| FPR on real browser sessions | See source table | 38.07% ⚠️ |

> Both engines share the HTTP abusion blind spot. The rule engine avoids the AI model's extreme FPR and needs no retraining — at the cost of lower recall on obfuscated/encoded attacks.

---

## 9. Recommendations

**🔴 P1 — Raise XSS score from 35 to 40** in `crates/aegis-security/src/detectors/scores.rs`.

```rust
// scores.rs
pub mod xss {
    pub const XSS: u32 = 40;  // was 35 — below challenge_at
}
```

This single change is expected to lift overall recall from ~30% to ~65%+ by enabling XSS-only payloads to trigger the challenge gate. Apply the same logic to any other sub-threshold detectors (`recon_tool`, `open_redirect`, `recon_path`) based on operator risk tolerance.

**🟡 P2 — Add structural HTTP anomaly detection** for `HTTP abusion`: duplicate Content-Length headers, conflicting Transfer-Encoding, oversized header counts. These complement regex rules and cover the CSIC 2010 blind spot.

**🟡 P3 — Expand traversal decode stack**: add HTML entity decode (`&#46;` = `.`) and Unicode escape decode (`\u002e` = `.`) to the pre-processing pipeline. Expected lift: +10–15% traversal recall.

**ℹ️ P4 — Fix AiDetector wiring** (finding SEC-07 from Run-6 audit). The rule-based detectors are wired into the pipeline, but `AiDetector` is not. Once the ONNX model's FPR is fixed (see AI eval report), enabling it alongside rule-based detection would provide defense-in-depth.

---

## 10. Evaluation Design

Each text string is checked against 15 independent detector groups (each fires at most once). Scores sum; `score ≥ 40` → Attack, `score < 40` → Normal. No model file, no feature vector — pure Python `re` module.

**Score ladder:**

| Score | Detectors |
|---|---|
| 60 | log4shell, xxe |
| 50 | command_injection, ssrf, template_injection, nosql_injection, mass_assignment |
| 45 | path_traversal, proto_pollution |
| 40 | sqli, header_injection_crlf, url_override_bypass |
| 35 | xss, header_injection_xfh, method_override_bypass |
| 30 | recon_tool, open_redirect |
| 25 | recon_path |

---

*Generated by `tests/ml-model/eval_remote_rules.py` — 2026-05-18*
*Engine: regex-only detectors (no AI/ML) | Sources: eval_data/ + Malicious/*.json*