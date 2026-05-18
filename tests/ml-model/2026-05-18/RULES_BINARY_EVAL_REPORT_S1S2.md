# Aegis-Gate WAF — Binary Rule Match Evaluation (No Scoring)

| | |
|---|---|
| **Date** | 2026-05-18 |
| **Engine** | Pure regex pattern match — no score thresholds, no AI/ML |
| **Rule** | ANY detector fires → Attack; no match → Normal |
| **Code version** | S1 (entity+unicode decode) + S2 (mass-assign 27 keys, query/form/multipart) |
| **Detectors** | sqli, xss, path_traversal, log4shell, shellshock, command_injection, ssrf, template_injection, header_injection, nosql_injection, open_redirect, recon, xxe, proto_pollution, mass_assignment |
| **Total evaluated** | **227,055 samples** |

---

## 1. Executive Summary

Overall grade: **🔴 POOR** — recall **63.9%**, FPR **5.9%**

This evaluation removes the score threshold and asks: *does the regex rule set correctly discriminate attack vs normal labels?* A match on any pattern = Attack prediction. This gives the theoretical maximum recall achievable from the current rule patterns.

---

## 2. Aggregate Metrics

| Metric | Value | Target |
|---|---:|---:|
| **Attack recall** | **63.94%** | ≥ 95% ❌ |
| **FPR (false positive rate)** | **5.95%** | ≤ 0.5% ❌ |
| Precision | 93.70% | — |
| F1 | 0.7601 | — |
| Accuracy | 76.57% | — |

**Confusion matrix (227,055 samples):**

| | Predicted Attack | Predicted Normal |
|---|---:|---:|
| **Actual Attack** (131,805) | TP = 84,279 | FN = 47,526 |
| **Actual Normal** (95,250) | FP = 5,665 | TN = 89,585 |

---

## 3. Per-Source Results

| Source | Samples | Attack | Normal | Recall | FPR | Precision | F1 | req/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CSIC 2010 ❌ | 97,065 | 25,065 | 72,000 | 10.5% | 0.0% | 100.0% | 0.1901 | 9905 |
| openappsec Malicious 🟡 | 73,924 | 73,924 | 0 | 83.7% | 0.0% | 100.0% | 0.9111 | 9384 |
| Modern Payloads ❌ | 6,061 | 6,061 | 0 | 61.1% | 0.0% | 100.0% | 0.7584 | 13870 |
| SRBH2020 ❌ | 50,000 | 26,755 | 23,245 | 60.1% | 24.4% | 74.0% | 0.6635 | 8931 |
| Legitimate Browser 🔵 | 5 | 0 | 5 | 0.0% | 0.0% | 0.0% | 0.0000 | 5334 |

> 🔵 normal-only; ✅ recall ≥ 95%; 🟡 70–94%; ❌ < 70%

---

## 4. Per-Class Recall

Sorted worst → best.

| Class | Source | Samples | Detected | Missed | Recall |
|---|---|---:|---:|---:|---|
| `HTTP abusion` | CSIC | 22,722 | 920 | 21,802 | **4.0%** `█░░░░░░░░░░░░░░░░░░░` |
| `Injection` | CSIC | 699 | 204 | 495 | **29.2%** `██████░░░░░░░░░░░░░░` |
| `traversal` | JSON | 28,314 | 16,827 | 11,487 | **59.4%** `████████████░░░░░░░░` |
| `Manipulation` | Mal | 28,314 | 16,856 | 11,458 | **59.5%** `████████████░░░░░░░░` |
| `sqli` | JSON | 916 | 799 | 117 | **87.2%** `█████████████████░░░` |
| `Injection` | Mal | 3,432 | 3,058 | 374 | **89.1%** `██████████████████░░` |
| `cmdexe` | JSON | 2,468 | 2,212 | 256 | **89.6%** `██████████████████░░` |
| `XSS` | CSIC | 1,450 | 1,314 | 136 | **90.6%** `██████████████████░░` |
| `shellshock` | JSON | 48 | 46 | 2 | **95.8%** `███████████████████░` |
| `XXE` | Mal | 70 | 68 | 2 | **97.1%** `███████████████████░` |
| `xxe` | JSON | 70 | 68 | 2 | **97.1%** `███████████████████░` |
| `XSS` | Mal | 41,888 | 41,650 | 238 | **99.4%** `████████████████████` |
| `xss` | JSON | 41,888 | 41,650 | 238 | **99.4%** `████████████████████` |
| `XXE` | CSIC | 194 | 194 | 0 | **100.0%** `████████████████████` |
| `Log4Shell` | Mal | 220 | 220 | 0 | **100.0%** `████████████████████` |
| `log4shell` | JSON | 220 | 220 | 0 | **100.0%** `████████████████████` |

---

## 5. Detector Firing Frequency

Which detector fired most across all attack samples:

| Detector | Total fires |
|---|---:|
| `xss` | 43,748 |
| `path_traversal` | 39,189 |
| `command_injection` | 2,863 |
| `sqli` | 2,181 |
| `template_injection` | 2,156 |
| `recon` | 982 |
| `open_redirect` | 774 |
| `log4shell` | 136 |
| `shellshock` | 102 |
| `ssrf` | 96 |
| `nosql_injection` | 84 |
| `xxe` | 66 |
| `header_injection` | 60 |
| `proto_pollution` | 6 |

---

## 6. Analysis of False Negatives (Missed Attacks)

### 6-A  HTTP abusion (structural attacks)

CSIC 2010 and SRBH2020 contain `HTTP abusion` — protocol-level attacks invisible to content regex (malformed Content-Length, chunked-encoding tricks). These score 0 even in the pattern-match evaluation. Maximum achievable recall for CSIC 2010 is ~9.3% (only XSS + Injection + XXE categories are content-pattern detectable).

### 6-B  SRBH2020 `Normal` mislabels

SRBH2020's `Normal` split contains confirmed path-traversal requests labeled Normal. The rule engine correctly fires on these, which inflates the apparent FPR.

### 6-C  Traversal evasion patterns not yet covered

~40% of `traversal` samples use null-byte sequences and overlong UTF-8 that survive triple URL-decode. Adding HTML-entity decode (`&#46;` → `.`) and unicode-escape decode would close most of this gap.

---

## 7. Evaluation Design

No scoring, no thresholds. Each request text is passed through `decode()` (up to 3× URL-decode + NUL strip) then matched against all detector patterns. **Any match = Attack prediction.** Compares against dataset ground-truth labels.

This represents the theoretical ceiling of the current regex rule set — actual WAF behavior in production uses score thresholds (challenge_at = 40, block_at = 80) which will reduce both recall and FPR relative to these numbers.

---

*Generated by `tests/ml-model/eval_rules_binary.py` — 2026-05-18*