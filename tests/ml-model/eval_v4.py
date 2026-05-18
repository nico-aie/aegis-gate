#!/usr/bin/env python3
"""
AI model evaluation against v4 adversarial dataset.

Ports the 27-feature extractor from:
  crates/aegis-security/src/detectors/ai/features.rs

Usage:
    python3 tests/ml-model/eval_v4.py [--out-dir tests/ml-model/2026-05-16] [--sample N]

Outputs (in --out-dir):
    eval_results.json       raw numbers (per-class + binary)
    MODEL_ACCURACY_REPORT.md  human-readable report
"""

import argparse
import json
import math
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import onnxruntime as ort

# ── Binary model class layout ─────────────────────────────────────────────────
# The shipped waf_model.onnx is a PURE BINARY classifier.
#   label_map.json: {"0": "Normal", "1": "Attack"}
#   probabilities output shape: [batch, 2]
#
# Evaluation is binary-only:
#   - All 21 v4 attack classes → expected label = ATTACK_CLASS_IDX (1)
#   - Clean baseline            → expected label = NORMAL_CLASS_IDX (0)
# No multi-class mapping is needed or meaningful.

MODEL_LABEL_MAP = {
    0: "Normal",
    1: "Attack",
}
NORMAL_CLASS_IDX = 0
ATTACK_CLASS_IDX = 1

# ── Feature extraction (exact port of features.rs) ───────────────────────────

NUM_FEATURES = 27

FEATURE_NAMES = [
    "request_len", "method_id", "path_len", "query_len", "body_len",
    "num_params", "entropy", "digit_ratio", "upper_ratio", "special_char_count",
    "single_quote_count", "double_quote_count", "angle_bracket_count",
    "semicolon_count", "pct_encoded_count", "sql_keyword_count",
    "xss_pattern_count", "path_traversal_count", "cmd_injection_count",
    "scanner_count", "ssrf_count", "php_pattern_count", "null_byte_count",
    "hex_encode_count", "crlf_inject_count", "double_encode_count",
    "ssti_count",
]

# Compiled regex patterns — mirroring features.rs Lazy<Regex> statics
_SQL_RE = re.compile(
    r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|where|from|having|order|group|join|table|database|schema|char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b"
)
_XSS_RE = re.compile(
    r"(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus=|alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\(|<iframe|<img\s|<svg|srcdoc=)"
)
_SCANNER_RE = re.compile(
    r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wfuzz|w3af|commix)"
)
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_CMD_RE = re.compile(r"[;|]|\|\||&&|\$\(|`[^`]*`")
_SSRF_RE = re.compile(
    r"(?i)(?:127\.0\.0\.1|localhost|169\.254\.|0\.0\.0\.0|::1|file://|dict://|gopher://|ftp://)"
)
_PHP_RE = re.compile(
    r"(?i)(?:\.php|eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)"
)
_NULL_BYTE_RE = re.compile(r"%00|\\x00|\\u0000")
_HEX_ENCODE_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
_CRLF_RE = re.compile(r"%0[aAdD]|\\r\\n|\r\n")
_DBL_ENC_RE = re.compile(r"%25[0-9a-fA-F]{2}")
_SSTI_RE = re.compile(
    r"(\{\{.*?\}\})|(\$\{[^}]{1,200}\})|(#\{[^}]{1,200}\})|(<%=.*?%>)|(\?\s*new\s*\()|(__(class|mro|subclasses|globals|builtins|import)__)|(freemarker\.template|velocity\.tools)|(\{\s*\d+\s*\*\s*\d+\s*\})",
    re.IGNORECASE | re.DOTALL
)

_METHOD_IDS = {"GET": 0.0, "POST": 1.0, "PUT": 2.0, "DELETE": 3.0,
               "PATCH": 4.0, "HEAD": 5.0, "OPTIONS": 6.0}


def _url_decode(s: str) -> str:
    """Decode %XX percent-encoding — mirrors url_decode() in features.rs."""
    out = []
    i = 0
    b = s.encode("latin-1", errors="replace")
    while i < len(b):
        if b[i] == ord('%') and i + 2 < len(b):
            hi_c = chr(b[i + 1])
            lo_c = chr(b[i + 2])
            try:
                val = int(hi_c + lo_c, 16)
                out.append(chr(val))
                i += 3
                continue
            except ValueError:
                pass
        out.append(chr(b[i]))
        i += 1
    return "".join(out)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[ord(c) & 0xFF] += 1
    n = len(s)
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_features(request: str) -> list:
    """
    Extract 27 WAF features from a raw HTTP request string.
    Format: "METHOD /path?query body\nHeader: value\n..." — matches AiDetector::build_request_string.
    Mirrors crates/aegis-security/src/detectors/ai/features.rs exactly.
    """
    # Split first line from headers (same as Rust: split on first \n)
    nl_pos = request.find('\n')
    if nl_pos != -1:
        first_line = request[:nl_pos]
        headers_text = request[nl_pos + 1:].replace('\n', ' ')
    else:
        first_line = request
        headers_text = ""

    # Three-piece split on first line: METHOD / URL / BODY
    parts = first_line.split(" ", 2)
    method = parts[0] if len(parts) > 0 else "GET"
    url = parts[1] if len(parts) > 1 else "/"
    body = parts[2] if len(parts) > 2 else ""

    if "?" in url:
        qpos = url.index("?")
        path = url[:qpos]
        query = url[qpos + 1:]
    else:
        path = url
        query = ""

    # "full" = URL + body + header values (matches Rust's full string)
    full = url
    if body:
        full = f"{full} {body}"
    if headers_text:
        full = f"{full} {headers_text}"

    full_dec = _url_decode(full)

    n = max(len(full), 1)

    num_params = (0 if not query else query.count("&") + 1) + \
                 (0 if not body else body.count("&") + 1)

    digit_count = sum(1 for c in full if c.isdigit())
    upper_count = sum(1 for c in full if c.isupper())
    special_count = sum(1 for c in full if c in "'\"<>;=%&+")

    full_dec_lower = full_dec.lower()
    path_traversal = full_dec_lower.count("../")

    method_id = _METHOD_IDS.get(method.upper(), 7.0)

    feats = [
        float(len(request)),                            # 0  request_len (incl. headers)
        method_id,                                      # 1  method_id
        float(len(path)),                               # 2  path_len
        float(len(query)),                              # 3  query_len
        float(len(body)),                               # 4  body_len (first line only)
        float(num_params),                              # 5  num_params
        _shannon_entropy(full),                         # 6  entropy
        digit_count / n,                                # 7  digit_ratio
        upper_count / n,                                # 8  upper_ratio
        float(special_count),                           # 9  special_char_count
        float(full.count("'")),                         # 10 single_quote_count
        float(full.count('"')),                         # 11 double_quote_count
        float(full.count("<") + full.count(">")),       # 12 angle_bracket_count
        float(full.count(";")),                         # 13 semicolon_count
        float(len(_PCT_RE.findall(full))),              # 14 pct_encoded_count  (raw)
        float(len(_SQL_RE.findall(full_dec))),          # 15 sql_keyword_count  (decoded)
        float(len(_XSS_RE.findall(full_dec))),          # 16 xss_pattern_count  (decoded)
        float(path_traversal),                          # 17 path_traversal_count
        float(len(_CMD_RE.findall(full_dec))),          # 18 cmd_injection_count (decoded)
        float(len(_SCANNER_RE.findall(full_dec))),      # 19 scanner_count       (decoded)
        float(len(_SSRF_RE.findall(full_dec))),         # 20 ssrf_count          (decoded)
        float(len(_PHP_RE.findall(full_dec))),          # 21 php_pattern_count   (decoded)
        float(len(_NULL_BYTE_RE.findall(full))),        # 22 null_byte_count     (raw)
        float(len(_HEX_ENCODE_RE.findall(full))),       # 23 hex_encode_count    (raw)
        float(len(_CRLF_RE.findall(full))),             # 24 crlf_inject_count   (raw)
        float(len(_DBL_ENC_RE.findall(full))),          # 25 double_encode_count (raw)
        float(len(_SSTI_RE.findall(full_dec))),         # 26 ssti_count          (decoded)
    ]
    return feats


def build_request_string(case: dict) -> str:
    """
    Build the multi-line request string that AiDetector::build_request_string produces:
        "METHOD /path?query body\nUser-Agent: ...\nCookie: ...\nReferer: ..."
    Only User-Agent, Cookie, Referer are folded in — same as the AiDetector.
    Body is capped at 4 KiB.
    """
    method = case.get("method", "GET")
    path = case.get("path", "/")
    query = case.get("query", "")
    body = case.get("body", "")
    headers = case.get("headers", {})

    url = f"{path}?{query}" if query else path
    body_peek = body[:4096] if body else ""  # 4KB cap, same as AiDetector
    if body_peek:
        line = f"{method} {url} {body_peek}"
    else:
        line = f"{method} {url}"

    # Fold in the three headers AiDetector includes
    header_lines = []
    for hdr, canonical in [("user-agent", "User-Agent"), ("cookie", "Cookie"), ("referer", "Referer")]:
        val = headers.get(hdr, headers.get(hdr.title(), ""))
        if val:
            header_lines.append(f"{canonical}: {val}")

    if header_lines:
        return line + "\n" + "\n".join(header_lines)
    return line


# ── ONNX inference ────────────────────────────────────────────────────────────

def load_model(model_path: str) -> ort.InferenceSession:
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 4
    opts.inter_op_num_threads = 2
    return ort.InferenceSession(model_path, sess_options=opts,
                                 providers=["CPUExecutionProvider"])


def predict_batch(session: ort.InferenceSession, feature_matrix: np.ndarray) -> np.ndarray:
    """Run inference on a batch, return class index array."""
    if feature_matrix.shape[0] == 0:
        return np.array([], dtype=np.int64)
    inputs = {session.get_inputs()[0].name: feature_matrix.astype(np.float32)}
    outputs = session.run(None, inputs)
    # output[0] = label tensor (argmax class index)
    # output[1] = probabilities (Sequence<Map> — not easily extractable; ignore)
    return np.array(outputs[0], dtype=np.int64).flatten()


# ── Data loading ──────────────────────────────────────────────────────────────

def load_ndjson(path: str, max_samples: int = 0):
    cases = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if max_samples and i >= max_samples:
                break
            line = line.strip()
            if line:
                try:
                    cases.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return cases


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_binary_metrics(y_true_attack: list, y_pred_attack: list):
    """y_true_attack / y_pred_attack: list of bool (True = attack)."""
    tp = sum(1 for t, p in zip(y_true_attack, y_pred_attack) if t and p)
    fp = sum(1 for t, p in zip(y_true_attack, y_pred_attack) if not t and p)
    fn = sum(1 for t, p in zip(y_true_attack, y_pred_attack) if t and not p)
    tn = sum(1 for t, p in zip(y_true_attack, y_pred_attack) if not t and not p)
    total = len(y_true_attack)
    acc = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0  # false positive rate
    return dict(total=total, tp=tp, fp=fp, fn=fn, tn=tn,
                accuracy=acc, precision=prec, recall=rec, f1=f1, fpr=fpr)


def compute_per_class_binary(cases, preds_is_attack):
    """Per-dataset-class binary recall (attack detected / total attacks)."""
    by_class = defaultdict(lambda: dict(total=0, detected=0, missed=0))
    for case, pred_attack in zip(cases, preds_is_attack):
        cls = case["class"]
        is_attack_true = case.get("expected_action", "block") == "block"
        by_class[cls]["total"] += 1
        if is_attack_true:
            if pred_attack:
                by_class[cls]["detected"] += 1
            else:
                by_class[cls]["missed"] += 1
        else:
            if pred_attack:
                by_class[cls]["fp"] = by_class[cls].get("fp", 0) + 1
    return dict(by_class)


def compute_obf_breakdown(cases, preds_is_attack):
    """Detection rate by obfuscation technique."""
    by_obf = defaultdict(lambda: dict(total=0, detected=0))
    for case, pred in zip(cases, preds_is_attack):
        if case.get("expected_action") != "block":
            continue
        obf = case.get("obf", "none")
        by_obf[obf]["total"] += 1
        if pred:
            by_obf[obf]["detected"] += 1
    return {k: {**v, "recall": v["detected"] / v["total"] if v["total"] else 0.0}
            for k, v in by_obf.items()}


# ── Main eval ─────────────────────────────────────────────────────────────────

def run_evaluation(model_path: str, attacks_path: str, clean_path: str,
                   out_dir: Path, sample: int = 0, batch_size: int = 4096):

    print(f"\n{'='*72}")
    print("  aegis-gate AI Model — v4 Adversarial Dataset Evaluation")
    print(f"{'='*72}")
    print(f"  Model  : {model_path}")
    print(f"  Attacks: {attacks_path}")
    print(f"  Clean  : {clean_path}")
    print(f"  Sample : {'ALL' if not sample else sample} per file")
    print(f"  Output : {out_dir}")

    # Load model
    print("\n[1/5] Loading ONNX model ...")
    t0 = time.time()
    session = load_model(model_path)
    print(f"      loaded in {time.time()-t0:.2f}s")

    # Load data
    print("[2/5] Loading dataset ...")
    t0 = time.time()
    attacks = load_ndjson(attacks_path, sample)
    clean = load_ndjson(clean_path, sample if not sample else max(sample // 20, 500))
    all_cases = attacks + clean
    print(f"      {len(attacks):,} attacks + {len(clean):,} clean = {len(all_cases):,} total  ({time.time()-t0:.1f}s)")

    # Build request strings
    print("[3/5] Building request strings ...")
    req_strings = [build_request_string(c) for c in all_cases]

    # Extract features (batch)
    print("[4/5] Extracting features + running inference ...")
    t0 = time.time()
    all_labels = []
    n_chunks = (len(all_cases) + batch_size - 1) // batch_size
    for chunk_i in range(n_chunks):
        sl = slice(chunk_i * batch_size, (chunk_i + 1) * batch_size)
        chunk_reqs = req_strings[sl]
        feat_matrix = np.array([extract_features(r) for r in chunk_reqs], dtype=np.float32)
        labels = predict_batch(session, feat_matrix)
        all_labels.extend(labels.tolist())
        if (chunk_i + 1) % 10 == 0 or chunk_i == n_chunks - 1:
            done = min((chunk_i + 1) * batch_size, len(all_cases))
            elapsed = time.time() - t0
            rps = done / elapsed
            print(f"      {done:>7,} / {len(all_cases):,}  ({rps:,.0f} req/s)", end="\r", flush=True)
    elapsed_total = time.time() - t0
    rps_total = len(all_cases) / elapsed_total
    print(f"      {len(all_cases):,} / {len(all_cases):,}  ({rps_total:,.0f} req/s) ✓          ")

    # Binary predictions
    preds_is_attack = [lbl != NORMAL_CLASS_IDX for lbl in all_labels]
    true_is_attack = [c.get("expected_action", "block") == "block" for c in all_cases]

    print("[5/5] Computing metrics ...")

    # Overall binary
    binary = compute_binary_metrics(true_is_attack, preds_is_attack)

    # Attack-only: recall (only on attacks subset)
    attacks_only_true = [True] * len(attacks)
    attacks_only_pred = preds_is_attack[:len(attacks)]
    attack_recall = sum(1 for p in attacks_only_pred if p) / len(attacks) if attacks else 0.0

    # Clean-only: FP rate
    clean_only_true = [False] * len(clean)
    clean_only_pred = preds_is_attack[len(attacks):]
    fp_count = sum(1 for p in clean_only_pred if p)
    fp_rate_clean = fp_count / len(clean) if clean else 0.0

    # Per-dataset-class breakdown
    per_class = compute_per_class_binary(all_cases, preds_is_attack)

    # Obfuscation breakdown
    obf_breakdown = compute_obf_breakdown(all_cases, preds_is_attack)

    # Model class distribution of predictions
    pred_dist = defaultdict(int)
    for lbl in all_labels:
        pred_dist[MODEL_LABEL_MAP.get(lbl, str(lbl))] += 1

    # Missed attacks breakdown (top classes)
    missed_by_class = {}
    for case, pred in zip(all_cases, preds_is_attack):
        if case.get("expected_action") == "block" and not pred:
            cls = case["class"]
            missed_by_class[cls] = missed_by_class.get(cls, 0) + 1

    # Latency benchmark (small sample)
    bench_n = min(1000, len(all_cases))
    bench_feats = np.array([extract_features(r) for r in req_strings[:bench_n]], dtype=np.float32)
    latencies = []
    for i in range(bench_n):
        row = bench_feats[i:i+1]
        t_s = time.time()
        predict_batch(session, row)
        latencies.append((time.time() - t_s) * 1000.0)
    lat = sorted(latencies)
    lat_stats = dict(
        mean_ms=sum(lat) / len(lat),
        p50_ms=lat[int(0.50 * len(lat))],
        p95_ms=lat[int(0.95 * len(lat))],
        p99_ms=lat[int(0.99 * len(lat))],
        max_ms=lat[-1],
    )

    results = dict(
        meta=dict(
            date="2026-05-16",
            model_path=model_path,
            attacks_path=attacks_path,
            clean_path=clean_path,
            total_attacks=len(attacks),
            total_clean=len(clean),
            total_samples=len(all_cases),
            inference_elapsed_s=round(elapsed_total, 2),
            throughput_rps=round(rps_total, 0),
            batch_size=batch_size,
        ),
        binary_overall=binary,
        attack_recall=round(attack_recall, 6),
        fp_rate_clean=round(fp_rate_clean, 6),
        fp_count_clean=fp_count,
        per_dataset_class=per_class,
        obfuscation_breakdown=obf_breakdown,
        model_prediction_distribution=dict(pred_dist),
        missed_attacks_by_class=missed_by_class,
        latency_per_request_ms=lat_stats,
    )

    return results


# ── Report writer ─────────────────────────────────────────────────────────────

def write_json(results: dict, out_dir: Path):
    path = out_dir / "eval_results.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    return path


def write_report(results: dict, out_dir: Path):
    meta = results["meta"]
    bin_ = results["binary_overall"]
    per_cls = results["per_dataset_class"]
    obf = results["obfuscation_breakdown"]
    lat = results["latency_per_request_ms"]
    missed = results["missed_attacks_by_class"]
    pred_dist = results["model_prediction_distribution"]

    # Sort per-class by recall ascending (worst first)
    classes_sorted = sorted(
        [(k, v) for k, v in per_cls.items() if k != "clean"],
        key=lambda x: x[1]["detected"] / x[1]["total"] if x[1]["total"] else 0.0,
    )

    attack_recall_pct = results["attack_recall"] * 100
    fp_rate_pct = results["fp_rate_clean"] * 100
    bin_acc_pct = bin_["accuracy"] * 100
    prec_pct = bin_["precision"] * 100
    rec_pct = bin_["recall"] * 100
    f1 = bin_["f1"]

    # Overall grade
    if attack_recall_pct >= 90 and fp_rate_pct <= 1.0:
        grade = "🟢 GOOD"
    elif attack_recall_pct >= 75 and fp_rate_pct <= 5.0:
        grade = "🟡 ACCEPTABLE"
    else:
        grade = "🔴 POOR"

    lines = []
    A = lines.append
    A("# AI Model Accuracy Report — v4 Adversarial Dataset")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A(f"| Run Date | {meta['date']} |")
    A(f"| Model | `{meta['model_path']}` |")
    A(f"| Attack dataset | `{meta['attacks_path']}` ({meta['total_attacks']:,} samples) |")
    A(f"| Clean dataset | `{meta['clean_path']}` ({meta['total_clean']:,} samples) |")
    A(f"| Total evaluated | **{meta['total_samples']:,}** |")
    A(f"| Throughput | {meta['throughput_rps']:,.0f} req/s |")
    A(f"| Total inference time | {meta['inference_elapsed_s']:.1f}s |")
    A(f"| Overall grade | {grade} |")
    A("")
    A("---")
    A("")
    A("## Executive Summary")
    A("")
    A(f"The model was evaluated on **{meta['total_attacks']:,} adversarial attack cases** spanning 21 attack classes "
      f"with 13 obfuscation techniques, plus **{meta['total_clean']:,} legitimate (FP-prone) clean baselines**.")
    A("")
    detected_attacks = int(round(results["attack_recall"] * meta["total_attacks"]))
    A(f"**Binary verdict (attack vs. normal):**")
    A(f"- Attack recall (detection rate): **{attack_recall_pct:.2f}%** "
      f"({detected_attacks:,}/{meta['total_attacks']:,} attacks detected)")
    A(f"- False positive rate on clean traffic: **{fp_rate_pct:.2f}%** "
      f"({results['fp_count_clean']:,}/{meta['total_clean']:,} clean requests mis-classified as attack)")
    A(f"- Accuracy (all samples): **{bin_acc_pct:.2f}%**")
    A(f"- Precision: **{prec_pct:.2f}%** | Recall: **{rec_pct:.2f}%** | F1: **{f1:.4f}**")
    A("")

    # Attack recall comment
    if attack_recall_pct < 60:
        A("> ⚠️ **Critical gap:** The model misses more than 40% of attack requests. "
          "Some attack classes may not be represented in the training data. "
          "Retraining on a broader binary corpus is required.")
    elif attack_recall_pct < 80:
        A("> ⚠️ **Detection gap:** The model misses a significant portion of attack traffic. "
          "Classes with heavy obfuscation (double/triple URL-encode) may be under-detected.")
    else:
        A("> ✅ The model achieves strong detection across the evaluated attack classes.")
    A("")
    A("---")
    A("")
    A("## Binary Detection Metrics")
    A("")
    A("| Metric | Value |")
    A("|---|---|")
    A(f"| Overall accuracy | **{bin_acc_pct:.4f}%** |")
    A(f"| Attack precision | **{prec_pct:.4f}%** |")
    A(f"| Attack recall | **{rec_pct:.4f}%** |")
    A(f"| Attack F1 | **{f1:.4f}** |")
    A(f"| True Positives | {bin_['tp']:,} |")
    A(f"| False Positives | {bin_['fp']:,} |")
    A(f"| False Negatives | {bin_['fn']:,} |")
    A(f"| True Negatives | {bin_['tn']:,} |")
    A(f"| FP rate (clean only) | **{fp_rate_pct:.4f}%** |")
    A("")
    A("---")
    A("")
    A("## Per-Class Detection Rate (Attack Recall)")
    A("")
    A("Sorted from worst to best recall. Classes not in the model's training distribution "
      "will show near-0% recall — the model predicts Normal for unknown attack shapes.")
    A("")
    A("**Binary model: all 21 attack classes are merged into a single `Attack` label (class 1).**")
    A("Normal = class 0. Recall shows what fraction of each attack class was correctly flagged as Attack.")
    A("")
    A("| Dataset Class | Total | Detected | Missed | Recall |")
    A("|---|---:|---:|---:|---:|")

    for cls, d in classes_sorted:
        total = d.get("total", 0)
        detected = d.get("detected", 0)
        missed_cnt = d.get("missed", 0)
        recall = detected / total * 100 if total else 0.0
        bar = "█" * int(recall / 5) + "░" * (20 - int(recall / 5))
        A(f"| `{cls}` | {total:,} | {detected:,} | {missed_cnt:,} | **{recall:.1f}%** `{bar}` |")
    A("")
    A("---")
    A("")
    A("## Obfuscation Technique Breakdown")
    A("")
    A("Detection rate per obfuscation layer applied to attack payloads.")
    A("")
    A("| Obfuscation | Total | Detected | Recall |")
    A("|---|---:|---:|---:|")
    for obf_name, d in sorted(obf.items(), key=lambda x: x[1]["recall"]):
        total = d["total"]
        detected = d["detected"]
        recall_pct = d["recall"] * 100
        bar = "█" * int(recall_pct / 5) + "░" * (20 - int(recall_pct / 5))
        A(f"| `{obf_name}` | {total:,} | {detected:,} | **{recall_pct:.1f}%** `{bar}` |")
    A("")
    A("---")
    A("")
    A("## Model Prediction Distribution")
    A("")
    A("What class the model predicted across all inputs (attacks + clean).")
    A("")
    A("| Predicted Class | Count | % of all |")
    A("|---|---:|---:|")
    total_preds = sum(pred_dist.values())
    for cls_name, cnt in sorted(pred_dist.items(), key=lambda x: -x[1]):
        pct = cnt / total_preds * 100 if total_preds else 0.0
        A(f"| {cls_name} | {cnt:,} | {pct:.2f}% |")
    A("")
    A("---")
    A("")
    A("## Top Missed Attack Classes")
    A("")
    A("Attack classes with the most false negatives (predicted Normal):")
    A("")
    A("| Class | Missed |")
    A("|---|---:|")
    for cls, cnt in sorted(missed.items(), key=lambda x: -x[1])[:15]:
        A(f"| `{cls}` | {cnt:,} |")
    A("")
    A("---")
    A("")
    A("## Inference Latency (per-request, Python/ONNX Runtime)")
    A("")
    A(f"Benchmark: {min(1000, meta['total_samples'])} single-request inferences on CPU.")
    A("")
    A("| Metric | Value |")
    A("|---|---|")
    A(f"| Mean | {lat['mean_ms']:.3f} ms |")
    A(f"| p50 | {lat['p50_ms']:.3f} ms |")
    A(f"| p95 | {lat['p95_ms']:.3f} ms |")
    A(f"| p99 | {lat['p99_ms']:.3f} ms |")
    A(f"| Max | {lat['max_ms']:.3f} ms |")
    A(f"| Throughput (batch={meta['batch_size']}) | **{meta['throughput_rps']:,.0f} req/s** |")
    A("")
    A("---")
    A("")
    A("## Binary Model Evaluation Design")
    A("")
    A("The shipped `waf_model.onnx` is a **pure binary classifier** (`label_map.json: {\"0\": \"Normal\", \"1\": \"Attack\"}`). "
      "Probabilities output shape is `[batch, 2]`.")
    A("")
    A("All 21 v4 attack classes are collapsed into a single `Attack` ground-truth label. "
      "The clean baseline uses `Normal`. Per-class recall shows how well the binary model's "
      "`Attack` decision generalises across different attack patterns and obfuscation layers.")
    A("")
    A("---")
    A("")
    A("## Recommendations")
    A("")
    low_recall_classes = [(cls, d) for cls, d in per_cls.items()
                          if cls != "clean" and d.get("total", 0) >= 500
                          and d.get("detected", 0) / d.get("total", 1) < 0.70]
    if attack_recall_pct < 70 or low_recall_classes:
        A("### 🔴 Priority 1 — Improve per-class attack coverage")
        A("")
        A("The following attack classes have recall below 70% — the binary model's feature "
          "set does not capture their characteristic patterns well:")
        A("")
        for cls, d in sorted(low_recall_classes, key=lambda x: x[1]["detected"] / max(x[1]["total"], 1)):
            total = d["total"]
            rec = d["detected"] / total * 100
            A(f"- **`{cls}`** ({total:,} cases): {rec:.1f}% recall")
        A("")
        A("**Action:** Retrain `waf_model.onnx` using the v4 dataset. "
          "The v4 generator at `tests/security/dataset/generator/generate_v4.py` produces "
          "balanced binary training data. All 21 attack classes can be merged into the `Attack` "
          "label to improve binary coverage across the full attack surface.")
        A("")

    if fp_rate_pct > 2.0:
        A("### 🟡 Priority 3 — Reduce false positive rate")
        A("")
        A(f"FP rate of {fp_rate_pct:.2f}% on clean traffic exceeds the 0.5% production target. "
          "Review which features are triggering on legitimate requests and adjust "
          "the confidence threshold or add a whitelist layer.")
        A("")

    A("### ℹ️ Additional notes")
    A("")
    A("- The 27-feature extractor used for this evaluation is a **Python port** of "
      "`crates/aegis-security/src/detectors/ai/features.rs`. "
      "Minor floating-point differences vs the Rust implementation may affect edge cases.")
    A("- `extract_confidence()` in `model.rs` is currently a **stub** (always returns `None` → confidence=1.0). "
      "The confidence threshold has no effect. Adding softmax probability extraction would allow "
      "fine-grained tuning of precision/recall trade-offs.")
    A("- These results reflect **offline evaluation**. Live WAF results will differ because "
      "`AiDetector` is currently not wired into `pipeline.inbound()` (SEC-07).")
    A("")
    A("---")
    A("")
    A(f"*Report generated by `tests/ml-model/eval_v4.py` — {meta['date']}.*")
    A(f"*Model: `{meta['model_path']}`  |  Dataset: v4 adversarial corpus (200k attacks + 10k clean)*")

    report_path = out_dir / "MODEL_ACCURACY_REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report_path


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Evaluate WAF AI model against v4 dataset")
    parser.add_argument("--model",   default="data/ai_model/waf_model.onnx")
    parser.add_argument("--attacks", default="tests/security/dataset/attacks_v4.ndjson")
    parser.add_argument("--clean",   default="tests/security/dataset/clean_baselines_v4.ndjson")
    parser.add_argument("--out-dir", default="tests/ml-model/2026-05-16")
    parser.add_argument("--sample",  type=int, default=0,
                        help="Limit samples per file (0=all). For quick tests: --sample 10000")
    parser.add_argument("--batch-size", type=int, default=4096)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = run_evaluation(
        model_path=args.model,
        attacks_path=args.attacks,
        clean_path=args.clean,
        out_dir=out_dir,
        sample=args.sample,
        batch_size=args.batch_size,
    )

    json_path = write_json(results, out_dir)
    report_path = write_report(results, out_dir)

    print(f"\n{'='*72}")
    print(f"  Results saved:")
    print(f"    JSON   : {json_path}")
    print(f"    Report : {report_path}")
    print(f"{'='*72}")
    print(f"\n  Binary summary:")
    b = results["binary_overall"]
    print(f"    Attack recall   : {results['attack_recall']*100:.2f}%")
    print(f"    FP rate (clean) : {results['fp_rate_clean']*100:.2f}%")
    print(f"    Accuracy        : {b['accuracy']*100:.2f}%")
    print(f"    F1              : {b['f1']:.4f}")
    print(f"    Throughput      : {results['meta']['throughput_rps']:,.0f} req/s")


if __name__ == "__main__":
    main()
