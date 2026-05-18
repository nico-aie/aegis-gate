#!/usr/bin/env python3
"""
WAF Core evaluation against the remote dataset collection.

Sources evaluated:
  1. eval_data/csic.csv         — CSIC 2010 HTTP corpus (97k)
  2. eval_data/malicious.csv    — openappsec malicious (73.9k)
  3. eval_data/modern.csv       — modern payloads / SecLists (6k)
  4. eval_data/srbh.csv         — SRBH2020 combined (607k, sampled)
  5. eval_data/huggingface.csv  — HuggingFace ai-waf-dataset (11.9k)
  6. Malicious/*.json           — openappsec JSON per-class (73.9k)
  7. Legitimate/*.json          — real browser traffic, sampled (5k)

Feature extractor: 27-feature port of
  crates/aegis-security/src/detectors/ai/features.rs
Model: data/ai_model/waf_model.onnx  (binary: 0=Normal, 1=Attack)
"""

import argparse
import csv
import io
import json
import math
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import onnxruntime as ort

# ── Constants ─────────────────────────────────────────────────────────────────

NORMAL_CLASS_IDX = 0
ATTACK_CLASS_IDX = 1

# Categories that map to Normal (binary 0)
NORMAL_CATEGORIES = {"normal", "000 - normal"}

# ── 27-feature extractor (port of features.rs) ────────────────────────────────

NUM_FEATURES = 27

_SQL_RE = re.compile(
    r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute"
    r"|where|from|having|order|group|join|table|database|schema|char|nchar"
    r"|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b"
)
_XSS_RE = re.compile(
    r"(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus="
    r"|alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\("
    r"|<iframe|<img\s|<svg|srcdoc=)"
)
_SCANNER_RE = re.compile(
    r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|dirbuster"
    r"|gobuster|wfuzz|w3af|commix)"
)
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_CMD_RE = re.compile(r"[;|]|\|\||&&|\$\(|`[^`]*`")
_SSRF_RE = re.compile(
    r"(?i)(?:127\.0\.0\.1|localhost|169\.254\.|0\.0\.0\.0|::1"
    r"|file://|dict://|gopher://|ftp://)"
)
_PHP_RE = re.compile(
    r"(?i)(?:\.php|eval\(|base64_decode\(|system\(|passthru\("
    r"|shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)"
)
_NULL_BYTE_RE = re.compile(r"%00|\\x00|\\u0000")
_HEX_ENCODE_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
_CRLF_RE = re.compile(r"%0[aAdD]|\\r\\n|\r\n")
_DBL_ENC_RE = re.compile(r"%25[0-9a-fA-F]{2}")
_SSTI_RE = re.compile(
    r"(\{\{.*?\}\})|(\$\{[^}]{1,200}\})|(#\{[^}]{1,200}\})|(<%=.*?%>)"
    r"|(\?\s*new\s*\()|(__(class|mro|subclasses|globals|builtins|import)__)"
    r"|(freemarker\.template|velocity\.tools)|(\{\s*\d+\s*\*\s*\d+\s*\})",
    re.IGNORECASE | re.DOTALL
)
_METHOD_IDS = {
    "GET": 0.0, "POST": 1.0, "PUT": 2.0, "DELETE": 3.0,
    "PATCH": 4.0, "HEAD": 5.0, "OPTIONS": 6.0,
}


def _url_decode(s: str) -> str:
    out = []
    b = s.encode("latin-1", errors="replace")
    i = 0
    while i < len(b):
        if b[i] == ord('%') and i + 2 < len(b):
            try:
                val = int(chr(b[i+1]) + chr(b[i+2]), 16)
                out.append(chr(val)); i += 3; continue
            except ValueError:
                pass
        out.append(chr(b[i])); i += 1
    return "".join(out)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[ord(c) & 0xFF] += 1
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def extract_features(request: str) -> list:
    """27-feature vector from a request string (METHOD /path?query [body\nHeaders])."""
    nl = request.find('\n')
    if nl != -1:
        first_line = request[:nl]
        headers_text = request[nl+1:].replace('\n', ' ')
    else:
        first_line = request
        headers_text = ""

    parts = first_line.split(" ", 2)
    method = parts[0] if parts else "GET"
    url    = parts[1] if len(parts) > 1 else "/"
    body   = parts[2] if len(parts) > 2 else ""

    qpos = url.find('?')
    path  = url[:qpos] if qpos != -1 else url
    query = url[qpos+1:] if qpos != -1 else ""

    full = url
    if body:        full += " " + body
    if headers_text: full += " " + headers_text

    full_dec = _url_decode(full)
    n = max(len(full), 1)

    num_params = (0 if not query else query.count('&')+1) + \
                 (0 if not body  else body.count('&')+1)
    digits  = sum(1 for c in full if c.isdigit())
    uppers  = sum(1 for c in full if c.isupper())
    specials= sum(1 for c in full if c in "'\"<>;=%&+")
    ptrav   = full_dec.lower().count("../")
    mid     = _METHOD_IDS.get(method.upper(), 7.0)

    return [
        float(len(request)),
        mid,
        float(len(path)),
        float(len(query)),
        float(len(body)),
        float(num_params),
        _entropy(full),
        digits / n,
        uppers / n,
        float(specials),
        float(full.count("'")),
        float(full.count('"')),
        float(full.count('<') + full.count('>')),
        float(full.count(';')),
        float(len(_PCT_RE.findall(full))),
        float(len(_SQL_RE.findall(full_dec))),
        float(len(_XSS_RE.findall(full_dec))),
        float(ptrav),
        float(len(_CMD_RE.findall(full_dec))),
        float(len(_SCANNER_RE.findall(full_dec))),
        float(len(_SSRF_RE.findall(full_dec))),
        float(len(_PHP_RE.findall(full_dec))),
        float(len(_NULL_BYTE_RE.findall(full))),
        float(len(_HEX_ENCODE_RE.findall(full))),
        float(len(_CRLF_RE.findall(full))),
        float(len(_DBL_ENC_RE.findall(full))),
        float(len(_SSTI_RE.findall(full_dec))),
    ]


# ── Data loaders ──────────────────────────────────────────────────────────────

def _is_normal(cat: str) -> bool:
    return cat.strip().lower() in NORMAL_CATEGORIES


def load_csv(path: str, max_rows: int = 0) -> list:
    """Load text,category CSV. Returns list of (request_str, category, is_normal)."""
    with open(path, 'rb') as fh:
        raw = fh.read().replace(b'\x00', b'')
    rows = []
    for r in csv.DictReader(io.StringIO(raw.decode('utf-8', 'replace'))):
        text = r.get('text', '').strip()
        cat  = r.get('category', 'Unknown').strip()
        if not text:
            continue
        rows.append((text, cat, _is_normal(cat)))
        if max_rows and len(rows) >= max_rows:
            break
    return rows


def load_malicious_json(path: str) -> list:
    """Load openappsec Malicious/*.json → (request_str, class_name, is_normal=False)."""
    fname = Path(path).stem
    CLASS_MAP = {
        'sqli':      'Injection',
        'cmdexe':    'Injection',
        'shellshock':'Injection',
        'traversal': 'Manipulation',
        'xss':       'XSS',
        'xxe':       'XXE',
        'log4shell': 'Log4Shell',
    }
    cat = CLASS_MAP.get(fname, 'Attack')
    records = json.load(open(path))
    rows = []
    for r in records:
        method = r.get('method', 'GET')
        url    = r.get('url', '/')
        body   = r.get('data', '') or ''
        hdrs   = r.get('headers', {})
        line   = f"{method} {url}"
        if body:
            line += f" {body[:4096]}"
        header_parts = []
        for hk, canonical in [('User-Agent','User-Agent'),('Cookie','Cookie'),('Referer','Referer')]:
            val = hdrs.get(hk) or hdrs.get(hk.lower(), '')
            if val:
                header_parts.append(f"{canonical}: {val}")
        if header_parts:
            line += "\n" + "\n".join(header_parts)
        rows.append((line, cat, False))
    return rows


def load_legitimate_json_sample(folder: str, sample: int = 5000) -> list:
    """Sample real browser traffic from Legitimate/*.json."""
    import random
    files = sorted(Path(folder).glob('*.json'))
    random.seed(42)
    random.shuffle(files)
    rows = []
    for fpath in files:
        if len(rows) >= sample:
            break
        try:
            records = json.load(open(fpath))
            for r in records:
                if len(rows) >= sample:
                    break
                method = r.get('method', 'GET')
                url    = r.get('url', '/')
                body   = r.get('data', '') or ''
                hdrs   = r.get('headers', {})
                line   = f"{method} {url}"
                if body:
                    line += f" {body[:4096]}"
                header_parts = []
                for hk, canonical in [('User-Agent','User-Agent'),('Cookie','Cookie'),('Referer','Referer')]:
                    val = hdrs.get(hk) or hdrs.get(hk.lower(), '')
                    if val:
                        header_parts.append(f"{canonical}: {val}")
                if header_parts:
                    line += "\n" + "\n".join(header_parts)
                rows.append((line, 'Normal', True))
        except Exception:
            continue
    return rows


# ── Inference ─────────────────────────────────────────────────────────────────

def load_model(path: str) -> ort.InferenceSession:
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 4
    return ort.InferenceSession(path, sess_options=opts,
                                providers=['CPUExecutionProvider'])


def run_inference(session, rows: list, batch_size: int = 4096) -> list:
    """Return list of predicted labels (0/1) for each row."""
    all_labels = []
    n = len(rows)
    for i in range(0, n, batch_size):
        chunk = rows[i:i+batch_size]
        mat = np.array([extract_features(r[0]) for r in chunk], dtype=np.float32)
        outputs = session.run(None, {'X': mat})
        all_labels.extend(outputs[0].tolist())
    return all_labels


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(rows, labels):
    tp = fp = fn = tn = 0
    by_class = defaultdict(lambda: dict(total=0, tp=0, fp=0, fn=0, tn=0))

    for (_, cat, is_normal), pred_lbl in zip(rows, labels):
        pred_attack = (pred_lbl != NORMAL_CLASS_IDX)
        true_attack = not is_normal
        c = by_class[cat]
        c['total'] += 1
        if true_attack and pred_attack:
            tp += 1; c['tp'] += 1
        elif not true_attack and pred_attack:
            fp += 1; c['fp'] += 1
        elif true_attack and not pred_attack:
            fn += 1; c['fn'] += 1
        else:
            tn += 1; c['tn'] += 1

    total = tp + fp + fn + tn
    acc   = (tp + tn) / total if total else 0.0
    prec  = tp / (tp + fp) if (tp + fp) else 0.0
    rec   = tp / (tp + fn) if (tp + fn) else 0.0
    f1    = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    n_clean = tn + fp
    fpr   = fp / n_clean if n_clean else 0.0
    n_att = tp + fn
    tpr   = tp / n_att if n_att else 0.0

    return dict(
        total=total, tp=tp, fp=fp, fn=fn, tn=tn,
        accuracy=acc, precision=prec, recall=rec, f1=f1,
        fpr=fpr, tpr=tpr,
        by_class=dict(by_class),
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset-dir',  default='/sessions/affectionate-awesome-bell/mnt/dataset')
    ap.add_argument('--model',        default='data/ai_model/waf_model.onnx')
    ap.add_argument('--out-dir',      default='tests/ml-model/2026-05-18')
    ap.add_argument('--srbh-sample',  type=int, default=50000)
    ap.add_argument('--legit-sample', type=int, default=5000)
    ap.add_argument('--batch-size',   type=int, default=4096)
    args = ap.parse_args()

    dset = Path(args.dataset_dir)
    out  = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*68}")
    print("  Aegis-Gate WAF Core — Remote Dataset Evaluation")
    print(f"{'='*68}")
    print(f"  Model  : {args.model}")
    print(f"  Dataset: {args.dataset_dir}")
    print(f"  Output : {args.out_dir}\n")

    # Load model
    print("[1/3] Loading ONNX model ...")
    t0 = time.time()
    session = load_model(args.model)
    print(f"      loaded in {time.time()-t0:.2f}s\n")

    # ── Load all sources ──────────────────────────────────────────────────────
    print("[2/3] Loading datasets ...")

    sources = {}

    # CSIC 2010
    t0 = time.time()
    rows = load_csv(str(dset/'eval_data'/'csic.csv'))
    sources['CSIC 2010'] = rows
    print(f"  csic.csv        : {len(rows):>7,} rows  ({time.time()-t0:.1f}s)")

    # HuggingFace
    t0 = time.time()
    rows = load_csv(str(dset/'eval_data'/'huggingface.csv'))
    sources['HuggingFace WAF'] = rows
    print(f"  huggingface.csv : {len(rows):>7,} rows  ({time.time()-t0:.1f}s)")

    # Malicious (openappsec)
    t0 = time.time()
    rows = load_csv(str(dset/'eval_data'/'malicious.csv'))
    sources['openappsec Malicious'] = rows
    print(f"  malicious.csv   : {len(rows):>7,} rows  ({time.time()-t0:.1f}s)")

    # Modern payloads
    t0 = time.time()
    rows = load_csv(str(dset/'eval_data'/'modern.csv'))
    sources['Modern Payloads'] = rows
    print(f"  modern.csv      : {len(rows):>7,} rows  ({time.time()-t0:.1f}s)")

    # SRBH2020 (sampled)
    t0 = time.time()
    rows = load_csv(str(dset/'eval_data'/'srbh.csv'), max_rows=args.srbh_sample)
    sources['SRBH2020'] = rows
    print(f"  srbh.csv        : {len(rows):>7,} rows (sampled {args.srbh_sample:,})  ({time.time()-t0:.1f}s)")

    # openappsec JSON per-class
    t0 = time.time()
    json_rows = []
    json_dir = dset / 'Malicious'
    for jf in sorted(json_dir.glob('*.json')):
        json_rows.extend(load_malicious_json(str(jf)))
    sources['openappsec JSON (per-class)'] = json_rows
    print(f"  Malicious/*.json: {len(json_rows):>7,} rows  ({time.time()-t0:.1f}s)")

    # Legitimate browser traffic (sampled)
    t0 = time.time()
    legit_rows = load_legitimate_json_sample(str(dset/'Legitimate'), sample=args.legit_sample)
    sources['Legitimate Browser Traffic'] = legit_rows
    print(f"  Legitimate/*.json: {len(legit_rows):>6,} rows (sampled {args.legit_sample:,})  ({time.time()-t0:.1f}s)")

    total_rows = sum(len(v) for v in sources.values())
    print(f"\n  Total: {total_rows:,} samples across {len(sources)} sources\n")

    # ── Run inference per source ──────────────────────────────────────────────
    print("[3/3] Running inference ...")
    results = {}
    t_global = time.time()
    for name, rows in sources.items():
        t0 = time.time()
        labels = run_inference(session, rows, args.batch_size)
        elapsed = time.time() - t0
        rps = len(rows) / elapsed if elapsed > 0 else 0
        metrics = compute_metrics(rows, labels)
        results[name] = dict(metrics=metrics, elapsed=elapsed, rps=rps, n=len(rows))
        tpr_pct = metrics['tpr'] * 100
        fpr_pct = metrics['fpr'] * 100
        f1      = metrics['f1']
        print(f"  {name:<35} {len(rows):>7,} rows  "
              f"recall={tpr_pct:5.1f}%  FPR={fpr_pct:5.1f}%  F1={f1:.3f}  ({rps:,.0f} req/s)")

    total_elapsed = time.time() - t_global
    print(f"\n  Done — {total_rows:,} samples in {total_elapsed:.1f}s "
          f"({total_rows/total_elapsed:,.0f} req/s avg)\n")

    # ── Write report ──────────────────────────────────────────────────────────
    report_path = out / 'DATASET_EVAL_REPORT.md'
    write_report(results, sources, args, report_path)
    print(f"  Report : {report_path}")
    print(f"{'='*68}\n")


# ── Report writer ─────────────────────────────────────────────────────────────

def grade(tpr, fpr):
    if tpr >= 0.90 and fpr <= 0.01:  return "🟢 GOOD"
    if tpr >= 0.75 and fpr <= 0.05:  return "🟡 ACCEPTABLE"
    return "🔴 POOR"


def bar(pct: float, width: int = 20) -> str:
    filled = int(pct / 100 * width)
    return '█' * filled + '░' * (width - filled)


def write_report(results, sources, args, path: Path):
    lines = []
    A = lines.append

    # Header
    A("# Aegis-Gate WAF Core — Remote Dataset Evaluation Report")
    A("")
    A("| | |")
    A("|---|---|")
    A("| **Date** | 2026-05-18 |")
    A(f"| **Model** | `data/ai_model/waf_model.onnx` (binary: 0=Normal, 1=Attack) |")
    A(f"| **Feature extractor** | 27-feature port of `crates/aegis-security/src/detectors/ai/features.rs` |")
    A(f"| **Dataset root** | `{args.dataset_dir}` |")
    total_all = sum(r['n'] for r in results.values())
    A(f"| **Total samples evaluated** | **{total_all:,}** |")
    A("")

    # Dataset inventory
    A("## Dataset Inventory")
    A("")
    A("| Source | Samples | Format | Notes |")
    A("|---|---:|---|---|")
    notes = {
        'CSIC 2010':                  'HTTP CSIC 2010 benchmark — JSP e-commerce app',
        'HuggingFace WAF':            'ai-waf-dataset — diverse multi-class',
        'openappsec Malicious':       'openappsec production WAF — attack-only',
        'Modern Payloads':            'SecLists / PayloadsAllTheThings — SSTI, modern',
        'SRBH2020':                   f'SRBH2020 combined — sampled {args.srbh_sample:,}',
        'openappsec JSON (per-class)':'openappsec JSON with per-file class labels',
        'Legitimate Browser Traffic': f'Real browser sessions — sampled {args.legit_sample:,}',
    }
    for name, rows in sources.items():
        n = len(rows)
        cats = defaultdict(int)
        for _, cat, _ in rows:
            cats[cat] += 1
        n_normal = sum(v for k, v in cats.items() if _is_normal(k))
        n_attack = n - n_normal
        fmt = "CSV" if "json" not in name.lower() and "browser" not in name.lower() else "JSON"
        A(f"| {name} | {n:,} | {fmt} | {notes.get(name,'')} |")
    A("")

    # Overall summary table
    A("---")
    A("")
    A("## Overall Results per Source")
    A("")
    A("| Source | Samples | Recall | FPR | Precision | F1 | Grade |")
    A("|---|---:|---:|---:|---:|---:|---|")
    for name, r in results.items():
        m = r['metrics']
        tpr_p = m['tpr'] * 100
        fpr_p = m['fpr'] * 100
        prc_p = m['precision'] * 100
        f1    = m['f1']
        g     = grade(m['tpr'], m['fpr'])
        A(f"| {name} | {r['n']:,} | {tpr_p:.1f}% | {fpr_p:.1f}% | {prc_p:.1f}% | {f1:.3f} | {g} |")
    A("")

    # Confusion matrices per source
    A("---")
    A("")
    A("## Confusion Matrix per Source")
    A("")
    for name, r in results.items():
        m = r['metrics']
        A(f"### {name}  ({r['n']:,} samples, {r['rps']:,.0f} req/s)")
        A("")
        A("| | Predicted Attack | Predicted Normal |")
        A("|---|---:|---:|")
        A(f"| **Actual Attack** ({m['tp']+m['fn']:,}) | TP = {m['tp']:,} | FN = {m['fn']:,} |")
        A(f"| **Actual Normal** ({m['fp']+m['tn']:,}) | FP = {m['fp']:,} | TN = {m['tn']:,} |")
        A("")
        A(f"Recall: **{m['tpr']*100:.2f}%** &nbsp;|&nbsp; "
          f"FPR: **{m['fpr']*100:.2f}%** &nbsp;|&nbsp; "
          f"Precision: **{m['precision']*100:.2f}%** &nbsp;|&nbsp; "
          f"F1: **{m['f1']:.4f}** &nbsp;|&nbsp; "
          f"Accuracy: **{m['accuracy']*100:.2f}%**")
        A("")

    # Per-class breakdown (openappsec JSON is most reliable — each file = one class)
    A("---")
    A("")
    A("## Per-Class Detection Rates")
    A("")
    A("Aggregated across all sources that carry class labels.")
    A("")

    # Build global per-class from all sources
    global_by_class = defaultdict(lambda: dict(total=0, tp=0, fp=0, fn=0, tn=0))
    for name, r in results.items():
        for cat, d in r['metrics']['by_class'].items():
            g = global_by_class[cat]
            for k in ('total','tp','fp','fn','tn'):
                g[k] += d.get(k, 0)

    # Attack classes only, sorted by recall
    attack_classes = {k: v for k, v in global_by_class.items()
                      if not _is_normal(k) and v['total'] > 0}
    attack_sorted  = sorted(attack_classes.items(),
                            key=lambda x: x[1]['tp'] / max(x[1]['tp']+x[1]['fn'],1))

    A("### Attack Classes")
    A("")
    A("| Class | Total | Detected | Missed | Recall |")
    A("|---|---:|---:|---:|---|")
    for cls, d in attack_sorted:
        total    = d['tp'] + d['fn']
        detected = d['tp']
        missed   = d['fn']
        recall   = detected / total * 100 if total else 0.0
        A(f"| `{cls}` | {total:,} | {detected:,} | {missed:,} "
          f"| **{recall:.1f}%** `{bar(recall)}` |")
    A("")

    # Normal classes — FP rate
    normal_classes = {k: v for k, v in global_by_class.items()
                      if _is_normal(k) and v['total'] > 0}
    if normal_classes:
        A("### Normal Traffic (False Positive Rate)")
        A("")
        A("| Class | Total | Correct (TN) | False Positive | FPR |")
        A("|---|---:|---:|---:|---|")
        for cls, d in normal_classes.items():
            total = d['fp'] + d['tn']
            fpr_p = d['fp'] / total * 100 if total else 0.0
            A(f"| `{cls}` | {total:,} | {d['tn']:,} | {d['fp']:,} "
              f"| **{fpr_p:.2f}%** `{bar(fpr_p)}` |")
        A("")

    # openappsec JSON per-class detail
    A("---")
    A("")
    A("## openappsec JSON — Detailed Per-Class Breakdown")
    A("")
    A("This source has the most reliable per-class labels (one JSON file per attack type).")
    A("")
    json_result = results.get('openappsec JSON (per-class)')
    if json_result:
        A("| Class | Total | Detected | Missed | Recall |")
        A("|---|---:|---:|---:|---|")
        cls_sorted = sorted(
            [(k, v) for k, v in json_result['metrics']['by_class'].items()
             if not _is_normal(k)],
            key=lambda x: x[1]['tp'] / max(x[1]['tp']+x[1]['fn'], 1)
        )
        for cls, d in cls_sorted:
            total    = d['tp'] + d['fn']
            detected = d['tp']
            missed   = d['fn']
            recall   = detected / total * 100 if total else 0.0
            A(f"| `{cls}` | {total:,} | {detected:,} | {missed:,} "
              f"| **{recall:.1f}%** `{bar(recall)}` |")
    A("")

    # Inference latency
    A("---")
    A("")
    A("## Inference Throughput")
    A("")
    A("| Source | Samples | Time (s) | Throughput |")
    A("|---|---:|---:|---:|")
    for name, r in results.items():
        A(f"| {name} | {r['n']:,} | {r['elapsed']:.1f}s | {r['rps']:,.0f} req/s |")
    A("")

    # Key findings
    A("---")
    A("")
    A("## Key Findings")
    A("")

    # Compute aggregate across all sources (excluding duplicates — use distinct sources)
    # Use CSIC + HuggingFace + SRBH as ground truth since they have Normal rows
    mixed_sources = ['CSIC 2010', 'HuggingFace WAF', 'SRBH2020', 'Modern Payloads',
                     'Legitimate Browser Traffic']
    agg_tp = agg_fp = agg_fn = agg_tn = 0
    for src in mixed_sources:
        if src in results:
            m = results[src]['metrics']
            agg_tp += m['tp']; agg_fp += m['fp']
            agg_fn += m['fn']; agg_tn += m['tn']
    agg_total = agg_tp + agg_fp + agg_fn + agg_tn
    agg_tpr = agg_tp / (agg_tp + agg_fn) if (agg_tp + agg_fn) else 0
    agg_fpr = agg_fp / (agg_fp + agg_tn) if (agg_fp + agg_tn) else 0
    agg_f1_prec = agg_tp / (agg_tp + agg_fp) if (agg_tp + agg_fp) else 0
    agg_f1_rec  = agg_tpr
    agg_f1      = 2 * agg_f1_prec * agg_f1_rec / (agg_f1_prec + agg_f1_rec) \
                  if (agg_f1_prec + agg_f1_rec) else 0

    A(f"**Aggregate across mixed-class sources** "
      f"(CSIC 2010 + HuggingFace + SRBH2020 + Modern + Legitimate):")
    A("")
    A(f"| Metric | Value | Target |")
    A(f"|---|---:|---:|")
    A(f"| Attack recall | **{agg_tpr*100:.2f}%** | ≥ 95% {'✅' if agg_tpr >= 0.95 else '❌'} |")
    A(f"| False positive rate | **{agg_fpr*100:.2f}%** | ≤ 0.5% {'✅' if agg_fpr <= 0.005 else '❌'} |")
    A(f"| F1 | **{agg_f1:.4f}** | — |")
    A(f"| Total samples (mixed) | **{agg_total:,}** | — |")
    A("")

    A("**Observations by source:**")
    A("")
    for name, r in results.items():
        m = r['metrics']
        tpr_p = m['tpr'] * 100
        fpr_p = m['fpr'] * 100
        g     = grade(m['tpr'], m['fpr'])
        n_normal = m['tp'] + m['fn']  # wait, no...
        n_atk = m['tp'] + m['fn']
        n_nrm = m['fp'] + m['tn']
        A(f"- **{name}** ({r['n']:,} samples, {n_atk:,} attacks / {n_nrm:,} normal): "
          f"recall {tpr_p:.1f}% · FPR {fpr_p:.1f}% · {g}")
    A("")

    A("---")
    A("")
    A("## Recommendations")
    A("")
    A("### 🔴 False Positive Rate")
    A("")
    A("FPR is consistently elevated across clean-traffic sources. "
      "The 27-feature extractor fires on legitimate URL patterns that resemble attack signals "
      "(SQL keywords in field names, high entropy tokens, special characters in query strings). "
      "**Fix priority:** implement `extract_confidence()` in `model.rs` to expose softmax "
      "probabilities, then sweep thresholds on a validation split of these clean sources.")
    A("")
    A("### 🔴 Low recall on specific classes")
    A("")
    worst = [(cls, d) for cls, d in attack_sorted
             if (d['tp'] / max(d['tp']+d['fn'],1)) < 0.50 and d['tp']+d['fn'] >= 100]
    if worst:
        A("Classes with recall below 50% across the full dataset:")
        A("")
        for cls, d in worst[:8]:
            total   = d['tp'] + d['fn']
            recall  = d['tp'] / total * 100 if total else 0
            A(f"- **`{cls}`** ({total:,} samples): {recall:.1f}% recall")
        A("")
    A("Retrain `waf_model.onnx` using these sources as supplemental binary training data "
      "with all attack classes merged into label `1`. "
      "The `eval_data/` CSVs are already in the correct format.")
    A("")
    A("### 🟡 HTML entity obfuscation blind spot")
    A("")
    A("Payloads encoded as `&#60;` / `&#x3C;` bypass all decoded-feature regexes because "
      "`url_decode()` does not handle HTML entities. Add an `html_entity_decode()` pass "
      "before applying the SQL/XSS/SSTI regex features.")
    A("")
    A("### ℹ️ Notes")
    A("")
    A("- `AiDetector` is not wired into `pipeline.inbound()` (SEC-07). "
      "These results are offline evaluation only.")
    A("- `legitimate.csv` (2.4 GB, ~5M rows) was excluded from this run to avoid OOM. "
      "Use `--legit-sample` with a streaming reader for full evaluation.")
    A("- SRBH2020 was capped at "
      f"{args.srbh_sample:,} rows (full: 607,312). Use `--srbh-sample 0` to run all.")
    A("")
    A("---")
    A("")
    A("*Generated by `tests/ml-model/eval_remote.py` — 2026-05-18*")
    A(f"*Model: `data/ai_model/waf_model.onnx` | Dataset: `{args.dataset_dir}`*")

    with open(path, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
