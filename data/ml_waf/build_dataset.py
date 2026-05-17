#!/usr/bin/env python3
"""
Merge 7 WAF data sources into dataset_unified.csv.
Original source directories are untouched.

Sources
-------
1. malicious/Malicious/*.json          — openappsec synthetic attack payloads
2. legitimate/Legitimate/*.json        — real browser sessions (browsing_2024_*)
3. SRBH2020/dataset_capec_combine.csv
4. SRBH2020/dataset_capec_transfer.csv
5. csic2010/*.txt                      — CSIC 2010 HTTP dataset (raw HTTP requests)
6. modern_payloads/ai_waf_dataset.parquet — HuggingFace modern REST/JSON attacks
7. modern_payloads/*.txt / *.fuzz      — PayloadsAllTheThings: SSTI, NoSQL, polyglots

Output columns: text, category
  text     : "METHOD /path?query [body]"   (same format as SRBH2020)
  category : unified class label

Usage
-----
    python build_dataset.py               # default cap 50 000/class
    python build_dataset.py --cap 30000   # custom cap
    python build_dataset.py --no-cap      # no sampling (raw merge)
"""
import glob
import json
import os
import random
import re
import sys
import time
import urllib.parse
from collections import defaultdict

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 42
random.seed(SEED)

OUT_PATH = os.path.join(HERE, "dataset_unified.csv")
DEFAULT_CAP = 600_000

# ── Category mapping ──────────────────────────────────────────────────────────

# Maps malicious JSON filename → unified category
# sqli/cmdexe/shellshock → "Injection"  (align with SRBH2020)
# traversal              → "Manipulation"
# xss/xxe/log4shell      → new classes (absent from SRBH2020)
MALICIOUS_CATEGORY = {
    "sqli":       "Injection",
    "cmdexe":     "Injection",
    "shellshock": "Injection",
    "traversal":  "Manipulation",
    "xss":        "XSS",
    "xxe":        "XXE",
    "log4shell":  "Log4Shell",
}

# ── JSON → text helper ────────────────────────────────────────────────────────

# Headers included in the text representation (order matters — most useful first)
_INCLUDE_HEADERS = (
    "User-Agent",
    "Cookie",
    "Referer",
    "Authorization",
    "Content-Type",
    "X-Forwarded-For",
    "X-Real-IP",
)


def entry_to_text(entry: dict) -> str:
    """Convert a JSON request object to multi-line text.

    Format:
        Line 0:  METHOD /url [body]
        Lines 1+: Header: value   (important headers only, if present)
    """
    method = (entry.get("method") or "GET").strip()
    url    = (entry.get("url")    or "/").strip()
    body   = entry.get("data") or ""
    if isinstance(body, (dict, list)):
        body = json.dumps(body, separators=(",", ":"))
    body = str(body).strip().replace("\r", "").replace("\n", " ")

    headers = entry.get("headers") or {}
    header_lines = [
        f"{k}: {str(headers[k]).strip()}"
        for k in _INCLUDE_HEADERS
        if headers.get(k)
    ]

    text = f"{method} {url}" + (f" {body}" if body else "")
    if header_lines:
        text += "\n" + "\n".join(header_lines)
    return text

# ── Loaders ───────────────────────────────────────────────────────────────────

def load_malicious() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    base = os.path.join(HERE, "malicious", "Malicious")
    for name, category in MALICIOUS_CATEGORY.items():
        path = os.path.join(base, f"{name}.json")
        if not os.path.exists(path):
            print(f"  [WARN] {path} not found — skipping")
            continue
        with open(path, encoding="utf-8") as f:
            entries = json.load(f)
        for e in entries:
            rows.append((entry_to_text(e), category))
        print(f"  {name:<12} -> {category:<30}  {len(entries):>7,} samples")
    return rows


def load_legitimate(cap: int) -> list[tuple[str, str]]:
    """
    Load up to `cap` Normal samples from legitimate JSON files.
    Files are shuffled so the sample spans many different websites.
    """
    pattern = os.path.join(HERE, "legitimate", "Legitimate", "*.json")
    files = sorted(glob.glob(pattern))
    random.shuffle(files)
    print(f"  {len(files)} JSON files found")

    rows: list[tuple[str, str]] = []
    for path in files:
        if len(rows) >= cap:
            break
        try:
            with open(path, encoding="utf-8") as f:
                entries = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        remaining = cap - len(rows)
        # Sample proportionally if this file alone would exceed the cap
        sample = entries if len(entries) <= remaining else random.sample(entries, remaining)
        for e in sample:
            rows.append((entry_to_text(e), "Normal"))

    print(f"  Loaded {len(rows):,} Normal samples (cap={cap:,})")
    return rows


# ── CSIC 2010 helpers ─────────────────────────────────────────────────────────

_SQL_RE  = re.compile(
    r'\b(select|union|insert|update|delete|drop|alter|truncate|exec|'
    r'having|order\s+by|group\s+by|--\s|/\*)\b',
    re.IGNORECASE,
)
_XSS_RE  = re.compile(r'(<\s*script|javascript:|on\w+\s*=|alert\s*\(|%3cscript)', re.IGNORECASE)
_TRAV_RE = re.compile(r'(\.\.[\\/]|%2e%2e|%252e)', re.IGNORECASE)
_XXE_RE  = re.compile(r'(<!entity|system\s+"|\bfile://|/etc/passwd)', re.IGNORECASE)
_SSTI_RE = re.compile(r'(\{\{.{1,60}\}\}|\$\{.{1,60}\}|<%=.{1,60}%>|\{%.{1,60}%\}|#\{.{1,60}\})', re.IGNORECASE)
_NOSQL_RE = re.compile(r'"\$\s*(gt|lt|gte|lte|ne|eq|in|nin|exists|regex|where|or|and)"\s*:', re.IGNORECASE)
_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}


def _classify_anomalous(path_query: str, body: str) -> str:
    decoded = urllib.parse.unquote_plus(path_query + " " + body)
    if _XXE_RE.search(decoded):   return "XXE"
    if _SSTI_RE.search(decoded):  return "SSTI"
    if _NOSQL_RE.search(decoded): return "Injection"
    if _XSS_RE.search(decoded):   return "XSS"
    if _SQL_RE.search(decoded):   return "Injection"
    if _TRAV_RE.search(decoded):  return "Manipulation"
    return "HTTP abusion"


def _parse_csic_file(filepath: str, label_fn) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    try:
        lines = open(filepath, encoding="latin-1", errors="replace").read().splitlines()
    except OSError:
        return rows
    i = 0
    while i < len(lines):
        parts = lines[i].split(" ", 2)
        if len(parts) >= 2 and parts[0] in _METHODS:
            method = parts[0]
            parsed = urllib.parse.urlparse(parts[1])
            pq     = parsed.path + ("?" + parsed.query if parsed.query else "")
            j = i + 1
            # collect headers (was: skip headers)
            raw_headers: dict[str, str] = {}
            while j < len(lines) and lines[j].strip():
                if ":" in lines[j]:
                    k, _, v = lines[j].partition(":")
                    raw_headers[k.strip()] = v.strip()
                j += 1
            j += 1                                        # skip blank line
            body_parts: list[str] = []
            while j < len(lines) and lines[j].strip():   # collect body
                body_parts.append(lines[j].strip())
                j += 1
            body = " ".join(body_parts)
            header_lines = [
                f"{k}: {raw_headers[k]}"
                for k in _INCLUDE_HEADERS
                if raw_headers.get(k)
            ]
            text = f"{method} {pq}" + (f" {body}" if body else "")
            if header_lines:
                text += "\n" + "\n".join(header_lines)
            rows.append((text, label_fn(pq, body)))
            i = j
        else:
            i += 1
    return rows


def load_csic2010() -> list[tuple[str, str]]:
    base = os.path.join(HERE, "csic2010")
    rows: list[tuple[str, str]] = []
    for fname in ("normalTrafficTraining.txt", "normalTrafficTest.txt"):
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            print(f"  [WARN] {path} not found — skipping")
            continue
        chunk = _parse_csic_file(path, lambda *_: "Normal")
        rows.extend(chunk)
        print(f"  {fname}: {len(chunk):,} Normal samples")
    anom = os.path.join(base, "anomalousTrafficTest.txt")
    if os.path.exists(anom):
        chunk = _parse_csic_file(anom, _classify_anomalous)
        rows.extend(chunk)
        counts: dict[str, int] = defaultdict(int)
        for _, cat in chunk:
            counts[cat] += 1
        print(f"  anomalousTrafficTest.txt: {len(chunk):,} samples")
        for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"    {cat:<40} {n:>7,}")
    else:
        print(f"  [WARN] {anom} not found — skipping")
    return rows


def load_srbh2020() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    base = os.path.join(HERE, "SRBH2020")
    for fname in ("dataset_capec_combine.csv", "dataset_capec_transfer.csv"):
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            print(f"  [WARN] {path} not found — skipping")
            continue
        df = pd.read_csv(path).dropna(subset=["text", "category"])
        for _, row in df.iterrows():
            rows.append((str(row["text"]), str(row["category"])))
        counts = df["category"].value_counts().to_dict()
        print(f"  {fname}: {len(df):,} samples")
        for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"    {cat:<40} {n:>7,}")
    return rows

# ── HuggingFace ai-waf-dataset ────────────────────────────────────────────────

def _parse_hf_request(text: str) -> str:
    """Full HTTP text → multi-line format with method, url, body, and important headers."""
    lines = text.split("\n")
    if not lines:
        return ""
    parts = lines[0].split(" ", 2)          # METHOD /path HTTP/1.1
    if len(parts) < 2:
        return ""
    method = parts[0]
    url    = parts[1]                        # already /path?query, no host
    raw_headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
            elif ":" in line:
                k, _, v = line.partition(":")
                raw_headers[k.strip()] = v.strip()
        else:
            if line.strip():
                body_lines.append(line.strip())
    body = " ".join(body_lines)
    header_lines = [
        f"{k}: {raw_headers[k]}"
        for k in _INCLUDE_HEADERS
        if raw_headers.get(k)
    ]
    result = f"{method} {url}" + (f" {body}" if body else "")
    if header_lines:
        result += "\n" + "\n".join(header_lines)
    return result


def load_hf_waf_dataset() -> list[tuple[str, str]]:
    path = os.path.join(HERE, "modern_payloads", "ai_waf_dataset.parquet")
    if not os.path.exists(path):
        print(f"  [WARN] {path} not found — skipping")
        return []
    df = pd.read_parquet(path)
    rows: list[tuple[str, str]] = []
    skipped = 0
    for _, row in df.iterrows():
        text = _parse_hf_request(str(row["text"]))
        if not text:
            skipped += 1
            continue
        if row["label"] == "benign":
            cat = "Normal"
        else:
            pq   = text.split(" ", 2)[1] if " " in text else ""
            body = text.split(" ", 2)[2] if text.count(" ") >= 2 else ""
            cat  = _classify_anomalous(pq, body)
        rows.append((text, cat))
    counts: dict[str, int] = defaultdict(int)
    for _, cat in rows:
        counts[cat] += 1
    print(f"  ai_waf_dataset.parquet: {len(rows):,} samples  (skipped {skipped})")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:<40} {n:>7,}")
    return rows


# ── PayloadsAllTheThings — modern synthetic requests ──────────────────────────

# REST API path templates for wrapping raw payloads
_REST_TEMPLATES: list[str] = [
    "GET /api/v1/search?q={p}",
    "GET /api/v2/items?id={p}",
    "GET /api/v1/users?filter={p}",
    "POST /api/v1/data {{\"value\":\"{p}\"}}",
    "POST /api/v2/query {{\"input\":\"{p}\"}}",
    "POST /api/v1/render {{\"template\":\"{p}\"}}",
    "GET /app/view?page={p}",
    "POST /graphql {{\"query\":\"{{ items(id:\\\"{p}\\\") {{ name }} }}\"}}",
]


def _wrap_payload(payload: str, templates: list[str]) -> list[str]:
    out = []
    for tmpl in templates:
        try:
            out.append(tmpl.format(p=payload.replace('"', '\\"')))
        except (KeyError, IndexError):
            pass
    return out


def load_modern_payloads() -> list[tuple[str, str]]:
    base = os.path.join(HERE, "modern_payloads")
    rows: list[tuple[str, str]] = []

    payload_files: list[tuple[str, str, list[str]]] = [
        # (filename, category, templates to use)
        ("ssti.fuzz",          "SSTI",       _REST_TEMPLATES),
        ("ssti_engines.txt",   "SSTI",       _REST_TEMPLATES),
        ("nosql_mongodb.txt",  "Injection",  _REST_TEMPLATES[:6]),
        ("nosql_generic.txt",  "Injection",  _REST_TEMPLATES[:6]),
        ("sqli_polyglots.txt", "Injection",  _REST_TEMPLATES[:6]),
        ("sqli_generic.txt",   "Injection",  _REST_TEMPLATES[:6]),
        ("xss_polyglots.txt",  "XSS",        _REST_TEMPLATES[:6]),
        ("xss_jhaddix.txt",    "XSS",        _REST_TEMPLATES[:5]),
        ("cmd_unix.txt",       "Injection",  _REST_TEMPLATES[:5]),
        ("lfi_jhaddix.txt",    "Manipulation", _REST_TEMPLATES[:4]),
    ]

    for fname, category, templates in payload_files:
        fpath = os.path.join(base, fname)
        if not os.path.exists(fpath):
            print(f"  [WARN] {fpath} not found — skipping")
            continue
        payloads = [
            l.strip() for l in open(fpath, encoding="utf-8", errors="replace")
            if l.strip() and not l.startswith("#")
        ]
        before = len(rows)
        for p in payloads:
            for req in _wrap_payload(p, templates):
                rows.append((req, category))
        print(f"  {fname:<30} -> {category:<15} +{len(rows)-before:>6,} samples")

    return rows


# ── Sampling ──────────────────────────────────────────────────────────────────

def apply_cap(
    rows: list[tuple[str, str]], cap: int | None
) -> list[tuple[str, str]]:
    if cap is None:
        return rows
    by_class: dict[str, list[str]] = defaultdict(list)
    for text, cat in rows:
        by_class[cat].append(text)
    result: list[tuple[str, str]] = []
    for cat, texts in sorted(by_class.items()):
        if len(texts) > cap:
            texts = random.sample(texts, cap)
        for t in texts:
            result.append((t, cat))
    return result

# ── Stats printer ─────────────────────────────────────────────────────────────

def print_stats(
    label: str,
    before: dict[str, int],
    after: dict[str, int] | None = None,
) -> None:
    all_cats = sorted(before.keys())
    total_before = sum(before.values())
    total_after  = sum(after.values()) if after else total_before

    print(f"\n{'='*65}")
    print(f" {label}")
    print(f"{'='*65}")
    if after:
        print(f"  {'Category':<40} {'Before':>8}  {'After':>8}")
        print(f"  {'-'*58}")
        for cat in all_cats:
            b = before.get(cat, 0)
            a = after.get(cat, 0)
            flag = " (capped)" if a < b else ""
            print(f"  {cat:<40} {b:>8,}  {a:>8,}{flag}")
        print(f"  {'-'*58}")
        print(f"  {'TOTAL':<40} {total_before:>8,}  {total_after:>8,}")
    else:
        print(f"  {'Category':<40} {'Samples':>8}  {'%':>6}")
        print(f"  {'-'*58}")
        for cat in all_cats:
            n = before[cat]
            print(f"  {cat:<40} {n:>8,}  {n/total_before*100:>5.1f}%")
        print(f"  {'-'*58}")
        print(f"  {'TOTAL':<40} {total_before:>8,}")

# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> int | None:
    if "--no-cap" in sys.argv:
        return None
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--cap" and i < len(sys.argv):
            return int(sys.argv[i + 1])
        if arg.startswith("--cap="):
            return int(arg.split("=", 1)[1])
    return DEFAULT_CAP


def main() -> None:
    cap = parse_args()

    print(f"\n{'='*65}")
    print(" Building unified WAF dataset")
    print(f"  Per-class cap : {'none (--no-cap)' if cap is None else f'{cap:,}'}")
    print(f"  Random seed   : {SEED}")
    print(f"{'='*65}")

    t0 = time.perf_counter()

    print("\n[1/6] Malicious JSON ...")
    malicious = load_malicious()

    print("\n[2/6] Legitimate JSON ...")
    legit_cap = cap if cap is not None else 100_000
    legit = load_legitimate(legit_cap)

    print("\n[3/6] SRBH2020 CSVs ...")
    srbh = load_srbh2020()

    print("\n[4/6] CSIC 2010 ...")
    csic = load_csic2010()

    print("\n[5/6] HuggingFace ai-waf-dataset (modern REST/JSON attacks) ...")
    hf = load_hf_waf_dataset()

    print("\n[6/6] Modern payloads (SSTI, NoSQL, polyglots) ...")
    modern = load_modern_payloads()

    # ── Merge ─────────────────────────────────────────────────────────────────
    all_rows = malicious + legit + srbh + csic + hf + modern
    print(f"\nMerged {len(all_rows):,} rows total — applying per-class cap ...")

    before: dict[str, int] = defaultdict(int)
    for _, cat in all_rows:
        before[cat] += 1

    sampled = apply_cap(all_rows, cap)
    random.shuffle(sampled)

    after: dict[str, int] = defaultdict(int)
    for _, cat in sampled:
        after[cat] += 1

    print_stats("Class distribution (before -> after sampling)", before, after)

    # ── Write ─────────────────────────────────────────────────────────────────
    df_out = pd.DataFrame(sampled, columns=["text", "category"])
    df_out.to_csv(OUT_PATH, index=False)

    elapsed = time.perf_counter() - t0
    print(f"\nSaved {len(df_out):,} rows -> {OUT_PATH}  ({elapsed:.1f}s)")
    print("\nNext step:  python train.py")


if __name__ == "__main__":
    main()
