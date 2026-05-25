#!/usr/bin/env python3
"""
Build clean unified WAF dataset — structured CSV format.

Sources and loading policy
--------------------------
1. openappsec Malicious       — ALL
2. openappsec Legitimate      — ALL
3. SRBH2020 combine           — ALL (static-asset noise filter applied)
4. SRBH2020 transfer          — Normal only, attacks dropped
5. CSIC 2010                  — Normal only, anomalous skipped entirely
6. HuggingFace ai-waf-dataset — ALL (static-asset noise filter applied)
7. PayloadsAllTheThings       — ALL
8. hackathon_attacks          — ALL (13 attack classes, openapi-targeted)
9. attack_based_malicious     — ALL (6 attack classes, real payloads on openapi endpoints)
10. normal_api                — ALL (Normal, openapi-schema traffic)
11. normal_traffic            — ALL (Normal, benign browser traffic)

Global cleaning (all sources)
------------------------------
- Remove exact-duplicate (method, url, body, category) tuples
- Remove rows where url is shorter than 2 characters

Output CSV columns
------------------
  text     : "METHOD /url[ body][\\nHeader: value]..."  ← backward-compat with train.py
  method   : HTTP method (GET/POST/…)
  url      : /path?query
  body     : request body (empty string if none)
  headers  : JSON-encoded dict of selected request headers
  category : unified class label
  source   : source dataset identifier

Usage
-----
    python build_clean_dataset.py              # no per-class cap (recommended)
    python build_clean_dataset.py --cap 50000  # optional per-class cap
"""
import csv
import glob
csv.field_size_limit(2**31 - 1)   # some text/body fields exceed the 128 KB default
import json
import os
import random
import re
import sys
import time
import urllib.parse
from collections import defaultdict

import pandas as pd

HERE     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
SEED     = 42
random.seed(SEED)

OUT_PATH = os.path.join(HERE, "dataset_unified.csv")

# ── Category mappings ──────────────────────────────────────────────────────────

MALICIOUS_CATEGORY: dict[str, str] = {
    "sqli":       "Injection",
    "cmdexe":     "Injection",
    "shellshock": "Injection",
    "traversal":  "Manipulation",
    "xss":        "XSS",
    "xxe":        "XXE",
    "log4shell":  "Log4Shell",
}

# Maps hackathon_attacks class names -> project taxonomy
HACKATHON_CLASS_MAP: dict[str, str] = {
    "sqli":              "Injection",
    "xss":               "XSS",
    "path_traversal":    "Manipulation",
    "ssrf":              "Fake the Source of Data",
    "command_injection": "Injection",
    "ssti":              "SSTI",
    "nosql_injection":   "Injection",
    "log4shell":         "Log4Shell",
    "header_injection":  "HTTP abusion",
    "xxe":               "XXE",
    "open_redirect":     "Manipulation",
    "mass_assignment":   "HTTP abusion",
    "recon":             "Scanning for Vulnerable Software",
}

# Headers worth preserving across all sources
_INCLUDE_HEADERS = (
    "User-Agent", "Cookie", "Referer", "Authorization",
    "Content-Type", "X-Forwarded-For", "X-Real-IP",
)
_HEADER_LOWER_MAP = {k.lower(): k for k in _INCLUDE_HEADERS}

_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"}


def _normalize_url(raw: str) -> str:
    """Strip scheme+host from absolute URLs; return /path[?query] only.

    Source datasets sometimes store full URLs (https://host/path?q=1).
    At inference the WAF only sees the relative request target (/path?q=1),
    so we must normalize to the same form before feature extraction.
    """
    if not raw:
        return "/"
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if parsed.fragment:
            path += "#" + parsed.fragment
        return path
    return raw


# WAF only needs the first few KB to classify — truncate to keep the dataset sane
_MAX_URL_LEN  = 4_096   # 4 KB
_MAX_BODY_LEN = 8_192   # 8 KB

ATTACK_CATEGORIES = {
    "Injection", "XSS", "XXE", "Manipulation", "HTTP abusion",
    "Log4Shell", "SSTI", "Scanning for Vulnerable Software",
    "Fake the Source of Data", "16 - Dictionary-based Password Attack",
}

# ── Static-asset noise filter (SRBH2020 + HuggingFace) ────────────────────────

_CMS_STATIC_RE = re.compile(
    r'/(?:wp-includes|wp-content/(?:themes|plugins)|assets|static|dist|'
    r'build|vendor|node_modules|public/js|public/css)/'
    r'[^?#]*\.(min\.js|min\.css|js|css|woff2?|ttf|eot|svg|png|jpg|gif|ico|map)(\?|#|$)',
    re.IGNORECASE,
)
_ATTACK_SIGNAL_RE = re.compile(
    r'(?:%00|%0[aAdD]|%25[0-9a-fA-F]{2}|'
    r'\bselect\b|\bunion\b|\bdrop\b|'
    r'<script|javascript:|'
    r'\.\./|%2e%2e|'
    r'\$\{|%24%7B|'
    r'%5[bBdD]|'
    r'NULL|SLEEP\s*\(|WAITFOR)',
    re.IGNORECASE,
)


def _is_noisy_static(url: str, category: str) -> bool:
    """True if URL is a clean CMS static asset mislabeled as an attack."""
    if category not in ATTACK_CATEGORIES:
        return False
    if not _CMS_STATIC_RE.search(url):
        return False
    return not _ATTACK_SIGNAL_RE.search(url)


# ── Row helpers ────────────────────────────────────────────────────────────────

def _filter_headers(raw: dict) -> dict:
    """Keep only important headers; normalize keys to canonical casing."""
    out: dict[str, str] = {}
    for k, v in raw.items():
        canonical = _HEADER_LOWER_MAP.get(k.lower())
        if canonical and v:
            out[canonical] = str(v).strip()
    return out


def make_row(method: str, url: str, body: str, headers: dict,
             category: str, source: str) -> dict:
    return {
        "method":   method.upper().strip(),
        "url":      url.strip()[:_MAX_URL_LEN],
        "body":     str(body).strip().replace("\r\n", "\n").replace("\r", "\n")[:_MAX_BODY_LEN],
        "headers":  headers,   # kept as dict until CSV write
        "category": category,
        "source":   source,
    }


# ── Payload classifiers (HuggingFace auto-label) ──────────────────────────────

_SQL_RE   = re.compile(r'\b(select|union|insert|update|delete|drop|alter|truncate|exec|having|order\s+by|group\s+by|--\s|/\*)\b', re.IGNORECASE)
_XSS_RE   = re.compile(r'(<\s*script|javascript:|on\w+\s*=|alert\s*\(|%3cscript)', re.IGNORECASE)
_TRAV_RE  = re.compile(r'(\.\.[\\/]|%2e%2e|%252e)', re.IGNORECASE)
_XXE_RE   = re.compile(r'(<!entity|system\s+"|\bfile://|/etc/passwd)', re.IGNORECASE)
_SSTI_RE  = re.compile(r'(\{\{.{1,60}\}\}|\$\{.{1,60}\}|<%=.{1,60}%>|\{%.{1,60}%\}|#\{.{1,60}\})', re.IGNORECASE)
_NOSQL_RE = re.compile(r'"\$\s*(gt|lt|gte|lte|ne|eq|in|nin|exists|regex|where|or|and)"\s*:', re.IGNORECASE)


def _classify_payload(url: str, body: str) -> str:
    decoded = urllib.parse.unquote_plus(url + " " + body)
    if _XXE_RE.search(decoded):   return "XXE"
    if _SSTI_RE.search(decoded):  return "SSTI"
    if _NOSQL_RE.search(decoded): return "Injection"
    if _XSS_RE.search(decoded):   return "XSS"
    if _SQL_RE.search(decoded):   return "Injection"
    if _TRAV_RE.search(decoded):  return "Manipulation"
    return "HTTP abusion"


# ── Source 1: openappsec Malicious ────────────────────────────────────────────

def load_malicious() -> list[dict]:
    rows: list[dict] = []
    base = os.path.join(DATA_DIR, "malicious", "Malicious")
    for name, category in MALICIOUS_CATEGORY.items():
        path = os.path.join(base, f"{name}.json")
        if not os.path.exists(path):
            print(f"  [WARN] {path} not found — skipping")
            continue
        with open(path, encoding="utf-8") as f:
            entries = json.load(f)
        for e in entries:
            method = (e.get("method") or "GET").strip()
            url    = _normalize_url((e.get("url") or "/").strip())
            body   = e.get("data") or ""
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":"))
            rows.append(make_row(method, url, str(body),
                                 _filter_headers(e.get("headers") or {}),
                                 category, "openappsec_malicious"))
        print(f"  {name:<12} -> {category:<35} {len(entries):>7,}")
    return rows


# ── Source 2: openappsec Legitimate ───────────────────────────────────────────

def load_legitimate() -> list[dict]:
    pattern = os.path.join(DATA_DIR, "legitimate", "Legitimate", "*.json")
    files = sorted(glob.glob(pattern))
    print(f"  {len(files)} JSON files found — loading ALL ...")
    rows: list[dict] = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                entries = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for e in entries:
            method = (e.get("method") or "GET").strip()
            url    = _normalize_url((e.get("url") or "/").strip())
            body   = e.get("data") or ""
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":"))
            rows.append(make_row(method, url, str(body),
                                 _filter_headers(e.get("headers") or {}),
                                 "Normal", "openappsec_legitimate"))
        if len(rows) % 200_000 == 0 and len(rows) > 0:
            print(f"    ... {len(rows):,} loaded")
    print(f"  Loaded {len(rows):,} Normal samples")
    return rows


# ── Source 3: SRBH2020 combine ────────────────────────────────────────────────

def _parse_srbh_text(text: str) -> tuple[str, str, str]:
    """Parse 'METHOD /path [body]' -> (method, url, body). No headers in SRBH2020."""
    first_line = text.split("\n")[0].strip()
    parts = first_line.split(" ", 2)
    method = parts[0] if parts and parts[0] in _METHODS else "GET"
    url    = _normalize_url(parts[1] if len(parts) > 1 else "/")
    body   = parts[2] if len(parts) > 2 else ""
    return method, url, body


def load_srbh2020_combine() -> list[dict]:
    path = os.path.join(DATA_DIR, "SRBH2020", "dataset_capec_combine.csv")
    if not os.path.exists(path):
        print(f"  [WARN] {path} not found — skipping")
        return []
    df = pd.read_csv(path, usecols=["text", "category"],
                     dtype={"text": "object", "category": "object"}).dropna(subset=["text", "category"])
    rows: list[dict] = []
    noise = 0
    counts: dict[str, int] = defaultdict(int)
    for row in df.itertuples(index=False):
        method, url, body = _parse_srbh_text(row.text)
        category = row.category
        if _is_noisy_static(url, category):
            noise += 1
            continue
        rows.append(make_row(method, url, body, {}, category, "srbh2020_combine"))
        counts[category] += 1
    print(f"  dataset_capec_combine.csv: {len(rows):,} rows kept  (noise filtered: {noise:,})")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:<45} {n:>7,}")
    return rows


# ── Source 4: SRBH2020 transfer — Normal only ─────────────────────────────────

def load_srbh2020_transfer_normal() -> list[dict]:
    path = os.path.join(DATA_DIR, "SRBH2020", "dataset_capec_transfer.csv")
    if not os.path.exists(path):
        print(f"  [WARN] {path} not found — skipping")
        return []
    df = pd.read_csv(path, usecols=["text", "category"],
                     dtype={"text": "object", "category": "object"}).dropna(subset=["text", "category"])
    normal_df = df[df["category"] == "Normal"]
    rows: list[dict] = []
    for row in normal_df.itertuples(index=False):
        method, url, body = _parse_srbh_text(row.text)
        rows.append(make_row(method, url, body, {}, "Normal", "srbh2020_transfer"))
    dropped = len(df) - len(normal_df)
    if len(rows) == 0:
        print(f"  dataset_capec_transfer.csv: 0 Normal rows found — {dropped:,} attacks dropped")
        print(f"  [NOTE] transfer set contains only attack classes; no Normal data available")
    else:
        print(f"  dataset_capec_transfer.csv: {len(rows):,} Normal kept  (dropped {dropped:,} attacks)")
    return rows


# ── Source 5: CSIC 2010 — Normal only ────────────────────────────────────────

def load_csic2010_normal() -> list[dict]:
    base = os.path.join(DATA_DIR, "csic2010")
    rows: list[dict] = []
    for fname in ("normalTrafficTraining.txt", "normalTrafficTest.txt"):
        fpath = os.path.join(base, fname)
        if not os.path.exists(fpath):
            print(f"  [WARN] {fpath} not found — skipping")
            continue
        try:
            lines = open(fpath, encoding="latin-1", errors="replace").read().splitlines()
        except OSError:
            continue
        chunk: list[dict] = []
        i = 0
        while i < len(lines):
            parts = lines[i].split(" ", 2)
            if len(parts) >= 2 and parts[0] in _METHODS:
                method = parts[0]
                parsed = urllib.parse.urlparse(parts[1])
                url = parsed.path + ("?" + parsed.query if parsed.query else "")
                j = i + 1
                raw_hdrs: dict[str, str] = {}
                while j < len(lines) and lines[j].strip():
                    if ":" in lines[j]:
                        k, _, v = lines[j].partition(":")
                        raw_hdrs[k.strip()] = v.strip()
                    j += 1
                j += 1
                body_parts: list[str] = []
                while j < len(lines) and lines[j].strip():
                    body_parts.append(lines[j].strip())
                    j += 1
                chunk.append(make_row(method, url, " ".join(body_parts),
                                      _filter_headers(raw_hdrs),
                                      "Normal", "csic2010"))
                i = j
            else:
                i += 1
        rows.extend(chunk)
        print(f"  {fname}: {len(chunk):,} Normal samples")
    print(f"  anomalousTrafficTest.txt: skipped — all attacks dropped per policy")
    return rows


# ── Source 6: HuggingFace ai-waf-dataset ──────────────────────────────────────

# Map known HuggingFace attack label strings to project taxonomy.
# Only "benign" → Normal; everything else is an attack — use the label directly
# if it's in this table, otherwise fall back to regex-based _classify_payload().
_HF_LABEL_MAP: dict[str, str] = {
    "sqli":              "Injection",
    "sql_injection":     "Injection",
    "nosql_injection":   "Injection",
    "nosql":             "Injection",
    "command_injection": "Injection",
    "rce":               "Injection",
    "xss":               "XSS",
    "cross_site_scripting": "XSS",
    "path_traversal":    "Manipulation",
    "lfi":               "Manipulation",
    "rfi":               "Manipulation",
    "open_redirect":     "Manipulation",
    "xxe":               "XXE",
    "ssti":              "SSTI",
    "ssrf":              "Fake the Source of Data",
    "log4shell":         "Log4Shell",
    "header_injection":  "HTTP abusion",
    "mass_assignment":   "HTTP abusion",
    "recon":             "Scanning for Vulnerable Software",
    "scanning":          "Scanning for Vulnerable Software",
    "malicious":         None,  # generic label — fall through to _classify_payload
}

def _parse_hf_entry(text: str) -> tuple[str, str, str, dict]:
    """Full HTTP text -> (method, url, body, headers)."""
    lines = text.split("\n")
    if not lines:
        return "", "", "", {}
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return "", "", "", {}
    method, url = parts[0], _normalize_url(parts[1])
    raw_hdrs: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if not line.strip():
                in_body = True
            elif ":" in line:
                k, _, v = line.partition(":")
                raw_hdrs[k.strip()] = v.strip()
        elif line.strip():
            body_lines.append(line.strip())
    return method, url, " ".join(body_lines), _filter_headers(raw_hdrs)


def load_hf_waf_dataset() -> list[dict]:
    path = os.path.join(DATA_DIR, "modern_payloads", "ai_waf_dataset.parquet")
    if not os.path.exists(path):
        print(f"  [WARN] {path} not found — skipping")
        return []
    df = pd.read_parquet(path)
    rows: list[dict] = []
    skipped = noise = 0
    counts: dict[str, int] = defaultdict(int)
    for row in df.itertuples(index=False):
        method, url, body, headers = _parse_hf_entry(row.text)
        if not method or not url:
            skipped += 1
            continue
        raw_label = str(row.label).lower().strip()
        if raw_label == "benign":
            category = "Normal"
        else:
            # Use the original label if it maps directly to our taxonomy;
            # fall back to regex-based classification only for generic labels
            # (e.g. "malicious") or unknown strings.
            mapped = _HF_LABEL_MAP.get(raw_label)
            category = mapped if mapped is not None else _classify_payload(url, body)
            if _is_noisy_static(url, category):
                noise += 1
                continue
        rows.append(make_row(method, url, body, headers, category, "huggingface"))
        counts[category] += 1
    print(f"  ai_waf_dataset.parquet: {len(rows):,} rows  (skipped {skipped}, noise {noise})")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:<45} {n:>7,}")
    return rows


# ── Source 7: PayloadsAllTheThings / SecLists ─────────────────────────────────

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


def load_modern_payloads() -> list[dict]:
    base = os.path.join(DATA_DIR, "modern_payloads")
    rows: list[dict] = []

    payload_files: list[tuple[str, str, list[str]]] = [
        ("ssti.fuzz",          "SSTI",        _REST_TEMPLATES),
        ("ssti_engines.txt",   "SSTI",        _REST_TEMPLATES),
        ("nosql_mongodb.txt",  "Injection",   _REST_TEMPLATES[:6]),
        ("nosql_generic.txt",  "Injection",   _REST_TEMPLATES[:6]),
        ("sqli_polyglots.txt", "Injection",   _REST_TEMPLATES[:6]),
        ("sqli_generic.txt",   "Injection",   _REST_TEMPLATES[:6]),
        ("xss_polyglots.txt",  "XSS",         _REST_TEMPLATES[:6]),
        ("xss_jhaddix.txt",    "XSS",         _REST_TEMPLATES[:5]),
        ("cmd_unix.txt",       "Injection",   _REST_TEMPLATES[:5]),
        ("lfi_jhaddix.txt",    "Manipulation", _REST_TEMPLATES[:4]),
    ]

    for fname, category, templates in payload_files:
        fpath = os.path.join(base, fname)
        if not os.path.exists(fpath):
            print(f"  [WARN] {fpath} not found — skipping")
            continue
        with open(fpath, encoding="utf-8", errors="replace") as _f:
            payloads = [ln.strip() for ln in _f if ln.strip() and not ln.startswith("#")]
        before = len(rows)
        for p in payloads:
            for tmpl in templates:
                try:
                    req = tmpl.format(p=p.replace('"', '\\"'))
                except (KeyError, IndexError):
                    continue
                parts = req.split(" ", 2)
                if len(parts) < 2:
                    continue
                rows.append(make_row(
                    parts[0], parts[1],
                    parts[2] if len(parts) > 2 else "",
                    {}, category, "payloads_all_the_things",
                ))
        print(f"  {fname:<30} -> {category:<15} +{len(rows) - before:>6,}")
    return rows


# ── Generic attack JSON dir loader ────────────────────────────────────────────
# Used for hackathon_attacks, attack_based_malicious, and any future dir that
# follows the same format: list of {method, url, headers, data} per JSON file,
# filename stem = attack class name mappable via HACKATHON_CLASS_MAP.

def load_attack_json_dir(dirname: str) -> list[dict]:
    base = os.path.join(DATA_DIR, dirname)
    if not os.path.exists(base):
        print(f"  [WARN] {base} not found — skipping")
        return []
    rows: list[dict] = []
    for fname in sorted(os.listdir(base)):
        if not fname.endswith(".json") or fname.startswith("_"):
            continue
        stem = fname[:-5]
        category = HACKATHON_CLASS_MAP.get(stem, "Injection")
        path = os.path.join(base, fname)
        with open(path, encoding="utf-8") as f:
            entries = json.load(f)
        for e in entries:
            method = (e.get("method") or "GET").strip()
            url    = _normalize_url((e.get("url") or "/").strip())
            body   = e.get("data") or ""
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":"))
            rows.append(make_row(method, url, str(body),
                                 _filter_headers(e.get("headers") or {}),
                                 category, dirname))
        print(f"  {fname:<35} -> {category:<35} {len(entries):>7,}")
    print(f"  {dirname}: {len(rows):,} attack samples")
    return rows


# ── Source 9 & 10: normal_api / normal_traffic ─────────────────────────────────

def load_normal_json_dir(dirname: str) -> list[dict]:
    base = os.path.join(DATA_DIR, dirname)
    if not os.path.exists(base):
        print(f"  [WARN] {base} not found — skipping")
        return []
    rows: list[dict] = []
    for fname in sorted(os.listdir(base)):
        if not fname.endswith(".json") or fname.startswith("_"):
            continue
        path = os.path.join(base, fname)
        try:
            with open(path, encoding="utf-8") as f:
                entries = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for e in entries:
            method = (e.get("method") or "GET").strip()
            url    = _normalize_url((e.get("url") or "/").strip())
            body   = e.get("data") or ""
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":"))
            rows.append(make_row(method, url, str(body),
                                 _filter_headers(e.get("headers") or {}),
                                 "Normal", dirname))
        print(f"  {fname:<35} {len(entries):>8,} Normal samples")
    print(f"  {dirname}: {len(rows):,} total")
    return rows


# ── Global cleaning ────────────────────────────────────────────────────────────

def deduplicate(rows: list[dict]) -> tuple[list[dict], int]:
    seen: set[int] = set()
    out: list[dict] = []
    for r in rows:
        # Include headers so two identical requests from different sources but
        # with different header context are both kept as distinct training examples.
        hdr_key = tuple(sorted(r["headers"].items()))
        key = hash((r["method"], r["url"], r["body"], r["category"], hdr_key))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out, len(rows) - len(out)


def filter_short(rows: list[dict]) -> tuple[list[dict], int]:
    # Drop only truly empty URLs — "/" is a valid root path and must be kept.
    cleaned = [r for r in rows if r["url"].strip()]
    return cleaned, len(rows) - len(cleaned)


# ── Sampling (optional) ────────────────────────────────────────────────────────

def apply_cap(rows: list[dict], cap: int | None) -> list[dict]:
    if cap is None:
        return rows
    by_class: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_class[r["category"]].append(r)
    result: list[dict] = []
    for cat, items in sorted(by_class.items()):
        if len(items) > cap:
            items = random.sample(items, cap)
        result.extend(items)
    return result


# ── Stats ──────────────────────────────────────────────────────────────────────

def print_stats(rows: list[dict], label: str) -> None:
    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        counts[r["category"]] += 1
    total = sum(counts.values())
    print(f"\n{'='*65}")
    print(f" {label}  ({total:,} total)")
    print(f"{'='*65}")
    print(f"  {'Category':<45} {'N':>8}  {'%':>5}")
    print(f"  {'-'*60}")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:<45} {n:>8,}  {n / total * 100:>4.1f}%")
    print(f"  {'-'*60}")
    print(f"  {'TOTAL':<45} {total:>8,}")


# ── Output ─────────────────────────────────────────────────────────────────────

_CSV_FIELDS = ["text", "method", "url", "body", "headers", "category", "source"]


def save_csv(rows: list[dict], path: str) -> None:
    """Stream rows to CSV one at a time — avoids large in-memory DataFrame."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for r in rows:
            hdrs      = r["headers"]
            hdr_lines = [f"{k}: {v}" for k, v in hdrs.items()]
            body      = r["body"]
            # text column: body newlines → space so the "METHOD /url body" first
            # line stays on one line (features.py splits on the first \n to find
            # where headers start).  The raw body (with \n) is preserved in the
            # separate `body` column.
            body_for_text = body.replace("\n", " ")
            text = f"{r['method']} {r['url']}" + (f" {body_for_text}" if body else "")
            if hdr_lines:
                text += "\n" + "\n".join(hdr_lines)
            writer.writerow({
                "text":     text,
                "method":   r["method"],
                "url":      r["url"],
                "body":     body,
                "headers":  json.dumps(hdrs, ensure_ascii=False),
                "category": r["category"],
                "source":   r["source"],
            })


# ── Args ───────────────────────────────────────────────────────────────────────

def parse_args() -> int | None:
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--cap" and i + 1 < len(sys.argv):
            return int(sys.argv[i + 1])
        if arg.startswith("--cap="):
            return int(arg.split("=", 1)[1])
    return None  # default: no cap


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    cap = parse_args()

    print(f"\n{'='*65}")
    print(" Building CLEAN unified WAF dataset")
    print(f"  Per-class cap : {'none (all data)' if cap is None else f'{cap:,}'}")
    print(f"  Random seed   : {SEED}")
    print(f"  Output        : {OUT_PATH}")
    print(f"{'='*65}")

    t0 = time.perf_counter()

    print("\n[ 1/11] openappsec Malicious ...")
    malicious = load_malicious()

    print("\n[ 2/11] openappsec Legitimate (loading ALL — may take several minutes) ...")
    legit = load_legitimate()

    print("\n[ 3/11] SRBH2020 combine ...")
    srbh_combine = load_srbh2020_combine()

    print("\n[ 4/11] SRBH2020 transfer — Normal only ...")
    srbh_transfer = load_srbh2020_transfer_normal()

    print("\n[ 5/11] CSIC 2010 — Normal only ...")
    csic = load_csic2010_normal()

    print("\n[ 6/11] HuggingFace ai-waf-dataset ...")
    hf = load_hf_waf_dataset()

    print("\n[ 7/11] PayloadsAllTheThings / SecLists ...")
    modern = load_modern_payloads()

    print("\n[ 8/11] hackathon_attacks ...")
    hackathon = load_attack_json_dir("hackathon_attacks")

    print("\n[ 9/11] attack_based_malicious ...")
    attack_based = load_attack_json_dir("attack_based_malicious")

    print("\n[10/11] normal_api ...")
    normal_api = load_normal_json_dir("normal_api")

    print("\n[11/11] normal_traffic ...")
    normal_traffic = load_normal_json_dir("normal_traffic")

    all_rows = malicious + legit + srbh_combine + srbh_transfer + csic + hf + modern + hackathon + attack_based + normal_api + normal_traffic
    print(f"\nMerged {len(all_rows):,} rows total — applying global cleaning ...")

    all_rows, n_dup = deduplicate(all_rows)
    print(f"  Exact duplicates removed : {n_dup:,}")

    all_rows, n_short = filter_short(all_rows)
    print(f"  Empty-URL rows removed   : {n_short:,}")

    print_stats(all_rows, "Distribution before cap")

    if cap is not None:
        print(f"\nApplying per-class cap = {cap:,} ...")
        all_rows = apply_cap(all_rows, cap)
        print_stats(all_rows, "Distribution after cap")

    random.shuffle(all_rows)
    save_csv(all_rows, OUT_PATH)

    elapsed = time.perf_counter() - t0
    print(f"\nSaved {len(all_rows):,} rows -> {OUT_PATH}  ({elapsed:.1f}s)")
    print("Next step: python train.py")


if __name__ == "__main__":
    main()
