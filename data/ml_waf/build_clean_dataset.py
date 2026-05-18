#!/usr/bin/env python3
"""
Build a noise-filtered version of the unified WAF dataset.

Cleaning steps (source files are NEVER modified):
  1. SRBH2020: remove CMS static-asset URLs (*.js, *.css, fonts, images)
               that carry attack labels but show no payload indicators
               → these are SRBH2020 label noise from network-level CAPEC labeling
  2. CSIC 2010 Normal: cap at 10 000 (was 72 000) to reduce distribution
               shift caused by shop-specific traffic (tienda1)
  3. CSIC 2010 Anomalous: drop the "HTTP abusion" auto-label bucket entirely
               (90 % of anomalous; labels assigned by regex with ~60 % certainty)
               → keep only XSS (1 450) and Injection (699) which have clear signals
  4. Global: drop exact-duplicate (text, category) pairs
  5. Global: drop rows whose text is shorter than 8 chars (garbage / empty)

Output: dataset_unified.csv  (same path that train.py expects)
Usage : python build_clean_dataset.py [--cap N | --no-cap]
"""
import os, re, random, sys, time
from collections import defaultdict

import pandas as pd

# ── Re-use all loaders from build_dataset ──────────────────────────────────────
from build_dataset import (
    HERE, SEED, OUT_PATH, DEFAULT_CAP,
    load_malicious, load_legitimate, load_srbh2020,
    load_hf_waf_dataset, load_modern_payloads,
    _parse_csic_file, _classify_anomalous,
    apply_cap, print_stats,
)

random.seed(SEED)

# ─────────────────────────────────────────────────────────────────────────────
# Cleaning helpers
# ─────────────────────────────────────────────────────────────────────────────

# Regex to identify CMS / framework static resource paths
_CMS_STATIC_RE = re.compile(
    r'/(?:wp-includes|wp-content/(?:themes|plugins)|assets|static|dist|'
    r'build|vendor|node_modules|public/js|public/css)/'
    r'[^?#]*\.(min\.js|min\.css|js|css|woff2?|ttf|eot|svg|png|jpg|gif|ico|map)(\?|#|$)',
    re.IGNORECASE,
)

# URL characters that signal a real attack payload in the path
_ATTACK_SIGNAL_RE = re.compile(
    r'(?:%00|%0[aAdD]|%25[0-9a-fA-F]{2}|'   # null-byte, CRLF, double-encode
    r'\bselect\b|\bunion\b|\bdrop\b|'         # SQLi keywords
    r'<script|javascript:|'                   # XSS
    r'\.\./|%2e%2e|'                          # path traversal
    r'\$\{|%24%7B|'                           # SSTI / Log4Shell
    r'%5[bBdD]|'                              # encoded [ ]  (injection marker)
    r'NULL|SLEEP\s*\(|WAITFOR)',              # blind SQLi
    re.IGNORECASE,
)

ATTACK_CLASSES = {
    "Injection", "XSS", "XXE", "Manipulation", "HTTP abusion",
    "Log4Shell", "SSTI", "Scanning for Vulnerable Software",
    "Fake the Source of Data", "16 - Dictionary-based Password Attack",
}

CSIC_NORMAL_CAP    = 10_000   # was 72 000
CSIC_KEEP_CLASSES  = {"XSS", "Injection"}   # drop HTTP abusion from anomalous


def _url_from_text(text: str) -> str:
    parts = text.split(" ", 2)
    return parts[1] if len(parts) >= 2 else ""


def is_noisy_static(text: str, category: str) -> bool:
    """
    Returns True if this row is a false-positive attack label:
    the URL is a clean CMS static resource with no attack signal.
    """
    if category not in ATTACK_CLASSES:
        return False
    url = _url_from_text(text)
    if not _CMS_STATIC_RE.search(url):
        return False
    if _ATTACK_SIGNAL_RE.search(url):
        return False    # has attack payload — keep it
    return True         # clean CMS asset mis-labeled → noise


# ─────────────────────────────────────────────────────────────────────────────
# CSIC 2010 clean loader (overrides build_dataset version)
# ─────────────────────────────────────────────────────────────────────────────

def load_csic2010_clean() -> list[tuple[str, str]]:
    base = os.path.join(HERE, "csic2010")
    rows: list[tuple[str, str]] = []

    # Normal — capped lower to reduce distribution shift
    for fname in ("normalTrafficTraining.txt", "normalTrafficTest.txt"):
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            print(f"  [WARN] {path} not found — skipping")
            continue
        chunk = _parse_csic_file(path, lambda *_: "Normal")
        # sample without replacement up to CSIC_NORMAL_CAP total
        remaining = max(0, CSIC_NORMAL_CAP - sum(1 for _, c in rows if c == "Normal"))
        if len(chunk) > remaining:
            chunk = random.sample(chunk, remaining)
        rows.extend(chunk)
        normal_now = sum(1 for _, c in rows if c == "Normal")
        print(f"  {fname}: kept {len(chunk):,} Normal  (running total {normal_now:,}/{CSIC_NORMAL_CAP:,})")

    # Anomalous — keep only high-certainty classes, drop HTTP abusion
    anom = os.path.join(base, "anomalousTrafficTest.txt")
    if os.path.exists(anom):
        all_anom = _parse_csic_file(anom, _classify_anomalous)
        kept = [(t, c) for t, c in all_anom if c in CSIC_KEEP_CLASSES]
        dropped_abusion = sum(1 for _, c in all_anom if c == "HTTP abusion")
        dropped_other   = len(all_anom) - len(kept) - dropped_abusion
        rows.extend(kept)
        print(f"  anomalousTrafficTest.txt:")
        print(f"    kept    {len(kept):>6,}  (classes: {CSIC_KEEP_CLASSES})")
        print(f"    dropped {dropped_abusion:>6,}  HTTP abusion  (auto-label noise)")
        print(f"    dropped {dropped_other:>6,}  other uncertain classes")
    else:
        print(f"  [WARN] {anom} not found — skipping")

    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Apply static-asset noise filter to a list of rows
# ─────────────────────────────────────────────────────────────────────────────

def filter_static_noise(
    rows: list[tuple[str, str]],
    source_name: str,
) -> tuple[list[tuple[str, str]], int]:
    before = len(rows)
    cleaned = [(t, c) for t, c in rows if not is_noisy_static(t, c)]
    removed = before - len(cleaned)
    if removed:
        print(f"  [{source_name}] static-asset noise removed: {removed:,} rows")
    return cleaned, removed


# ─────────────────────────────────────────────────────────────────────────────
# Global dedup + min-length filter
# ─────────────────────────────────────────────────────────────────────────────

def deduplicate(rows: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], int]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for pair in rows:
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    removed = len(rows) - len(out)
    return out, removed


def filter_short(rows: list[tuple[str, str]], min_len: int = 8) -> tuple[list[tuple[str, str]], int]:
    cleaned = [(t, c) for t, c in rows if len(t.strip()) >= min_len]
    return cleaned, len(rows) - len(cleaned)


# ─────────────────────────────────────────────────────────────────────────────
# Arg parsing (same as build_dataset)
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> int | None:
    if "--no-cap" in sys.argv:
        return None
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--cap" and i < len(sys.argv):
            return int(sys.argv[i + 1])
        if arg.startswith("--cap="):
            return int(arg.split("=", 1)[1])
    return DEFAULT_CAP


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    cap = parse_args()

    print(f"\n{'='*65}")
    print(" Building CLEAN unified WAF dataset")
    print(f"  Per-class cap     : {'none (--no-cap)' if cap is None else f'{cap:,}'}")
    print(f"  Random seed       : {SEED}")
    print(f"  CSIC Normal cap   : {CSIC_NORMAL_CAP:,}")
    print(f"  CSIC keep classes : {CSIC_KEEP_CLASSES}")
    print(f"{'='*65}")

    total_noise = 0
    t0 = time.perf_counter()

    # ── Load ──────────────────────────────────────────────────────────────────
    print("\n[1/6] Malicious JSON ...")
    malicious = load_malicious()
    # No noise filter needed — labels come from filename (reliable)

    print("\n[2/6] Legitimate JSON ...")
    legit_cap = cap if cap is not None else 100_000
    legit = load_legitimate(legit_cap)

    print("\n[3/6] SRBH2020 CSVs ...")
    srbh = load_srbh2020()
    srbh, n = filter_static_noise(srbh, "SRBH2020")
    total_noise += n

    print("\n[4/6] CSIC 2010 (clean loader) ...")
    csic = load_csic2010_clean()
    # No static-noise filter needed — CSIC is raw HTTP, no CMS paths

    print("\n[5/6] HuggingFace ai-waf-dataset ...")
    hf = load_hf_waf_dataset()
    hf, n = filter_static_noise(hf, "HuggingFace")
    total_noise += n

    print("\n[6/6] Modern payloads (SSTI, NoSQL, polyglots) ...")
    modern = load_modern_payloads()
    # Synthetic payloads — no noise filter needed

    # ── Merge ─────────────────────────────────────────────────────────────────
    all_rows = malicious + legit + srbh + csic + hf + modern
    print(f"\nMerged {len(all_rows):,} rows — applying global cleaning ...")

    all_rows, n_dup = deduplicate(all_rows)
    total_noise += n_dup
    print(f"  Duplicates removed     : {n_dup:,}")

    all_rows, n_short = filter_short(all_rows, min_len=8)
    total_noise += n_short
    print(f"  Short texts removed    : {n_short:,}")

    print(f"  Total noise removed    : {total_noise:,}")

    # ── Cap & shuffle ─────────────────────────────────────────────────────────
    before: dict[str, int] = defaultdict(int)
    for _, cat in all_rows:
        before[cat] += 1

    print(f"\nApplying per-class cap ...")
    sampled = apply_cap(all_rows, cap)
    random.shuffle(sampled)

    after: dict[str, int] = defaultdict(int)
    for _, cat in sampled:
        after[cat] += 1

    print_stats("Class distribution (before cap -> after cap)", before, after)

    # ── Write ─────────────────────────────────────────────────────────────────
    df_out = pd.DataFrame(sampled, columns=["text", "category"])
    df_out.to_csv(OUT_PATH, index=False)

    elapsed = time.perf_counter() - t0
    print(f"\nTotal noise removed : {total_noise:,} rows")
    print(f"Saved {len(df_out):,} rows -> {OUT_PATH}  ({elapsed:.1f}s)")
    print("\nNext step:  python train.py")


if __name__ == "__main__":
    main()
