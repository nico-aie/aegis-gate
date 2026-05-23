#!/usr/bin/env python3
"""
eval_waf_dataset_headers.py
===========================
Chạy TOÀN BỘ regex_dataset qua WAF live và đọc x-waf-* response headers
để xác định detector nào fired, action là gì, score bao nhiêu.

Khác với eval_hit_waf_test_set.py:
  • Verdict dựa trên x-waf-rule-id / x-waf-action (không chỉ HTTP status)
  • In đầy đủ WAF header cho mỗi record (--verbose)
  • Per-class breakdown: detected / missed / FP / action distribution
  • Export CSV + JSON summary

Dataset:
  tests/security/regex_dataset/evasion_attacks.ndjson   (expected = miss)
  tests/security/regex_dataset/fp_candidates.ndjson     (expected = allow)

Usage:
  python eval_waf_dataset_headers.py                    # full run
  python eval_waf_dataset_headers.py --sample 100       # 100 per class
  python eval_waf_dataset_headers.py --sample 100 --only-evasion
  python eval_waf_dataset_headers.py --class sqli xss   # chỉ test 2 class
  python eval_waf_dataset_headers.py --workers 32 --timeout 10
  python eval_waf_dataset_headers.py --verbose          # print mọi header
  python eval_waf_dataset_headers.py --out-dir ./results
"""

from __future__ import annotations

import argparse
import csv
import http.client
import json
import socket
import ssl
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
DATASET_DIR  = Path(__file__).parent.parent / "security" / "regex_dataset"
EVASION_FILE = DATASET_DIR / "evasion_attacks.ndjson"
FP_FILE      = DATASET_DIR / "fp_candidates.ndjson"

# ─────────────────────────────────────────────────────────────────────────────
# WAF header names  (crates/aegis-control/src/interop/headers.rs)
# ─────────────────────────────────────────────────────────────────────────────
H_REQUEST_ID        = "x-waf-request-id"
H_RISK_SCORE        = "x-waf-risk-score"
H_ACTION            = "x-waf-action"
H_RULE_ID           = "x-waf-rule-id"
H_CACHE             = "x-waf-cache"
H_MODE              = "x-waf-mode"
H_OVERHEAD_LATENCY  = "x-waf-overhead-latency"

# Optional benchmark headers  (crates/aegis-proxy/src/benchmark.rs)
H_STAGE_TOTAL       = "x-aegis-stage-total-us"
H_STAGE_SECURITY    = "x-aegis-stage-security-us"
H_TIER              = "x-aegis-tier"
H_DECISION          = "x-aegis-decision"
H_AEGIS_RULE        = "x-aegis-rule-id"
H_AEGIS_BUILD       = "x-aegis-build"

WAF_HEADERS_OF_INTEREST = [
    H_ACTION, H_RULE_ID, H_RISK_SCORE, H_MODE,
    H_CACHE, H_OVERHEAD_LATENCY, H_REQUEST_ID,
    H_STAGE_TOTAL, H_STAGE_SECURITY, H_TIER, H_DECISION,
    H_AEGIS_RULE, H_AEGIS_BUILD,
]

# ─────────────────────────────────────────────────────────────────────────────
# Defaults / thresholds
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_HOST     = "waf.hk-aegis-gate.com"
DEFAULT_PORT     = 443
DEFAULT_TLS      = True
DEFAULT_WORKERS  = 64
DEFAULT_TIMEOUT  = 10.0

BLOCK_CODES      = {400, 403, 406, 429, 503}
CHALLENGE_AT     = 40
BLOCK_AT         = 80

DATASET_CLASS_MAP = {"nosql": "nosql_injection"}

ALL_CLASSES = [
    "sqli", "xss", "path_traversal", "command_injection", "ssrf",
    "recon", "header_injection", "nosql_injection", "template_injection",
    "open_redirect",
]

# Các rule ID được WAF trả về là REGEX detector (10 class + sub-rules)
# Dùng để tách regex_fired khỏi ai / risk-score / brute_force / ...
REGEX_DETECTOR_RULES: set[str] = {
    "sqli", "xss", "path_traversal", "command_injection", "ssrf",
    "recon", "recon_path", "recon_tool",
    "header_injection", "header_xfh",
    "nosql_injection", "template_injection",
    "open_redirect", "log4shell",
}

# Rule do các hệ thống khác (không phải regex detector)
NON_REGEX_RULES: set[str] = {
    "ai", "risk-score", "brute_force", "mass_assignment",
    "rate_limit", "circuit_breaker",
}

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colors (disabled if --no-color or non-TTY)
# ─────────────────────────────────────────────────────────────────────────────
_USE_COLOR = True

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

# ─────────────────────────────────────────────────────────────────────────────
# TLS context
# ─────────────────────────────────────────────────────────────────────────────
def _tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _make_conn(host: str, port: int, timeout: float, tls: bool):
    if tls:
        return http.client.HTTPSConnection(
            host, port=port, timeout=timeout, context=_tls_ctx()
        )
    return http.client.HTTPConnection(host, port=port, timeout=timeout)

# ─────────────────────────────────────────────────────────────────────────────
# WAF sender — captures x-waf-* headers
# ─────────────────────────────────────────────────────────────────────────────
def waf_send(rec: dict, host: str, port: int, timeout: float, tls: bool) -> dict:
    """
    Gửi một record dataset lên WAF, trả về dict đầy đủ bao gồm x-waf-* headers.
    """
    method     = (rec.get("method") or "GET").upper()
    path       = rec.get("path", "/") or "/"
    query      = rec.get("query", "") or ""
    req_headers= dict(rec.get("headers") or {})
    body       = rec.get("body", "") or ""

    url = f"{path}?{query}" if query else path

    scheme_port = 443 if tls else 80
    req_headers.setdefault("Host", host if port == scheme_port else f"{host}:{port}")
    req_headers.setdefault("User-Agent", "AegisEval/1.0")
    req_headers.setdefault("Accept", "*/*")
    req_headers.setdefault("Connection", "close")

    body_bytes = body.encode("utf-8", errors="replace") if body else b""
    if body_bytes:
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req_headers["Content-Length"] = str(len(body_bytes))

    status      = None
    error       = None
    resp_headers: dict[str, str] = {}
    t0 = time.monotonic()

    def _do_request(conn):
        nonlocal status, resp_headers
        conn.request(method, url, body=body_bytes or None, headers=req_headers)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp.read()          # consume body
        conn.close()

    try:
        _do_request(_make_conn(host, port, timeout, tls))
    except ssl.SSLCertVerificationError:
        # Self-signed cert fallback (already using CERT_NONE ctx, so this is
        # for edge cases where the initial ctx didn't help)
        try:
            _do_request(_make_conn(host, port, timeout, tls))
        except Exception as e2:
            error = f"SSL+{type(e2).__name__}: {e2}"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = (time.monotonic() - t0) * 1000

    # ── parse WAF verdict from headers ──────────────────────────────────────
    waf_action    = resp_headers.get(H_ACTION, "")
    waf_rule_id   = resp_headers.get(H_RULE_ID, "none")
    waf_risk_score= resp_headers.get(H_RISK_SCORE, "")
    waf_mode      = resp_headers.get(H_MODE, "")
    waf_cache     = resp_headers.get(H_CACHE, "")
    waf_overhead  = resp_headers.get(H_OVERHEAD_LATENCY, "")
    waf_req_id    = resp_headers.get(H_REQUEST_ID, "")

    # Tất cả rule IDs trong response (comma-separated)
    raw_rule_str = waf_rule_id.lower().strip()
    all_fired_rules = (
        [r.strip() for r in raw_rule_str.split(",")]
        if raw_rule_str not in ("none", "", "—") else []
    )

    # Tách: regex detector rule vs non-regex (ai / risk-score / ...)
    regex_rules_fired = [r for r in all_fired_rules if r in REGEX_DETECTOR_RULES]
    non_regex_fired   = [r for r in all_fired_rules if r not in REGEX_DETECTOR_RULES]
    ai_fired          = "ai"         in all_fired_rules
    risk_score_fired  = "risk-score" in all_fired_rules

    # detector_fired = CHỈ tính khi regex rule thực sự fired
    # (dùng cho đánh giá evasion detection và FP rate)
    detector_fired  = len(regex_rules_fired) > 0
    # any_rule_fired  = bất kỳ rule nào (kể cả ai, risk-score)
    any_rule_fired  = len(all_fired_rules) > 0

    # Fallback: also check HTTP status for backward compat
    blocked_by_status = status in BLOCK_CODES if status is not None else False

    return {
        # identity
        "id":              rec.get("id", ""),
        "detector_class":  DATASET_CLASS_MAP.get(
                               rec.get("detector_class", ""),
                               rec.get("detector_class", "")
                           ),
        "technique":       rec.get("technique", ""),
        "label":           rec.get("label", ""),
        "expected":        rec.get("expected_waf_outcome", ""),
        # HTTP
        "status_code":     status,
        "elapsed_ms":      round(elapsed_ms, 2),
        "error":           error,
        # WAF headers
        "waf_action":      waf_action,
        "waf_rule_id":     waf_rule_id,
        "waf_risk_score":  waf_risk_score,
        "waf_mode":        waf_mode,
        "waf_cache":       waf_cache,
        "waf_overhead_ms": waf_overhead,
        "waf_request_id":  waf_req_id,
        # derived — REGEX detector verdict (primary metric)
        "detector_fired":      detector_fired,       # regex rule fired
        "detector_names":      regex_rules_fired,    # which regex rules
        # derived — full verdict (kể cả ai / risk-score)
        "any_rule_fired":      any_rule_fired,
        "all_fired_rules":     all_fired_rules,
        "non_regex_fired":     non_regex_fired,
        "ai_fired":            ai_fired,
        "risk_score_fired":    risk_score_fired,
        "blocked_by_status":   blocked_by_status,
        # all headers (for --verbose / debug)
        "_all_headers":        resp_headers,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Dataset loader
# ─────────────────────────────────────────────────────────────────────────────
def load_ndjson(path: Path, sample: int = 0,
                classes: Optional[list[str]] = None) -> list[dict]:
    records: list[dict] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            cls = DATASET_CLASS_MAP.get(r.get("detector_class", ""),
                                        r.get("detector_class", ""))
            if classes and cls not in classes:
                continue
            records.append(r)

    if sample <= 0:
        return records

    import random
    rng = random.Random(42)
    by_cls: dict[str, list] = defaultdict(list)
    for r in records:
        cls = DATASET_CLASS_MAP.get(r.get("detector_class", ""),
                                    r.get("detector_class", ""))
        by_cls[cls].append(r)
    out: list[dict] = []
    for items in by_cls.values():
        rng.shuffle(items)
        out.extend(items[:sample])
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Progress bar
# ─────────────────────────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total: int, label: str = ""):
        self.total = total
        self.label = label
        self._n    = 0
        self._lock = threading.Lock()
        self._t0   = time.monotonic()

    def inc(self):
        with self._lock:
            self._n += 1
            if self._n % 100 == 0 or self._n == self.total:
                el  = time.monotonic() - self._t0
                rps = self._n / el if el else 0
                eta = (self.total - self._n) / rps if rps else 0
                pct = self._n / self.total * 100
                print(
                    f"\r  {self.label} {self._n:>7,}/{self.total:,}"
                    f"  ({pct:5.1f}%)  {rps:>6,.0f} rq/s  ETA {eta:>5.0f}s   ",
                    end="", flush=True,
                )

    def done(self):
        el  = time.monotonic() - self._t0
        rps = self.total / el if el else 0
        print(
            f"\r  {self.label} {self.total:,}/{self.total:,}"
            f"  (100.0%)  {rps:>6,.0f} rq/s  {el:.1f}s      ",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Concurrent runner
# ─────────────────────────────────────────────────────────────────────────────
def run_all(
    records: list[dict],
    host: str,
    port: int,
    timeout: float,
    tls: bool,
    workers: int,
    verbose: bool = False,
) -> list[dict]:
    results: list[dict] = []
    prog = Progress(len(records), label="WAF")
    lock = threading.Lock()

    def task(rec: dict) -> dict:
        r = waf_send(rec, host, port, timeout, tls)
        prog.inc()
        if verbose:
            _print_verbose(r)
        return r

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(task, rec): rec for rec in records}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:
                rec = futs[fut]
                results.append({
                    "id":              rec.get("id", ""),
                    "detector_class":  rec.get("detector_class", ""),
                    "technique":       rec.get("technique", ""),
                    "label":           rec.get("label", ""),
                    "expected":        rec.get("expected_waf_outcome", ""),
                    "error":           str(exc),
                    "detector_fired":  False,
                    "detector_names":  [],
                })

    prog.done()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Verbose single-record print
# ─────────────────────────────────────────────────────────────────────────────
def _print_verbose(r: dict) -> None:
    sep   = "─" * 60
    fired = r.get("detector_fired", False)
    action= r.get("waf_action", "—")
    rule  = r.get("waf_rule_id", "none")

    verdict_str = (
        red(f"DETECTED  rule={rule}  action={action}")
        if fired else
        green(f"CLEAN  action={action}")
    )
    print(f"\n{sep}")
    print(f"  id={r['id']}  class={r['detector_class']}  expected={r['expected']}")
    print(f"  HTTP {r.get('status_code','?')}  {r.get('elapsed_ms',0):.1f}ms")
    print(f"  WAF  {verdict_str}")
    for h in WAF_HEADERS_OF_INTEREST:
        v = r.get("_all_headers", {}).get(h)
        if v:
            print(f"       {dim(h+':'):<40} {v}")


# ─────────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────────
def compute_stats(results: list[dict]) -> dict:
    """
    Returns nested dict:
      stats[cls][split] = {
        total, detected, missed, errors,
        also_ai, also_risk_score,        ← fired by non-regex rules
        actions: {allow, block, ...},
        rules_found: {rule_name: count},
      }
    split = "evasion" | "fp"

    Verdict (detected/missed) dựa trên REGEX detector rule,
    KHÔNG tính ai / risk-score / brute_force.
    """
    stats: dict = defaultdict(lambda: {
        "evasion": _empty_bucket(),
        "fp":      _empty_bucket(),
    })

    for r in results:
        cls      = r.get("detector_class", "unknown")
        expected = r.get("expected", "")
        split    = "evasion" if expected == "miss" else "fp"
        bucket   = stats[cls][split]

        bucket["total"] += 1

        if r.get("error") and not r.get("status_code"):
            bucket["errors"] += 1
            continue

        # Verdict: regex rule fired hay không
        regex_fired = r.get("detector_fired", False)   # only regex rules
        action      = r.get("waf_action", "unknown").lower() or "unknown"

        if split == "evasion":
            if regex_fired:
                bucket["detected"] += 1      # TP: WAF bắt được
            else:
                bucket["missed"] += 1        # FN: evasion thành công
        else:
            # FP split: mong muốn regex KHÔNG fire
            if regex_fired:
                bucket["detected"] += 1      # FP: regex báo nhầm
            else:
                bucket["missed"] += 1        # TN: correctly allowed

        # Thống kê riêng ai / risk-score (để thấy noise)
        if r.get("ai_fired"):
            bucket["also_ai"] += 1
        if r.get("risk_score_fired"):
            bucket["also_risk_score"] += 1

        bucket["actions"][action] = bucket["actions"].get(action, 0) + 1

        for rule in r.get("detector_names", []):     # only regex rule names
            bucket["rules_found"][rule] = bucket["rules_found"].get(rule, 0) + 1

    return dict(stats)


def _empty_bucket() -> dict:
    return {
        "total":            0,
        "detected":         0,
        "missed":           0,
        "errors":           0,
        "also_ai":          0,
        "also_risk_score":  0,
        "actions":          {},
        "rules_found":      {},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────
def print_report(stats: dict, results: list[dict]) -> None:
    bar = "═" * 78
    thin= "─" * 78

    total_results = len(results)
    total_errors  = sum(1 for r in results if r.get("error") and not r.get("status_code"))
    total_evasion = sum(1 for r in results if r.get("expected") == "miss")
    total_fp      = sum(1 for r in results if r.get("expected") == "allow")

    print(f"\n{bar}")
    print(bold("  AEGIS-GATE WAF — FULL DATASET EVALUATION"))
    print(f"  Ran at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Records: {total_results:,}  "
          f"(evasion={total_evasion:,}  fp={total_fp:,}  errors={total_errors:,})")
    print(bar)

    # ── Per-class table ──────────────────────────────────────────────────────
    all_classes = sorted(stats.keys())

    # Evasion section
    print(f"\n{bold('  EVASION ATTACKS')}"
          f"  (expected=miss → WAF should DETECT via regex rule)")
    print(f"  {dim('class'):<22} {'total':>7} {'det(rgx)':>9} {'missed':>8} "
          f"{'det%':>6} {'err':>5}  {'also_ai':>8} {'also_rs':>8}")
    print(f"  {thin[:78]}")
    ev_total = ev_det = ev_miss = 0
    for cls in all_classes:
        b = stats[cls]["evasion"]
        t = b["total"]
        if t == 0:
            continue
        d   = b["detected"]
        m   = b["missed"]
        e   = b["errors"]
        ai  = b["also_ai"]
        rs  = b["also_risk_score"]
        pct = d / (t - e) * 100 if (t - e) > 0 else 0
        pct_str = green(f"{pct:5.1f}%") if pct >= 80 else (
                      yellow(f"{pct:5.1f}%") if pct >= 50 else
                      red(f"{pct:5.1f}%"))
        print(f"  {cls:<22} {t:>7,} {d:>9,} {m:>8,} {pct_str}  {e:>5,}  {ai:>8,} {rs:>8,}")
        ev_total += t; ev_det += d; ev_miss += m
    ev_pct = ev_det / (ev_total or 1) * 100
    print(f"  {'TOTAL':<22} {ev_total:>7,} {ev_det:>9,} {ev_miss:>8,} "
          f"{bold(f'{ev_pct:5.1f}%')}")

    # FP section
    print(f"\n{bold('  FALSE-POSITIVE CANDIDATES')}"
          f"  (expected=allow → REGEX rule should NOT fire)")
    print(f"  {dim('class'):<22} {'total':>7} {'fp(rgx)':>9} {'clean':>8} "
          f"{'fp%':>6} {'err':>5}  {'also_ai':>8} {'also_rs':>8}")
    print(f"  {thin[:78]}")
    fp_total = fp_fired = fp_clean = 0
    for cls in all_classes:
        b = stats[cls]["fp"]
        t = b["total"]
        if t == 0:
            continue
        d   = b["detected"]    # = FP: regex fired on normal traffic
        m   = b["missed"]      # = TN: correctly allowed by regex
        e   = b["errors"]
        ai  = b["also_ai"]
        rs  = b["also_risk_score"]
        pct = d / (t - e) * 100 if (t - e) > 0 else 0
        pct_str = red(f"{pct:5.1f}%") if pct >= 20 else (
                      yellow(f"{pct:5.1f}%") if pct >= 5 else
                      green(f"{pct:5.1f}%"))
        print(f"  {cls:<22} {t:>7,} {d:>9,} {m:>8,} {pct_str}  {e:>5,}  {ai:>8,} {rs:>8,}")
        fp_total += t; fp_fired += d; fp_clean += m
    fp_pct = fp_fired / (fp_total or 1) * 100
    print(f"  {'TOTAL':<22} {fp_total:>7,} {fp_fired:>9,} {fp_clean:>8,} "
          f"{bold(f'{fp_pct:5.1f}%')}")
    print(f"\n  {dim('fp(rgx) = regex detector báo nhầm trên traffic bình thường')}")
    print(f"  {dim('also_ai = bị ML model fire thêm  |  also_rs = bị risk-score fire thêm')}")

    # ── Regex rules seen ─────────────────────────────────────────────────────
    print(f"\n{bold('  REGEX RULE IDs FIRED')}")
    regex_rule_agg: dict[str, int] = defaultdict(int)
    for r in results:
        for rule in r.get("detector_names", []):   # only regex rules
            regex_rule_agg[rule] += 1
    if regex_rule_agg:
        for rule, cnt in sorted(regex_rule_agg.items(), key=lambda x: -x[1]):
            print(f"  {rule:<35} {cnt:>7,}")
    else:
        print(f"  {dim('(none)')}")

    # ── Non-regex rules seen ─────────────────────────────────────────────────
    print(f"\n{bold('  NON-REGEX RULES FIRED  (ai / risk-score / other)')}")
    nonrx_agg: dict[str, int] = defaultdict(int)
    for r in results:
        for rule in r.get("non_regex_fired", []):
            nonrx_agg[rule] += 1
    if nonrx_agg:
        for rule, cnt in sorted(nonrx_agg.items(), key=lambda x: -x[1]):
            mark = dim("← ML model") if rule == "ai" else (
                   dim("← IP score") if rule == "risk-score" else "")
            print(f"  {rule:<35} {cnt:>7,}  {mark}")
    else:
        print(f"  {dim('(none)')}")

    # ── Action distribution ──────────────────────────────────────────────────
    print(f"\n{bold('  WAF ACTION DISTRIBUTION (all records)')}")
    action_agg: dict[str, int] = defaultdict(int)
    for r in results:
        a = r.get("waf_action", "") or "no_header"
        action_agg[a.lower()] += 1
    for act, cnt in sorted(action_agg.items(), key=lambda x: -x[1]):
        pct = cnt / total_results * 100
        bar_len = int(pct / 2)
        bar_s   = "█" * bar_len
        print(f"  {act:<18} {cnt:>7,}  ({pct:5.1f}%)  {dim(bar_s)}")

    print(f"\n{bar}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────
def export_csv(results: list[dict], path: Path) -> None:
    fields = [
        "id", "detector_class", "technique", "label", "expected",
        "status_code", "elapsed_ms", "error",
        "waf_action", "waf_rule_id", "waf_risk_score",
        "waf_mode", "waf_cache", "waf_overhead_ms", "waf_request_id",
        # regex verdict
        "detector_fired", "detector_names",
        # full verdict
        "any_rule_fired", "all_fired_rules", "non_regex_fired",
        "ai_fired", "risk_score_fired",
        "blocked_by_status",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = dict(r)
            row["detector_names"]  = "|".join(r.get("detector_names", []))
            row["all_fired_rules"] = "|".join(r.get("all_fired_rules", []))
            row["non_regex_fired"] = "|".join(r.get("non_regex_fired", []))
            writer.writerow(row)
    print(f"  CSV  → {path}")


def export_json_summary(stats: dict, results: list[dict], path: Path) -> None:
    summary = {
        "generated_at": datetime.now().isoformat(),
        "total_records": len(results),
        "total_errors": sum(1 for r in results if r.get("error") and not r.get("status_code")),
        "per_class": {},
    }
    for cls, splits in stats.items():
        summary["per_class"][cls] = {}
        for split, b in splits.items():
            t = b["total"]
            d = b["detected"]
            e = b["errors"]
            summary["per_class"][cls][split] = {
                "total":    t,
                "detected": d,
                "missed":   b["missed"],
                "errors":   e,
                "det_pct":  round(d / (t - e) * 100, 2) if (t - e) > 0 else None,
                "actions":  b["actions"],
                "rules_found": b["rules_found"],
            }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    print(f"  JSON → {path}")


def export_ndjson_raw(results: list[dict], path: Path) -> None:
    """Export raw per-record results (without _all_headers bulk data)."""
    with path.open("w", encoding="utf-8") as fh:
        for r in results:
            row = {k: v for k, v in r.items() if k != "_all_headers"}
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"  NDJSON → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Wrong-case log  (human-readable text file)
# ─────────────────────────────────────────────────────────────────────────────
def export_wrong_cases(results: list[dict], path: Path) -> None:
    """
    Ghi ra file text tất cả các record bị đánh giá SAI:

      • EVASION  (expected=miss)  + detector_fired=False
          → WAF không bắt được, payload bypass hoàn toàn

      • FP       (expected=allow) + detector_fired=True
          → WAF báo nhầm, request bình thường bị block/challenge

    Format mỗi entry:
      [MISS]  hoặc  [FP]
      id / class / technique
      URL path?query
      Headers gửi đi (nếu có)
      WAF response: action | rule_id | risk_score | mode | overhead
      HTTP status / elapsed
      ---
    """
    wrong: list[dict] = []
    for r in results:
        expected    = r.get("expected", "")
        regex_fired = r.get("detector_fired", False)   # chỉ regex rule
        error       = r.get("error") and not r.get("status_code")

        if error:
            continue  # network error — không xác định được đúng/sai

        if expected == "miss" and not regex_fired:
            # Evasion thành công: regex rule không bắt được
            # (AI/risk-score có thể đã fire riêng — ghi chú thêm)
            wrong.append(("MISS", r))
        elif expected == "allow" and regex_fired:
            # FP: regex rule báo nhầm trên normal traffic
            wrong.append(("FP", r))

    # Sort: class → type → technique
    wrong.sort(key=lambda x: (
        x[1].get("detector_class", ""),
        x[0],
        x[1].get("technique", ""),
    ))

    sep  = "─" * 72
    sep2 = "═" * 72

    miss_count = sum(1 for t, _ in wrong if t == "MISS")
    fp_count   = sum(1 for t, _ in wrong if t == "FP")

    with path.open("w", encoding="utf-8") as fh:
        def w(line: str = "") -> None:
            fh.write(line + "\n")

        w(sep2)
        w("AEGIS-GATE WAF — WRONG CASES LOG")
        w(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        w(f"Total     : {len(wrong):,}  "
          f"(MISS={miss_count:,}  FP={fp_count:,})")
        w()
        w("  MISS = evasion attack NOT detected by WAF  (bypass thành công)")
        w("  FP   = normal request flagged by WAF       (false positive)")
        w(sep2)

        current_cls = None
        for tag, r in wrong:
            cls = r.get("detector_class", "?")
            if cls != current_cls:
                w()
                w(f"{'━'*72}")
                w(f"  CLASS: {cls.upper()}")
                w(f"{'━'*72}")
                current_cls = cls

            # Build URL representation from record fields
            rec_path  = r.get("path", "/") or "/"
            rec_query = r.get("query", "") or ""
            rec_body  = r.get("body", "") or ""
            rec_method= r.get("method", "GET") or "GET"
            url_str   = f"{rec_path}?{rec_query}" if rec_query else rec_path
            if len(url_str) > 200:
                url_str = url_str[:197] + "..."

            # Extra headers from record (exclude standard ones)
            rec_headers = dict(r.get("_all_headers") or {})
            sent_headers = {}
            # The record's own "headers" field (what we sent)
            # We don't store it in results, but we can reconstruct from the
            # dataset record embedded in technique/label context is not
            # available post-eval — show WAF response headers instead.

            w()
            w(f"  [{tag}]  id={r.get('id', '?')}  technique={r.get('technique', '?')}")
            w(f"  {rec_method} {url_str}")
            if rec_body:
                body_preview = rec_body[:300] + ("..." if len(rec_body) > 300 else "")
                w(f"  body: {body_preview}")
            w()
            w(f"  WAF response headers:")
            w(f"    x-waf-action          : {r.get('waf_action', '—')}")
            w(f"    x-waf-rule-id         : {r.get('waf_rule_id', '—')}")
            w(f"    x-waf-risk-score      : {r.get('waf_risk_score', '—')}")
            w(f"    x-waf-mode            : {r.get('waf_mode', '—')}")
            w(f"    x-waf-cache           : {r.get('waf_cache', '—')}")
            w(f"    x-waf-overhead-latency: {r.get('waf_overhead_ms', '—')} ms")
            w(f"    x-waf-request-id      : {r.get('waf_request_id', '—')}")
            w(f"  HTTP {r.get('status_code', '?')}  elapsed={r.get('elapsed_ms', 0):.1f}ms")
            if tag == "MISS":
                # Có thể AI/risk-score đã fire dù regex miss
                non_rx = r.get("non_regex_fired", [])
                if non_rx:
                    w(f"  ↳ Regex '{cls}' did NOT fire  "
                      f"(nhưng non-regex rules fired: {', '.join(non_rx)})")
                else:
                    w(f"  ↳ Regex '{cls}' did NOT fire  — request bypassed WAF completely")
            else:
                fired_rules = ", ".join(r.get("detector_names", []))
                non_rx = r.get("non_regex_fired", [])
                extra  = f"  + non-regex: {', '.join(non_rx)}" if non_rx else ""
                w(f"  ↳ False positive — regex rule(s) fired: {fired_rules}{extra}")
            w(sep)

        w()
        w(sep2)
        w(f"SUMMARY BY CLASS")
        w(sep2)

        # Per-class counts
        cls_miss: dict[str, int] = defaultdict(int)
        cls_fp:   dict[str, int] = defaultdict(int)
        for tag, r in wrong:
            cls = r.get("detector_class", "?")
            if tag == "MISS": cls_miss[cls] += 1
            else:             cls_fp[cls]   += 1

        all_cls = sorted(set(list(cls_miss.keys()) + list(cls_fp.keys())))
        w(f"  {'class':<25} {'MISS':>8} {'FP':>8}")
        w(f"  {'─'*43}")
        for cls in all_cls:
            w(f"  {cls:<25} {cls_miss.get(cls,0):>8,} {cls_fp.get(cls,0):>8,}")
        w(f"  {'─'*43}")
        w(f"  {'TOTAL':<25} {miss_count:>8,} {fp_count:>8,}")
        w()

    print(f"  WRONG → {path}  ({len(wrong):,} cases: MISS={miss_count} FP={fp_count})")


# ─────────────────────────────────────────────────────────────────────────────
# DNS pre-check
# ─────────────────────────────────────────────────────────────────────────────
def check_dns(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return True
    except socket.gaierror as exc:
        print(f"\n{red('✗ DNS resolution failed')}: {host} → {exc}", file=sys.stderr)
        print("  Script must run on a machine with internet access.", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Full-dataset WAF evaluation using x-waf-* response headers."
    )
    p.add_argument("--host",    default=DEFAULT_HOST,   help="WAF host (default: %(default)s)")
    p.add_argument("--port",    default=DEFAULT_PORT,   type=int)
    p.add_argument("--no-tls",  action="store_true",    help="Plain HTTP")
    p.add_argument("--timeout", default=DEFAULT_TIMEOUT,type=float, help="Per-request timeout (s)")
    p.add_argument("--workers", default=DEFAULT_WORKERS,type=int,   help="Concurrent workers")
    p.add_argument("--sample",  default=0,              type=int,
                   help="Records per class (0 = all)")
    p.add_argument("--class",   dest="classes", nargs="+", metavar="CLASS",
                   help=f"Only test these class(es): {', '.join(ALL_CLASSES)}")
    p.add_argument("--only-evasion", action="store_true", help="Skip fp_candidates.ndjson")
    p.add_argument("--only-fp",      action="store_true", help="Skip evasion_attacks.ndjson")
    p.add_argument("--verbose", "-v", action="store_true", help="Print every request/response")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-report", action="store_true", help="Skip console report (still exports)")
    p.add_argument("--out-dir", default=None,
                   help="Directory for CSV/JSON output (default: same dir as script)")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    global _USE_COLOR
    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    host = args.host
    port = args.port
    tls  = not args.no_tls

    if not check_dns(host):
        sys.exit(1)

    # Verify dataset files exist
    for f in [EVASION_FILE, FP_FILE]:
        if not f.exists():
            print(f"{red('✗')} Dataset not found: {f}", file=sys.stderr)
            sys.exit(1)

    classes_filter: Optional[list[str]] = args.classes

    # Load records
    records: list[dict] = []
    if not args.only_fp:
        ev = load_ndjson(EVASION_FILE, sample=args.sample, classes=classes_filter)
        print(f"  Loaded {len(ev):,} evasion records from {EVASION_FILE.name}")
        records.extend(ev)
    if not args.only_evasion:
        fp = load_ndjson(FP_FILE, sample=args.sample, classes=classes_filter)
        print(f"  Loaded {len(fp):,} FP records from {FP_FILE.name}")
        records.extend(fp)

    if not records:
        print(red("No records to process. Check --class / --only-* flags."), file=sys.stderr)
        sys.exit(1)

    print(f"\n{bold('Aegis-Gate WAF — Dataset Header Evaluation')}")
    print(f"  Target  : {'https' if tls else 'http'}://{host}:{port}/")
    print(f"  Records : {len(records):,}")
    print(f"  Workers : {args.workers}")
    print(f"  Timeout : {args.timeout}s")
    print()

    t_start = time.monotonic()
    results = run_all(
        records, host, port, args.timeout, tls,
        workers=args.workers, verbose=args.verbose,
    )
    elapsed = time.monotonic() - t_start
    print(f"\n  Done in {elapsed:.1f}s  "
          f"({len(results)/elapsed:,.0f} rq/s avg)\n")

    # Stats + report
    stats = compute_stats(results)
    if not args.no_report:
        print_report(stats, results)

    # Export
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else Path(__file__).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  {bold('Exporting results...')}")
    export_csv(results, out_dir / f"eval_waf_headers_{ts}.csv")
    export_json_summary(stats, results, out_dir / f"eval_waf_headers_{ts}_summary.json")
    export_ndjson_raw(results, out_dir / f"eval_waf_headers_{ts}_raw.ndjson")
    export_wrong_cases(results, out_dir / f"eval_waf_headers_{ts}_wrong.txt")


if __name__ == "__main__":
    main()
