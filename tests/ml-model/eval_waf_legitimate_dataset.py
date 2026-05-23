#!/usr/bin/env python3
"""
eval_waf_legitimate_dataset.py
==============================
Chạy dataset Legitimate (real browser traffic từ 692 websites) qua WAF live,
đọc x-waf-* headers, đo False Positive rate thực tế trên traffic bình thường.

Engine tự động:
  • aiohttp   — async, connection pool, target 10k+ RPS   (pip install aiohttp)
  • threading — fallback nếu không có aiohttp, ~1-2k RPS

Dataset format:
  { "method": "GET", "url": "/path?query",
    "headers": {"Host": "..."}, "data": "" }

Sau khi chạy tự xuất:
  <ts>_legitimate_results.csv / _summary.json / _report.md

Usage:
  python eval_waf_legitimate_dataset.py --max-total 50000 --random
  python eval_waf_legitimate_dataset.py --concurrency 1000 --timeout 8
  python eval_waf_legitimate_dataset.py --sample 200 --verbose
  python eval_waf_legitimate_dataset.py --files "browsing_2024_amazon*"

Nếu chưa có aiohttp:
  pip install aiohttp
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import http.client
import json
import math
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
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# ─────────────────────────────────────────────────────────────────────────────
# Dataset path
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_DATASET_DIR = Path("/Users/admin/Documents/workspace/remote/dataset/Legitimate")

# ─────────────────────────────────────────────────────────────────────────────
# WAF headers
# ─────────────────────────────────────────────────────────────────────────────
H_REQUEST_ID       = "x-waf-request-id"
H_RISK_SCORE       = "x-waf-risk-score"
H_ACTION           = "x-waf-action"
H_RULE_ID          = "x-waf-rule-id"
H_CACHE            = "x-waf-cache"
H_MODE             = "x-waf-mode"
H_OVERHEAD_LATENCY = "x-waf-overhead-latency"

# ─────────────────────────────────────────────────────────────────────────────
# Regex detector rules (tách khỏi ai / risk-score / other)
# ─────────────────────────────────────────────────────────────────────────────
REGEX_DETECTOR_RULES: set[str] = {
    "sqli", "xss", "path_traversal", "command_injection", "ssrf",
    "recon", "recon_path", "recon_tool",
    "header_injection", "header_xfh",
    "nosql_injection", "template_injection",
    "open_redirect", "log4shell",
}

NON_REGEX_RULES: set[str] = {
    "ai", "risk-score", "brute_force", "mass_assignment",
    "rate_limit", "circuit_breaker",
}

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_HOST        = "18.140.47.62"
DEFAULT_PORT        = 443
DEFAULT_TLS         = True
DEFAULT_CONCURRENCY = 1000   # async engine
DEFAULT_WORKERS     = 128    # threading fallback
DEFAULT_TIMEOUT     = 8.0
BLOCK_CODES         = {400, 403, 406, 429, 503}

# ─────────────────────────────────────────────────────────────────────────────
# ANSI
# ─────────────────────────────────────────────────────────────────────────────
_USE_COLOR = True

def _c(code, t): return f"\033[{code}m{t}\033[0m" if _USE_COLOR else t
def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

# ─────────────────────────────────────────────────────────────────────────────
# TLS helpers
# ─────────────────────────────────────────────────────────────────────────────
def _tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _make_conn(host, port, timeout, tls):
    if tls:
        return http.client.HTTPSConnection(host, port=port, timeout=timeout, context=_tls_ctx())
    return http.client.HTTPConnection(host, port=port, timeout=timeout)

# ─────────────────────────────────────────────────────────────────────────────
# Dataset loader
# ─────────────────────────────────────────────────────────────────────────────
def load_legitimate_dataset(
    dataset_dir: Path,
    sample_per_file: int = 0,
    max_total: int = 0,
    file_glob: str = "*.json",
    random_seed: Optional[int] = None,
) -> tuple[list[dict], dict]:
    """
    Load records từ Legitimate dataset.

    Random mode (random_seed is not None):
      Tính số records cần lấy mỗi file = ceil(max_total / n_files),
      rồi random.sample trong mỗi file — tránh load toàn bộ 1M+ records vào RAM.

    Sequential mode:
      Lấy theo thứ tự, dừng khi đủ max_total.
    """
    import random as _random
    import math

    files = sorted(dataset_dir.glob(file_glob))
    if not files:
        print(f"{red('✗')} No files found in {dataset_dir} matching '{file_glob}'", file=sys.stderr)
        sys.exit(1)

    rng = _random.Random(random_seed) if random_seed is not None else None

    # Random mode: tính quota per file để tổng ≈ max_total
    if rng is not None and max_total > 0:
        files_list = list(files)
        rng.shuffle(files_list)
        files = files_list
        per_file_quota = math.ceil(max_total / len(files))
    else:
        per_file_quota = sample_per_file  # sequential mode

    records: list[dict] = []
    files_loaded = 0
    files_errored = 0
    total_in_files = 0

    for fp in files:
        try:
            raw = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            files_errored += 1
            continue

        if not isinstance(raw, list):
            files_errored += 1
            continue

        site_name = fp.stem
        total_in_files += len(raw)

        if rng is not None:
            # Random sample trong file — không cần shuffle toàn bộ
            k = min(per_file_quota, len(raw))
            batch = rng.sample(raw, k)
        elif per_file_quota > 0:
            batch = raw[:per_file_quota]
        else:
            batch = raw

        for r in batch:
            records.append({
                "_site":   site_name,
                "_file":   fp.name,
                "method":  (r.get("method") or "GET").upper(),
                "url":     r.get("url", "/") or "/",
                "headers": dict(r.get("headers") or {}),
                "data":    r.get("data", "") or "",
            })

        files_loaded += 1

        # Sequential mode: dừng sớm khi đủ
        if rng is None and max_total > 0 and len(records) >= max_total:
            records = records[:max_total]
            break

    # Random mode: cap đúng max_total và shuffle lần cuối
    if rng is not None and max_total > 0 and len(records) > max_total:
        rng.shuffle(records)
        records = records[:max_total]

    meta = {
        "files_total":            len(files),
        "files_loaded":           files_loaded,
        "files_errored":          files_errored,
        "records_total_in_files": total_in_files,
        "records_loaded":         len(records),
        "random_seed":            random_seed,
    }
    return records, meta


# ─────────────────────────────────────────────────────────────────────────────
# URL parser
# ─────────────────────────────────────────────────────────────────────────────
def parse_url(url: str) -> tuple[str, str]:
    """
    Trả về (path, query). Xử lý cả absolute URL và relative path.
    """
    if url.startswith("http://") or url.startswith("https://"):
        p = urlparse(url)
        return (p.path or "/"), (p.query or "")
    idx = url.find("?")
    if idx == -1:
        return url or "/", ""
    return url[:idx] or "/", url[idx+1:]


# ─────────────────────────────────────────────────────────────────────────────
# Shared: build result dict từ parsed WAF response headers
# ─────────────────────────────────────────────────────────────────────────────
def _make_result(rec: dict, path: str, query: str,
                 status: Optional[int], resp_headers: dict,
                 elapsed_ms: float, error: Optional[str]) -> dict:
    waf_action     = resp_headers.get(H_ACTION, "")
    waf_rule_id    = resp_headers.get(H_RULE_ID, "none")
    waf_risk_score = resp_headers.get(H_RISK_SCORE, "")
    waf_mode       = resp_headers.get(H_MODE, "")
    waf_overhead   = resp_headers.get(H_OVERHEAD_LATENCY, "")
    waf_req_id     = resp_headers.get(H_REQUEST_ID, "")

    raw_rule  = waf_rule_id.lower().strip()
    all_fired = (
        [r.strip() for r in raw_rule.split(",")]
        if raw_rule not in ("none", "", "—") else []
    )
    regex_fired     = [r for r in all_fired if r in REGEX_DETECTOR_RULES]
    non_regex_fired = [r for r in all_fired if r not in REGEX_DETECTOR_RULES]

    return {
        "_site":            rec["_site"],
        "_file":            rec["_file"],
        "method":           rec["method"],
        "url":              rec["url"][:200],
        "path":             path,
        "query":            query[:200],
        "orig_host":        rec["headers"].get("Host", rec["headers"].get("host", "")),
        "status_code":      status,
        "elapsed_ms":       round(elapsed_ms, 2),
        "error":            error,
        "waf_action":       waf_action,
        "waf_rule_id":      waf_rule_id,
        "waf_risk_score":   waf_risk_score,
        "waf_mode":         waf_mode,
        "waf_overhead_ms":  waf_overhead,
        "waf_request_id":   waf_req_id,
        "detector_fired":   len(regex_fired) > 0,
        "detector_names":   regex_fired,
        "any_rule_fired":   len(all_fired) > 0,
        "all_fired_rules":  all_fired,
        "non_regex_fired":  non_regex_fired,
        "ai_fired":         "ai"          in all_fired,
        "risk_score_fired": "risk-score"  in all_fired,
        "blocked_by_status": status in BLOCK_CODES if status is not None else False,
    }


def _error_result(rec: dict, error: str) -> dict:
    path, query = parse_url(rec.get("url", "/"))
    return _make_result(rec, path, query, None, {}, 0.0, error)


# ─────────────────────────────────────────────────────────────────────────────
# Engine A: aiohttp async (target: 10k+ RPS)
# ─────────────────────────────────────────────────────────────────────────────
def _build_body(rec: dict) -> bytes:
    raw = rec.get("data", "") or ""
    if isinstance(raw, bytes): return raw
    return raw.encode("utf-8", errors="replace")


if HAS_AIOHTTP:
    async def _async_send_one(
        session: "aiohttp.ClientSession",
        sem: asyncio.Semaphore,
        rec: dict,
        waf_host: str,
        port: int,
        tls: bool,
        timeout_s: float,
    ) -> dict:
        path, query = parse_url(rec["url"])
        req_path    = f"{path}?{query}" if query else path
        scheme      = "https" if tls else "http"
        url         = f"{scheme}://{waf_host}:{port}{req_path}"

        req_headers = {k: v for k, v in rec["headers"].items()
                       if k.lower() not in ("content-length", "transfer-encoding")}
        req_headers["host"] = waf_host

        body = _build_body(rec) or None
        if body:
            req_headers.setdefault("content-type", "application/x-www-form-urlencoded")

        t0 = time.monotonic()
        async with sem:
            try:
                to = aiohttp.ClientTimeout(total=timeout_s)
                async with session.request(
                    rec["method"], url,
                    headers=req_headers, data=body,
                    timeout=to, allow_redirects=False,
                ) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    await resp.read()
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    return _make_result(rec, path, query, resp.status, resp_headers, elapsed_ms, None)
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t0) * 1000
                return _make_result(rec, path, query, None, {}, elapsed_ms,
                                    f"{type(exc).__name__}: {exc}")

    async def _run_async(
        records: list[dict], waf_host: str, port: int,
        timeout: float, tls: bool, concurrency: int, verbose: bool,
    ) -> list[dict]:
        ssl_ctx    = _tls_ctx() if tls else False
        connector  = aiohttp.TCPConnector(
            limit=concurrency,
            ssl=ssl_ctx,
            enable_cleanup_closed=True,
            force_close=False,         # keep-alive
            ttl_dns_cache=300,
        )
        sem     = asyncio.Semaphore(concurrency)
        total   = len(records)
        results = [None] * total
        counter = {"n": 0}
        t_start = time.monotonic()
        lock    = asyncio.Lock()

        async def _print_progress():
            while True:
                await asyncio.sleep(1)
                n   = counter["n"]
                el  = time.monotonic() - t_start
                rps = n / el if el else 0
                eta = (total - n) / rps if rps else 0
                pct = n / total * 100
                print(
                    f"\r  WAF {n:>8,}/{total:,}"
                    f"  ({pct:5.1f}%)  {rps:>7,.0f} rq/s  ETA {eta:>4.0f}s   ",
                    end="", flush=True,
                )
                if n >= total:
                    break

        async with aiohttp.ClientSession(connector=connector) as session:
            prog_task = asyncio.create_task(_print_progress())

            async def _do(i, rec):
                r = await _async_send_one(session, sem, rec, waf_host, port, tls, timeout)
                results[i] = r
                counter["n"] += 1
                if verbose and r.get("detector_fired"):
                    rules = ", ".join(r["detector_names"])
                    print(f"\n  {red('[FP]')} {r['_site'][:28]}  "
                          f"{r['method']} {r['url'][:55]}  → {rules}")

            await asyncio.gather(*[_do(i, rec) for i, rec in enumerate(records)])
            prog_task.cancel()

        el  = time.monotonic() - t_start
        rps = total / el if el else 0
        print(f"\r  WAF {total:,}/{total:,}  (100.0%)  {rps:>7,.0f} rq/s  {el:.1f}s      ")
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Engine B: threading fallback (no aiohttp)
# ─────────────────────────────────────────────────────────────────────────────
def _thread_send(rec: dict, waf_host: str, port: int, timeout: float, tls: bool) -> dict:
    path, query = parse_url(rec["url"])
    req_path    = f"{path}?{query}" if query else path

    req_headers = {k: v for k, v in rec["headers"].items()}
    req_headers["host"]       = waf_host
    req_headers["connection"] = "keep-alive"
    req_headers.setdefault("accept", "*/*")

    body = _build_body(rec)
    if body:
        req_headers["content-length"] = str(len(body))
        req_headers.setdefault("content-type", "application/x-www-form-urlencoded")
    elif "content-length" in req_headers:
        del req_headers["content-length"]

    status: Optional[int] = None
    resp_headers: dict     = {}
    error: Optional[str]   = None
    t0 = time.monotonic()
    try:
        conn = _make_conn(waf_host, port, timeout, tls)
        conn.request(rec["method"], req_path, body=body or None, headers=req_headers)
        resp         = conn.getresponse()
        status       = resp.status
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp.read()
        conn.close()
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = (time.monotonic() - t0) * 1000
    return _make_result(rec, path, query, status, resp_headers, elapsed_ms, error)


# ─────────────────────────────────────────────────────────────────────────────
# Progress bar (threading engine)
# ─────────────────────────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total: int):
        self.total = total
        self._n    = 0
        self._lock = threading.Lock()
        self._t0   = time.monotonic()

    def inc(self):
        with self._lock:
            self._n += 1
            if self._n % 200 == 0 or self._n == self.total:
                el  = time.monotonic() - self._t0
                rps = self._n / el if el else 0
                eta = (self.total - self._n) / rps if rps else 0
                pct = self._n / self.total * 100
                print(
                    f"\r  WAF {self._n:>8,}/{self.total:,}"
                    f"  ({pct:5.1f}%)  {rps:>7,.0f} rq/s  ETA {eta:>4.0f}s   ",
                    end="", flush=True,
                )

    def done(self):
        el  = time.monotonic() - self._t0
        rps = self.total / el if el else 0
        print(f"\r  WAF {self.total:,}/{self.total:,}"
              f"  (100.0%)  {rps:>7,.0f} rq/s  {el:.1f}s      ")


# ─────────────────────────────────────────────────────────────────────────────
# Unified runner — chọn engine tự động
# ─────────────────────────────────────────────────────────────────────────────
def run_all(
    records: list[dict], waf_host: str, port: int,
    timeout: float, tls: bool, concurrency: int, verbose: bool,
) -> list[dict]:
    if HAS_AIOHTTP:
        return asyncio.run(_run_async(records, waf_host, port, timeout, tls, concurrency, verbose))

    # Threading fallback
    prog = Progress(len(records))

    def task(rec):
        r = _thread_send(rec, waf_host, port, timeout, tls)
        prog.inc()
        if verbose and r.get("detector_fired"):
            rules = ", ".join(r["detector_names"])
            print(f"\n  {red('[FP]')} {r['_site'][:28]}  {r['method']} {r['url'][:55]}"
                  f"  → {rules}  action={r['waf_action']}")
        return r

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, DEFAULT_WORKERS)) as pool:
        futs = {pool.submit(task, rec): rec for rec in records}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append(_error_result(futs[fut], str(exc)))

    prog.done()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────────
def compute_stats(results: list[dict]) -> dict:
    total       = len(results)
    errors      = sum(1 for r in results if r.get("error") and not r.get("status_code"))
    effective   = total - errors

    fp_regex    = [r for r in results if r.get("detector_fired") and not r.get("error")]
    fp_ai       = [r for r in results if r.get("ai_fired")       and not r.get("error")]
    fp_rs       = [r for r in results if r.get("risk_score_fired") and not r.get("error")]

    # Per-rule breakdown
    rule_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for rule in r.get("detector_names", []):
            rule_counts[rule] += 1

    non_regex_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for rule in r.get("non_regex_fired", []):
            non_regex_counts[rule] += 1

    # Per-site FP counts
    site_fp: dict[str, dict] = defaultdict(lambda: {"total": 0, "fp": 0, "rules": defaultdict(int)})
    for r in results:
        if r.get("error") and not r.get("status_code"):
            continue
        site = r.get("_site", "unknown")
        site_fp[site]["total"] += 1
        if r.get("detector_fired"):
            site_fp[site]["fp"] += 1
            for rule in r.get("detector_names", []):
                site_fp[site]["rules"][rule] += 1

    # Per-method breakdown
    method_fp: dict[str, dict] = defaultdict(lambda: {"total": 0, "fp": 0})
    for r in results:
        if r.get("error") and not r.get("status_code"):
            continue
        m = r.get("method", "GET")
        method_fp[m]["total"] += 1
        if r.get("detector_fired"):
            method_fp[m]["fp"] += 1

    # Action distribution
    action_dist: dict[str, int] = defaultdict(int)
    for r in results:
        a = r.get("waf_action", "") or "no_header"
        action_dist[a.lower()] += 1

    # Top FP paths
    path_fp: dict[str, int] = defaultdict(int)
    for r in results:
        if r.get("detector_fired"):
            path_fp[r.get("path", "/")[:80]] += 1

    return {
        "total":            total,
        "errors":           errors,
        "effective":        effective,
        "fp_regex_count":   len(fp_regex),
        "fp_regex_pct":     round(len(fp_regex) / effective * 100, 2) if effective else 0,
        "fp_ai_count":      len(fp_ai),
        "fp_rs_count":      len(fp_rs),
        "rule_counts":      dict(rule_counts),
        "non_regex_counts": dict(non_regex_counts),
        "site_fp":          {k: {"total": v["total"], "fp": v["fp"],
                                 "rules": dict(v["rules"])}
                             for k, v in site_fp.items()},
        "method_fp":        dict(method_fp),
        "action_dist":      dict(action_dist),
        "top_fp_paths":     dict(sorted(path_fp.items(), key=lambda x: -x[1])[:30]),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Console report
# ─────────────────────────────────────────────────────────────────────────────
def print_console_report(stats: dict) -> None:
    bar = "═" * 72
    print(f"\n{bar}")
    print(bold("  LEGITIMATE TRAFFIC — WAF FALSE POSITIVE EVALUATION"))
    print(f"  Records: {stats['total']:,}  "
          f"effective={stats['effective']:,}  errors={stats['errors']:,}")
    print(bar)

    fp   = stats["fp_regex_count"]
    eff  = stats["effective"]
    pct  = stats["fp_regex_pct"]
    pct_str = green(f"{pct:.2f}%") if pct < 2 else yellow(f"{pct:.2f}%") if pct < 10 else red(f"{pct:.2f}%")
    print(f"\n  {bold('FP rate (regex rules):')} {pct_str}  ({fp:,} / {eff:,} records)")
    print(f"  AI model fires  : {stats['fp_ai_count']:,}")
    print(f"  risk-score fires: {stats['fp_rs_count']:,}")

    print(f"\n  {bold('Regex rules fired:')}")
    for rule, cnt in sorted(stats["rule_counts"].items(), key=lambda x: -x[1]):
        pct_r = cnt / eff * 100 if eff else 0
        print(f"  {rule:<28} {cnt:>7,}  ({pct_r:5.2f}%)")

    print(f"\n  {bold('Non-regex rules:')}")
    for rule, cnt in sorted(stats["non_regex_counts"].items(), key=lambda x: -x[1]):
        print(f"  {rule:<28} {cnt:>7,}  {dim('← ML/IP' if rule in ('ai','risk-score') else '')}")

    print(f"\n  {bold('Per-method:')}")
    for method, v in sorted(stats["method_fp"].items()):
        t, f = v["total"], v["fp"]
        p = f / t * 100 if t else 0
        print(f"  {method:<8} total={t:>8,}  fp={f:>7,}  ({p:.2f}%)")

    print(f"\n  {bold('Top FP paths (top 10):')}")
    for path, cnt in list(stats["top_fp_paths"].items())[:10]:
        print(f"  {cnt:>6,}  {path}")

    print(f"\n{bar}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report generator
# ─────────────────────────────────────────────────────────────────────────────
def generate_md_report(
    stats: dict,
    load_meta: dict,
    waf_host: str,
    elapsed_total: float,
    dataset_dir: Path,
    ts: str,
) -> str:

    fp_pct     = stats["fp_regex_pct"]
    fp_count   = stats["fp_regex_count"]
    effective  = stats["effective"]
    total      = stats["total"]
    errors     = stats["errors"]

    def pct_badge(p: float) -> str:
        if p < 2:   return f"{p:.2f}% ✅"
        if p < 10:  return f"{p:.2f}% ⚠️"
        return f"{p:.2f}% ❌"

    lines: list[str] = []
    w = lines.append

    w(f"# Aegis-Gate WAF — Legitimate Traffic FP Report")
    w(f"")
    w(f"**Ngày chạy:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    w(f"**Endpoint:** `https://{waf_host}`  ")
    w(f"**Dataset:** `{dataset_dir}`  ")
    w(f"**Script:** `eval_waf_legitimate_dataset.py`")
    w(f"")
    w(f"---")
    w(f"")

    # Overview
    w(f"## Tổng quan")
    w(f"")
    w(f"| Chỉ số | Giá trị |")
    w(f"|--------|---------|")
    w(f"| Files dataset | {load_meta['files_total']:,} |")
    w(f"| Files loaded | {load_meta['files_loaded']:,} |")
    w(f"| Files lỗi parse | {load_meta['files_errored']:,} |")
    w(f"| Tổng records gửi | {total:,} |")
    w(f"| Network errors | {errors:,} ({errors/total*100:.1f}%) |")
    w(f"| Effective records | {effective:,} |")
    w(f"| Thời gian chạy | {elapsed_total/60:.1f} phút |")
    w(f"| Throughput | {total/elapsed_total:,.0f} rq/s |")
    w(f"")

    # Action distribution
    w(f"### WAF action distribution")
    w(f"")
    w(f"| Action | Count | % |")
    w(f"|--------|------:|--:|")
    for act, cnt in sorted(stats["action_dist"].items(), key=lambda x: -x[1]):
        w(f"| `{act}` | {cnt:,} | {cnt/total*100:.1f}% |")
    w(f"")

    # FP Summary
    w(f"---")
    w(f"")
    w(f"## False Positive Rate")
    w(f"")
    w(f"> **Mục tiêu:** Tất cả records là traffic hợp lệ — WAF không được fire regex detector.")
    w(f"")
    w(f"| Metric | Giá trị |")
    w(f"|--------|---------|")
    w(f"| **FP rate (regex rule)** | **{pct_badge(fp_pct)}** |")
    w(f"| FP count (regex) | {fp_count:,} / {effective:,} |")
    w(f"| AI model fires | {stats['fp_ai_count']:,} ({stats['fp_ai_count']/effective*100:.1f}%) |")
    w(f"| IP risk-score fires | {stats['fp_rs_count']:,} ({stats['fp_rs_count']/effective*100:.1f}%) |")
    w(f"")

    # Per-rule FP
    w(f"### Regex rules fired trên legitimate traffic")
    w(f"")
    if stats["rule_counts"]:
        w(f"| Rule | Fires | FP % |")
        w(f"|------|------:|-----:|")
        for rule, cnt in sorted(stats["rule_counts"].items(), key=lambda x: -x[1]):
            p = cnt / effective * 100 if effective else 0
            badge = "✅" if p < 2 else "⚠️" if p < 10 else "❌"
            w(f"| `{rule}` | {cnt:,} | {p:.2f}% {badge} |")
    else:
        w(f"_Không có regex rule nào fired._")
    w(f"")

    # Non-regex noise
    w(f"### Non-regex rules (noise — không tính vào FP)")
    w(f"")
    if stats["non_regex_counts"]:
        w(f"| Rule | Fires | Ghi chú |")
        w(f"|------|------:|---------|")
        for rule, cnt in sorted(stats["non_regex_counts"].items(), key=lambda x: -x[1]):
            note = "ML model" if rule == "ai" else "IP risk score" if rule == "risk-score" else ""
            w(f"| `{rule}` | {cnt:,} | {note} |")
    else:
        w(f"_Không có non-regex rule fired._")
    w(f"")

    # Per-method
    w(f"---")
    w(f"")
    w(f"## FP theo HTTP method")
    w(f"")
    w(f"| Method | Total | FP fires | FP % |")
    w(f"|--------|------:|---------:|-----:|")
    for method, v in sorted(stats["method_fp"].items()):
        t, f = v["total"], v["fp"]
        p = f / t * 100 if t else 0
        w(f"| `{method}` | {t:,} | {f:,} | {p:.2f}% |")
    w(f"")

    # Top FP sites
    w(f"---")
    w(f"")
    w(f"## Top sites có FP cao nhất (top 20)")
    w(f"")
    site_fp = stats["site_fp"]
    top_sites = sorted(
        [(site, v) for site, v in site_fp.items() if v["fp"] > 0],
        key=lambda x: -x[1]["fp"]
    )[:20]

    if top_sites:
        w(f"| Site | Total | FP | FP % | Rules fired |")
        w(f"|------|------:|---:|-----:|-------------|")
        for site, v in top_sites:
            t, f = v["total"], v["fp"]
            p = f / t * 100 if t else 0
            rules_str = ", ".join(f"`{r}`×{c}" for r, c in sorted(v["rules"].items(), key=lambda x: -x[1]))
            site_short = site.replace("browsing_2024_", "")
            w(f"| {site_short} | {t:,} | {f:,} | {p:.1f}% | {rules_str} |")
    else:
        w(f"_Không có site nào có FP._")
    w(f"")

    # Top FP paths
    w(f"---")
    w(f"")
    w(f"## Top paths kích hoạt FP (top 20)")
    w(f"")
    if stats["top_fp_paths"]:
        w(f"| Fires | Path |")
        w(f"|------:|------|")
        for path, cnt in list(stats["top_fp_paths"].items())[:20]:
            w(f"| {cnt:,} | `{path}` |")
    else:
        w(f"_Không có FP path._")
    w(f"")

    # Comparison with regex_dataset FP
    w(f"---")
    w(f"")
    w(f"## So sánh với regex_dataset FP")
    w(f"")
    w(f"| Class | regex_dataset FP% | legitimate_dataset FP% |")
    w(f"|-------|------------------:|-----------------------:|")
    regex_dataset_fp = {
        "xss": 75.3, "recon": 55.0, "open_redirect": 29.2,
        "command_injection": 27.8, "header_injection": 27.8,
        "template_injection": 23.1, "path_traversal": 10.2,
        "sqli": 8.3, "ssrf": 4.6, "nosql_injection": 2.5,
    }
    for rule in sorted(regex_dataset_fp.keys()):
        prev = regex_dataset_fp[rule]
        curr = stats["rule_counts"].get(rule, 0) / effective * 100 if effective else 0
        trend = "↓" if curr < prev else ("↑" if curr > prev else "=")
        w(f"| `{rule}` | {prev:.1f}% | {curr:.2f}% {trend} |")
    w(f"")

    # Analysis
    w(f"---")
    w(f"")
    w(f"## Phân tích & Kết luận")
    w(f"")

    # Auto-generate conclusions based on data
    critical = [(r, c) for r, c in stats["rule_counts"].items() if c/effective*100 >= 10] if effective else []
    high     = [(r, c) for r, c in stats["rule_counts"].items() if 2 <= c/effective*100 < 10] if effective else []
    good     = [(r, c) for r, c in stats["rule_counts"].items() if c/effective*100 < 2] if effective else []

    if not stats["rule_counts"]:
        w(f"**✅ Kết quả xuất sắc:** Không có regex detector nào fire trên {effective:,} legitimate requests.")
        w(f"WAF có FP rate = 0% trên tập traffic thực tế này.")
    else:
        if critical:
            w(f"### 🔴 Critical — FP rate ≥ 10%")
            w(f"")
            for rule, cnt in sorted(critical, key=lambda x: -x[1]):
                p = cnt / effective * 100
                w(f"- **`{rule}`**: {cnt:,} fires ({p:.2f}%) — cần thu hẹp pattern hoặc thêm whitelist context")
            w(f"")
        if high:
            w(f"### 🟠 High — FP rate 2–10%")
            w(f"")
            for rule, cnt in sorted(high, key=lambda x: -x[1]):
                p = cnt / effective * 100
                w(f"- **`{rule}`**: {cnt:,} fires ({p:.2f}%)")
            w(f"")
        if good or not critical:
            good_rules = [r for r in REGEX_DETECTOR_RULES if r not in stats["rule_counts"]]
            if good_rules:
                w(f"### ✅ Tốt — không fire trên legitimate traffic")
                w(f"")
                w(f"{', '.join(f'`{r}`' for r in sorted(good_rules))}")
                w(f"")

    w(f"### Về AI model và risk-score")
    w(f"")
    w(f"- `ai` fired {stats['fp_ai_count']:,} lần ({stats['fp_ai_count']/effective*100:.1f}% nếu effective>0) — ML model có thể cần tune threshold")
    w(f"- `risk-score` fired {stats['fp_rs_count']:,} lần — IP test tích lũy score trong session, không phản ánh real-world")
    w(f"")

    # Files output
    w(f"---")
    w(f"")
    w(f"## Files output")
    w(f"")
    w(f"| File | Mô tả |")
    w(f"|------|-------|")
    w(f"| `{ts}_legitimate_results.csv` | Per-record results với tất cả WAF header fields |")
    w(f"| `{ts}_legitimate_summary.json` | Stats tổng hợp |")
    w(f"| `{ts}_legitimate_report.md` | File này |")
    w(f"")
    w(f"---")
    w(f"")
    w(f"*Generated by `eval_waf_legitimate_dataset.py`*")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────
def export_csv(results: list[dict], path: Path) -> None:
    fields = [
        "_site", "_file", "method", "url", "path", "query", "orig_host",
        "status_code", "elapsed_ms", "error",
        "waf_action", "waf_rule_id", "waf_risk_score",
        "waf_mode", "waf_overhead_ms", "waf_request_id",
        "detector_fired", "detector_names", "any_rule_fired",
        "all_fired_rules", "non_regex_fired", "ai_fired", "risk_score_fired",
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
    print(f"  CSV    → {path}")


def export_json(stats: dict, load_meta: dict, path: Path) -> None:
    out = {"load_meta": load_meta, "stats": stats}
    with path.open("w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print(f"  JSON   → {path}")


def export_md(content: str, path: Path) -> None:
    path.write_text(content, encoding="utf-8")
    print(f"  MD     → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# DNS check
# ─────────────────────────────────────────────────────────────────────────────
def check_dns(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return True
    except socket.gaierror as e:
        print(f"\n{red('✗ DNS failed')}: {host} → {e}", file=sys.stderr)
        print("  Run on a machine with internet access.", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Test WAF FP rate on real Legitimate browsing traffic."
    )
    p.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR),
                   help="Path to Legitimate dataset directory")
    p.add_argument("--host",    default=DEFAULT_HOST)
    p.add_argument("--port",    default=DEFAULT_PORT, type=int)
    p.add_argument("--no-tls",  action="store_true")
    p.add_argument("--timeout", default=DEFAULT_TIMEOUT, type=float)
    p.add_argument("--sample",  default=0, type=int,
                   help="Max records per file (0 = all)")
    p.add_argument("--max-total", default=0, type=int,
                   help="Max total records across all files (0 = unlimited)")
    p.add_argument("--files",   default="*.json",
                   help="Glob pattern to filter files, e.g. 'browsing_2024_amazon*'")
    p.add_argument("--random", action="store_true",
                   help="Random sample thay vì lấy theo thứ tự")
    p.add_argument("--seed", default=42, type=int,
                   help="Random seed (default: 42)")
    p.add_argument("--concurrency", default=DEFAULT_CONCURRENCY, type=int,
                   help=f"Concurrent connections (async engine, default: {DEFAULT_CONCURRENCY})")
    p.add_argument("--workers", default=DEFAULT_WORKERS, type=int,
                   help=f"Thread workers (fallback engine, default: {DEFAULT_WORKERS})")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print each FP immediately when detected")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--out-dir", default=None)
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    global _USE_COLOR
    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    waf_host = args.host
    port     = args.port
    tls      = not args.no_tls
    dataset_dir = Path(args.dataset_dir)

    if not dataset_dir.exists():
        print(f"{red('✗')} Dataset directory not found: {dataset_dir}", file=sys.stderr)
        sys.exit(1)

    if not check_dns(waf_host):
        sys.exit(1)

    # Load
    random_seed = args.seed if args.random else None

    print(f"\n{bold('Loading Legitimate dataset...')}")
    if random_seed is not None:
        print(f"  Mode   : random sample (seed={random_seed})")
    records, load_meta = load_legitimate_dataset(
        dataset_dir,
        sample_per_file=args.sample,
        max_total=args.max_total,
        file_glob=args.files,
        random_seed=random_seed,
    )
    print(f"  Files  : {load_meta['files_loaded']:,} / {load_meta['files_total']:,}"
          f"  (errors: {load_meta['files_errored']})")
    print(f"  Records: {load_meta['records_loaded']:,}"
          f"  (total in files: {load_meta['records_total_in_files']:,})")

    concurrency = args.concurrency if HAS_AIOHTTP else args.workers
    engine_name = f"aiohttp async  concurrency={concurrency}" if HAS_AIOHTTP \
                  else f"threading fallback  workers={concurrency}"

    print(f"\n{bold('Aegis-Gate WAF — Legitimate Traffic Probe')}")
    print(f"  Target  : {'https' if tls else 'http'}://{waf_host}:{port}/")
    print(f"  Records : {len(records):,}")
    print(f"  Engine  : {engine_name}")
    print(f"  Timeout : {args.timeout}s")
    if not HAS_AIOHTTP:
        print(f"  {yellow('Tip: pip install aiohttp  →  10k+ RPS async engine')}")
    print()

    t0 = time.monotonic()
    results = run_all(records, waf_host, port, args.timeout, tls, concurrency, args.verbose)
    elapsed = time.monotonic() - t0
    print(f"\n  Done in {elapsed:.1f}s  ({len(results)/elapsed:,.0f} rq/s)\n")

    # Stats + console report
    stats = compute_stats(results)
    print_console_report(stats)

    # Export
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else Path(__file__).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  {bold('Exporting...')}")
    export_csv(results, out_dir / f"{ts}_legitimate_results.csv")
    export_json(stats, load_meta, out_dir / f"{ts}_legitimate_summary.json")

    md_content = generate_md_report(stats, load_meta, waf_host, elapsed, dataset_dir, ts)
    export_md(md_content, out_dir / f"{ts}_legitimate_report.md")
    print()


if __name__ == "__main__":
    main()
