#!/usr/bin/env python3
"""
eval_ai_serving_legitimate.py
==============================
Đánh giá AI serving server (aegis-infer) với Legitimate browser traffic dataset.
Đo False Positive rate của ONNX model trên real traffic bình thường.

Dataset : /Users/admin/Documents/workspace/remote/dataset/Legitimate
          692 JSON files, mỗi file là 1 website, mỗi entry là 1 HTTP request

Server  : aegis-infer gRPC (TCP hoặc UDS)
Protocol: gRPC — ClassifyRequest với raw_request string

Output  :
  <ts>_ai_serving_results.csv     — 1 row/request
  <ts>_ai_serving_summary.json    — aggregate metrics
  <ts>_ai_serving_report.md       — human-readable report

Usage:
  # Cơ bản (server trên localhost:50051)
  python eval_ai_serving_legitimate.py

  # UDS socket
  python eval_ai_serving_legitimate.py --endpoint unix:///tmp/aegis-infer.sock

  # Giới hạn số request, concurrency cao
  python eval_ai_serving_legitimate.py --max-total 20000 --concurrency 400

  # Chỉ lấy mẫu ngẫu nhiên từ mỗi file
  python eval_ai_serving_legitimate.py --sample 50 --random

  # Chi tiết từng request bị đánh dấu là attack
  python eval_ai_serving_legitimate.py --verbose-fp

Dependencies (tự động cài nếu thiếu):
  pip install grpcio grpcio-tools
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean, median
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

DATASET_DIR   = Path("/Users/admin/Documents/workspace/remote/dataset/Legitimate")
PROTO_FILE    = Path(__file__).parent.parent.parent / "data" / "serving-server" / "proto" / "aegis_infer.proto"
GRPC_OUT_DIR  = Path(__file__).parent / "__grpc__"
OUTPUT_DIR    = Path(__file__).parent

# ─────────────────────────────────────────────────────────────────────────────
# Dependency & proto stub setup
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_dependencies() -> None:
    """Install grpcio + grpcio-tools if missing."""
    missing = []
    try:
        import grpc  # noqa: F401
    except ImportError:
        missing.append("grpcio")
    try:
        import grpc_tools  # noqa: F401
    except ImportError:
        missing.append("grpcio-tools")

    if missing:
        print(f"[setup] Installing {', '.join(missing)} …")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
            stdout=subprocess.DEVNULL,
        )
        print("[setup] Done.")


def _ensure_stubs() -> None:
    """Generate Python gRPC stubs from proto if not already generated."""
    pb2_file = GRPC_OUT_DIR / "aegis_infer_pb2.py"
    grpc_file = GRPC_OUT_DIR / "aegis_infer_pb2_grpc.py"

    if pb2_file.exists() and grpc_file.exists():
        return  # Already generated.

    if not PROTO_FILE.exists():
        print(f"[error] Proto file not found: {PROTO_FILE}", file=sys.stderr)
        print("        Make sure data/serving-server/proto/aegis_infer.proto exists.", file=sys.stderr)
        sys.exit(1)

    GRPC_OUT_DIR.mkdir(parents=True, exist_ok=True)
    (GRPC_OUT_DIR / "__init__.py").touch()

    print(f"[setup] Generating gRPC stubs from {PROTO_FILE} …")
    from grpc_tools import protoc  # type: ignore

    result = protoc.main([
        "grpc_tools.protoc",
        f"--proto_path={PROTO_FILE.parent}",
        f"--python_out={GRPC_OUT_DIR}",
        f"--grpc_python_out={GRPC_OUT_DIR}",
        str(PROTO_FILE.name),
    ])
    if result != 0:
        print("[error] proto compilation failed", file=sys.stderr)
        sys.exit(1)

    # Fix relative import in generated _grpc file (grpcio-tools quirk)
    grpc_src = grpc_file.read_text()
    grpc_src = grpc_src.replace(
        "import aegis_infer_pb2",
        "from __grpc__ import aegis_infer_pb2",
    )
    grpc_file.write_text(grpc_src)
    print("[setup] Stubs ready.")


# ─────────────────────────────────────────────────────────────────────────────
# Dataset loading
# ─────────────────────────────────────────────────────────────────────────────

def build_raw_request(entry: dict) -> str:
    """
    Xây dựng raw request string theo format mà aegis-infer expects:
      "METHOD /path?query body\nUser-Agent: …\nCookie: …\nReferer: …"

    Khớp với aegis-security::AiDetector::build_request_string().
    """
    method  = entry.get("method", "GET").upper()
    url     = entry.get("url", "/")
    body    = entry.get("data", "") or ""
    headers = entry.get("headers", {})

    # Truncate body to match server-side MAX_BODY_BYTES=8192
    if isinstance(body, str):
        body_str = body[:8192]
    elif isinstance(body, (dict, list)):
        body_str = json.dumps(body)[:8192]
    else:
        body_str = str(body)[:8192]

    # First line: METHOD /path body
    line1 = f"{method} {url} {body_str}".rstrip()

    # Selected security-relevant headers (same set as WAF)
    relevant = ["user-agent", "cookie", "referer", "x-forwarded-for",
                "authorization", "content-type", "host"]
    header_lines = []
    for key, val in headers.items():
        if key.lower() in relevant:
            header_lines.append(f"{key}: {val}")

    return "\n".join([line1] + header_lines)


def load_dataset(
    dataset_dir: Path,
    max_total:   Optional[int],
    sample:      Optional[int],
    random_order: bool,
    file_glob:   str = "*.json",
) -> tuple[list[tuple[str, str, dict]], int]:
    """
    Returns list of (file_stem, request_id, entry) and total_files count.
    """
    files = sorted(dataset_dir.glob(file_glob))
    if not files:
        print(f"[error] No JSON files found in {dataset_dir}", file=sys.stderr)
        sys.exit(1)

    if random_order:
        random.shuffle(files)

    records: list[tuple[str, str, dict]] = []  # (source_file, req_id, entry)

    for f in files:
        try:
            entries = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[warn] Skip {f.name}: {e}")
            continue

        if not isinstance(entries, list):
            continue

        if sample is not None:
            if random_order:
                entries = random.sample(entries, min(sample, len(entries)))
            else:
                entries = entries[:sample]

        for i, entry in enumerate(entries):
            req_id = f"{f.stem}::{i}"
            records.append((f.stem, req_id, entry))

        if max_total and len(records) >= max_total:
            break

    if max_total:
        records = records[:max_total]

    return records, len(files)


# ─────────────────────────────────────────────────────────────────────────────
# gRPC client
# ─────────────────────────────────────────────────────────────────────────────

class AegisInferClient:
    """Async gRPC client wrapping the aegis-infer service."""

    def __init__(self, endpoint: str, timeout: float = 10.0):
        self.endpoint = endpoint
        self.timeout  = timeout
        self._channel = None
        self._stub    = None

    async def connect(self) -> None:
        import grpc
        from grpc import aio as grpc_aio
        sys.path.insert(0, str(GRPC_OUT_DIR.parent))
        from __grpc__ import aegis_infer_pb2_grpc  # type: ignore

        if self.endpoint.startswith("unix://"):
            # UDS: strip scheme for grpc
            uds_path = self.endpoint.replace("unix://", "")
            self._channel = grpc_aio.insecure_channel(f"unix:{uds_path}")
        else:
            self._channel = grpc_aio.insecure_channel(self.endpoint)

        self._stub = aegis_infer_pb2_grpc.AegisInferStub(self._channel)

    async def health(self) -> dict:
        from __grpc__ import aegis_infer_pb2  # type: ignore
        resp = await self._stub.Health(
            aegis_infer_pb2.HealthRequest(),
            timeout=self.timeout,
        )
        return {
            "ok":        resp.ok,
            "mode":      resp.mode,
            "workers":   resp.workers,
            "max_batch": resp.max_batch,
            "delay_ms":  resp.delay_ms,
        }

    async def classify(self, request_id: str, raw_request: str) -> dict:
        from __grpc__ import aegis_infer_pb2  # type: ignore
        t0   = time.perf_counter()
        resp = await self._stub.Classify(
            aegis_infer_pb2.ClassifyRequest(
                request_id  = request_id,
                raw_request = raw_request,
            ),
            timeout=self.timeout,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "request_id":  resp.request_id,
            "prob_attack": resp.prob_attack,
            "is_attack":   resp.is_attack,
            "batch_size":  resp.batch_size,
            "infer_us":    resp.infer_us,
            "queue_ms":    resp.queue_ms,
            "client_ms":   round(elapsed_ms, 2),
        }

    async def stats(self) -> dict:
        from __grpc__ import aegis_infer_pb2  # type: ignore
        resp = await self._stub.Stats(
            aegis_infer_pb2.StatsRequest(),
            timeout=self.timeout,
        )
        return {
            "total_requests":  resp.total_requests,
            "total_batches":   resp.total_batches,
            "avg_batch_size":  round(resp.avg_batch_size, 1),
            "avg_infer_us":    round(resp.avg_infer_us),
            "total_attacks":   resp.total_attacks,
            "max_batch_seen":  resp.max_batch_seen,
            "uptime_secs":     resp.uptime_secs,
        }

    async def close(self) -> None:
        if self._channel:
            await self._channel.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main evaluation loop
# ─────────────────────────────────────────────────────────────────────────────

class EvalResult:
    __slots__ = (
        "source_file", "request_id", "method", "url",
        "prob_attack", "is_attack", "batch_size",
        "infer_us", "queue_ms", "client_ms", "error",
    )

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


async def run_eval(
    records:     list[tuple[str, str, dict]],
    client:      AegisInferClient,
    concurrency: int,
    verbose_fp:  bool,
) -> list[EvalResult]:
    sem      = asyncio.Semaphore(concurrency)
    results  = [None] * len(records)
    done_ctr = [0]
    total    = len(records)
    t_start  = time.perf_counter()

    async def classify_one(idx: int, source_file: str, req_id: str, entry: dict):
        async with sem:
            raw = build_raw_request(entry)
            method = entry.get("method", "GET").upper()
            url    = entry.get("url", "/")
            try:
                r = await client.classify(req_id, raw)
                result = EvalResult(
                    source_file = source_file,
                    request_id  = req_id,
                    method      = method,
                    url         = url[:200],
                    prob_attack = r["prob_attack"],
                    is_attack   = r["is_attack"],
                    batch_size  = r["batch_size"],
                    infer_us    = r["infer_us"],
                    queue_ms    = r["queue_ms"],
                    client_ms   = r["client_ms"],
                    error       = None,
                )
                if verbose_fp and r["is_attack"]:
                    print(
                        f"  [FP] {source_file} | {method} {url[:80]}"
                        f" | prob={r['prob_attack']:.3f}"
                    )
            except Exception as e:
                result = EvalResult(
                    source_file = source_file,
                    request_id  = req_id,
                    method      = method,
                    url         = url[:200],
                    prob_attack = -1.0,
                    is_attack   = False,
                    batch_size  = 0,
                    infer_us    = 0,
                    queue_ms    = 0.0,
                    client_ms   = 0.0,
                    error       = str(e),
                )

            results[idx] = result
            done_ctr[0] += 1
            n = done_ctr[0]
            if n % 500 == 0 or n == total:
                elapsed = time.perf_counter() - t_start
                rps     = n / elapsed if elapsed > 0 else 0
                print(f"  progress: {n:>6}/{total}  ({rps:.0f} RPS)", end="\r", flush=True)

    tasks = [
        classify_one(i, src, rid, entry)
        for i, (src, rid, entry) in enumerate(records)
    ]
    await asyncio.gather(*tasks)
    print()  # newline after progress
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def compute_percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    sv = sorted(values)
    idx = int(len(sv) * p / 100)
    return sv[min(idx, len(sv) - 1)]


def write_results(
    results:   list[EvalResult],
    ts:        str,
    health:    dict,
    srv_stats: dict,
    args,
) -> None:
    ok_results  = [r for r in results if r.error is None]
    err_results = [r for r in results if r.error is not None]
    fp_results  = [r for r in ok_results if r.is_attack]
    total       = len(results)
    ok_count    = len(ok_results)
    fp_count    = len(fp_results)
    err_count   = len(err_results)
    fp_rate     = fp_count / ok_count * 100 if ok_count else 0.0

    latencies   = [r.client_ms  for r in ok_results]
    queue_ms_v  = [r.queue_ms   for r in ok_results]
    probs       = [r.prob_attack for r in ok_results]

    # ── Per-file FP breakdown ────────────────────────────────────────────────
    file_total: dict[str, int] = defaultdict(int)
    file_fp:    dict[str, int] = defaultdict(int)
    for r in ok_results:
        file_total[r.source_file] += 1
        if r.is_attack:
            file_fp[r.source_file] += 1

    file_fp_rate = {
        f: file_fp[f] / file_total[f] * 100
        for f in file_total
        if file_total[f] > 0
    }
    worst_files = sorted(file_fp_rate.items(), key=lambda x: -x[1])[:15]

    # ── Prob distribution buckets ────────────────────────────────────────────
    buckets = [0] * 10  # [0,0.1), [0.1,0.2), …, [0.9,1.0]
    for p in probs:
        idx = min(int(p * 10), 9)
        buckets[idx] += 1

    # ── CSV ──────────────────────────────────────────────────────────────────
    csv_path = OUTPUT_DIR / f"{ts}_ai_serving_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "source_file", "request_id", "method", "url",
            "prob_attack", "is_attack", "batch_size",
            "infer_us", "queue_ms", "client_ms", "error",
        ])
        for r in results:
            writer.writerow([
                r.source_file, r.request_id, r.method, r.url,
                f"{r.prob_attack:.4f}", r.is_attack, r.batch_size,
                r.infer_us, f"{r.queue_ms:.2f}", f"{r.client_ms:.2f}",
                r.error or "",
            ])
    print(f"  CSV  → {csv_path}")

    # ── JSON summary ─────────────────────────────────────────────────────────
    summary = {
        "timestamp":     ts,
        "endpoint":      args.endpoint,
        "server": {
            "mode":      health.get("mode"),
            "workers":   health.get("workers"),
            "max_batch": health.get("max_batch"),
            "delay_ms":  health.get("delay_ms"),
        },
        "dataset": {
            "dir":          str(args.dataset_dir),
            "total_files":  args.total_files,
            "max_total":    args.max_total,
            "sample":       args.sample,
        },
        "results": {
            "total":        total,
            "ok":           ok_count,
            "errors":       err_count,
            "false_positives": fp_count,
            "fp_rate_pct":  round(fp_rate, 3),
        },
        "latency_ms": {
            "p50":  round(compute_percentile(latencies, 50),  2),
            "p90":  round(compute_percentile(latencies, 90),  2),
            "p95":  round(compute_percentile(latencies, 95),  2),
            "p99":  round(compute_percentile(latencies, 99),  2),
            "p999": round(compute_percentile(latencies, 99.9), 2),
            "mean": round(mean(latencies), 2) if latencies else 0,
        },
        "queue_ms": {
            "mean": round(mean(queue_ms_v), 2)    if queue_ms_v else 0,
            "p99":  round(compute_percentile(queue_ms_v, 99), 2),
        },
        "server_stats":  srv_stats,
        "prob_distribution": {
            f"{i/10:.1f}-{(i+1)/10:.1f}": buckets[i]
            for i in range(10)
        },
        "worst_fp_files": [
            {"file": f, "fp_rate_pct": round(r, 1), "fp": file_fp[f], "total": file_total[f]}
            for f, r in worst_files
        ],
    }

    json_path = OUTPUT_DIR / f"{ts}_ai_serving_summary.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"  JSON → {json_path}")

    # ── Markdown report ───────────────────────────────────────────────────────
    def _bar(count: int, total: int, width: int = 30) -> str:
        n = int(count / total * width) if total > 0 else 0
        return "█" * n + "░" * (width - n)

    verdict = "✅ PASS" if fp_rate < 1.0 else ("⚠️  MARGINAL" if fp_rate < 5.0 else "❌ FAIL")

    md_lines = [
        f"# AI Serving Server — Legitimate Dataset Eval",
        f"",
        f"**Thời gian**: {ts}  ",
        f"**Endpoint**: `{args.endpoint}`  ",
        f"**Verdict**: {verdict}",
        f"",
        f"## Server Info",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Mode | `{health.get('mode')}` |",
        f"| Workers | {health.get('workers')} |",
        f"| Max batch | {health.get('max_batch')} |",
        f"| Batch delay | {health.get('delay_ms')} ms |",
        f"",
        f"## Kết quả tổng quan",
        f"",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Tổng requests | {total:,} |",
        f"| Thành công | {ok_count:,} |",
        f"| Lỗi gRPC | {err_count:,} |",
        f"| **False Positives** | **{fp_count:,}** |",
        f"| **FP Rate** | **{fp_rate:.3f}%** |",
        f"",
        f"## Latency (client end-to-end, ms)",
        f"",
        f"| P50 | P90 | P95 | P99 | P99.9 | Mean |",
        f"|---|---|---|---|---|---|",
        f"| {compute_percentile(latencies,50):.1f} "
        f"| {compute_percentile(latencies,90):.1f} "
        f"| {compute_percentile(latencies,95):.1f} "
        f"| {compute_percentile(latencies,99):.1f} "
        f"| {compute_percentile(latencies,99.9):.1f} "
        f"| {(mean(latencies) if latencies else 0):.1f} |",
        f"",
        f"## Server-side Stats",
        f"",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Avg batch size | {srv_stats.get('avg_batch_size')} |",
        f"| Max batch seen | {srv_stats.get('max_batch_seen')} |",
        f"| Avg infer latency | {srv_stats.get('avg_infer_us')} µs |",
        f"| Total attacks flagged | {srv_stats.get('total_attacks'):,} |",
        f"",
        f"## Phân phối prob_attack",
        f"",
        f"```",
    ]

    for i in range(10):
        lo, hi = i / 10, (i + 1) / 10
        cnt    = buckets[i]
        bar    = _bar(cnt, ok_count, 40) if ok_count else ""
        md_lines.append(f"  [{lo:.1f}–{hi:.1f})  {bar}  {cnt:>6,}")

    md_lines += [
        f"```",
        f"",
        f"## Top 15 files có FP cao nhất",
        f"",
        f"| File | FP | Total | FP Rate |",
        f"|---|---|---|---|",
    ]
    for fname, rate in worst_files:
        fp_n  = file_fp[fname]
        tot_n = file_total[fname]
        if fp_n > 0:
            md_lines.append(f"| {fname} | {fp_n} | {tot_n} | {rate:.1f}% |")

    if not any(file_fp[f] > 0 for f, _ in worst_files):
        md_lines.append("| — | — | — | 0% — no false positives |")

    md_lines += [
        f"",
        f"## Errors",
        f"",
    ]
    if err_results:
        md_lines.append(f"{err_count} requests failed:")
        md_lines.append("")
        for r in err_results[:10]:
            md_lines.append(f"- `{r.request_id}`: {r.error}")
        if err_count > 10:
            md_lines.append(f"- … {err_count - 10} more")
    else:
        md_lines.append("No errors.")

    md_lines += ["", f"---", f"*Generated by eval_ai_serving_legitimate.py*"]

    md_path = OUTPUT_DIR / f"{ts}_ai_serving_report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"  MD   → {md_path}")

    # ── Console summary ───────────────────────────────────────────────────────
    print()
    print("┌─────────────────────────────────────────────────────────────┐")
    print(f"│  {verdict:^59}│")
    print("├─────────────────────────────────────────────────────────────┤")
    print(f"│  Total requests   : {total:>8,}                              │")
    print(f"│  False Positives  : {fp_count:>8,}  ({fp_rate:.3f}%)               │")
    print(f"│  Errors           : {err_count:>8,}                              │")
    print("├─────────────────────────────────────────────────────────────┤")
    print(f"│  Latency P50/P95/P99 : {compute_percentile(latencies,50):.1f} / "
          f"{compute_percentile(latencies,95):.1f} / {compute_percentile(latencies,99):.1f} ms      │")
    print(f"│  Avg batch size   : {srv_stats.get('avg_batch_size'):>8}                              │")
    print(f"│  Avg infer        : {srv_stats.get('avg_infer_us'):>8} µs                            │")
    print("└─────────────────────────────────────────────────────────────┘")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Eval AI serving server với Legitimate browser traffic dataset",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--endpoint", default="127.0.0.1:50051",
        help="gRPC endpoint: '127.0.0.1:50051' hoặc 'unix:///tmp/aegis-infer.sock'",
    )
    p.add_argument(
        "--dataset-dir", type=Path, default=DATASET_DIR,
        help="Thư mục chứa Legitimate JSON dataset",
    )
    p.add_argument(
        "--max-total", type=int, default=None,
        help="Giới hạn tổng số requests (None = tất cả)",
    )
    p.add_argument(
        "--sample", type=int, default=None,
        help="Lấy tối đa N requests mỗi file (None = tất cả)",
    )
    p.add_argument(
        "--random", action="store_true",
        help="Shuffle file list và sample ngẫu nhiên",
    )
    p.add_argument(
        "--concurrency", type=int, default=200,
        help="Số gRPC calls đồng thời",
    )
    p.add_argument(
        "--timeout", type=float, default=10.0,
        help="gRPC call timeout (giây)",
    )
    p.add_argument(
        "--files", default="*.json",
        help="Glob filter cho file dataset, vd: 'browsing_2024_amazon*'",
    )
    p.add_argument(
        "--verbose-fp", action="store_true",
        help="In ra từng request bị đánh dấu False Positive khi chạy",
    )
    p.add_argument(
        "--no-report", action="store_true",
        help="Bỏ qua export file CSV/JSON/MD",
    )
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def async_main(args: argparse.Namespace) -> int:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── 1. Load dataset ───────────────────────────────────────────────────────
    print(f"\n[1/4] Loading dataset from {args.dataset_dir} …")
    if not args.dataset_dir.exists():
        print(f"[error] Dataset dir not found: {args.dataset_dir}", file=sys.stderr)
        return 1

    records, total_files = load_dataset(
        dataset_dir  = args.dataset_dir,
        max_total    = args.max_total,
        sample       = args.sample,
        random_order = args.random,
        file_glob    = args.files,
    )
    args.total_files = total_files
    print(f"  {len(records):,} requests loaded from {total_files} files")

    if not records:
        print("[error] No records loaded — check dataset path and --files filter")
        return 1

    # ── 2. Connect & health check ─────────────────────────────────────────────
    print(f"\n[2/4] Connecting to {args.endpoint} …")
    client = AegisInferClient(args.endpoint, timeout=args.timeout)
    await client.connect()

    try:
        health = await client.health()
    except Exception as e:
        print(f"[error] Health check failed: {e}", file=sys.stderr)
        print("        Is aegis-infer running? Start with:", file=sys.stderr)
        print("          cargo run --release --bin aegis-infer -- --mock", file=sys.stderr)
        print("          (or --model-path path/to/waf_model.onnx)", file=sys.stderr)
        await client.close()
        return 1

    print(f"  Server OK — mode={health['mode']}  workers={health['workers']}"
          f"  max_batch={health['max_batch']}  delay={health['delay_ms']}ms")

    # ── 3. Run inference ──────────────────────────────────────────────────────
    print(f"\n[3/4] Running inference  ({len(records):,} requests, concurrency={args.concurrency}) …")
    t0      = time.perf_counter()
    results = await run_eval(records, client, args.concurrency, args.verbose_fp)
    elapsed = time.perf_counter() - t0
    rps     = len(records) / elapsed if elapsed > 0 else 0

    # Fetch final server stats
    try:
        srv_stats = await client.stats()
    except Exception:
        srv_stats = {}

    await client.close()

    print(f"  Completed in {elapsed:.1f}s  ({rps:.0f} RPS)")

    # ── 4. Report ─────────────────────────────────────────────────────────────
    print(f"\n[4/4] Writing report …")
    if not args.no_report:
        write_results(results, ts, health, srv_stats, args)
    else:
        ok  = sum(1 for r in results if r.error is None)
        fp  = sum(1 for r in results if r.is_attack)
        fpr = fp / ok * 100 if ok else 0
        print(f"  {ok:,} OK  |  {fp:,} FP  |  FP rate = {fpr:.3f}%")

    fp_count = sum(1 for r in results if r.is_attack)
    fp_rate  = fp_count / len([r for r in results if r.error is None]) * 100 if results else 0
    return 0 if fp_rate < 5.0 else 1


def main() -> None:
    _ensure_dependencies()
    _ensure_stubs()

    args = parse_args()

    try:
        exit_code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[interrupted]")
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
