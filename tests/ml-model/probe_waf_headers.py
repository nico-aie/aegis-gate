#!/usr/bin/env python3
"""
probe_waf_headers.py
====================
Sends one or more SQLi probe requests to the Aegis-Gate WAF and prints a
detailed interpretation of every x-waf-* response header.

Default probe:
  GET /game?1%27%3B%20SELECT%20CASE%20WHEN%20(1=1)%20THEN%20PG_SLEEP(5)%20ELSE%20PG_SLEEP(0)%20END%20--
  X-Forwarded-For: 5.195.235.51
  Host: waf.hk-aegis-gate.com

Usage:
  python probe_waf_headers.py                      # run default probe set
  python probe_waf_headers.py --url "..."          # run a single custom URL
  python probe_waf_headers.py --verbose            # also dump raw headers
  python probe_waf_headers.py --no-tls             # plain HTTP
  python probe_waf_headers.py --host 18.140.47.62  # different host
"""

import argparse
import http.client
import json
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_HOST    = "waf.hk-aegis-gate.com"
DEFAULT_PORT    = 443
DEFAULT_TLS     = True
DEFAULT_TIMEOUT = 15.0

# The original curl payload (exact percent-encoding preserved)
ORIGINAL_PATH   = "/game"
ORIGINAL_QUERY  = "1%27%3B%20SELECT%20CASE%20WHEN%20(1=1)%20THEN%20PG_SLEEP(5)%20ELSE%20PG_SLEEP(0)%20END%20--"
ORIGINAL_XFF    = "5.195.235.51"

# ---------------------------------------------------------------------------
# WAF header constants (from crates/aegis-control/src/interop/headers.rs)
# ---------------------------------------------------------------------------
H_REQUEST_ID       = "x-waf-request-id"
H_RISK_SCORE       = "x-waf-risk-score"
H_ACTION           = "x-waf-action"
H_RULE_ID          = "x-waf-rule-id"
H_CACHE            = "x-waf-cache"
H_MODE             = "x-waf-mode"
H_OVERHEAD_LATENCY = "x-waf-overhead-latency"

# Optional benchmark headers (from crates/aegis-proxy/src/benchmark.rs)
H_STAGE_TOTAL    = "x-aegis-stage-total-us"
H_STAGE_SECURITY = "x-aegis-stage-security-us"
H_TIER           = "x-aegis-tier"
H_DECISION       = "x-aegis-decision"
H_AEGIS_RULE     = "x-aegis-rule-id"
H_AEGIS_REQ_ID   = "x-aegis-request-id"
H_AEGIS_BUILD    = "x-aegis-build"

WAF_ALWAYS_ON_HEADERS = [
    H_REQUEST_ID, H_RISK_SCORE, H_ACTION, H_RULE_ID,
    H_CACHE, H_MODE, H_OVERHEAD_LATENCY,
]
WAF_BENCHMARK_HEADERS = [
    H_STAGE_TOTAL, H_STAGE_SECURITY, H_TIER,
    H_DECISION, H_AEGIS_RULE, H_AEGIS_REQ_ID, H_AEGIS_BUILD,
]

# ---------------------------------------------------------------------------
# Score thresholds (from crates/aegis-security/src/detectors/scores.rs)
# ---------------------------------------------------------------------------
CHALLENGE_AT = 40
BLOCK_AT     = 80

# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------
@dataclass
class Probe:
    label: str
    path: str
    query: str                          # raw (may be percent-encoded)
    extra_headers: dict = field(default_factory=dict)
    description: str = ""

DEFAULT_PROBES = [
    Probe(
        label="[ORIGINAL] PostgreSQL time-based blind SQLi",
        path=ORIGINAL_PATH,
        query=ORIGINAL_QUERY,
        extra_headers={"X-Forwarded-For": ORIGINAL_XFF},
        description="Exact payload from curl: 1'; SELECT CASE WHEN (1=1) THEN PG_SLEEP(5) ELSE PG_SLEEP(0) END --",
    ),
    Probe(
        label="[VARIANT 1] Double URL-encoded SQLi",
        path=ORIGINAL_PATH,
        # 1%2527%253B%2520... — one extra layer of percent-encoding
        query="1%2527%253B%2520SELECT%2520CASE%2520WHEN%25281%253D1%2529%2520THEN%2520PG_SLEEP%25285%2529%2520ELSE%2520PG_SLEEP%25280%2529%2520END%2520--",
        extra_headers={"X-Forwarded-For": ORIGINAL_XFF},
        description="Double percent-encoded variant — tests normalize_for_detection second decode pass",
    ),
    Probe(
        label="[VARIANT 2] Plain decoded SQLi (no encoding)",
        path=ORIGINAL_PATH,
        query=urllib.parse.quote("1'; SELECT CASE WHEN (1=1) THEN PG_SLEEP(5) ELSE PG_SLEEP(0) END --", safe=""),
        extra_headers={"X-Forwarded-For": ORIGINAL_XFF},
        description="Re-encoded from decoded form — produces identical decoded value",
    ),
    Probe(
        label="[VARIANT 3] SQLi in referer header",
        path=ORIGINAL_PATH,
        query="id=1",
        extra_headers={
            "X-Forwarded-For": ORIGINAL_XFF,
            "Referer": "https://example.com/?q=1'; SELECT CASE WHEN (1=1) THEN PG_SLEEP(5) ELSE PG_SLEEP(0) END --",
        },
        description="Payload moved to Referer header — tests header scanning branch of detect_sqli",
    ),
    Probe(
        label="[VARIANT 4] Union-based SQLi",
        path=ORIGINAL_PATH,
        query=urllib.parse.quote("id=1' UNION SELECT NULL,NULL,table_name FROM information_schema.tables--", safe="=&"),
        extra_headers={"X-Forwarded-For": ORIGINAL_XFF},
        description="UNION-based SQLi — broad pattern coverage test",
    ),
    Probe(
        label="[CLEAN] Normal request (no SQLi)",
        path="/game",
        query="level=5&player=alice",
        extra_headers={"X-Forwarded-For": ORIGINAL_XFF},
        description="Benign request — WAF should allow with no rule_id",
    ),
]

# ---------------------------------------------------------------------------
# HTTP sending
# ---------------------------------------------------------------------------
def make_tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

@dataclass
class WafResponse:
    probe_label: str
    url: str
    status_code: Optional[int]
    reason: Optional[str]
    headers: dict          # lowercased key → value
    elapsed_s: float
    error: Optional[str]

    # Parsed WAF fields
    @property
    def waf_action(self)          -> str: return self.headers.get(H_ACTION, "—")
    @property
    def waf_rule_id(self)         -> str: return self.headers.get(H_RULE_ID, "—")
    @property
    def waf_risk_score(self)      -> str: return self.headers.get(H_RISK_SCORE, "—")
    @property
    def waf_mode(self)            -> str: return self.headers.get(H_MODE, "—")
    @property
    def waf_cache(self)           -> str: return self.headers.get(H_CACHE, "—")
    @property
    def waf_overhead_latency(self)-> str: return self.headers.get(H_OVERHEAD_LATENCY, "—")
    @property
    def waf_request_id(self)      -> str: return self.headers.get(H_REQUEST_ID, "—")

    @property
    def detector_fired(self) -> bool:
        rule = self.headers.get(H_RULE_ID, "none").lower()
        return rule not in ("none", "—", "")

    @property
    def detector_names(self) -> list[str]:
        rule = self.headers.get(H_RULE_ID, "none")
        if rule.lower() in ("none", ""):
            return []
        return [r.strip() for r in rule.split(",")]

    @property
    def action_emoji(self) -> str:
        a = self.waf_action.lower()
        return {"allow": "✅", "block": "🚫", "challenge": "⚠️",
                "rate_limit": "🔁", "timeout": "⏱️", "circuit_breaker": "⚡"}.get(a, "❓")


def send_probe(
    probe: Probe,
    host: str,
    port: int,
    tls: bool,
    timeout: float,
) -> WafResponse:
    url = f"{'https' if tls else 'http'}://{host}:{port}{probe.path}?{probe.query}"
    req_path = f"{probe.path}?{probe.query}"

    headers = {
        "Host": host,
        "User-Agent": "AegisWAF-Probe/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    headers.update(probe.extra_headers)

    t0 = time.monotonic()
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                host, port=port, timeout=timeout, context=make_tls_ctx()
            )
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=timeout)

        conn.request("GET", req_path, headers=headers)
        resp = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        elapsed = time.monotonic() - t0

        return WafResponse(
            probe_label=probe.label,
            url=url,
            status_code=resp.status,
            reason=resp.reason,
            headers=resp_headers,
            elapsed_s=elapsed,
            error=None,
        )
    except Exception as exc:
        elapsed = time.monotonic() - t0
        return WafResponse(
            probe_label=probe.label,
            url=url,
            status_code=None,
            reason=None,
            headers={},
            elapsed_s=elapsed,
            error=str(exc),
        )

# ---------------------------------------------------------------------------
# Pretty-printing
# ---------------------------------------------------------------------------
BOLD  = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[32m"
RED   = "\033[31m"
YELLOW= "\033[33m"
CYAN  = "\033[36m"
DIM   = "\033[2m"

def color_action(action: str) -> str:
    a = action.lower()
    if a == "allow":   return f"{GREEN}{action}{RESET}"
    if a == "block":   return f"{RED}{action}{RESET}"
    if a == "challenge": return f"{YELLOW}{action}{RESET}"
    return f"{CYAN}{action}{RESET}"

def print_response(r: WafResponse, verbose: bool = False) -> None:
    sep = "─" * 72
    print(f"\n{sep}")
    print(f"{BOLD}{r.probe_label}{RESET}")
    if r.error:
        print(f"  {RED}ERROR: {r.error}{RESET}")
        print(f"  URL  : {r.url}")
        return

    print(f"  URL    : {DIM}{r.url}{RESET}")
    print(f"  HTTP   : {r.status_code} {r.reason}  ({r.elapsed_s:.3f}s)")

    print()
    print(f"  {BOLD}── WAF Verdict ──{RESET}")
    print(f"  Action         : {r.action_emoji}  {color_action(r.waf_action)}")
    if r.detector_fired:
        print(f"  Detector fired : {RED}YES{RESET}  →  {', '.join(r.detector_names)}")
    else:
        print(f"  Detector fired : {GREEN}NO{RESET}  (rule_id = none)")
    print(f"  Risk score     : {r.waf_risk_score}")
    print(f"  WAF mode       : {r.waf_mode}")

    print()
    print(f"  {BOLD}── WAF Metadata ──{RESET}")
    print(f"  Request ID     : {r.waf_request_id}")
    print(f"  Cache          : {r.waf_cache}")
    print(f"  Overhead       : {r.waf_overhead_latency} ms")

    # Optional benchmark headers
    bench = {k: r.headers[k] for k in WAF_BENCHMARK_HEADERS if k in r.headers}
    if bench:
        print()
        print(f"  {BOLD}── Benchmark Headers ──{RESET}")
        for k, v in bench.items():
            print(f"  {k:30s}: {v}")

    if verbose:
        print()
        print(f"  {BOLD}── All Response Headers ──{RESET}")
        for k, v in sorted(r.headers.items()):
            marker = " ◀" if k.startswith("x-waf") or k.startswith("x-aegis") else ""
            print(f"  {k:40s}: {v}{marker}")

    # Interpretation note
    print()
    print(f"  {BOLD}── Interpretation ──{RESET}")
    _interpret(r)


def _interpret(r: WafResponse) -> None:
    action = r.waf_action.lower()
    rules  = r.detector_names

    if r.error:
        print(f"  ⚠️  Could not reach WAF: {r.error}")
        return

    if not rules:
        print(f"  ✅  Request was CLEAN — no detector matched.")
        print(f"      WAF let it through (action={action}).")
        return

    print(f"  🔴  Detector(s) matched: {', '.join(rules)}")

    score_hint = ""
    try:
        score = int(r.waf_risk_score)
        if score >= BLOCK_AT:
            score_hint = f"  Risk score {score} ≥ BLOCK_AT ({BLOCK_AT}) — request should be BLOCKED."
        elif score >= CHALLENGE_AT:
            score_hint = f"  Risk score {score} ≥ CHALLENGE_AT ({CHALLENGE_AT}) — request should be CHALLENGED."
        else:
            score_hint = f"  Risk score {score} < CHALLENGE_AT ({CHALLENGE_AT}) — scored but below action threshold."
    except (ValueError, TypeError):
        score_hint = f"  Risk score: {r.waf_risk_score} (could not parse as int)."
    print(f"  {score_hint}")

    action_desc = {
        "block":          "🚫  Traffic was BLOCKED by the WAF.",
        "challenge":      "⚠️   Traffic was CHALLENGED (e.g. CAPTCHA / rate limit page).",
        "allow":          "⚠️   Traffic was ALLOWED despite detector match (log_only mode or score below threshold).",
        "rate_limit":     "🔁  Traffic was RATE LIMITED.",
        "timeout":        "⏱️   Request timed out at the WAF.",
        "circuit_breaker":"⚡  Circuit breaker tripped — backend protection.",
    }.get(action, f"❓  Unknown action '{action}'.")
    print(f"  {action_desc}")

    if action == "allow" and r.waf_mode.lower() == "log_only":
        print(f"  ℹ️   WAF is in LOG_ONLY mode — it logs but never blocks.")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
def print_summary(results: list[WafResponse]) -> None:
    sep = "═" * 72
    print(f"\n{sep}")
    print(f"{BOLD}SUMMARY{RESET}")
    print(f"{sep}")
    header = f"{'#':<3} {'Action':<12} {'Rule(s)':<30} {'Score':<7} {'ms':<8} {'Label'}"
    print(f"  {DIM}{header}{RESET}")
    print(f"  {'─'*68}")
    for i, r in enumerate(results, 1):
        if r.error:
            row = f"{i:<3} {'ERROR':<12} {r.error[:30]:<30} {'—':<7} {'—':<8} {r.probe_label}"
        else:
            rule_short = (", ".join(r.detector_names) or "none")[:30]
            overhead   = r.waf_overhead_latency if r.waf_overhead_latency != "—" else "—"
            row = (
                f"{i:<3} "
                f"{r.waf_action:<12} "
                f"{rule_short:<30} "
                f"{r.waf_risk_score:<7} "
                f"{overhead:<8} "
                f"{r.probe_label[:50]}"
            )
        print(f"  {row}")
    print()

    fired  = sum(1 for r in results if not r.error and r.detector_fired)
    clean  = sum(1 for r in results if not r.error and not r.detector_fired)
    errors = sum(1 for r in results if r.error)
    print(f"  Total probes : {len(results)}")
    print(f"  Detector hit : {fired}")
    print(f"  Clean (pass) : {clean}")
    print(f"  Errors       : {errors}")
    print(f"{sep}\n")


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------
def to_json(results: list[WafResponse]) -> list[dict]:
    out = []
    for r in results:
        out.append({
            "probe":           r.probe_label,
            "url":             r.url,
            "status_code":     r.status_code,
            "reason":          r.reason,
            "elapsed_s":       round(r.elapsed_s, 4),
            "error":           r.error,
            "waf_action":      r.waf_action,
            "waf_rule_id":     r.waf_rule_id,
            "waf_risk_score":  r.waf_risk_score,
            "waf_mode":        r.waf_mode,
            "waf_cache":       r.waf_cache,
            "waf_overhead_ms": r.waf_overhead_latency,
            "waf_request_id":  r.waf_request_id,
            "detector_fired":  r.detector_fired,
            "detector_names":  r.detector_names,
            "all_headers":     r.headers,
        })
    return out


# ---------------------------------------------------------------------------
# DNS pre-check
# ---------------------------------------------------------------------------
def check_dns(host: str) -> bool:
    import socket
    try:
        socket.getaddrinfo(host, 443)
        return True
    except socket.gaierror as e:
        print(f"{RED}DNS resolution failed for '{host}': {e}{RESET}", file=sys.stderr)
        print("Run this script on a machine with internet access.", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Probe Aegis-Gate WAF with SQLi payloads and interpret x-waf-* headers."
    )
    p.add_argument("--host",    default=DEFAULT_HOST,    help="WAF hostname (default: %(default)s)")
    p.add_argument("--port",    default=DEFAULT_PORT,    type=int, help="WAF port (default: %(default)s)")
    p.add_argument("--no-tls",  action="store_true",     help="Use plain HTTP instead of HTTPS")
    p.add_argument("--timeout", default=DEFAULT_TIMEOUT, type=float, help="Request timeout in seconds")
    p.add_argument("--url",     default=None,            help="Send a single custom URL instead of the default probe set")
    p.add_argument("--xff",     default=ORIGINAL_XFF,   help="X-Forwarded-For header value (default: %(default)s)")
    p.add_argument("--verbose", "-v", action="store_true", help="Dump all response headers")
    p.add_argument("--json",    default=None,            metavar="FILE", help="Save full results to a JSON file")
    p.add_argument("--no-color", action="store_true",   help="Disable ANSI color output")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Disable color if requested or not a TTY
    if args.no_color or not sys.stdout.isatty():
        global BOLD, RESET, GREEN, RED, YELLOW, CYAN, DIM
        BOLD = RESET = GREEN = RED = YELLOW = CYAN = DIM = ""

    host = args.host
    port = args.port
    tls  = not args.no_tls

    # DNS check
    if not check_dns(host):
        sys.exit(1)

    # Build probe list
    if args.url:
        parsed = urllib.parse.urlparse(args.url)
        probes = [Probe(
            label="[CUSTOM] User-provided URL",
            path=parsed.path or "/",
            query=parsed.query or "",
            extra_headers={"X-Forwarded-For": args.xff},
            description=args.url,
        )]
    else:
        probes = DEFAULT_PROBES

    print(f"\n{BOLD}Aegis-Gate WAF Header Probe{RESET}")
    print(f"Target : {'https' if tls else 'http'}://{host}:{port}/")
    print(f"Probes : {len(probes)}")
    print(f"Timeout: {args.timeout}s")

    results: list[WafResponse] = []
    for probe in probes:
        print(f"\n  ↗  Sending: {probe.label} …", end="", flush=True)
        r = send_probe(probe, host, port, tls, args.timeout)
        results.append(r)
        status = f"{r.status_code}" if r.status_code else "ERR"
        action = r.waf_action if not r.error else "error"
        print(f" {status} / {action}")

    # Detailed output
    for r in results:
        print_response(r, verbose=args.verbose)

    # Summary
    print_summary(results)

    # JSON export
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(results), fh, indent=2, ensure_ascii=False)
        print(f"Results saved to: {args.json}")


if __name__ == "__main__":
    main()
