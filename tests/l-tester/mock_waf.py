#!/usr/bin/env python3
"""
mock_waf.py — Reference implementation of WAF Interop Contract v2.3
                for the l-tester test suite.  v2 — 2026-05-09

Listens on:
  DATA  http://0.0.0.0:8080  — data plane (proxied to upstream 9999)
  ADMIN http://127.0.0.1:9443  — admin plane (control endpoints)

Contract sections implemented:
  §2  Control plane (capabilities, reset_state, set_profile, flush_cache)
  §3  Decision classes (allow, block, challenge, rate_limit)
  §4  HTTP response semantics
  §5  Mandatory observability headers on every response
  §6  Audit log (JSONL, ./waf_audit.log)
  §7  Decision normalization (enforce vs log_only)
  §9  Cache observability (BYPASS on sensitive routes)
  §10 Source IP trust model (TCP peer, not XFF)

v2 changes (2026-05-09 bug-hunter run):
  - FEATURES dict aligned with real WAF (rate_limit, risk_engine; removed challenge)
  - rules_engine policies expanded to all 13 (including ai, template_injection, etc.)
  - RULE_TO_FEATURE map for per-policy mode resolution
  - reset_state NO LONGER clears mode overrides (§2.4: operator-set config preserved)
  - set_profile scope=all rejects extra fields (features/feature/policies) → 400
  - set_profile scope=policies with unknown feature → 422 (not 200)
  - set_profile: unknown JSON fields rejected → 400
  - detect_threat: added template_injection, nosql_injection, open_redirect
  - get_mode uses per-rule feature/policy hierarchy
  - X-WAF-Overhead-Latency bonus header on every data-plane response
"""

import http.server
import http.client
import json
import re
import time
import uuid
import threading
import sys
import os
import ipaddress
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_BIND   = ("0.0.0.0", 8080)
ADMIN_BIND  = ("127.0.0.1", 9443)
UPSTREAM    = ("127.0.0.1", 9999)
BENCH_SECRET = "waf-hackathon-2026-ctrl"
AUDIT_LOG   = os.environ.get("WAF_AUDIT_LOG", "./waf_audit.log")

# ---------------------------------------------------------------------------
# Feature / policy catalogue  (mirrors real WAF run.rs build_interop_runtime)
# ---------------------------------------------------------------------------
FEATURES = {
    "access_control": {
        "supported": True,
        "toggleable": True,
        "policies": ["blacklist", "whitelist"]
    },
    "rules_engine": {
        "supported": True,
        "toggleable": True,
        "policies": [
            "sqli", "xss", "path_traversal", "ssrf",
            "header_injection", "body_abuse", "recon",
            "brute_force", "ai", "command_injection",
            "template_injection", "nosql_injection", "open_redirect"
        ]
    },
    "rate_limit": {          # NOTE: rate_limit (not rate_limiting)
        "supported": True,
        "toggleable": True,
        "policies": ["per_ip"]
    },
    "risk_engine": {         # Added in v2.3 capabilities
        "supported": True,
        "toggleable": True,
        "policies": ["score", "strikes"]
    },
}

# Allowed fields in set_profile request body  (deny_unknown_fields)
SET_PROFILE_ALLOWED_FIELDS = {"scope", "mode", "features", "feature", "policies"}

# rule_id string → (feature, policy) for per-policy mode resolution
RULE_TO_FEATURE = {
    "sqli":               ("rules_engine", "sqli"),
    "xss":                ("rules_engine", "xss"),
    "path_traversal":     ("rules_engine", "path_traversal"),
    "ssrf":               ("rules_engine", "ssrf"),
    "header_injection":   ("rules_engine", "header_injection"),
    "header_inj":         ("rules_engine", "header_injection"),
    "body_abuse":         ("rules_engine", "body_abuse"),
    "xxe":                ("rules_engine", "body_abuse"),
    "recon":              ("rules_engine", "recon"),
    "brute_force":        ("rules_engine", "brute_force"),
    "ai":                 ("rules_engine", "ai"),
    "cmdi":               ("rules_engine", "command_injection"),
    "command_injection":  ("rules_engine", "command_injection"),
    "template_injection": ("rules_engine", "template_injection"),
    "ssti":               ("rules_engine", "template_injection"),
    "nosql_injection":    ("rules_engine", "nosql_injection"),
    "nosqli":             ("rules_engine", "nosql_injection"),
    "open_redirect":      ("rules_engine", "open_redirect"),
    "openredir":          ("rules_engine", "open_redirect"),
    "blacklist":          ("access_control", "blacklist"),
    "whitelist":          ("access_control", "whitelist"),
    "ip-rate-limit":      ("rate_limit", "per_ip"),
    "rate_limit":         ("rate_limit", "per_ip"),
    "risk-score":         ("risk_engine", "score"),
    "risk-challenge":     ("risk_engine", "score"),
    "risk-strikes":       ("risk_engine", "strikes"),
}

# ---------------------------------------------------------------------------
# WAF runtime state (protected by a lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()

_state = {
    "default_mode": "enforce",      # enforce | log_only
    "overrides": {},                 # feature or feature.policy → mode
    "cache": {},                     # path -> {"action": .., "ts": ..}
    "rate_counters": {},             # ip -> [ts, ...]
    "risk_scores": {},               # ip -> int
}

RATE_LIMIT_WINDOW = 10   # seconds
RATE_LIMIT_MAX    = 200  # requests per window per IP
RISK_BLOCK_AT     = 80
RISK_CHALLENGE_AT = 40

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    re.compile(r"(?i)(\bselect\b|\bunion\b|\binsert\b|\bdrop\b|\bdelete\b|\bupdate\b).{0,30}(from|into|table)"),
    re.compile(r"(?i)(\bor\b|\band\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?"),
    re.compile(r"(?i)(--|\#|\/\*)"),
    re.compile(r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)"),
    re.compile(r"1'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),
]
XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror", re.IGNORECASE),
]
CMDI_PATTERNS = [
    re.compile(r"(;|\|{1,2}|&&)\s*(cat|ls|id|whoami|uname|passwd|shadow|wget|curl)"),
    re.compile(r"\$\(.*\)"),
    re.compile(r"(?i)(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)"),
]
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\.[/\\]"),
    re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE),
    re.compile(r"(?i)(etc\/passwd|etc\/shadow|proc\/self)"),
]
SSRF_PATTERNS = [
    re.compile(r"(?i)https?://(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)"),
    re.compile(r"(?i)https?://localhost"),
    re.compile(r"169\.254\.169\.254"),
]
TEMPLATE_INJECTION_PATTERNS = [
    re.compile(r"\{\{.+?\}\}"),            # Jinja2/Twig: {{7*7}}
    re.compile(r"\$\{.+?\}"),              # Spring EL/Freemarker: ${7*7}
    re.compile(r"<%=.+?%>"),              # ERB/JSP: <%= 7*7 %>
    re.compile(r"#\{.+?\}"),              # Ruby ERB: #{7*7}
    re.compile(r"\$\$\{.+?\}"),           # Groovy: $${7*7}
    re.compile(r"(?i)\{%.*?(for|if|block|extends|import|include|from|set|endif|endfor).*?%\}"),
]
NOSQL_PATTERNS = [
    re.compile(r"\[\s*\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|expr)\s*\]", re.IGNORECASE),
    re.compile(r"\$(?:where|gt|gte|lt|lte|ne|in|nin|or|and|nor|not|exists|type|regex|expr)\s*[\"':\[]", re.IGNORECASE),
    re.compile(r"\{[\"']?\$", re.IGNORECASE),
]
OPEN_REDIRECT_PATTERNS = [
    re.compile(r"(?i)(?:redirect|url|next|return|goto|dest|target|returnTo|successUrl|errorUrl)\s*=\s*(?:https?:|ftp:|//)"),
]

SENSITIVE_PATHS = {
    "/login", "/admin", "/account", "/checkout", "/api/token",
    "/api/user", "/protected", "/__admin", "/auth", "/session"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_ms():
    return int(time.time() * 1000)

def write_audit(entry: dict):
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[audit] write error: {e}", file=sys.stderr)

def _resolve_mode_for_rule(rule_id):
    with _lock:
        return _resolve_mode_for_rule_locked(rule_id)

def _resolve_mode_for_rule_locked(rule_id):
    dm = _state["default_mode"]
    if not rule_id or rule_id == "none":
        return dm
    primary = rule_id.split(",")[0].strip()
    pair = RULE_TO_FEATURE.get(primary)
    if not pair:
        return "enforce"
    feature, policy = pair
    pol_key = f"{feature}.{policy}"
    if pol_key in _state["overrides"]:
        return _state["overrides"][pol_key]
    if feature in _state["overrides"]:
        return _state["overrides"][feature]
    return dm

def get_mode_for_rule(rule_id):
    return _resolve_mode_for_rule(rule_id)

def is_sensitive(path):
    p = path.split("?")[0].rstrip("/")
    for s in SENSITIVE_PATHS:
        if p == s or p.startswith(s + "/"):
            return True
    return False

def detect_threat(path, headers_raw):
    """Returns (threat_type, rule_id) or (None, 'none').
    Double URL-decodes path before matching."""
    target = unquote(unquote(path))
    for pat in SQLI_PATTERNS:
        if pat.search(target):
            return "sqli", "sqli"
    for pat in XSS_PATTERNS:
        if pat.search(target):
            return "xss", "xss"
    for pat in CMDI_PATTERNS:
        if pat.search(target):
            return "cmdi", "cmdi"
    for pat in PATH_TRAVERSAL_PATTERNS:
        if pat.search(target):
            return "path_traversal", "path_traversal"
    for pat in SSRF_PATTERNS:
        if pat.search(target):
            return "ssrf", "ssrf"
    for pat in TEMPLATE_INJECTION_PATTERNS:
        if pat.search(target):
            return "template_injection", "template_injection"
    for pat in NOSQL_PATTERNS:
        if pat.search(target):
            return "nosql_injection", "nosql_injection"
    for pat in OPEN_REDIRECT_PATTERNS:
        if pat.search(target):
            return "open_redirect", "open_redirect"
    return None, "none"

def check_rate_limit(ip):
    now = time.time()
    with _lock:
        entries = _state["rate_counters"].get(ip, [])
        entries = [ts for ts in entries if now - ts < RATE_LIMIT_WINDOW]
        entries.append(now)
        _state["rate_counters"][ip] = entries
        return len(entries) > RATE_LIMIT_MAX

def get_risk_score(ip):
    with _lock:
        return _state["risk_scores"].get(ip, 0)

def add_risk(ip, delta):
    with _lock:
        current = _state["risk_scores"].get(ip, 0)
        _state["risk_scores"][ip] = min(100, current + delta)

def reset_state():
    with _lock:
        _state["cache"] = {}
        _state["rate_counters"] = {}
        _state["risk_scores"] = {}

def get_cache(path):
    with _lock:
        entry = _state["cache"].get(path)
        if entry and time.time() - entry["ts"] < 60:
            return entry
        return None

def set_cache(path, action):
    with _lock:
        _state["cache"][path] = {"action": action, "ts": time.time()}

def flush_cache():
    with _lock:
        _state["cache"] = {}

# ---------------------------------------------------------------------------
# Data plane handler
# ---------------------------------------------------------------------------

class DataHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def handle_request(self):
        t_start = time.time()
        method = self.command
        path   = self.path
        rid    = str(uuid.uuid4())
        ip     = self.client_address[0]

        threat, rule_id = detect_threat(path, self.headers)

        rate_limited = check_rate_limit(ip)

        if threat:
            add_risk(ip, 25)
        risk_score = get_risk_score(ip)

        intended_action = "allow"
        effective_rule_id = rule_id

        if rate_limited:
            intended_action = "rate_limit"
            effective_rule_id = "ip-rate-limit"
        elif threat:
            if risk_score >= RISK_BLOCK_AT:
                intended_action = "block"
            elif risk_score >= RISK_CHALLENGE_AT:
                intended_action = "challenge"
            else:
                intended_action = "block"

        mode = get_mode_for_rule(effective_rule_id if intended_action != "allow" else None)

        cache_header = "BYPASS"
        if not is_sensitive(path) and intended_action == "allow":
            cached = get_cache(path)
            if cached:
                cache_header = "HIT"
            else:
                cache_header = "MISS"
                if method == "GET":
                    set_cache(path, "allow")
        else:
            cache_header = "BYPASS"

        if mode == "enforce":
            final_action = intended_action
        else:
            final_action = "allow"

        elapsed_ms = (time.time() - t_start) * 1000

        obs_headers = {
            "X-WAF-Request-Id":      rid,
            "X-WAF-Risk-Score":      str(risk_score),
            "X-WAF-Action":          intended_action,
            "X-WAF-Rule-Id":         effective_rule_id,
            "X-WAF-Cache":           cache_header,
            "X-WAF-Mode":            mode,
            "X-WAF-Overhead-Latency": f"{elapsed_ms:.3f}",
        }

        write_audit({
            "request_id": rid,
            "ts_ms":      now_ms(),
            "ip":         ip,
            "method":     method.upper(),
            "path":       path,
            "action":     intended_action,
            "risk_score": risk_score,
            "mode":       mode,
        })

        if mode == "enforce" and final_action != "allow":
            self._send_denial(final_action, obs_headers)
        else:
            self._proxy_upstream(method, path, obs_headers)

    def _send_denial(self, action, obs_headers):
        if action == "block":
            status = 403
            body = json.dumps({"error": "blocked", "action": "block"}).encode()
        elif action == "challenge":
            status = 429
            body = json.dumps({
                "challenge": True,
                "challenge_type": "proof_of_work",
                "challenge_token": str(uuid.uuid4()),
                "difficulty": 4,
                "submit_url": "/challenge/verify",
                "submit_method": "POST"
            }).encode()
        elif action == "rate_limit":
            status = 429
            body = json.dumps({"error": "rate limited", "action": "rate_limit"}).encode()
        else:
            status = 403
            body = json.dumps({"error": action}).encode()

        self.send_response(status)
        for k, v in obs_headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy_upstream(self, method, path, obs_headers):
        try:
            conn = http.client.HTTPConnection(*UPSTREAM, timeout=3)
            clen = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(clen) if clen > 0 else None
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            resp_body = resp.read()
            conn.close()
            status = resp.status
        except Exception:
            status = 502
            resp_body = b'{"error":"upstream unavailable"}'

        self.send_response(status)
        for k, v in obs_headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):    self.handle_request()
    def do_POST(self):   self.handle_request()
    def do_PUT(self):    self.handle_request()
    def do_DELETE(self): self.handle_request()
    def do_HEAD(self):   self.handle_request()
    def do_OPTIONS(self): self.handle_request()


# ---------------------------------------------------------------------------
# Admin plane handler
# ---------------------------------------------------------------------------

class AdminHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _auth(self):
        secret = self.headers.get("X-Benchmark-Secret", "")
        if secret != BENCH_SECRET:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"error": "forbidden", "ok": False}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        return True

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        clen = int(self.headers.get("Content-Length", 0))
        if clen > 0:
            raw = self.rfile.read(clen)
            try:
                return json.loads(raw)
            except Exception:
                return None
        return {}

    def _handle_healthz(self):
        body = ('{"status":"ok","ts_ms":' + str(now_ms()) + '}').encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_capabilities(self):
        if not self._auth(): return
        with _lock:
            dm = _state["default_mode"]
            ov = dict(_state["overrides"])
        self._json(200, {
            "ok": True,
            "features": FEATURES,
            "active": {
                "default_mode": dm,
                "overrides": ov,
            }
        })

    def _handle_reset_state(self):
        if not self._auth(): return
        reset_state()
        self._json(200, {
            "ok": True,
            "action": "reset_state",
            "audit_log_preserved": True,
            "ts_ms": now_ms(),
        })

    def _handle_set_profile(self):
        if not self._auth(): return
        body = self._read_body()
        if body is None:
            self._json(400, {"ok": False, "error": "invalid JSON"})
            return

        extra_fields = set(body.keys()) - SET_PROFILE_ALLOWED_FIELDS
        if extra_fields:
            self._json(400, {"ok": False,
                             "error": f"unknown fields: {', '.join(sorted(extra_fields))}"})
            return

        scope = body.get("scope")
        mode  = body.get("mode")
        if scope not in ("all", "features", "policies") or mode not in ("enforce", "log_only"):
            self._json(400, {"ok": False, "error": "missing or invalid scope/mode",
                             "unsupported": []})
            return

        unsupported = []
        applied = {"scope": scope, "mode": mode}

        with _lock:
            if scope == "all":
                if any(k in body for k in ("features", "feature", "policies")):
                    pass  # handled below after lock release

                _state["default_mode"] = mode
                _state["overrides"] = {}

            elif scope == "features":
                feats = body.get("features")
                if feats is None:
                    pass  # handled after lock
                elif len(feats) == 0:
                    pass  # empty list → 400, handled after lock
                else:
                    applied["features"] = feats
                    for feat in feats:
                        if feat in FEATURES:
                            _state["overrides"][feat] = mode
                        else:
                            unsupported.append(feat)

            elif scope == "policies":
                feat    = body.get("feature", "")
                polices = body.get("policies", [])
                applied["feature"]  = feat
                applied["policies"] = polices

                if feat not in FEATURES:
                    pass  # Unknown feature → 422, handled after lock
                else:
                    if not polices:
                        pass  # empty policies → 400, handled after lock
                    else:
                        valid_policies = FEATURES[feat]["policies"]
                        for pol in polices:
                            if pol in valid_policies:
                                _state["overrides"][f"{feat}.{pol}"] = mode
                            else:
                                unsupported.append(pol)

            dm = _state["default_mode"]
            ov = dict(_state["overrides"])

        # ---- post-lock error returns ----
        if scope == "all" and any(k in body for k in ("features", "feature", "policies")):
            self._json(400, {"ok": False,
                             "error": "scope=all must not include features/feature/policies"})
            return
        if scope == "features":
            feats = body.get("features")
            if feats is None:
                self._json(400, {"ok": False, "error": "scope=features requires `features: [...]`"})
                return
            if len(feats) == 0:
                self._json(400, {"ok": False, "error": "features list must not be empty"})
                return
        if scope == "policies":
            feat = body.get("feature", "")
            if feat not in FEATURES:
                self._json(422, {"ok": False,
                                 "error": f"unsupported feature: {feat}",
                                 "unsupported": [feat]})
                return
            polices = body.get("policies", [])
            if not polices:
                self._json(400, {"ok": False, "error": "policies list must not be empty"})
                return

        self._json(200, {
            "ok": True,
            "action": "set_profile",
            "applied": applied,
            "active": {
                "default_mode": dm,
                "overrides": ov,
            },
            "unsupported": unsupported,
            "ts_ms": now_ms(),
        })

    def _handle_flush_cache(self):
        if not self._auth(): return
        flush_cache()
        self._json(200, {
            "ok": True,
            "action": "flush_cache",
            "supported": True,
            "ts_ms": now_ms(),
        })

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/healthz/ready", "/healthz"):
            self._handle_healthz()
        elif p == "/__waf_control/capabilities":
            self._handle_capabilities()
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/__waf_control/reset_state":
            self._handle_reset_state()
        elif p == "/__waf_control/set_profile":
            self._handle_set_profile()
        elif p == "/__waf_control/flush_cache":
            self._handle_flush_cache()
        else:
            if not self._auth(): return
            self._json(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    pass

def run():
    print(f"[mock-waf] data plane  → {DATA_BIND[0]}:{DATA_BIND[1]}", flush=True)
    print(f"[mock-waf] admin plane → {ADMIN_BIND[0]}:{ADMIN_BIND[1]}", flush=True)
    print(f"[mock-waf] audit log   → {AUDIT_LOG}", flush=True)
    print(f"[mock-waf] upstream    → {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)

    data_srv  = ThreadedHTTPServer(DATA_BIND,  DataHandler)
    admin_srv = ThreadedHTTPServer(ADMIN_BIND, AdminHandler)

    t_data  = threading.Thread(target=data_srv.serve_forever,  daemon=True)
    t_admin = threading.Thread(target=admin_srv.serve_forever, daemon=True)
    t_data.start()
    t_admin.start()

    print("[mock-waf] ready", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[mock-waf] stopping", flush=True)
        data_srv.shutdown()
        admin_srv.shutdown()

if __name__ == "__main__":
    run()
