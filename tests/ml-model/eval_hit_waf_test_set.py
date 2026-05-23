#!/usr/bin/env python3
"""
eval_hit_waf_test_set.py
========================
Đánh giá WAF trên regex_dataset bằng cách:

  (A) LOCAL  — chạy Python port chính xác từng Rust detector (10 class)
               trên mỗi record để biết regex rule có "nên" bắt được không.
  (B) LIVE   — gửi HTTP request thực lên WAF endpoint và xem response code.

Từ đó đo:
  • Evasion attacks (label=attack, expected_waf_outcome=miss):
      local_hit  = rule bắt được (evasion THẤT BẠI)
      local_miss = rule không bắt (evasion thành công về mặt regex)
      waf_hit    = WAF trả 4xx (WAF bắt được dù qua rule)
      waf_miss   = WAF cho qua   (bypass hoàn toàn)

  • FP candidates (label=normal, expected_waf_outcome=allow):
      local_fp   = rule báo động nhầm (FP trong regex)
      waf_fp     = WAF block nhầm

SOURCE MAP — Rust → Python port
  crates/aegis-security/src/detectors/sqli.rs              → SqliDetector
  crates/aegis-security/src/detectors/xss.rs               → XssDetector
  crates/aegis-security/src/detectors/path_traversal.rs    → PathTraversalDetector
  crates/aegis-security/src/detectors/command_injection.rs → CommandInjectionDetector
  crates/aegis-security/src/detectors/ssrf.rs              → SsrfDetector
  crates/aegis-security/src/detectors/recon.rs             → ReconDetector
  crates/aegis-security/src/detectors/header_injection.rs  → HeaderInjectionDetector
  crates/aegis-security/src/detectors/nosql_injection.rs   → NoSqlDetector
  crates/aegis-security/src/detectors/template_injection.rs→ TemplateInjectionDetector
  crates/aegis-security/src/detectors/open_redirect.rs     → OpenRedirectDetector
  crates/aegis-security/src/detectors/scores.rs            → SCORES, thresholds

⚠ Dataset class-name discrepancy:
  dataset field "detector_class" = "nosql"
  Rust detector id()             = "nosql_injection"
  → script maps "nosql" → "nosql_injection" automatically.

Usage:
  python3 eval_hit_waf_test_set.py                          # local + live WAF
  python3 eval_hit_waf_test_set.py --local-only             # no network
  python3 eval_hit_waf_test_set.py --waf-only               # skip local
  python3 eval_hit_waf_test_set.py --sample 200 --workers 32
  python3 eval_hit_waf_test_set.py --host waf.hk-aegis-gate.com --port 443
"""

from __future__ import annotations

import argparse
import html
import http.client
import json
import math
import re
import socket
import ssl
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# Paths & defaults
# ═══════════════════════════════════════════════════════════════════════════════

DATASET_DIR  = Path(__file__).parent.parent / "security" / "regex_dataset"
EVASION_FILE = DATASET_DIR / "evasion_attacks.ndjson"
FP_FILE      = DATASET_DIR / "fp_candidates.ndjson"
DEFAULT_OUT  = Path(__file__).parent / datetime.now().strftime("%Y-%m-%d")

DEFAULT_HOST    = "waf.hk-aegis-gate.com"
DEFAULT_PORT    = 443
DEFAULT_WORKERS = 64
DEFAULT_TIMEOUT = 8.0   # seconds

# HTTP status codes that indicate the WAF blocked the request
BLOCK_CODES = {400, 403, 406, 429, 503}

# scores.rs — single source of truth
SCORES = {
    "sqli":               70,
    "xss":                70,
    "path_traversal":     70,
    "ssrf":               70,
    "command_injection":  70,   # baseline; log4shell = 90
    "log4shell":          90,
    "template_injection": 70,
    "nosql_injection":    70,
    "header_injection":   70,   # CRLF; XFH = 50
    "header_xfh":         50,
    "open_redirect":      50,
    "recon_path":         25,
    "recon_tool":         50,
}
CHALLENGE_AT = 40
BLOCK_AT     = 80

# Dataset "nosql" → Rust detector id "nosql_injection"
DATASET_CLASS_MAP = {"nosql": "nosql_injection"}

# ═══════════════════════════════════════════════════════════════════════════════
# Decoder pipeline  (port of crates/aegis-security/src/detectors/mod.rs)
# ═══════════════════════════════════════════════════════════════════════════════

_PCT = re.compile(r"%([0-9a-fA-F]{2})")

def _url_decode_once(s: str) -> str:
    """Single-pass percent-decoding (handles `+` as space in query context)."""
    def _sub(m: re.Match) -> str:
        return chr(int(m.group(1), 16))
    return _PCT.sub(_sub, s.replace("+", " "))


def url_decode(s: str) -> str:
    return _url_decode_once(s)


# Named HTML entities relevant to attack evasion (from Rust html_entity_decode)
_HTML_ENTITIES: dict[str, str] = {
    "&lt;":      "<",
    "&gt;":      ">",
    "&amp;":     "&",
    "&apos;":    "'",
    "&quot;":    '"',
    "&period;":  ".",
    "&dot;":     ".",
    "&sol;":     "/",
    "&dollar;":  "$",
    "&semi;":    ";",
    "&colon;":   ":",
    "&lpar;":    "(",
    "&rpar;":    ")",
    "&num;":     "#",
    "&excl;":    "!",
    "&ast;":     "*",
    "&commat;":  "@",
    "&plus;":    "+",
    "&equals;":  "=",
}

_NAMED_ENTITY_RE  = re.compile(r"&[a-zA-Z]+;")
_NUM_DEC_ENTITY   = re.compile(r"&#(\d+);")
_NUM_HEX_ENTITY   = re.compile(r"&#[xX]([0-9a-fA-F]+);")
_UNICODE_ESC_RE   = re.compile(r"\\u([0-9a-fA-F]{4})")
_HEX_ESC_RE       = re.compile(r"\\x([0-9a-fA-F]{2})")


def html_entity_decode(s: str) -> str:
    """Decode numeric + common named HTML entities."""
    # Numeric hex: &#x3c; → <
    s = _NUM_HEX_ENTITY.sub(lambda m: chr(int(m.group(1), 16)), s)
    # Numeric decimal: &#60; → <
    s = _NUM_DEC_ENTITY.sub(lambda m: chr(int(m.group(1))), s)
    # Named entities from our table
    s = _NAMED_ENTITY_RE.sub(lambda m: _HTML_ENTITIES.get(m.group(0), m.group(0)), s)
    return s


def unicode_escape_decode(s: str) -> str:
    return _UNICODE_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)


def hex_escape_decode(s: str) -> str:
    return _HEX_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)


def normalize_for_detection(s: str) -> list[str]:
    """
    Port of `normalize_for_detection()` from mod.rs (S1 2026-05-18).
    Returns multiple decode variants; callers break on first match.
    """
    variants: list[str] = [s]

    d1 = _url_decode_once(s)
    if d1 != s:
        variants.append(d1)

    d2 = _url_decode_once(d1)
    if d2 != d1:
        variants.append(d2)

    # HTML entity decode of the url-decoded form
    ed = html_entity_decode(d1)
    if ed != d1:
        variants.append(ed)

    # Unicode escape on raw
    ued = unicode_escape_decode(s)
    if ued != s:
        variants.append(ued)

    # Hex escape on raw
    hed = hex_escape_decode(s)
    if hed != s:
        variants.append(hed)

    return variants


# ═══════════════════════════════════════════════════════════════════════════════
# Detector ports — exact regex patterns from Rust source
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1. SQLi (sqli.rs) ─────────────────────────────────────────────────────────
# Scan: URI variants, body variants, headers [cookie, referer, x-forwarded-for, user-agent]

_SQLI = [re.compile(p) for p in [
    r"(?i)(?:UNION\s+(?:ALL\s+)?SELECT)",
    r"(?i)(?:SELECT\s+.+\s+FROM\s+)",
    r"(?i)(?:INSERT\s+INTO\s+)",
    r"(?i)(?:UPDATE\s+.+\s+SET\s+)",
    r"(?i)(?:DELETE\s+FROM\s+)",
    r"(?i)(?:DROP\s+TABLE\s+)",
    r"(?i)(?:ALTER\s+TABLE\s+)",
    r"(?i)(?:OR\s+1\s*=\s*1)",
    r"(?i)(?:AND\s+1\s*=\s*1)",
    r"(?i)(?:'\s*OR\s+'[^']*'\s*=\s*')",
    r"(?i)(?:'\s*;\s*(?:DROP|DELETE|UPDATE|INSERT))",
    r"(?i)(?:--\s*$)",
    r"(?i)(?:/\*.*\*/)",
    r"(?i)(?:WAITFOR\s+DELAY)",
    r"(?i)(?:BENCHMARK\s*\()",
    r"(?i)(?:SLEEP\s*\()",
    r"(?i)(?:LOAD_FILE\s*\()",
    r"(?i)(?:INTO\s+(?:OUT|DUMP)FILE)",
    r"(?i)(?:EXEC(?:UTE)?\s+)",
    r"(?i)(?:xp_cmdshell)",
    r"(?i)(?:information_schema)",
    r"(?i)(?:sys\.(?:objects|columns|tables))",
    r"(?i)(?:0x[0-9a-f]{8,})",
    r"(?i)(?:CHAR\s*\(\s*\d+\s*\))",
    r"(?i)(?:CONCAT\s*\()",
    r"(?i)(?:GROUP\s+BY\s+.+\s+HAVING)",
    r"(?i)(?:ORDER\s+BY\s+\d+)",
    r"(?i)(?:CASE\s+WHEN\s+)",
    r"(?i)(?:EXTRACTVALUE\s*\()",
    r"(?i)(?:UPDATEXML\s*\()",
]]
_SQLI_HEADERS = {"cookie", "referer", "x-forwarded-for", "user-agent"}

def _sqli_match(text: str) -> bool:
    return any(p.search(text) for p in _SQLI)

def detect_sqli(rec: dict) -> tuple[bool, str]:
    """Returns (matched, field)."""
    uri = _build_uri(rec)
    for v in normalize_for_detection(uri):
        if _sqli_match(v):
            return True, "uri"
    body = rec.get("body", "") or ""
    if body:
        for v in normalize_for_detection(body):
            if _sqli_match(v):
                return True, "body"
    for h, val in (rec.get("headers") or {}).items():
        if h.lower() in _SQLI_HEADERS and _sqli_match(val):
            return True, h
    return False, ""


# ── 2. XSS (xss.rs) ──────────────────────────────────────────────────────────
# Scan: URI (url_decode + entity_decode), body, headers [cookie, referer, user-agent]

_XSS = [re.compile(p) for p in [
    r"(?i)<script[\s>]",
    r"(?i)</script>",
    r"(?i)javascript\s*:",
    r"(?i)vbscript\s*:",
    r"(?i)on(?:load|error|click|mouse|focus|blur|submit|change|key|drag|touch|animat|transitionend)\s*=",
    r"(?i)<iframe[\s>]",
    r"(?i)<object[\s>]",
    r"(?i)<embed[\s>]",
    r"(?i)<applet[\s>]",
    r"(?i)<form[\s>]",
    r"(?i)<svg[\s>].*?(?:onload|onerror)",
    r"(?i)<img\s+[^>]*(?:onerror|onload)\s*=",
    r"(?i)expression\s*\(",
    r'(?i)url\s*\(\s*[\'"]?\s*javascript:',
    r"(?i)data\s*:\s*text/html",
    r"(?i)&#x?[0-9a-f]+;",
    r"(?i)alert\s*\(",
    r"(?i)prompt\s*\(",
    r"(?i)confirm\s*\(",
    r"(?i)document\.(?:cookie|write|location|domain)",
    r"(?i)window\.(?:location|open|eval)",
    r"(?i)eval\s*\(",
    r"(?i)setTimeout\s*\(",
    r"(?i)setInterval\s*\(",
    r"(?i)Function\s*\(",
    r"(?i)\.innerHTML\s*=",
    r"(?i)\.outerHTML\s*=",
    r"(?i)fromCharCode\s*\(",
    r"(?i)\\u00[0-9a-f]{2}",
    r'(?i)<meta\s+[^>]*http-equiv\s*=\s*[\'"]?refresh',
]]
_XSS_HEADERS = {"cookie", "referer", "user-agent"}

def _xss_match(text: str) -> bool:
    return any(p.search(text) for p in _XSS)

def detect_xss(rec: dict) -> tuple[bool, str]:
    uri = _build_uri(rec)
    ud  = url_decode(uri)
    ed  = html_entity_decode(ud)
    for v in [ud, ed]:
        if _xss_match(v):
            return True, "uri"
    body = rec.get("body", "") or ""
    if body:
        udb = url_decode(body)
        edb = html_entity_decode(udb)
        for v in [udb, edb]:
            if _xss_match(v):
                return True, "body"
    for h, val in (rec.get("headers") or {}).items():
        if h.lower() in _XSS_HEADERS:
            ev = html_entity_decode(val)
            if _xss_match(val) or _xss_match(ev):
                return True, h
    return False, ""


# ── 3. Path Traversal (path_traversal.rs) ────────────────────────────────────
# Scan: URI variants, body variants

_TRAV = [re.compile(p) for p in [
    r"(?:\.\.[\\/])",
    r"(?:%2e%2e[\\/])",
    r"(?:%2e%2e%2f)",
    r"(?:%252e%252e%252f)",
    r"(?:\.\.%2f)",
    r"(?:%2e%2e/)",
    r"(?:\.%2e/)",
    r"(?:%2e\./)",
    r"(?:/etc/(?:passwd|shadow|hosts|resolv\.conf))",
    r"(?:/proc/self/(?:environ|cmdline|fd))",
    r"(?:(?:c|d):[\\/])",
    r"(?:boot\.ini)",
    r"(?:win\.ini)",
    r"(?:\\\\[^\\]+\\)",
    r"(?:%00|\x00)",
    r"(?:%5c)",
    r"(?i)(?:%c0%ae){2,}",
    r"(?i)%c0%af",
    r"(?i)%c0%5c|%c1%9c",
    r"(?i)/var/run/docker\.sock\b",
]]

def _trav_match(text: str) -> bool:
    return any(p.search(text) for p in _TRAV)

def detect_path_traversal(rec: dict) -> tuple[bool, str]:
    uri = _build_uri(rec)
    for v in normalize_for_detection(uri):
        if _trav_match(v):
            return True, "uri"
    body = rec.get("body", "") or ""
    if body:
        for v in normalize_for_detection(body):
            if _trav_match(v):
                return True, "body"
    return False, ""


# ── 4. Command Injection (command_injection.rs) ───────────────────────────────
# Scan: URI variants, body variants, headers (allowlist below)

_LOG4SHELL = [re.compile(p) for p in [
    r"(?i)\$\{jndi\s*:\s*(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http|https)\s*:",
    r"(?i)\$\{jndi\s*:",
    r"(?i)\$\{[^}]*\$\{[^}]*j[^}]*\}[^}]*\$\{[^}]*n[^}]*\}[^}]*\$\{[^}]*d[^}]*\}[^}]*\$\{[^}]*i[^}]*\}[^}]*:",
    r"(?i)\$\{[^}]*\$\{(?:lower|upper|env|sys|date)\s*:[^}]*\}[^}]*\}",
]]
_CMDI = [re.compile(p) for p in [
    r"(?i)\$\([^)]+\)",
    r"(?i)`[^`]+`",
    r"(?i)\$\{[A-Za-z_][^}]+\}",
    r"(?i)\|\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe|sleep\b|timeout\b)\b",
    r"(?i);\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe|sleep\b|timeout\b)\b",
    r"(?i)(?:&&|\|\|)\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|sleep\b|timeout\b)\b",
    r"(?i)/bin/(?:sh|bash|zsh|ksh|dash)\b",
    r"(?i)cat\s+/etc/passwd",
    r"(?i)bash\s+-i\b",
    r"(?i)nc\s+-e\b",
    r"(?i)mkfifo\s+",
    r"(?i)(?:^|;|\|\|?|&&|`|\$\()\s*(?:wget|curl)\s+[a-z]+://",
]]
_CMDI_HEADERS = {
    "user-agent", "referer", "x-api-version", "x-forwarded-for",
    "x-real-ip", "authorization", "cookie", "x-requested-with",
}

def _cmdi_check(text: str) -> tuple[bool, int]:
    """Returns (matched, score). Log4shell score 90, baseline 70."""
    for p in _LOG4SHELL:
        if p.search(text):
            return True, 90
    for p in _CMDI:
        if p.search(text):
            return True, 70
    return False, 0

def detect_command_injection(rec: dict) -> tuple[bool, str]:
    uri = _build_uri(rec)
    for v in normalize_for_detection(uri):
        ok, _ = _cmdi_check(v)
        if ok:
            return True, "uri"
    body = rec.get("body", "") or ""
    if body:
        for v in normalize_for_detection(body):
            ok, _ = _cmdi_check(v)
            if ok:
                return True, "body"
    for h, val in (rec.get("headers") or {}).items():
        if h.lower() in _CMDI_HEADERS:
            ok, _ = _cmdi_check(val)
            if not ok:
                ok, _ = _cmdi_check(url_decode(val))
            if ok:
                return True, h
    return False, ""


# ── 5. SSRF (ssrf.rs) ────────────────────────────────────────────────────────
# Scan: query (url_decoded), path (url_decoded), body (url_decoded),
#       headers [x-original-url, x-rewrite-url]  — NOT full URI (self-trip risk)

_SSRF = [re.compile(p) for p in [
    r"(?i)(?:https?://(?:127\.0\.0\.1|localhost))",
    r"(?i)(?:https?://0\.0\.0\.0)",
    r"(?i)(?:https?://\[::1?\])",
    r"(?i)(?:https?://169\.254\.169\.254)",
    r"(?i)(?:https?://metadata\.google\.internal)",
    r"(?i)(?:https?://100\.100\.100\.200)",
    r"(?i)(?:https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    r"(?i)(?:https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
    r"(?i)(?:https?://192\.168\.\d{1,3}\.\d{1,3})",
    r"(?i)(?:file://)",
    r"(?i)(?:gopher://)",
    r"(?i)(?:dict://)",
    r"(?i)(?:ftp://(?:127|10|192\.168|172\.(?:1[6-9]|2\d|3[01])))",
    r"(?i)(?:https?://0x[0-9a-f]+)",
    r"(?i)(?:https?://\d{8,10})",
    r"(?i)(?:https?://0[0-7]+\.)",
    r"(?i)https?://[^@/\s]+@",
    r"(?i)(?:https?://\[::ffff:(?:127|10|0|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)",
    r"(?i)(?:https?://\[::ffff:(?:7f00|0a[0-9a-f]{2}|a9fe|c0a8|ac1[0-9a-f]):)",
]]
_SSRF_HEADERS = {"x-original-url", "x-rewrite-url"}

def _ssrf_match(text: str) -> bool:
    return any(p.search(text) for p in _SSRF)

def detect_ssrf(rec: dict) -> tuple[bool, str]:
    query = rec.get("query", "") or ""
    if query and _ssrf_match(url_decode(query)):
        return True, "query"
    path = rec.get("path", "") or ""
    if path and _ssrf_match(url_decode(path)):
        return True, "path"
    body = rec.get("body", "") or ""
    if body and _ssrf_match(url_decode(body)):
        return True, "body"
    for h, val in (rec.get("headers") or {}).items():
        if h.lower() in _SSRF_HEADERS and _ssrf_match(val):
            return True, h
    return False, ""


# ── 6. Recon (recon.rs) ──────────────────────────────────────────────────────
# Scan: path_and_query (RECON_PATHS, score 25), user-agent (RECON_UA, score 50)

_RECON_PATHS = [re.compile(p) for p in [
    r"(?i)(?:\.env(?:\.|$))",
    r"(?i)(?:\.git(?:/|$))",
    r"(?i)(?:\.svn(?:/|$))",
    r"(?i)(?:\.hg(?:/|$))",
    r"(?i)(?:\.DS_Store)",
    r"(?i)(?:\.htaccess)",
    r"(?i)(?:\.htpasswd)",
    r"(?i)(?:wp-config\.php)",
    r"(?i)(?:web\.config)",
    r"(?i)(?:phpinfo\(\))",
    r"(?i)(?:wp-admin)",
    r"(?i)(?:wp-login)",
    r"(?i)(?:administrator)",
    r"(?i)(?:phpmyadmin)",
    r"(?i)(?:adminer)",
    r"(?i)(?:/debug/)",
    r"(?i)(?:/console)",
    r"(?i)(?:elmah\.axd)",
    r"(?i)(?:trace\.axd)",
    r"(?i)(?:server-status)",
    r"(?i)(?:server-info)",
    r"(?i)(?:backup\.(?:sql|zip|tar|gz|bak))",
    r"(?i)(?:database\.(?:sql|dump))",
    r"(?i)(?:\.(?:bak|old|orig|save|swp|tmp)$)",
    r"(?i)(?:~$)",
    r"(?i)(?:Dockerfile)",
    r"(?i)(?:docker-compose\.ya?ml)",
    r"(?i)(?:^|/)v\d+\.\d+/(?:containers|images|networks|volumes|services|tasks|secrets|configs|swarm|nodes|plugins|info|version|events|system|build|auth)\b",
    r"(?i)(?:^|/)_ping\b",
    r"(?i)(?:Makefile$)",
    r"(?i)(?:\.aws/credentials)",
    r"(?i)(?:\.ssh/)",
    r"(?i)/actuator/(?:heapdump|threaddump|env|configprops|loggers|trace|httptrace|auditevents|dump|jolokia|liquibase|flyway|gateway|conditions|beans|mappings|metrics/.*|sessions|shutdown)\b",
    r"(?i)/_ignition/(?:execute-solution|health-check|update-config)\b",
    r"(?i)/(?:swagger-ui\.html|swagger\.json|swagger\.yaml|v\d+/api-docs|api-docs|openapi\.json|openapi\.yaml)\b",
    r"(?i)(?:__schema\b|\bIntrospectionQuery\b|__type\s*\()",
    r"(?i)/graphiql(?:/|\?|$)",
    r"(?i)/playground(?:/|\?|$)",
    r"(?i)/api/v1/namespaces\b",
    r"(?i)/api/v1/pods\b",
    r"(?i)/apis/apps/v1/deployments\b",
    r"(?i)/(?:app/kibana|kibana/(?:app|api)|\.kibana(?:/|/_search)|_cat/indices|_cluster/health)\b",
    r"(?i)/(?:script(?:Text)?|jnlpJars/jenkins-cli\.jar|manage|computer/(?:\(master\)|\(built-in\))/script)\b",
    r"(?i)/cgi-bin/(?:printenv\.pl|test-cgi|php-cgi|\.\.)\b",
    r"(?i)/metrics\?(?:format=|target=|module=)",
    r"(?i)/actuator(?:$|\?|#)",
    r"(?i)/rails/info(?:/|$)",
    r"(?i)/(?:phpinfo|info|test|i)\.php(?:$|\?|/)",
]]
_RECON_UA = [re.compile(p) for p in [
    r"(?i)(?:sqlmap)",   r"(?i)(?:nikto)",   r"(?i)(?:nmap)",
    r"(?i)(?:masscan)",  r"(?i)(?:dirbuster)",r"(?i)(?:gobuster)",
    r"(?i)(?:feroxbuster)", r"(?i)(?:wfuzz)", r"(?i)(?:ffuf)",
    r"(?i)(?:nuclei)",   r"(?i)(?:burp)",    r"(?i)(?:zap)",
    r"(?i)(?:acunetix)", r"(?i)(?:nessus)",  r"(?i)(?:openvas)",
    r"(?i)(?:w3af)",     r"(?i)(?:whatweb)", r"(?i)(?:wpscan)",
    r"(?i)(?:joomscan)", r"(?i)(?:arachni)",
]]

def detect_recon(rec: dict) -> tuple[bool, str]:
    path_q = str(rec.get("path", "") or "")
    query  = str(rec.get("query", "") or "")
    pq     = (path_q + ("?" + query if query else ""))
    for p in _RECON_PATHS:
        if p.search(pq):
            return True, "uri"
    ua = (rec.get("headers") or {}).get("user-agent", "") or \
         (rec.get("headers") or {}).get("User-Agent", "") or ""
    for p in _RECON_UA:
        if p.search(ua):
            return True, "user-agent"
    return False, ""


# ── 7. Header Injection (header_injection.rs) ─────────────────────────────────
# Scan: query (raw + decoded), all headers CRLF, XFH, URL-override, method-override

_HINJ_ALL = [re.compile(p) for p in [
    r"(?:\r\n|\r|\n)",
    r"(?:%0d%0a)",
    r"(?:%0d)",
    r"(?:%0a)",
    r"(?:%0D%0A)",
    r"(?:\\r\\n)",
    r"(?i)(?:Set-Cookie\s*:)",
    r"(?i)(?:Location\s*:\s*https?://)",
    r"(?i)(?:Content-Type\s*:)",
    r"(?i)(?:Transfer-Encoding\s*:)",
    r"(?i)(?:X-Forwarded-For\s*:)",
    r"(?i)(?:HTTP/\d\.\d\s+\d{3})",
]]
_HINJ_CRLF = _HINJ_ALL[:6]  # only first 6 for header values

_URL_OVERRIDE_HEADERS = {
    "x-original-url", "x-rewrite-url",
    "x-override-url",  "x-http-method-override-url",
}
_URL_OVERRIDE_DANGER = [re.compile(p) for p in [
    r"(?i)^/*(?:admin|administrator|wp-admin|manage|console|internal|_admin|__internal)\b",
    r"(?i)/?(?:\.env(?:$|/|\.)|wp-config\.php|\.git/config|\.aws/credentials|\.ssh/)",
    r"(?i)\.\.[/\\]|%2e%2e[/\\]|%252e%252e",
]]
_METHOD_OVERRIDE_HEADERS = {
    "x-http-method-override", "x-method-override", "x-http-method",
}
_DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH", "CONNECT", "TRACE"}

def _xfh_suspicious(xfh: str, host: str) -> bool:
    if not xfh:
        return False
    if any(b < 0x20 or b in (ord('\r'), ord('\n')) for b in xfh.encode("latin-1", errors="replace")):
        return True
    if xfh.count(',') >= 2:
        return True
    # Internal IP in first host
    first = xfh.split(',')[0].strip().split(':')[0]
    parts = first.split('.')
    if len(parts) == 4:
        try:
            octets = [int(p) for p in parts]
            if (octets[0] == 127 or octets[0] == 10
                    or (octets[0] == 169 and octets[1] == 254)
                    or (octets[0] == 192 and octets[1] == 168)
                    or (octets[0] == 172 and 16 <= octets[1] <= 31)):
                return True
        except ValueError:
            pass
    lc = first.lower()
    if lc in ("::1", "[::1]") or lc.startswith("fe80:"):
        return True
    # Structural needles (JS/data/vbscript/file: or HTML metachars)
    if host and not xfh.lower() == host.lower():
        xfh_lc = xfh.lower()
        for needle in ["javascript:", "data:", "vbscript:", "file:", "<", ">", '"', "'"]:
            if needle in xfh_lc:
                return True
    return False

def detect_header_injection(rec: dict) -> tuple[bool, str]:
    query = rec.get("query", "") or ""
    if query:
        for v in [query, url_decode(query)]:
            if any(p.search(v) for p in _HINJ_ALL):
                return True, "query"
    headers = rec.get("headers") or {}
    skip    = {"host", "content-length", "content-type"}
    host    = headers.get("host", "") or headers.get("Host", "") or ""

    for h, val in headers.items():
        hl = h.lower()
        if hl in skip:
            continue
        if any(p.search(val) for p in _HINJ_CRLF):
            return True, h
        if hl == "x-forwarded-host" and _xfh_suspicious(val, host):
            return True, "x-forwarded-host"
        if hl in _URL_OVERRIDE_HEADERS:
            decoded = url_decode(val)
            for p in _URL_OVERRIDE_DANGER:
                if p.search(val) or p.search(decoded):
                    return True, h
        if hl in _METHOD_OVERRIDE_HEADERS:
            if val.strip().upper() in _DESTRUCTIVE_METHODS:
                return True, h
    return False, ""


# ── 8. NoSQL Injection (nosql_injection.rs) ───────────────────────────────────
# Scan: URI raw + url_decode, body raw + url_decode
# Dataset class: "nosql" → detector id "nosql_injection"

_NOSQL = [re.compile(p) for p in [
    r"(?i)\[\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|or|and|not|nor|exists|type|elemMatch|all|size|expr|jsonSchema|mod|geoIntersects|geoWithin|near|nearSphere|text|search|comment)\]",
    r'(?i)"\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|or|and|not|nor|exists|type|elemMatch|all|size|expr|jsonSchema|mod|geoIntersects|geoWithin|near|nearSphere|text|search|comment)"\s*:',
    r"(?i)\$where\s*:\s*function\s*\(",
]]

def _nosql_match(text: str) -> bool:
    return any(p.search(text) for p in _NOSQL)

def detect_nosql_injection(rec: dict) -> tuple[bool, str]:
    uri = _build_uri(rec)
    ud  = url_decode(uri)
    if _nosql_match(uri) or _nosql_match(ud):
        return True, "uri"
    body = rec.get("body", "") or ""
    if body:
        udb = url_decode(body)
        if _nosql_match(body) or _nosql_match(udb):
            return True, "body"
    return False, ""


# ── 9. Template Injection / SSTI (template_injection.rs) ─────────────────────
# Scan: URI raw + url_decode, body raw + url_decode

_SSTI = [re.compile(p) for p in [
    r"""(?i)\{\{\s*['"']?\d+['"']?\s*\*\s*['"']?\d+['"']?\s*\}\}""",
    r"(?i)\{\{[^}]*\.\s*__\w+__",
    r"(?i)\{\{\s*config\s*\}\}",
    r"(?i)\{\{\s*(?:cycler\.|joiner\.|namespace\(|self\.|request\.|lipsum\.|url_for)",
    r"(?i)\{%\s*(?:set|for|if|import|extends|include|with)\b",
    r"(?i)<#\s*(?:assign|list|if|include|import|setting|escape)\b",
    r"(?i)#(?:set|if|foreach|parse|include|macro|evaluate)\s*\(",
    r"(?i)<%[!=]?\s*",
    r"""(?i)\$\{\s*['"']?\d+['"']?\s*\*\s*['"']?\d+['"']?\s*\}""",
    r'''(?i)\$\{\s*T\s*\(\s*['"]''',
    r"(?i)\$\{\s*#root\.|\$\{\s*@\w+\.",
    r"(?i)\$\{\s*new\s+\w+",
    r"(?i)\{\{#with\s|\{\{#each\s",
    r"(?i)\{\{lookup\s+\(",
]]

def _ssti_match(text: str) -> bool:
    return any(p.search(text) for p in _SSTI)

def detect_template_injection(rec: dict) -> tuple[bool, str]:
    uri = _build_uri(rec)
    ud  = url_decode(uri)
    if _ssti_match(uri) or _ssti_match(ud):
        return True, "uri"
    body = rec.get("body", "") or ""
    if body:
        udb = url_decode(body)
        if _ssti_match(body) or _ssti_match(udb):
            return True, "body"
    return False, ""


# ── 10. Open Redirect (open_redirect.rs) ──────────────────────────────────────
# Scan: only redirect-param query keys; evasion shapes always flag;
#       absolute URLs only flag when allowed_domains configured (default: empty → no flag)

_REDIR_PARAMS = {
    "next", "url", "to", "redirect", "redirect_uri", "redirect_url",
    "return", "return_to", "return_url", "rurl", "destination", "dest",
    "goto", "continue", "forward", "callback", "checkout_url",
    "image_url", "domain",
}
_REDIR_EVASION = [re.compile(p) for p in [
    r"(?i)^\s*javascript\s*:",
    r"(?i)^\s*data\s*:",
    r"(?i)^\s*(?:%2[fF])(?:%2[fF])?(?:https?|javascript|data)?\s*(?:%3[aA]|:)?",
    r"(?i)^\s*https?://[^/?#]*@",
    r"^\s*(?:\\|/\\|\\/)",
    r"(?i)^\s*//\w",
]]

def detect_open_redirect(rec: dict) -> tuple[bool, str]:
    query = rec.get("query", "") or ""
    if not query:
        return False, ""
    for pair in re.split(r"[&;]", query):
        eq = pair.find("=")
        if eq < 0:
            continue
        key   = pair[:eq]
        value = pair[eq + 1:]
        if not key.lower() in _REDIR_PARAMS or not value:
            continue
        decoded = url_decode(value)
        for p in _REDIR_EVASION:
            if p.search(value) or p.search(decoded):
                return True, "query"
    return False, ""


# ═══════════════════════════════════════════════════════════════════════════════
# Dispatcher — map detector_class → detect_fn
# ═══════════════════════════════════════════════════════════════════════════════

_DETECT_FNS: dict[str, callable] = {
    "sqli":               detect_sqli,
    "xss":                detect_xss,
    "path_traversal":     detect_path_traversal,
    "command_injection":  detect_command_injection,
    "ssrf":               detect_ssrf,
    "recon":              detect_recon,
    "header_injection":   detect_header_injection,
    "nosql_injection":    detect_nosql_injection,
    "template_injection": detect_template_injection,
    "open_redirect":      detect_open_redirect,
}

def local_detect(rec: dict) -> tuple[bool, str]:
    """Run the correct Python-ported detector for this record's class."""
    cls = DATASET_CLASS_MAP.get(rec["detector_class"], rec["detector_class"])
    fn  = _DETECT_FNS.get(cls)
    if fn is None:
        return False, f"unknown_class:{cls}"
    return fn(rec)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper: build URI string from a dataset record
# ═══════════════════════════════════════════════════════════════════════════════

def _build_uri(rec: dict) -> str:
    path  = rec.get("path", "") or "/"
    query = rec.get("query", "") or ""
    return f"{path}?{query}" if query else path


# ═══════════════════════════════════════════════════════════════════════════════
# Live WAF — HTTP(S) sender
# ═══════════════════════════════════════════════════════════════════════════════

def _make_conn(host: str, port: int, timeout: float, tls: bool) -> http.client.HTTPConnection:
    if tls:
        ctx = ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def waf_send(rec: dict, host: str, port: int, timeout: float, tls: bool) -> dict:
    method  = (rec.get("method") or "GET").upper()
    path    = rec.get("path", "/") or "/"
    query   = rec.get("query", "") or ""
    headers = dict(rec.get("headers") or {})
    body    = rec.get("body", "") or ""

    url        = f"{path}?{query}" if query else path
    scheme_port= 443 if tls else 80
    headers.setdefault("Host", host if port == scheme_port else f"{host}:{port}")
    headers.setdefault("User-Agent", "AegisEval/1.0")
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Connection", "close")

    body_bytes = body.encode("utf-8", errors="replace") if body else b""
    if body_bytes:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        headers["Content-Length"] = str(len(body_bytes))

    status = None
    error  = None
    t0     = time.monotonic()
    try:
        conn = _make_conn(host, port, timeout, tls)
        conn.request(method, url, body=body_bytes or None, headers=headers)
        resp   = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
    except ssl.SSLCertVerificationError as exc:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            conn.request(method, url, body=body_bytes or None, headers=headers)
            resp   = conn.getresponse()
            status = resp.status
            resp.read()
            conn.close()
            error  = f"SSL cert untrusted (ignored)"
        except Exception as e2:
            error = f"SSL then {type(e2).__name__}: {e2}"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    latency_ms = (time.monotonic() - t0) * 1000
    blocked    = status in BLOCK_CODES if status is not None else False
    return {
        "id":             rec["id"],
        "detector_class": DATASET_CLASS_MAP.get(rec["detector_class"], rec["detector_class"]),
        "technique":      rec.get("technique", ""),
        "label":          rec["label"],
        "expected":       rec["expected_waf_outcome"],
        "status_code":    status,
        "blocked":        blocked,
        "error":          error,
        "latency_ms":     latency_ms,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset loader
# ═══════════════════════════════════════════════════════════════════════════════

def load_ndjson(path: Path, sample: int = 0) -> list[dict]:
    records = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    if sample <= 0:
        return records
    import random
    rng = random.Random(42)
    by_cls: dict = defaultdict(list)
    for r in records:
        by_cls[r["detector_class"]].append(r)
    out: list[dict] = []
    for items in by_cls.values():
        rng.shuffle(items)
        out.extend(items[:sample])
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# Progress
# ═══════════════════════════════════════════════════════════════════════════════

class Progress:
    def __init__(self, total: int, label: str):
        self.total = total
        self.label = label
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
                print(f"\r  [{self.label}] {self._n:>7,}/{self.total:,}  "
                      f"({pct:5.1f}%)  {rps:,.0f} rq/s  ETA {eta:.0f}s  ",
                      end="", flush=True)

    def done(self):
        el  = time.monotonic() - self._t0
        rps = self.total / el if el else 0
        print(f"\r  [{self.label}] {self.total:,}/{self.total:,}  "
              f"(100.0%)  {rps:,.0f} rq/s  {el:.1f}s      ")


# ═══════════════════════════════════════════════════════════════════════════════
# Evaluator — run local + waf per record
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_one(rec: dict, host: str, port: int, timeout: float,
                 tls: bool, run_local: bool, run_waf: bool) -> dict:
    loc_hit = loc_field = None
    waf_status = waf_blocked = waf_error = waf_latency = None

    if run_local:
        loc_hit, loc_field = local_detect(rec)

    waf_res = None
    if run_waf:
        waf_res     = waf_send(rec, host, port, timeout, tls)
        waf_status  = waf_res["status_code"]
        waf_blocked = waf_res["blocked"]
        waf_error   = waf_res["error"]
        waf_latency = waf_res["latency_ms"]

    return {
        "id":             rec["id"],
        "detector_class": DATASET_CLASS_MAP.get(rec["detector_class"], rec["detector_class"]),
        "technique":      rec.get("technique", ""),
        "label":          rec["label"],
        "expected":       rec["expected_waf_outcome"],
        "loc_hit":        loc_hit,
        "loc_field":      loc_field,
        "waf_status":     waf_status,
        "waf_blocked":    waf_blocked,
        "waf_error":      waf_error,
        "waf_latency_ms": waf_latency,
    }


def run_dataset(records: list[dict], host: str, port: int, timeout: float,
                tls: bool, workers: int, run_local: bool, run_waf: bool,
                label: str) -> list[dict]:
    results = []
    prog    = Progress(len(records), label)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(evaluate_one, rec, host, port, timeout,
                        tls, run_local, run_waf): rec
            for rec in records
        }
        for fut in as_completed(futs):
            results.append(fut.result())
            prog.inc()

    prog.done()
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# Metrics
# ═══════════════════════════════════════════════════════════════════════════════

def compute_evasion_metrics(results: list[dict]) -> dict:
    """
    Evasion attacks (label=attack, expected_waf_outcome=miss):
      local_hit  = local detector CAN catch it  (evasion fails)
      local_miss = local detector misses         (true evasion in regex)
      waf_hit    = WAF blocked (4xx)             (WAF catches via any mechanism)
      waf_miss   = WAF passed                    (full bypass)
    """
    totals = dict(total=0, local_hit=0, local_miss=0,
                  waf_hit=0, waf_miss=0, waf_err=0, loc_none=0)
    by_cls: dict = defaultdict(lambda: dict(
        total=0, local_hit=0, local_miss=0,
        waf_hit=0, waf_miss=0, waf_err=0,
        techniques=defaultdict(lambda: dict(local_hit=0, local_miss=0,
                                            waf_hit=0, waf_miss=0))
    ))
    for r in results:
        cls  = r["detector_class"]
        tech = r["technique"]
        c    = by_cls[cls]
        totals["total"] += 1
        c["total"] += 1

        # Local
        if r["loc_hit"] is None:
            totals["loc_none"] += 1
        elif r["loc_hit"]:
            totals["local_hit"] += 1
            c["local_hit"] += 1
            c["techniques"][tech]["local_hit"] += 1
        else:
            totals["local_miss"] += 1
            c["local_miss"] += 1
            c["techniques"][tech]["local_miss"] += 1

        # WAF
        if r["waf_blocked"] is None:
            pass
        elif r["waf_error"] and r["waf_status"] is None:
            totals["waf_err"] += 1
            c["waf_err"] += 1
        elif r["waf_blocked"]:
            totals["waf_hit"] += 1
            c["waf_hit"] += 1
            c["techniques"][tech]["waf_hit"] += 1
        else:
            totals["waf_miss"] += 1
            c["waf_miss"] += 1
            c["techniques"][tech]["waf_miss"] += 1

    # Rates
    lv = totals["local_hit"] + totals["local_miss"]
    wv = totals["waf_hit"]   + totals["waf_miss"]
    totals["local_hit_rate"] = totals["local_hit"] / lv if lv else None
    totals["waf_hit_rate"]   = totals["waf_hit"]   / wv if wv else None
    return dict(totals=totals, by_class={k: dict(v) for k, v in by_cls.items()})


def compute_fp_metrics(results: list[dict]) -> dict:
    """
    FP candidates (label=normal, expected_waf_outcome=allow):
      local_fp = local detector flags (FP in regex rules)
      waf_fp   = WAF blocks           (FP in live system)
    """
    totals = dict(total=0, local_fp=0, local_tn=0,
                  waf_fp=0, waf_tn=0, waf_err=0, loc_none=0)
    by_cls: dict = defaultdict(lambda: dict(
        total=0, local_fp=0, local_tn=0,
        waf_fp=0, waf_tn=0, waf_err=0,
        techniques=defaultdict(lambda: dict(local_fp=0, local_tn=0,
                                            waf_fp=0, waf_tn=0))
    ))
    for r in results:
        cls  = r["detector_class"]
        tech = r["technique"]
        c    = by_cls[cls]
        totals["total"] += 1
        c["total"] += 1

        if r["loc_hit"] is None:
            totals["loc_none"] += 1
        elif r["loc_hit"]:
            totals["local_fp"] += 1
            c["local_fp"] += 1
            c["techniques"][tech]["local_fp"] += 1
        else:
            totals["local_tn"] += 1
            c["local_tn"] += 1
            c["techniques"][tech]["local_tn"] += 1

        if r["waf_blocked"] is None:
            pass
        elif r["waf_error"] and r["waf_status"] is None:
            totals["waf_err"] += 1
            c["waf_err"] += 1
        elif r["waf_blocked"]:
            totals["waf_fp"] += 1
            c["waf_fp"] += 1
            c["techniques"][tech]["waf_fp"] += 1
        else:
            totals["waf_tn"] += 1
            c["waf_tn"] += 1
            c["techniques"][tech]["waf_tn"] += 1

    lv = totals["local_fp"] + totals["local_tn"]
    wv = totals["waf_fp"]   + totals["waf_tn"]
    totals["local_fpr"] = totals["local_fp"] / lv if lv else None
    totals["waf_fpr"]   = totals["waf_fp"]   / wv if wv else None
    return dict(totals=totals, by_class={k: dict(v) for k, v in by_cls.items()})


# ═══════════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════════

def _bar(pct: float, w: int = 20) -> str:
    f = int(pct / 100 * w)
    return "█" * f + "░" * (w - f)

def _pct(v: int, d: int) -> str:
    return f"{v/d*100:.1f}%" if d else "—"

def _grade_hit(r: float | None) -> str:
    if r is None: return "—"
    if r >= 0.90: return "🟢 GOOD"
    if r >= 0.70: return "🟡 OK"
    return "🔴 POOR"

def _grade_fpr(r: float | None) -> str:
    if r is None: return "—"
    if r <= 0.01: return "🟢 GOOD"
    if r <= 0.05: return "🟡 OK"
    return "🔴 HIGH"


def write_report(ev_m: dict, fp_m: dict, args, out_dir: Path,
                 elapsed: float, tls: bool) -> Path:
    A    = []
    now  = datetime.now().strftime("%Y-%m-%d %H:%M")
    sch  = "https" if tls else "http"
    local_ran = args.waf_only is False
    waf_ran   = args.local_only is False

    A.append("# Aegis-Gate WAF — Detector Evaluation Report")
    A.append("")
    A.append("| | |")
    A.append("|---|---|")
    A.append(f"| **Date** | {now} |")
    A.append(f"| **WAF endpoint** | `{sch}://{args.host}:{args.port}` |")
    A.append(f"| **Dataset** | `tests/security/regex_dataset/` |")
    A.append(f"| **Sample per class** | {args.sample if args.sample else 'all (15 000)'} |")
    A.append(f"| **Local detector** | {'✅ ran' if local_ran else '⏭ skipped'} |")
    A.append(f"| **Live WAF** | {'✅ ran' if waf_ran else '⏭ skipped'} |")
    A.append(f"| **Total elapsed** | {elapsed:.1f}s |")
    A.append("")

    # ── Class name note ──────────────────────────────────────────────────────
    A.append("> **Class-name mapping**: dataset field `detector_class=\"nosql\"` maps to")
    A.append("> Rust detector id `\"nosql_injection\"` (confirmed from `nosql_injection.rs`).")
    A.append("")

    # ── Executive summary ────────────────────────────────────────────────────
    A.append("---")
    A.append("## Executive Summary")
    A.append("")
    et = ev_m["totals"]
    ft = fp_m["totals"]
    ev_lv = et["local_hit"]  + et["local_miss"]
    ev_wv = et["waf_hit"]    + et["waf_miss"]
    fp_lv = ft["local_fp"]   + ft["local_tn"]
    fp_wv = ft["waf_fp"]     + ft["waf_tn"]

    A.append("### Evasion Attacks")
    A.append("")
    A.append("| Mode | Hit | Miss | Valid | Hit Rate | Target | Grade |")
    A.append("|---|---:|---:|---:|---:|---:|---|")
    if local_ran:
        A.append(f"| Local detector (regex port) | {et['local_hit']:,} | {et['local_miss']:,} | "
                 f"{ev_lv:,} | **{_pct(et['local_hit'],ev_lv)}** | ≥70% | "
                 f"{_grade_hit(et['local_hit_rate'])} |")
    if waf_ran:
        A.append(f"| Live WAF `{sch}://{args.host}` | {et['waf_hit']:,} | {et['waf_miss']:,} | "
                 f"{ev_wv:,} | **{_pct(et['waf_hit'],ev_wv)}** | ≥90% | "
                 f"{_grade_hit(et['waf_hit_rate'])} |")
    A.append("")

    A.append("### FP Candidates")
    A.append("")
    A.append("| Mode | FP | TN | Valid | FPR | Target | Grade |")
    A.append("|---|---:|---:|---:|---:|---:|---|")
    if local_ran:
        A.append(f"| Local detector (regex port) | {ft['local_fp']:,} | {ft['local_tn']:,} | "
                 f"{fp_lv:,} | **{_pct(ft['local_fp'],fp_lv)}** | ≤5% | "
                 f"{_grade_fpr(ft['local_fpr'])} |")
    if waf_ran:
        A.append(f"| Live WAF `{sch}://{args.host}` | {ft['waf_fp']:,} | {ft['waf_tn']:,} | "
                 f"{fp_wv:,} | **{_pct(ft['waf_fp'],fp_wv)}** | ≤1% | "
                 f"{_grade_fpr(ft['waf_fpr'])} |")
    A.append("")

    # ── Per-class evasion ────────────────────────────────────────────────────
    A.append("---")
    A.append("## Evasion Attack Detection — Per Detector Class")
    A.append("")
    A.append("> **Local hit** = Python port of Rust regex catches the payload.  ")
    A.append("> **WAF hit**   = live WAF returns 4xx.  ")
    A.append("> Classes sorted by WAF hit rate ascending (worst first).")
    A.append("")

    cols = []
    hdr  = "| Detector Class | Total |"
    sep  = "|---|---:|"
    if local_ran:
        hdr += " Loc-Hit | Loc-Miss | Loc-Rate |"
        sep += "---:|---:|---:|"
    if waf_ran:
        hdr += " WAF-Hit | WAF-Miss | WAF-Rate |"
        sep += "---:|---:|---:|"
    A.append(hdr)
    A.append(sep)

    sorted_ev = sorted(
        ev_m["by_class"].items(),
        key=lambda x: (x[1].get("waf_hit", 0) /
                       max(x[1].get("waf_hit", 0) + x[1].get("waf_miss", 0), 1))
    )
    for cls, d in sorted_ev:
        row = f"| `{cls}` | {d['total']:,} |"
        if local_ran:
            lv = d["local_hit"] + d["local_miss"]
            row += f" {d['local_hit']:,} | {d['local_miss']:,} | **{_pct(d['local_hit'], lv)}** |"
        if waf_ran:
            wv = d["waf_hit"] + d["waf_miss"]
            row += f" {d['waf_hit']:,} | {d['waf_miss']:,} | **{_pct(d['waf_hit'], wv)}** |"
        A.append(row)
    A.append("")

    # Top missed techniques
    if local_ran or waf_ran:
        A.append("### Top Evasion Techniques (most misses)")
        A.append("")
        top_miss = sorted(
            [(cls, d) for cls, d in ev_m["by_class"].items()
             if (d.get("waf_miss", 0) + d.get("local_miss", 0)) > 0],
            key=lambda x: -(x[1].get("waf_miss", 0))
        )[:5]
        for cls, d in top_miss:
            techs = d.get("techniques", {})
            worst = sorted(
                [(t, v) for t, v in techs.items()
                 if v.get("waf_miss", 0) + v.get("local_miss", 0) > 0],
                key=lambda x: -x[1].get("waf_miss", 0)
            )[:6]
            if not worst:
                continue
            A.append(f"**`{cls}`**")
            A.append("")
            A.append("| Technique | Loc-Hit | Loc-Miss | WAF-Hit | WAF-Miss |")
            A.append("|---|---:|---:|---:|---:|")
            for tech, tv in worst:
                A.append(f"| `{tech}` | {tv.get('local_hit',0)} | {tv.get('local_miss',0)} | "
                         f"{tv.get('waf_hit',0)} | {tv.get('waf_miss',0)} |")
            A.append("")

    # ── Per-class FPR ────────────────────────────────────────────────────────
    A.append("---")
    A.append("## False Positive Rate — Per Detector Class")
    A.append("")
    hdr2 = "| Detector Class | Total |"
    sep2 = "|---|---:|"
    if local_ran:
        hdr2 += " Loc-FP | Loc-TN | Loc-FPR |"
        sep2 += "---:|---:|---:|"
    if waf_ran:
        hdr2 += " WAF-FP | WAF-TN | WAF-FPR |"
        sep2 += "---:|---:|---:|"
    A.append(hdr2)
    A.append(sep2)

    sorted_fp = sorted(
        fp_m["by_class"].items(),
        key=lambda x: -(x[1].get("waf_fp", 0) /
                        max(x[1].get("waf_fp", 0) + x[1].get("waf_tn", 0), 1))
    )
    for cls, d in sorted_fp:
        row2 = f"| `{cls}` | {d['total']:,} |"
        if local_ran:
            lv2 = d["local_fp"] + d["local_tn"]
            row2 += f" {d['local_fp']:,} | {d['local_tn']:,} | **{_pct(d['local_fp'], lv2)}** |"
        if waf_ran:
            wv2 = d["waf_fp"] + d["waf_tn"]
            row2 += f" {d['waf_fp']:,} | {d['waf_tn']:,} | **{_pct(d['waf_fp'], wv2)}** |"
        A.append(row2)
    A.append("")

    # ── Detector source reference ─────────────────────────────────────────────
    A.append("---")
    A.append("## Detector Source Reference")
    A.append("")
    A.append("Patterns ported exactly from `crates/aegis-security/src/detectors/`.")
    A.append("")
    A.append("| Class | Rust File | Score | Scan Surface |")
    A.append("|---|---|---:|---|")
    ref = [
        ("sqli",               "sqli.rs",               70, "URI variants, body variants, headers: cookie / referer / x-forwarded-for / user-agent"),
        ("xss",                "xss.rs",                70, "URI (url+entity decode), body, headers: cookie / referer / user-agent"),
        ("path_traversal",     "path_traversal.rs",     70, "URI variants, body variants"),
        ("command_injection",  "command_injection.rs",  70, "URI variants, body variants, headers: UA / referer / x-api-version / x-forwarded-for / x-real-ip / auth / cookie / x-requested-with. Log4Shell → score 90"),
        ("ssrf",               "ssrf.rs",               70, "query (decoded), path (decoded), body (decoded), headers: x-original-url / x-rewrite-url. NOT full URI (self-trip risk)"),
        ("recon",              "recon.rs",              25, "path_and_query (RECON_PATHS score 25), user-agent (RECON_UA score 50)"),
        ("header_injection",   "header_injection.rs",   70, "query raw+decoded (CRLF), all header values (CRLF), XFH poisoning, URL-override headers, method-override headers"),
        ("nosql_injection",    "nosql_injection.rs",    70, "URI raw+decoded, body raw+decoded. **Dataset field = 'nosql'**"),
        ("template_injection", "template_injection.rs", 70, "URI raw+decoded, body raw+decoded"),
        ("open_redirect",      "open_redirect.rs",      50, "Query-string redirect params only (next/url/redirect/return/goto/…). Evasion shapes always flag; bare https:// does NOT flag with empty allowlist"),
    ]
    for cls, f, sc, surf in ref:
        A.append(f"| `{cls}` | `{f}` | {sc} | {surf} |")
    A.append("")

    A.append("---")
    A.append(f"*Generated by `tests/ml-model/eval_hit_waf_test_set.py` — {now}*")

    out = out_dir / "WAF_DETECTOR_EVAL_REPORT.md"
    out.write_text("\n".join(A) + "\n")
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# Connectivity pre-check
# ═══════════════════════════════════════════════════════════════════════════════

def pre_check(host: str, port: int, timeout: float, tls: bool) -> bool:
    print("  [pre-check] DNS ... ", end="", flush=True)
    try:
        addr = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        print(f"OK → {addr[0][4][0]}")
    except socket.gaierror as e:
        print(f"FAIL: {e}")
        print(f"  → Cannot resolve '{host}'. Check hostname / VPN / /etc/hosts.")
        return False

    print("  [pre-check] TCP ... ", end="", flush=True)
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        print(f"OK (port {port})")
    except Exception as e:
        print(f"FAIL: {e}")
        print(f"  → Firewall or port closed. Try --port 80 --no-tls.")
        return False

    if tls:
        print("  [pre-check] TLS ... ", end="", flush=True)
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                                 server_hostname=host) as ss:
                print(f"OK ({ss.version()})")
        except ssl.SSLCertVerificationError as e:
            print(f"WARNING: {e} — proceeding with cert check disabled")
        except Exception as e:
            print(f"FAIL: {e}")
            print("  → Try --no-tls if server speaks plain HTTP.")
            return False

    print("  [pre-check] GET / ... ", end="", flush=True)
    probe = waf_send(
        {"id": "probe", "label": "normal", "expected_waf_outcome": "allow",
         "detector_class": "_probe", "technique": "", "note": "",
         "method": "GET", "path": "/", "query": "", "headers": {}, "body": ""},
        host, port, timeout, tls,
    )
    if probe["status_code"] is None and probe["error"]:
        print(f"FAIL: {probe['error']}")
        return False
    print(f"HTTP {probe['status_code']} ({probe['latency_ms']:.0f} ms)")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WAF eval: local Rust-detector port + live WAF hit-rate.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--host",         default=DEFAULT_HOST)
    ap.add_argument("--port",         type=int, default=DEFAULT_PORT)
    ap.add_argument("--no-tls",       action="store_true",
                    help="Plain HTTP instead of HTTPS")
    ap.add_argument("--dataset-dir",  default=str(DATASET_DIR))
    ap.add_argument("--out-dir",      default=str(DEFAULT_OUT))
    ap.add_argument("--sample",       type=int, default=0,
                    help="Records per detector_class per file (0 = all 15 000)")
    ap.add_argument("--workers",      type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--timeout",      type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--local-only",   action="store_true",
                    help="Skip live WAF, only run Python detector ports")
    ap.add_argument("--waf-only",     action="store_true",
                    help="Skip local detector, only hit live WAF")
    ap.add_argument("--only-evasion", action="store_true")
    ap.add_argument("--only-fp",      action="store_true")
    ap.add_argument("--no-report",    action="store_true")
    args = ap.parse_args()

    tls       = not args.no_tls
    run_local = not args.waf_only
    run_waf   = not args.local_only
    scheme    = "https" if tls else "http"

    dset_dir  = Path(args.dataset_dir)
    out_dir   = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*72}")
    print("  Aegis-Gate WAF — Detector Evaluation (local port + live WAF)")
    print(f"{'='*72}")
    print(f"  Endpoint : {scheme}://{args.host}:{args.port}")
    print(f"  Modes    : {'local ✓' if run_local else 'local ✗'}  "
          f"{'waf ✓' if run_waf else 'waf ✗'}")
    print(f"  Dataset  : {dset_dir}")
    print(f"  Sample   : {'all (15 000/class)' if args.sample == 0 else f'{args.sample}/class'}")
    print(f"  Workers  : {args.workers}   Timeout: {args.timeout}s")
    print(f"  Output   : {out_dir}")
    print(f"{'='*72}\n")

    if run_waf:
        ok = pre_check(args.host, args.port, args.timeout, tls)
        if not ok:
            sys.exit(1)
        print()

    ev_metrics = fp_metrics = None
    t_global   = time.monotonic()

    # ── Evasion attacks ──────────────────────────────────────────────────────
    if not args.only_fp:
        ev_path = dset_dir / "evasion_attacks.ndjson"
        print(f"[1/2] Loading {ev_path.name} ...")
        ev_recs = load_ndjson(ev_path, args.sample)
        print(f"      {len(ev_recs):,} records\n")

        ev_results = run_dataset(ev_recs, args.host, args.port, args.timeout,
                                 tls, args.workers, run_local, run_waf, "evasion")
        ev_metrics  = compute_evasion_metrics(ev_results)

        # Save raw
        raw = out_dir / "evasion_results.json"
        raw.write_text(json.dumps(ev_results, indent=2))

        et = ev_metrics["totals"]
        ev_lv = et["local_hit"] + et["local_miss"]
        ev_wv = et["waf_hit"]   + et["waf_miss"]
        print(f"\n  Evasion summary:")
        if run_local:
            print(f"    Local hit rate: {_pct(et['local_hit'], ev_lv)}"
                  f"  ({et['local_hit']:,}/{ev_lv:,}  miss={et['local_miss']:,})")
        if run_waf:
            print(f"    WAF  hit rate : {_pct(et['waf_hit'], ev_wv)}"
                  f"  ({et['waf_hit']:,}/{ev_wv:,}  miss={et['waf_miss']:,}  err={et['waf_err']:,})")
        print(f"    Raw JSON: {raw}\n")

        print("  Per-class evasion:")
        for cls, d in sorted(ev_metrics["by_class"].items(),
                              key=lambda x: x[1].get("waf_hit", 0) /
                                  max(x[1].get("waf_hit", 0)+x[1].get("waf_miss", 0), 1)):
            lv = d["local_hit"] + d["local_miss"]
            wv = d["waf_hit"]   + d["waf_miss"]
            loc_s = f"loc={_pct(d['local_hit'], lv)}" if run_local else ""
            waf_s = f"waf={_pct(d['waf_hit'],   wv)}" if run_waf   else ""
            print(f"    {cls:<22}  {loc_s:>12}  {waf_s:>12}  "
                  f"({d['total']:,} records)")
        print()

    # ── FP candidates ────────────────────────────────────────────────────────
    if not args.only_evasion:
        fp_path = dset_dir / "fp_candidates.ndjson"
        print(f"[2/2] Loading {fp_path.name} ...")
        fp_recs = load_ndjson(fp_path, args.sample)
        print(f"      {len(fp_recs):,} records\n")

        fp_results = run_dataset(fp_recs, args.host, args.port, args.timeout,
                                 tls, args.workers, run_local, run_waf, "fp-cands")
        fp_metrics  = compute_fp_metrics(fp_results)

        raw2 = out_dir / "fp_results.json"
        raw2.write_text(json.dumps(fp_results, indent=2))

        ft = fp_metrics["totals"]
        fp_lv = ft["local_fp"] + ft["local_tn"]
        fp_wv = ft["waf_fp"]   + ft["waf_tn"]
        print(f"\n  FP summary:")
        if run_local:
            print(f"    Local FPR: {_pct(ft['local_fp'], fp_lv)}"
                  f"  ({ft['local_fp']:,}/{fp_lv:,}  tn={ft['local_tn']:,})")
        if run_waf:
            print(f"    WAF   FPR: {_pct(ft['waf_fp'], fp_wv)}"
                  f"  ({ft['waf_fp']:,}/{fp_wv:,}  tn={ft['waf_tn']:,}  err={ft['waf_err']:,})")
        print(f"    Raw JSON: {raw2}\n")

    # ── Report ───────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - t_global
    if not args.no_report and ev_metrics and fp_metrics:
        rpt = write_report(ev_metrics, fp_metrics, args, out_dir, elapsed, tls)
        print(f"  Report: {rpt}")

    print(f"\n  Done in {elapsed:.1f}s")
    print(f"{'='*72}\n")


if __name__ == "__main__":
    main()
