#!/usr/bin/env python3
"""Mock upstream for the WAF Hackathon Round-1 stress test.

Implements the public surface of `Hackathon_Doc/openapi.public.yaml`
with canned JSON responses + small synthetic latency. No external
deps; runs on Python 3.10+.

Threading: socketserver.ThreadingMixIn so multiple k6 VUs can
hit it concurrently. Tested at ~10k RPS on an M-class laptop;
that's enough headroom for the WAF to be the bottleneck rather
than the upstream.

Usage:
    python3 server.py [--bind 127.0.0.1] [--port 9999] [--latency-ms 2]
"""
from __future__ import annotations

import argparse
import http.server
import json
import random
import socketserver
import sys
import time
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

# Fixed test creds matching openapi.public.yaml
USERS = {
    "alice":   {"password": "P@ssw0rd1",  "otp": "123456", "balance": 5000},
    "bob":     {"password": "S3cureP@ss", "otp": "654321", "balance": 1200},
    "charlie": {"password": "Ch@rlie99",  "otp": "111222", "balance":  300},
}
LOGIN_TOKENS: dict[str, str] = {}    # token -> username
SESSIONS: dict[str, str] = {}        # sid    -> username


def now_ms() -> int:
    return int(time.time() * 1000)


def jitter_ms(target_ms: float) -> None:
    """Sleep for target_ms ± 50% to emulate real DB latency."""
    if target_ms <= 0:
        return
    span = target_ms * 0.5
    delay = max(0.0, target_ms + random.uniform(-span, span))
    time.sleep(delay / 1000.0)


def gen_id(prefix: str = "id") -> str:
    return f"{prefix}_{random.randint(10**9, 10**10 - 1):x}"


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "HackathonMock/1.0"
    sys_version = ""

    # Suppress access logs — we benchmark hot loops
    def log_message(self, *_args, **_kwargs) -> None:
        return

    # --- helpers ----------------------------------------------------

    def _read_body(self) -> bytes:
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n > 0 else b""

    def _read_json(self) -> dict:
        try:
            return json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            return {}

    def _send_json(self, status: int, body: dict, set_cookie: str | None = None) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        if set_cookie:
            self.send_header("set-cookie", set_cookie)
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, body: str, ctype: str = "text/plain") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _session_user(self) -> str | None:
        cookie = self.headers.get("cookie") or ""
        for part in cookie.split(";"):
            kv = part.strip()
            if kv.startswith("sid="):
                return SESSIONS.get(kv[4:])
        return None

    def _require_session(self) -> str | None:
        user = self._session_user()
        if not user:
            self._send_json(401, {"error": "unauthenticated"})
            return None
        return user

    # --- routing ----------------------------------------------------

    def _route(self, method: str) -> None:
        path_only = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        jitter_ms(self.server.target_latency_ms)

        # Health + public
        if path_only == "/health":
            return self._send_json(200, {"status": "ok", "ts_ms": now_ms()})
        if path_only == "/api/public/stats":
            return self._send_json(200, {
                "active_users": random.randint(800, 1500),
                "total_bets":   random.randint(20000, 30000),
                "uptime_s":     int(time.monotonic()),
            })
        if path_only == "/about":
            return self._send_text(200, "<h1>Hackathon Target App</h1>", "text/html")
        if path_only == "/sitemap.xml":
            return self._send_text(200, "<urlset/>", "application/xml")

        # Auth
        if path_only == "/login" and method == "POST":
            body = self._read_json()
            user, password = body.get("username"), body.get("password")
            if user in USERS and USERS[user]["password"] == password:
                tok = gen_id("login")
                LOGIN_TOKENS[tok] = user
                return self._send_json(200, {"login_token": tok, "next": "otp"})
            return self._send_json(401, {"error": "invalid_credentials"})

        if path_only == "/otp" and method == "POST":
            body = self._read_json()
            tok = body.get("login_token")
            otp = body.get("otp_code")
            user = LOGIN_TOKENS.get(tok or "")
            if user and otp == USERS[user]["otp"]:
                sid = gen_id("sid")
                SESSIONS[sid] = user
                cookie = f"sid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
                return self._send_json(200, {"ok": True, "user": user}, set_cookie=cookie)
            return self._send_json(401, {"error": "invalid_otp"})

        # Static-ish
        if path_only.startswith("/static/") or path_only.startswith("/public/") or path_only.startswith("/assets/"):
            return self._send_text(200, f"// stub for {path_only}\n", "application/javascript")

        # Streams (treated as fast 200 for benchmarking; not a true SSE/WS)
        if path_only in ("/ws/live", "/api/notifications/stream"):
            return self._send_json(200, {"events": []})

        # All remaining endpoints require a session
        if path_only.startswith("/admin/") or path_only.startswith("/api/") or path_only in (
            "/deposit", "/withdrawal", "/user/settings",
        ) or path_only.startswith("/game"):
            user = self._require_session()
            if not user:
                return

        # Financial
        if path_only == "/deposit" and method == "POST":
            return self._send_json(201, {"ok": True, "txn_id": gen_id("dep"), "ts_ms": now_ms()})
        if path_only == "/withdrawal" and method == "POST":
            return self._send_json(201, {"ok": True, "txn_id": gen_id("wd"), "ts_ms": now_ms()})
        if path_only == "/api/rewards/claim" and method == "POST":
            return self._send_json(200, {"ok": True, "amount": random.randint(1, 50)})

        # Profile / Transactions / Settings
        if path_only == "/api/profile":
            user = self._session_user() or "alice"
            if method == "GET":
                return self._send_json(200, {"username": user, "email": f"{user}@example.com"})
            if method in ("PATCH", "PUT", "POST"):
                # Read body (don't apply — mass-assignment probes are
                # left for the WAF to flag; we just acknowledge)
                _ = self._read_json()
                return self._send_json(200, {"ok": True})
        if path_only == "/api/transactions" and method == "GET":
            limit = int((query.get("limit") or ["20"])[0])
            return self._send_json(200, {"items": [
                {"id": gen_id("tx"), "amount": random.randint(-200, 200)}
                for _ in range(min(limit, 50))
            ]})
        if path_only == "/user/settings":
            return self._send_json(200, {"theme": "light", "lang": "en"})

        # Games
        if path_only == "/game/list":
            return self._send_json(200, {"games": [
                {"id": f"g{i}", "name": f"Game {i}"} for i in range(1, 11)
            ]})
        if path_only.startswith("/game/"):
            tail = path_only.removeprefix("/game/")
            if tail.endswith("/play"):
                return self._send_json(200, {"ok": True, "outcome": random.choice(["win", "loss"])})
            return self._send_json(200, {"id": tail, "name": f"Game {tail}"})

        # Feedback / KYC / analytics
        if path_only == "/api/feedback" and method == "POST":
            _ = self._read_json()
            return self._send_json(201, {"ok": True, "id": gen_id("fb")})
        if path_only == "/api/kyc/document" and method == "POST":
            return self._send_json(201, {"ok": True, "id": gen_id("kyc")})
        if path_only == "/api/analytics/events" and method == "POST":
            return self._send_json(204, {})
        if path_only == "/api/bet-reports/export":
            return self._send_text(200, "txn_id,amount\n", "text/csv")

        # Admin
        if path_only == "/admin/dashboard":
            return self._send_json(200, {"users": len(USERS), "open_sessions": len(SESSIONS)})
        if path_only == "/admin/users":
            return self._send_json(200, {"users": list(USERS.keys())})

        # Fallback
        return self._send_json(404, {"error": "not_found", "path": path_only})

    # method shims
    def do_GET(self):
        try: self._route("GET")
        except (BrokenPipeError, ConnectionResetError): pass
    def do_POST(self):
        try: self._route("POST")
        except (BrokenPipeError, ConnectionResetError): pass
    def do_PUT(self):
        try: self._route("PUT")
        except (BrokenPipeError, ConnectionResetError): pass
    def do_PATCH(self):
        try: self._route("PATCH")
        except (BrokenPipeError, ConnectionResetError): pass
    def do_DELETE(self):
        try: self._route("DELETE")
        except (BrokenPipeError, ConnectionResetError): pass
    def do_HEAD(self):
        try: self._route("HEAD")
        except (BrokenPipeError, ConnectionResetError): pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    target_latency_ms: float = 2.0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--latency-ms", type=float, default=2.0,
                   help="synthetic per-request latency target (jittered ±50%)")
    args = p.parse_args()

    srv = ThreadedServer((args.bind, args.port), Handler)
    srv.target_latency_ms = args.latency_ms
    print(
        f"hackathon-mock listening on {args.bind}:{args.port} "
        f"(jitter ~{args.latency_ms} ms)",
        flush=True,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
