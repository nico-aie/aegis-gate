# Aegis-Gate Round-2 Regression — Recon & Log-Analysis Summary

**Author:** n-tester (security QA)  ·  **Date:** 2026-06-13  ·  **For:** WAF Hackathon round 2
**Scope:** Phase 1 (round-1 log analysis) + Phase 2 (live upstream recon) + reconciliation/gap analysis that drives the Phase-3 test set.

---

## 0. TL;DR

Round 1 only ever exercised **generic scanner/recon detection**. The committee's bot traffic never touched a single real NovaBet endpoint and never exercised any of the round-2 detector surfaces (**WebSocket, JWT, response caching**), nor the app-specific attack classes (SQLi/NoSQLi/SSRF against the betting API). Round 2 will almost certainly drive the real application — login → OTP → balance/games over a `sid` cookie, plus the live WebSocket and SSE channels — so the regression set is built around the **actual upstream surface** observed live, weighted heavily toward the three new detectors.

One structural finding worth stating up front: **the real app has no JWT anywhere.** Auth is a single HttpOnly `sid` cookie. The WAF nonetheless ships a JWT validator (`crates/aegis-security/src/auth/jwt.rs`). The `auth-jwt/` cases therefore test the *WAF's* JWT detector against `Authorization: Bearer …` tokens the app itself would never emit — valid as detector regression, but flagged here so nobody expects the upstream to consume them.

---

## 1. Phase 1 — Round-1 log analysis

Source: `tests/n-tester/hk-round-1/audit-2026-06-{10,11,12}.ndjson` (Aegis audit schema v1).

### 1.1 Volume & shape

| Metric | Value |
|---|---|
| Total events | **1,187** |
| Window | 2026-06-10 00:15 → 2026-06-12 16:50 UTC (~64.6 h) |
| Avg rate | ~0.3 req/min (low, diffuse — not a sustained benchmark run) |
| Unique source IPs | **208** |
| Event classes | `access` 396, `detection` 791 |
| Actions | `allow` 396, `block` 733, `challenge` 58 |
| Risk tier | `low` for 100% of events |

### 1.2 Methods, status, content-types

- **Methods:** GET 1066, POST 94, HEAD 26, PROPFIND 1. No PUT/DELETE/PATCH, **no WebSocket upgrades**.
- **Status (on allowed/passed):** 200 ×225, 404 ×158, 429 ×58 (challenges), 401 ×13. Blocked requests never reach upstream (status null).
- **Content-types:** `text/plain` 527, `application/x-www-form-urlencoded` 47, `application/dns-message` 20 (DNS-over-HTTPS probes), `multipart/form-data` 1.
- **User-Agents:** dominated by `libredtail-http` (581) — a mass-scanning botnet client — plus assorted spoofed browser UAs and `Go-http-client`, `python-httpx`.

### 1.3 What actually fired

| Detector / rule | Hits | Notes |
|---|---|---|
| `ai` (risk-score model) | 568 | "blocked by risk score" — the AI tier did most of the blocking |
| `recon_path` | 88 | scanning for known-vuln paths |
| `canary` | 35 | honeypot path hits |
| `path_traversal` | 30 | the cgi-bin `.%2e` clusters |
| `command_injection` | 30 | co-fired with traversal (RCE-via-CGI) |
| `xss` | 1 | a single reflected probe |
| `risk-challenge` | 58 | PoW/429 challenge band |

### 1.4 What the committee actually probed (top blocked/challenged targets)

Pure opportunistic CVE/again-the-internet noise, **none of it NovaBet-specific**:

- `/.env` (×27) — secret-file disclosure
- `/cgi-bin/.%2e/…/bin/sh` and `/cgi-bin/%%32%65…` (×30) — path traversal → RCE, double/over-encoded
- `/vendor/phpunit/.../eval-stdin.php` and ~40 path-variants — PHPUnit RCE (CVE-2017-9841)
- `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://…` — PHP-CGI argument injection (CVE-2012-1823)
- `/Core/Skin/Login.aspx`, `/robots.txt`, `/favicon.ico` — fingerprinting
- `application/dns-message` POSTs — open-resolver / DoH abuse probes

### 1.5 Phase-1 conclusion — coverage the committee did **not** exercise in round 1

Nothing in round 1 touched:

- **Any real NovaBet route** (`/login`, `/otp`, `/deposit`, `/withdrawal`, `/api/profile`, `/game/*`, `/api/*`).
- **WebSocket** (`/ws/live`) or **SSE** (`/api/notifications/stream`) — zero upgrades, zero `text/event-stream`.
- **JWT / bearer auth** — zero `Authorization` headers.
- **Cache** behaviour — no conditional GETs, no cache-poisoning headers, no static-vs-dynamic confusion.
- **SQLi / NoSQLi / SSRF / CORS / request-smuggling** as application-layer attacks.

➡️ Treat round-1 logs as a **baseline of committee scanner behaviour only**. Round-2 coverage must be built almost entirely from the live upstream map below.

---

## 2. Phase 2 — Live upstream reconnaissance

Target: `http://sec-team.waf-exams.info/` — **"NovaBet"**, a fintech/gambling app (the hackathon target).
Methods used (non-destructive): fetched `GET /openapi.yaml`; loaded the homepage and `GET /static/js/app.js` in a real browser and read the client source. No exploitation, no writes, no login state created.

### 2.1 Auth model (confirmed from spec **and** live client)

Two-step, **cookie-based — no JWT**:

1. `POST /login {username,password}` → `{login_token}` (valid 5 min).
2. `POST /otp {login_token,otp_code}` → sets `sid` cookie: **HttpOnly, SameSite=Strict, Path=/, 30-min sliding**.
3. Authenticated requests carry `sid`; the client uses `fetch(…, {credentials:"same-origin"})`.

Test credentials (published in the spec, reusable):

| Username | Password | OTP |
|---|---|---|
| alice | `P@ssw0rd1` | 123456 |
| bob | `S3cureP@ss` | 654321 |
| charlie | `Ch@rlie99` | 111222 |

### 2.2 Full endpoint inventory

| Method | Path | Auth | Notes / attack relevance |
|---|---|---|---|
| POST | `/login` | none | username/password → SQLi/NoSQLi sink; rate-limit/cred-stuffing |
| POST | `/otp` | none | login_token + otp → NoSQLi; brute force |
| POST | `/deposit` | sid | amount/currency |
| POST | `/withdrawal` | sid | amount/bank_account |
| GET/PUT | `/api/profile` | sid | returns **card_number, bank_account, ssn** (high-value); PUT email/display_name → stored XSS sink |
| GET | `/api/transactions?page&limit` | sid | numeric params → SQLi/NoSQLi via `page`/`limit` |
| GET/PUT | `/user/settings` | sid | preferences (withdrawal_limit) |
| GET | `/game/list` | none | catalogue (Blackjack, Roulette, Poker, Dice, Slots) |
| GET | `/game/{id}?name=` | none | **`name` reflected into server welcome msg → reflected XSS**; `{id}` path → SQLi |
| POST | `/game/{id}/play` | sid | bet; **`callback_url` → SSRF** |
| POST | `/api/feedback` | none | **`comment` → stored XSS** (see `stored_xss_active` flag) |
| POST | `/api/bet-reports/export` | sid | format pdf/csv/xlsx |
| GET | `/admin/dashboard`, `/admin/users` | sid* | *security is only `sessionCookie` — **no role check in spec → IDOR/priv-esc candidate** |
| POST | `/api/rewards/claim` | sid | one-time $100; 409 if claimed → **race-condition candidate** |
| GET | `/`, `/about`, `/sitemap.xml` | none | HTML/XML pages |
| GET | `/static/{path}` | none | JS/CSS, **ETag / If-None-Match → caching surface** |
| GET | `/public/{file}`, `/assets/{path}` | none | static; path-traversal targets |
| **GET** | **`/ws/live`** | sid (via cookie on Upgrade) | **WebSocket — new detector** |
| **GET** | **`/api/notifications/stream`** | sid | **SSE (text/event-stream)** |
| POST | `/api/kyc/document` | sid | **multipart/form-data** — WAF must not strip envelope |
| POST | `/api/analytics/events` | sid | JSON batch; spec allows gzip + chunked → decompression surface |
| POST | `/api/integrations/preview` | none | **`url` field with domain allowlist → SSRF / allowlist-bypass** |
| GET/OPTIONS | `/api/public/stats` | none | **CORS preflight** must pass |
| GET | `/health` | none | uptime |
| POST/GET | `/__control/*` | `X-Benchmark-Secret` | **benchmark-only admin** (reset/slow/error_mode/health_mode/state) — must be unreachable from the data plane |

### 2.3 Real-time channels — observed from the live client (`app.js` build v2.0.0)

This is the part round-1 never touched and where the new detectors live. Verbatim behaviour from the shipped client:

- **WebSocket** — `connectLive()` runs **only after** `GET /api/profile` succeeds (i.e. authenticated):
  - Opens `ws(s)://<host>/ws/live`; **no token in the URL or first frame** — it relies entirely on the `sid` cookie auto-attached to the Upgrade request.
  - First client frame: `{"op":"subscribe","topic":"balance"}`; server echoes it as ACK.
  - `onmessage` parses JSON and, for `{"type":"balance_update","balance":N}`, **writes `N` straight into `state.user.balance`** → a forged/injected frame directly corrupts displayed balance. This is exactly what the `ws_message_injection_*` cases target.
  - Reconnect: exponential backoff 1 s → ×2 → max 30 s.
  - **No client-side Origin check** → cross-site WebSocket hijack (CSWSH) is a real risk the WAF must cover at the handshake.
- **SSE** — `connectNotifications()` opens one `EventSource("/api/notifications/stream")` for the session; listens for named events `balance.ping`, `game.ping`, `welcome.ping`; toasts render via `textContent` (client-safe), but the raw stream is the injection target.
- **Analytics** — buffers events and `POST`s `/api/analytics/events` every 30 s as JSON (`credentials:same-origin`). Spec additionally permits `Content-Encoding: gzip` and chunked — both are decompression/normalization surfaces a WAF must handle without false-blocking.
- **KYC** — `uploadKYCDocument()` posts a `FormData` (multipart) to `/api/kyc/document`.

### 2.4 Caching surface (new detector)

Confirmed cacheable/keyed behaviour: `GET /static/{path}` advertises **ETag + 304 on If-None-Match**; `/api/public/stats` is described as "open + cached" and the client calls it on every page load. WAF code confirms a cache layer that stamps `X-WAF-Cache: HIT|MISS` and strips `X-WAF-*` from cacheable responses (`crates/aegis-proxy/src/cache/mod.rs`). Attack surface: **web cache poisoning** (unkeyed `X-Forwarded-Host`/`X-Host`/`Forwarded`), **cache deception** (request a private path with a static-looking suffix so the edge caches an authed body), and **cache-key normalization** tricks.

---

## 3. Reconciliation — logs vs live, and what's new

| Surface | Seen in round-1 logs? | Live on upstream? | Round-2 detector? | Action for test set |
|---|---|---|---|---|
| Generic recon / `.env` / phpunit / CGI RCE | ✅ heavy | n/a (no such routes) | existing | Keep a small **regression** subset (replay) |
| Path traversal / command injection | ✅ (cgi-bin) | `/static`,`/public`,`/assets`,`/cgi-bin` | existing | Expand with evasion variants |
| SQLi / NoSQLi | ❌ | ✅ (`page`,`limit`,`{id}`,login,`name`) | existing | **Build from scratch** |
| XSS (reflected/stored) | ⚠️ 1 probe | ✅ (`name` reflect, `feedback` store) | existing | **Build from scratch** |
| SSRF | ❌ | ✅ (`callback_url`, `integrations/preview`) | existing | **Build from scratch** |
| CORS | ❌ | ✅ (`/api/public/stats`, credentialed reads) | existing | Build (benign + abuse) |
| Request smuggling / CRLF / protocol | ❌ | ✅ (proxy in path) | existing | Build |
| Rate-limit / cred-stuffing | ⚠️ 58 challenges | ✅ (`/login`,`/otp`) | existing | Build burst cases |
| **WebSocket** (handshake + frames) | ❌ | ✅ `/ws/live` | **NEW** | **Heavy** — handshake abuse + frame injection + DoS |
| **SSE** | ❌ | ✅ `/api/notifications/stream` | **NEW (WS family)** | **Heavy** — hijack, splitting, auth-bypass |
| **JWT** | ❌ | ❌ (app is cookie-only) | **NEW** | Build against the WAF's Bearer detector; flag as synthetic |
| **Response caching** | ❌ | ✅ (`/static`, `/api/public/stats`) | **NEW** | **Heavy** — poisoning + deception |
| Admin/control exposure | ❌ | ✅ `/__control/*`, `/admin/*` | existing | Build (must block from data plane) |

### 3.1 Gaps the logs missed (now covered by the set)

1. **Every authenticated NovaBet route** — logs saw none; the set drives them with realistic benign traffic *and* attacks.
2. **WebSocket handshake + post-upgrade frames** — the single biggest new surface; 322 cases (crafted + the teammate 20k-sample dataset, retargeted to the local WAF).
3. **SSE** stream hijack / response-splitting / auth-bypass — 92 cases.
4. **Cache poisoning & deception** — 33 cases, plus benign conditional-GET FP checks.
5. **JWT detector** — 61 cases (alg:none, expired, nbf, wrong iss/aud, forged sig, alg-confusion, kid/jku injection) + benign well-formed tokens as FP checks.
6. **False-positive realism** — 122 benign cases including FP traps: names with apostrophes (`O'Brien`), prose containing `select`/`drop`/`union`, i18n display names, multipart KYC, gzip analytics, CORS preflight, conditional GETs, and a benign authenticated WS handshake/subscribe.

---

## 4. How the WAF signals a verdict (for the runner)

From the proxy/security crates:

- Responses carry **`X-Aegis-Decision: allow | block | challenge`** (primary signal), plus `X-Aegis-Rule-Id` (which detector fired) and `X-Aegis-Request-Id` (audit correlation).
- **Block** → HTTP **403** `{"error":"forbidden"}`; **challenge / rate-limit** → **429**; oversize body → **413**; WS oversize frame → fail-closed **1009** close in enforce mode.
- Cache hits expose **`X-WAF-Cache: HIT|MISS`**.

The runner reads `X-Aegis-Decision` first and falls back to status code. Local note: `waf.yaml`'s upstream is an inline **stub that returns "OK"** and issues no real session — so the runner uses a dummy `sid` cookie by default (`--login` will attempt the real flow if pointed at a full upstream). The cookie's *validity* doesn't matter for WAF-layer verdicts; request **shape** is what the detectors judge.

---

## 5. Test-set summary (Phase 3 output)

1,159 cases across 14 classes (1,037 attack / 122 benign). New-surface weighting: WebSocket 322, SSE 92, caching 33, auth-jwt 61. See `../cases/manifest.json` and the suite `../README.md`. Run with `../run.sh`.
