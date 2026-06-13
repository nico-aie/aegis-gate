# Aegis-Gate — Live WAF Report (Chrome-driven, partial)

**When:** 2026-06-13  ·  **Target:** `http://localhost:8080` (WAF → mock upstream :9999)
**Driver:** Claude-in-Chrome in-page `fetch` (runs on your Mac, reaches localhost; my code sandbox is network-isolated from your localhost, so curl from my side is blocked by the egress allowlist).
**Config under test:** all detectors enabled, cumulative IP-risk thresholds disabled.

## How verdicts were read
This WAF does **not** emit `X-Aegis-Decision` on these responses (only `X-WAF-Cache`), so verdict = **HTTP status**: `403/413 → block`, `429 → challenge`, `200/401/404/3xx → allow` (request passed the WAF; upstream answered). This matches the runner's documented status fallback.

## Coverage of this live run
Browser `fetch` cannot forge `Origin`, `Host`, `Cookie`, or `Upgrade`, so these classes are **NOT** in this run and must be done with the curl runner: **websocket (322), sse cross-origin, cors, protocol/smuggling/host-header**, and authenticated cases needing a real `sid`. What follows is **real** data for what the browser can faithfully send.

- **injection-sqli — full class: 110 cases, 102 pass, 0 FP, 8 FN.**
- **Cross-class probe — 35 representative cases: 27 pass, 2 FP, 6 FN** (cmdi, nosql, xss, path-traversal, ssrf, jwt, caching, control-endpoint, benign).

---

## ❌ False negatives — attacks the WAF let through (fix these)

| id / probe | class | request | got | why it matters |
|---|---|---|---|---|
| sqli-0096..0099 | sqli | `?page=0x27206f7220313d31` (hex for `' or 1=1`) on page/limit/`/game/{id}`/name | 200 | **Hex-literal encoding bypasses SQLi detection** — 4 variants all passed |
| sqli-0025/0050/0100 | sqli | `POST /login` with SQLi in `username` body | 401 | **Login JSON body not inspected for SQLi** (reached upstream) |
| sqli-0048 | sqli | `GET /game/1 AND 1=CONVERT(int,@@version)` | 200 | space-separated SQL after numeric path id not caught |
| cmdi-feedback-semi | cmdi | `POST /api/feedback {"comment":"; id"}` | 200 | **Command injection in JSON body not detected** |
| trav-dotdot | path-traversal | `/static/%2e%2e/%2e%2e/%2e%2e/.env` | 404 | **`%2e%2e` traversal not normalized/blocked** (passed to upstream) |
| jwt-expired | auth-jwt | expired HS256 `Bearer` on `/api/profile` | 200 | **JWT detector does not reject expired tokens** |
| jwt-forged | auth-jwt | forged-sig `Bearer` on `/admin/users` | 404 | forged token passed (upstream 404) |
| cache-deception | caching | `/api/profile/nonexistent.css` | 404 | cache-deception path not flagged |
| ctl-state | control | `/__control/state` + guessed secret | 404 | not exposed (effectively safe via 404) but not explicitly blocked |

The high-impact misses are the ones that returned **200** (reached and processed by upstream): **hex-encoded SQLi, login-body SQLi, command-injection in feedback, and the expired JWT.** The `404` ones are lower-impact (upstream rejected anyway) but still detector gaps.

## ⚠️ False positives — benign traffic the WAF blocked (tune these down)

| id / probe | request | got | note |
|---|---|---|---|
| ben-feedback-prose | `POST /api/feedback {"comment":"I would like to select a table and drop my old bet."}` | 403 | **SQLi rule over-matches natural-language prose** ("select"… "drop"). Highest-value FP to fix. |
| ben-deposit | `POST /deposit {"amount":500,"currency":"USD"}` | 403 | ⚠️ caveat: sent without a `sid` cookie (browser can't set it). Re-test with the curl runner's dummy `sid` to confirm whether this is a content FP or an auth artifact. |
| `/health` | `GET /health` | 403 | benign health endpoint returns 403 — confirm whether intended (recon-path policy?) or a FP. |

## ✅ Working well (confirmed real blocks)
- **SQLi 102/110:** classic `UNION SELECT`, `OR 1=1`, `admin'--`, comment-spacing, mixed-case, and double-URL-encoded variants → all 403.
- **XSS:** `<script>`, `<img onerror>`, `<svg onload>`, and URL-encoded `<svg/onload=alert\`1\`>` → 403 (reflected `name=` and stored `feedback`).
- **NoSQLi:** `$ne` / `$gt` / `$regex` operator injection on `/login` → 403.
- **SSRF:** `169.254.169.254` metadata, `127.0.0.1:9443`, and `callback_url` SSRF → 403.
- **JWT alg:none** → 403 (detector catches alg-none, but **misses expired** — see FN).
- **Path traversal** with URL-encoded slashes (`..%2f..%2f..%2fetc%2fpasswd`) → 403 (but `%2e%2e` dot-encoding missed — see FN).
- **Cache poisoning** via `X-Forwarded-Host` / `X-Original-URL` → 403.

---

## Top fixes suggested by this run
1. **SQLi decoder gap:** normalize/decode **hex literals** (`0x...`) and inspect them; 4 clean bypasses.
2. **Body coverage:** run SQLi/command-injection detectors on **JSON request bodies** for `/login` and `/api/feedback` (currently missed).
3. **JWT:** enforce **`exp`** (and `nbf`) — expired tokens currently pass.
4. **Path normalization:** decode **`%2e%2e`** before the traversal check.
5. **SQLi FP tuning:** stop matching plain-language `select`/`drop` in free-text fields like `feedback.comment`.

## To complete the picture (the part a browser can't send)
Run the full faithful suite locally — it sets `Origin`/`Host`/`Cookie`/`Upgrade` via curl, covers WebSocket/SSE/CORS/protocol, and uses a dummy `sid` for authed cases. Its report writes into this same `reports/` folder, which I can read and merge:

```sh
cd <repo>/tests/n-tester/r2-regression
WAF_BASE_URL=http://localhost:8080 bash run.sh --all
# or class-by-class, e.g. the new surfaces:
WAF_BASE_URL=http://localhost:8080 bash run.sh websocket cors protocol auth-jwt caching
```

It produces `reports/latest.md` (per-class detection rates + every FP/FN inline + bypass-by-evasion). Ping me when it's done and I'll fold it together with these live findings into one report.
