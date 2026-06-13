# TRIAGE — "WAF Security Report — NovaBet" (2026-06-10)

**Type:** gap analysis / triage + fix plan
**Severity:** 🟢 Low (one small, low-FP detector extension; everything else covered or out-of-scope)
**Source report:** [`waf_security_report.md`](./waf_security_report.md)
**Triaged:** 2026-06-13
**Status:** ✅ Phase 1 shipped 2026-06-13 — `recon` list extended (`config.yaml`/secret-yaml/key-keystore), score kept at 25. All other findings covered or out-of-scope (no further action).

---

## TL;DR

The source report is a **pentest of the intentionally-vulnerable benchmark
target** (NovaBet, `sec-team.waf-exams.info`), not an evaluation of aegis-gate.
Every "WAF Rule" it proposes is generic nginx / ModSecurity; it never looks at
our detectors. Mapped onto aegis-gate's actual pipeline, **12 of 14 findings are
either already covered by an existing detector or are app/gateway-layer logic
flaws outside the WAF boundary.**

The only finding that yields a real (and minor) WAF change is **VULN-03**:
`recon` flags `.env` / `.git` / `openapi.yaml` but not a bare `GET /config.yaml`
or private-key/keystore files. Fix = extend the `recon` path list (keep the
existing probe score 25 — accumulation is the intended model, per operator
decision 2026-06-13).

Two findings (VULN-13/14, HTTP-method hardening — TRACE/WebDAV/PUT/DELETE on
sensitive files) are **declared out of WAF scope**: method allowlisting belongs
in the router/gateway alongside token/HMAC/business-rule auth, same boundary call
as [[project_waf_vs_gateway_boundary]].

> The file name says "ws attack" in the triage request, but this report is **not**
> the WebSocket report — `/ws/live` is listed as Low risk in it. The real open WS
> gap (RC-2 Origin allowlist / RC-4 SSE CORS / RC-5 `Sec-WebSocket-Protocol`)
> stays tracked under [`WEBSOCKET_ATTACK_REPORT.md`](../WEBSOCKET_ATTACK_REPORT.md).

---

## 1. Finding-by-finding triage

Evidence column cites the detector source under
`crates/aegis-security/src/detectors/`.

### ✅ Already covered — the report is misleading on these

| ID | Report claim | Reality in aegis-gate | Evidence |
|----|--------------|------------------------|----------|
| VULN-04 | Path Traversal via `/static/../.env`, `/static/%2e%2e/.env`, encoded variants | `path_traversal` (score **70**) matches `../`, `%2e%2e[\\/]`, `%2e%2e%2f`, `%252e…`, `\..%5c`, overlong-UTF8 `%c0%af`, plus `/etc/passwd`, `/proc/self/*`, `docker.sock`. Decoder pass (`normalize_for_detection`) recovers double/triple URL- and HTML-entity-encoding. Blocks single-hit on critical/high/medium tiers. | `path_traversal.rs:10-69`, tests `double_url_encoded`, `mixed_encoding`, `overlong_utf8_slash` |
| VULN-07 | SSRF via `{"url":"http://169.254.169.254/…"}` — "can't block at WAF, URL is in body" | **False.** `ssrf` (score **70**) scans query, path, forwarding headers **and the request body** (`req.body.peek(8192)` + `url_decode`). Internal IPs, cloud-metadata, `file:`/`gopher:`/`dict:` schemes, userinfo-bypass all caught. | `ssrf.rs:69-99` (`check_ssrf(&url_decode(body), "body", …)`) |
| VULN-08 | Stored XSS in `/api/feedback` `comment` field | `xss` (score **70**) scans the body (URL- + HTML-entity-decoded) and headers. `<script>`, `javascript:`, event handlers caught. | `xss.rs:53-86` |
| VULN-01 | `GET /.env` serves DB password | `recon` flags `\.env(\.|$)` — but score **25** (probe tier): accumulates, does **not** single-block on protective tiers. Intentional (see §3). | `recon.rs:12`, `scores.rs:116` |
| VULN-02 | `GET /.git/config`, `/.git/HEAD` | `recon` flags `\.git(/|$)` at score **25**. Same accumulation model. | `recon.rs:13` |
| VULN-09 | `GET /openapi.yaml` exposes API spec | `recon` flags `openapi\.yaml` at score **25**. (Exposing the spec is also an app/deploy choice — it's served deliberately on this benchmark.) | `recon.rs:62` |
| VULN-10 | `GET /wp-admin` fake honeypot | `recon` flags `(?:^|/)wp-admin(?:$|[/?])` at score **25**. | `recon.rs:27` |

### 🚫 Out of WAF scope — app / gateway boundary

| ID | Report claim | Why it's not a WAF gap |
|----|--------------|------------------------|
| VULN-05 | Broken access control — admin routes don't check `role` | Authorization / role enforcement is gateway/app logic, not pattern detection. Same boundary as token/HMAC auth ([[project_waf_vs_gateway_boundary]]). |
| VULN-11 | `/__control/*` only protected by `X-Benchmark-Secret` | Secret-gated app control surface. A WAF path-block is possible but it's the target's own benchmark harness, not a production route — recording, not fixing. |
| VULN-12 | PII (SSN/card) returned by `GET /api/profile` | A *legitimate* authenticated endpoint returning the caller's own data. Response-side PII redaction would be a DLP feature, not an attack signal; out of this report's scope. |
| VULN-06 | Asymmetric DoS — `/api/bet-reports/export` returns ~287 KB for a tiny request | Response *size* amplification is app-side. The WAF's `rate_limit` module throttles request *rate* (partial mitigation only); it cannot cap an upstream's response size. Tunable per-route rate limit is the available lever if desired — not a detector gap. |

### ⚠️ Out of WAF scope by operator decision (2026-06-13) — recorded, not planned

| ID | Report claim | Decision |
|----|--------------|----------|
| VULN-13 | PATCH/PUT/DELETE/HEAD/OPTIONS accepted on `/.env`, `/config.yaml` | **Gateway, not WAF.** Per-route HTTP-method allowlisting belongs with the router/gateway auth layer. (Target returning 200 to PATCH `.env` is a target-app quirk; the request still trips `recon` on the `.env` path regardless of verb.) |
| VULN-14 | TRACE not blocked → XST risk | **Gateway, not WAF.** Same method-policy boundary call. Note: aegis-gate already has a `method_override_bypass` heuristic for the `X-HTTP-Method-Override` *header* carrying a destructive verb (`header_injection`, score 50) — that's the override-smuggling vector, distinct from restricting the real request method. |

### ✏️ True WAF gap — the only actionable item

| ID | Report claim | Gap | Fix |
|----|--------------|-----|-----|
| VULN-03 | `GET /config.yaml` serves DB password | `recon` covers `.env`/`.git`/swagger+openapi `.yaml`, but **not** a bare `config.yaml`/`config.yml`, nor private-key/keystore files (`.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`). A direct fetch of these is unflagged. | Phase 1 below — extend `RECON_PATHS`, FP-anchored, keep score 25. |

---

## 2. Phase 1 — extend `recon` sensitive-file coverage (only planned change)

**File:** `crates/aegis-security/src/detectors/recon.rs` (`RECON_PATHS`)
**Score:** unchanged — `recon::PATH` = 25 (probe tier; accumulates). Per operator
decision, sensitive-file hits stay on the accumulation model, **not** promoted to
a single-hit block.
**Risk:** Low. Additions are high-signal filenames; the FP concern is real for
generic extensions, so anchor each pattern (root or path-segment + value
boundary), exactly as the existing `.env`/admin-panel rules already do.

### Proposed patterns (review each for FP before merging)

```rust
// Bare config files at a path segment — DB creds / secrets land here.
// Anchored to a segment so it won't fire mid-word.
r"(?i)(?:^|/)config\.ya?ml(?:$|[?#])",
r"(?i)(?:^|/)(?:secrets?|settings|credentials)\.ya?ml(?:$|[?#])",

// Private-key / keystore material. Restrict to the private-bearing
// extensions; deliberately EXCLUDE .crt/.cer/.der (public certs are
// sometimes legitimately downloadable) to keep FP at zero.
r"(?i)\.(?:pem|key|p12|pfx|jks|keystore)(?:$|[?#])",
```

**Explicitly NOT added (FP risk > signal):**
- Generic `\.(yaml|yml|json|toml|ini|cfg|conf)$` (the report's nginx rule) — far
  too broad; legit APIs serve `*.json`/`*.yaml` (e.g. `/manifest.json`, config
  endpoints). The `recon` doc already rejects this style of blanket rule.
- `.crt` / `.cer` / `.der` — public certs are sometimes served intentionally.

### Tests to add (mirror existing `path_positive!` / `path_negative!` macros)

Positives:
- `/config.yaml`, `/config.yml`, `/app/config.yaml`
- `/secrets.yaml`, `/settings.yml`, `/credentials.yaml`
- `/server.pem`, `/tls.key`, `/keystore.p12`, `/store.jks`, `/cert.pfx`

Negatives (must stay clean — pin the anchoring):
- `/manifest.json`, `/api/data.json`, `/feed.xml`
- `/docs/config-guide` (substring, not a `.yaml` file)
- `/reconfigure.yaml`? → would match `config\.ya?ml`? No — `reconfigure` ends in
  `figure`, not `config.yaml`; add `/reconfigure-status` as an explicit negative
  to prove the segment anchor holds.
- `/public-key-info`, `/monkey.html` (no `.key` extension boundary)
- `/style.css`, `/main.js` (unrelated extensions)

### Acceptance gate — ✅ met 2026-06-13

- [x] `cargo test -p aegis-security recon` green — 160 unit + 5 red-team recon
      integration tests pass (17 new positives, 2 new negatives).
- [x] `cargo clippy -p aegis-security` introduces **no** new warnings in
      `recon.rs` (the 4 lib warnings are pre-existing in `open_redirect.rs`).
- [x] Score unchanged at 25 — no `scores.rs` edit; `recon_path` catalog row
      already documents the class accurately.
- [x] No regression in the existing `recon` FP negatives.

> Match surrounding `recon.rs` style by hand — do **not** `cargo fmt` the whole
> file ([[project_rustfmt_whole_crate_hazard]]).

---

## 3. Why sensitive-file hits stay at score 25 (design note)

`recon::PATH` = 25 sits in the *probe* tier deliberately. A lone `GET /.env` is a
recon probe, not an exploit — the scoring ladder reserves single-hit blocking
(70–100) for unambiguous exploits (sqli/xss/ssrf/traversal/RCE/canary). Probes
accumulate via the per-IP cumulative risk model (max-per-request + decay,
[[feedback_two_score_model]]) so a scanner sweeping `.env`→`.git`→`config.yaml`
climbs to a block, while a single stray hit doesn't nuke a real user. If an
operator wants a hard tripwire on a specific path, that's what `risk.canary_paths`
(score 100, single-hit block every tier) is for. Operator decision 2026-06-13:
keep this model; widen coverage only.

---

## 4. Out-of-scope items — disposition summary

| Finding | Disposition |
|---------|-------------|
| VULN-05 admin role authz | Gateway/app. No WAF action. |
| VULN-06 asymmetric DoS | App response-size; optional per-route `rate_limit` tuning only. |
| VULN-11 `/__control/*` secret gate | Benchmark harness surface; no WAF action. |
| VULN-12 PII in `/api/profile` | Legit authed endpoint; DLP-adjacent, not in scope. |
| VULN-13 methods on sensitive files | Gateway method-policy. No WAF action (operator decision). |
| VULN-14 TRACE / XST | Gateway method-policy. No WAF action (operator decision). |

---

## 5. Verification context (so a re-test reads correctly)

If anyone re-runs the report's requests against aegis-gate to confirm the
"already covered" rows, account for the harness gotchas already documented:

- The covered exploits (traversal/SSRF/XSS, score 70) block only when the route
  tier is protective (critical/high/medium) **and** the WAF is in enforce, not
  `log_only` — check HTTP status / `X-WAF-Mode`, not just `X-WAF-Action`
  ([[feedback_waf_action_vs_mode]]).
- `recon` probes (25) won't show a block on a single request by design (§3) —
  that is expected, not a miss ([[feedback_challenge_band_diagnostics]]).
- In dev, all traffic resolves to `127.0.0.1` and the per-IP risk gate poisons
  after the first attacks; reset between cases ([[feedback_dev_xff_single_ip_gates]]).
```
