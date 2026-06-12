# JWT attack detection + HTTP-smuggling hygiene (future plan)

> **Status:** Drafted 2026-06-12. Response to two security-team reports —
> `plans/issues/JWT_ATTACK_REPORT.md` (600 samples, 0% effective detection)
> and `plans/issues/HTTP_SMUGGLING_REPORT.md` (185 sent, 49.7% missed).
>
> **Honest reframing first** (code-verified against `develop`, per the
> standing "docs drift both ways" caution): the two reports are *not*
> equal-severity. The JWT gap is **real** — cookies pass through the WAF
> untouched and JWT decoding is a deferred stub. The smuggling gap is
> **mostly an attribution/observability problem, not a pass-through hole** —
> hyper already rejects the ambiguous requests before any detector runs,
> and the WAF re-serializes every upstream request with fresh framing, so
> the smuggled inner request never reaches the backend. Details in §1.
>
> Decisions locked with Nico (2026-06-12):
> - **JWT = detection-only attack shapes.** WAF decodes the JWT header +
>   payload and flags malicious *structure*. **No signature verification,
>   no secret handling, no expected-alg-per-app config** — signature/auth
>   stays in the gateway (see [[project_waf_vs_gateway_boundary]]).
> - **Rollout = structural blocks, heuristics log-first.** Unambiguous
>   shapes emit a blocking-tier score → 403 + audit attribution.
>   FP-prone claim heuristics ship `log_only` and graduate after traffic
>   observation.

---

## 1. Method + honest baseline

### 1.1 How a request reaches a detector (why this matters)

The data plane runs on **hyper**. By the time any detector sees a request:

- `data_plane.rs:722` — `req.into_parts()` then `body.collect().await`; the
  body is **fully buffered**.
- `data_plane.rs:752` — `BodyPeek::new(body_bytes, Some(len), false)` — note
  the hardcoded `chunked: false`. Detectors **never** see chunked framing or
  raw duplicate `Content-Length` / `Transfer-Encoding` bytes. They see a
  parsed `http::HeaderMap` and a flat body.
- Outbound, `data_plane.rs:2244` strips `Content-Length` + `Transfer-Encoding`
  and rebuilds the message as `Full<Bytes>` so **hyper computes framing**.

**Consequence for smuggling:** hyper's HTTP/1 parser is RFC-strict. A request
with conflicting `Content-Length` values, or `CL`+`TE` together, or a bad
chunked body, is rejected by hyper itself with **400 Bad Request** — that is
exactly the "WAF response: 400 Bad Request — not blocked" the report logs for
every TE technique. The report counts 400 as a *miss* because it isn't a 403,
but **the attack does not pass through**: the upstream request is a fresh,
hyper-serialized message with a fixed-length body. There is no frontend/backend
framing disagreement to exploit because the WAF *is* a strict re-serializing
hop.

So the smuggling report's "49.7% missed" decomposes into:

| Cause | What it really is |
|-------|-------------------|
| TE.CL / CL.TE / TE.TE → 400 | hyper **rejected** it; safe, but logged as generic 400 with no WAF attribution |
| `urllib` "connection error" rows | test-tool can't send raw chunked at all — not a WAF signal |
| H2.TE downgrade | the WAF does **not** downgrade H2→H1 to a pooled H1 backend by re-emitting `transfer-encoding`; H2 bodies are collected like H1. Forbidden H2 headers should still be rejected explicitly |
| CRLF-in-header-value | **partially covered today** by `header_injection` (`INJECTION_PATTERNS`) |

This does **not** mean "do nothing." It means the smuggling work is
**defense-in-depth + attribution**, not closing a live bypass — and should be
scoped/prioritized accordingly (below JWT).

### 1.2 What already exists (verified)

- **Detectors** live in `crates/aegis-security/src/detectors/`, registered in
  `default_detectors_with()` (`mod.rs:495`), gated by `DetectorClass` mask
  bits (`mask.rs:39`), scored from the central ladder (`scores.rs`).
- **`header_injection.rs`** already scans header values + query for CRLF,
  `Transfer-Encoding:` literals, response-splitting shapes, XFH poisoning,
  URL-override + method-override bypasses. This is the natural home for the
  smuggling header-hygiene rules.
- **`auth/jwt.rs`** is a **deferred stub** — `validate()` parses base64 but
  does not verify signatures, **zero callers**. It is roadmap scaffolding, not
  a live path. We will **not** wire it; the new work is a *detector*, not an
  auth validator.
- `view.version: http::Version` is available to every detector, so
  `HTTP_2`-specific rules are feasible.

---

## 2. Workstream A — JWT attack-shape detector (REAL gap, priority)

### 2.1 Goal

A new detector `jwt_inspection` that, for any request carrying a JWT-shaped
token, Base64URL-decodes **only the header (part 0) and payload (part 1)**,
parses them as JSON, and emits signals for malicious structure. **It never
touches the signature and never decides authenticity** — that is the gateway's
job. It is exactly analogous to the sqli/xss detectors: pattern-match an
attack shape in attacker-controlled input.

### 2.2 Where JWTs live

Reports put the token in `Cookie: sid=<jwt>`. Real traffic also uses
`Authorization: Bearer <jwt>`. The detector scans, in order:

1. `Authorization: Bearer …`
2. `Cookie:` values matching the JWT regex
   `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$` (any cookie name, not
   just `sid` — don't hardcode the corpus's name, per
   [[feedback_challenge_band_diagnostics]] anti-fixture discipline).

Cap: decode at most the first ~2 JWT-shaped tokens per request; cap each
decoded part at a few KB to bound CPU. Bail before allocating if no `.`-triple
shape is present.

### 2.3 Rules (map to the report's JWT-001…007)

| Sub-tag | Fires when | Action | Score |
|---------|-----------|--------|-------|
| `jwt_alg_none` | header `alg` (ASCII-lowercased, trimmed) ∈ {`none`,`null`,``} | **block** | 80 |
| `jwt_jku_external` | header has `jku`/`x5u` whose host ∉ allowlist | **block** | 80 |
| `jwt_x5c_inline` | header has `x5c` / `jwk` (inline key material) | **block** | 80 |
| `jwt_kid_injection` | `kid` contains `../`, `..\`, leading `/etc/ /dev/ /proc/ /sys/`, SQL metachars `' " ; -- OR/UNION`, or `http(s)://`/`file://` | **block** | 80 |
| `jwt_time_forged` | `exp` > now+10y, OR `iat` < now-10y, OR (`iat`==0 AND `nbf`==0) | **block** | 70 |
| `jwt_role_priv` | payload `role`/`scope` ∈ {admin,superadmin,root,…} | **log_only** | 50 |

Notes:
- `jwt_alg_none` covers both `alg_none_no_signature` and
  `alg_none_capital_bypass` via case-insensitive compare — the report's #1 and
  #2 (147 samples).
- `jwt_jku_external` + `jwt_x5c_inline` are the SSRF / key-injection families
  (#4, #5 — 156 samples). Allowlist defaults to **empty = block any external
  jku/x5u** (legit production tokens reference an internal JWKS, not a header
  URL). Operator-tunable via config like `open_redirect.allowed_domains`.
- `jwt_kid_injection` — #6 (69 samples).
- `jwt_time_forged` — #8 claim manipulation (72 samples), structural enough to
  block (no legit token sets `iat:0,nbf:0`).
- `jwt_role_priv` — the only heuristic; **log_only** because a real admin user
  legitimately carries `role:admin`. Graduates only after traffic review,
  ideally combined with a mismatch signal (see §2.5).

**Explicitly out of scope** (need a secret/key → gateway, not WAF):
- `weak_secret_brute_forced` (#7) — tokens have *valid* signatures; the WAF
  cannot distinguish them cryptographically. Mitigation is app-side secret
  entropy + rotation. Document as a non-WAF item.
- `rs256_to_hs256_confusion` (#3) — needs the app's expected alg + the public
  key. The report's own JWT-007 admits "requires WAF config per application."
  This is gateway/auth territory per [[project_waf_vs_gateway_boundary]]. We
  will note it; a *weak* structural proxy (flag `HS256` only if operator
  declares the app is RS256-only) is a possible later opt-in, off by default.

Realistic coverage: ~6 of 8 techniques, the 5 critical structural ones at
block. The 2 omitted are genuinely not WAF-solvable without crossing the
boundary.

### 2.4 Files to touch

- **New** `crates/aegis-security/src/detectors/jwt_inspection.rs` — detector +
  Base64URL/JSON decode helpers + the rule set + ~40 positive / ~40 negative
  unit tests (real legit JWTs must stay green: normal `alg:HS256`/`RS256`,
  internal `kid`, sane `exp`).
- `detectors/mod.rs` — `pub mod jwt_inspection;` + `Box::new(...)` in
  `default_detectors_with()`.
- `detectors/mask.rs` — add `DetectorClass::JwtInspection` (enum, `as_str` →
  `"jwt_inspection"`, bit `1 << N`, `all()`, `ToggleMask` plumbing).
- `detectors/scores.rs` — `pub mod jwt_inspection { … }` consts + `CATALOG`
  rows (tests assert every class has a catalog entry).
- `aegis-core/src/config.rs` — `DetectorsConfig` gains an optional
  `jwt_inspection { jku_allowed_domains: Vec<String> }`.
- Dashboard detector list + per-detector doc under `docs/security/`.
- Dependency: a small Base64URL decode (already pulled transitively, or hand-
  roll the URL-safe alphabet — no new heavy crate; `serde_json` is already a
  dep).

### 2.5 Stretch (after base ships)

`jwt_role_priv` → real signal: cross-check the decoded `role` against the
session/risk store for the same IP/device, or require a second signal (new IP +
`role:admin`) before scoring. Reuses the cumulative IP-risk model
([[feedback_two_score_model.md]]). Keep log_only until then.

---

## 3. Workstream B — Smuggling header hygiene + attribution (defense-in-depth)

> Lower priority than A. The attacks are already stopped by hyper (§1.1); this
> turns silent 400s into attributed `request_smuggling` WAF events and adds a
> cheap structural backstop in case a future code path ever forwards raw
> framing (e.g. the TCP-tunnel / H2C passthrough paths).

### 3.1 Rules — extend `header_injection.rs` (no new detector needed)

All are header-only, near-zero FP, run before body work.

| Sub-tag | Fires when | Action | Score | Report rule |
|---------|-----------|--------|-------|-------------|
| `smuggling_cl_te` | request has both `Content-Length` and `Transfer-Encoding` | **block** | 70 | SMUG-001 |
| `smuggling_multi_te` | `headers.get_all("transfer-encoding")` count > 1, OR a single TE value ∉ {`chunked`,`identity`,`gzip`,`deflate`,`compress`,`br`} (covers `xchunked`, `chunked, identity`, trailing-space obfuscation) | **block** | 70 | SMUG-002 |
| `smuggling_multi_cl` | `headers.get_all("content-length")` count > 1 | **block** | 70 | SMUG-001 |
| `smuggling_h2_forbidden` | `version == HTTP_2` AND header `transfer-encoding` or `connection` present (RFC 9113 §8.2.2) | **block** | 70 | SMUG-004 |

CRLF-in-header-value (SMUG-003) is **already covered** by the existing
`INJECTION_PATTERNS` / `check_crlf` — add explicit test cases pinning the
smuggling payloads, don't re-implement.

### 3.2 Body-embedded request line (SMUG-005) — optional, defense-in-depth

The WAF *does* have the buffered body (`BodyPeek`). A single anchored regex over
the first N KB of body —
`(?im)^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+/\S*\s+HTTP/\d\.\d` —
flags an embedded request line. **FP risk is real** (API docs, proxies-of-
proxies, log-ingestion endpoints legitimately carry request lines in bodies),
so this one ships **log_only** and is evaluated before any promotion. Lives in
`body_abuse.rs` (it already owns body scanning + its limits), not
`header_injection.rs`.

### 3.3 Why NOT to chase the rest

- SMUG-006 "strict chunked body validation" — **moot**. The WAF doesn't parse
  chunked; hyper does, and rejects bad chunks. Re-implementing a chunk parser
  to second-guess hyper is cost with no marginal safety.
- "Parse chunked body for embedded requests" — same; hyper already de-chunked.

### 3.4 Files to touch

- `detectors/header_injection.rs` — add the four §3.1 checks + `get_all`
  iteration; tests (positive smuggling payloads from the report + negatives:
  normal `Transfer-Encoding: gzip`, single CL, H2 without forbidden headers).
- `detectors/scores.rs` — `header_injection` mod gains `SMUGGLING` const (70)
  + catalog rows; or reuse `CRLF`.
- `detectors/body_abuse.rs` — optional §3.2 log_only rule + score const.
- Sub-tags surface on the existing `header_injection` / `body_abuse` classes —
  **no new `DetectorClass`**, so dashboard/mask wiring is untouched.

---

## 4. Phasing

| Phase | Scope | Gate to next |
|-------|-------|-------------|
| **A1** | JWT decode core + `jwt_alg_none`, `jwt_x5c_inline`, `jwt_kid_injection` (the no-config structural blocks) + tests | unit green, no FP on legit-JWT corpus |
| **A2** | `jwt_jku_external` (+ `jku_allowed_domains` config), `jwt_time_forged`; mask + scores + catalog + config + dashboard | `/api/detectors` shows class; toggle works |
| **A3** | `jwt_role_priv` **log_only**; per-detector doc; QC test-plan document (descriptive, per [[feedback_qc_script_means_doc]]) | reviewed in `log_only`, decide promote |
| **B1** | §3.1 four header-hygiene rules in `header_injection` + tests + scores | unit green; re-run smuggling dataset shows 403+attribution on CL/TE/multi-TE/H2 rows |
| **B2** | §3.2 body-embedded-request-line **log_only** | evaluate FP before any promote |

A-phases first. B is independent and can slot whenever; it's smaller.

## 5. Testing

- **Unit (primary):** per [[project_rustfmt_whole_crate_hazard]] hand-match
  style in the big shared files; only `rustfmt` files you author whole (the new
  `jwt_inspection.rs`). Each rule gets positive + negative cases. Negatives are
  the FP guard — a legit `RS256` token with internal `kid` and sane `exp` must
  stay green; `Transfer-Encoding: gzip` must not flag.
- **Anti-fixture discipline:** do not match the corpus's literal strings
  (`attacker.evil.com`, `sid=`, `novabet`). Match **structure** (external host,
  `alg:none`, inline key, traversal in `kid`) — the F-CRITICAL-012 lesson.
- **Integration:** drive real payloads through the data plane. JWT in a cookie
  → expect 403 + `jwt_inspection` audit tag. For smuggling, use raw sockets
  (`printf … | nc`, report §6) — confirm CL+TE now yields an **attributed**
  403/`request_smuggling` rather than a bare 400. Mind the dev single-IP / XFF
  gates and reset between runs ([[feedback_dev_xff_single_ip_gates]],
  [[feedback_e2e_docker_cleanup]]).
- **Verify actual outcome** via HTTP status / `X-WAF-Mode`, not just
  `X-WAF-Action` ([[feedback_waf_action_vs_mode]]) — heuristic rules in
  `log_only` will show the would-be action without enforcing.

## 6. Honest coverage estimate (set expectations for the report-back)

| Report technique | Outcome after this plan |
|------------------|------------------------|
| JWT alg:none (+case) | **blocked** (structural) |
| JWT jku/x5u SSRF | **blocked** (external-host) |
| JWT x5c/jwk inline | **blocked** |
| JWT kid traversal/SQLi | **blocked** |
| JWT time-claim forge | **blocked** |
| JWT role escalation | **logged** (log_only; heuristic) |
| JWT weak-secret crack | **out of scope** — valid sig, app-side fix |
| JWT RS256→HS256 | **out of scope** — needs key/expected-alg (gateway) |
| Smuggling CL/TE, multi-TE, multi-CL, H2-forbidden | **blocked + attributed** (were already 400-rejected by hyper; now labeled) |
| Smuggling CRLF-in-header | already covered; tests pinned |
| Smuggling body-embedded line | **logged** (log_only) |
| Smuggling chunk-body internals | **n/a** — hyper owns chunk parsing |

Net: JWT goes from ~0% → ~6/8 techniques blocked at the WAF, the 2 omitted are
genuinely gateway/app concerns. Smuggling goes from "looks 50% missed" to
"already safe, now properly attributed," with an honest note to the security
team that the original 400s were rejections, not bypasses.

## 7. Related

- [[project_waf_vs_gateway_boundary]] — why JWT is detection-only, not validation.
- [[feedback_two_score_model.md]] — how scores feed per-request + cumulative risk.
- [[project_docs_overstate_impl]] — this plan is code-verified; keep it honest.
- Reports: `plans/issues/JWT_ATTACK_REPORT.md`, `plans/issues/HTTP_SMUGGLING_REPORT.md`.
