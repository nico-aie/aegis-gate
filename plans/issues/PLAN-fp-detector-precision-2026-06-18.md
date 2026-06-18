# PLAN — Benign over-block triage: detector precision on the 200k atk/normal run (2026-06-18)

- **Type:** PLAN (report double-check → root-caused FP-fix backlog, per-rule fix specs)
- **Status:** 🟡 **IN PROGRESS** (2026-06-18) — detector-fixture loop landed for **S1, S4, S5, S2 (body gate)**
  on `develop`; full `aegis-security` lib suite green (1774 tests). Remaining: **S2-2** (URI opaque-segment
  guard), **S3** (jwt), **S6** (header/ssrf — blocked on **S0** harness instrumentation), **S7** (minor).
  - ✅ **S1** §2c — `MASS_ASSIGN_QUERY_KEYS` split: query scan restricted to privilege-escalation keys;
    credential/token/scope/financial/verified keys dropped from the query surface (body keeps full 27-key set).
  - ✅ **S4** §2b — xss `on<event>=` now requires HTML tag context (`<tag … onX=`); bare `?onload=`
    (Turnstile/reCAPTCHA callbacks) no longer fires.
  - ✅ **S5** §2e — cookie-injection: context-free `'`/`--`/`/*` triggers dropped; require SQL/NoSQL context
    (base64url `--` tokens clean).
  - ✅ **S2 (body)** §2a-1 — `form_body_is_opaque_beacon` gate wired into sqli/cmdi/template: skips
    form-urlencoded/text-plain single-dominant high-entropy sensor beacons. **Threshold (256 len / 4.5 bits /
    0.9 dominance) is conservative and flagged for corpus re-validation once S0 lands.**
  - ⏳ **S2-2** §2a-2 (URI opaque-segment guard), **S3, S6, S7** — deferred (S6 blocked on S0).
- **Source run:** `tests/n-tester/reports/2026-06-18-detectors/20260618_122533_atknorm_report.md`
  (detail: `…/20260618_122533_fp_logs/`). 200k records (100k normal / 100k attack), target `18.140.47.62:443`.
- **Decision inputs (2026-06-18):** tune each detector (keep enforcing — do **not** blanket-disable the
  gateway-boundary detectors); root-cause + per-rule fix spec for the core injection detectors too;
  this session writes the plan only.
- **Related:** `PLAN-sec-regression-2026-06-16-threshold-and-detectors.md` (AI score demote + URI/body decode
  work — this plan is the *normal-traffic* counterpart and extends the 2026-05-24 opaque-beacon FP fix to the
  URI surface). Boundary lens: token/JWT/business-rule auth belongs in the gateway, not the WAF.

---

## 0. Report double-check — math is right, the headline framing is not

I re-summed the **per-rule block counts** from the FP-log file headers; they total **exactly 2,434**, matching
the report's confusion-matrix `FP (normal blocked)`. Precision 96.66%, F1 81.48%, accuracy 83.99% are all
internally consistent. **No arithmetic error.**

**The framing is the problem.** The report leads with **"FP rate (regex detector) 0.58% ✅"** and its
"Regex rules fired on normal traffic" table lists only **3** rules (ssrf 247 / xss 168 / sqli 161 = 576). That
table **omits 14 of the 17 rules that actually block legit traffic**, hiding **1,858 blocks (76% of all benign
blocks)**. The number a customer feels — *legit traffic getting a hard 403* — is **2.43%, not 0.58%**.

The 0.58% "regex detector" figure is a narrow harness label (only sqli/xss/ssrf are tagged `regex_detector`;
everything else is `fp_type=blocked`). Reporting it as *the* FP success metric is misleading.

### True benign-block breakdown (from FP-log headers; sums to 2,434)

| Rule | Benign blocks | Score | Single-blocks at high(60)? | Bucket |
|------|--:|--:|--|--|
| mass-assignment | 574 | 60 | yes | boundary (query-surface) |
| command-injection | 427 | 70 | yes | core (beacon over-scan) |
| jwt-jku-external | 389 | 80 | yes | boundary (auth) |
| ssrf | 247 | 70 | yes | core |
| header-injection | 199 | 70 | yes | core (header-borne) |
| xss | 168 | 70 | yes | core (`onX=` context) |
| sqli | 161 | 70 | yes | core (beacon over-scan) |
| cookie-injection | 121 | 50 | crit-tier only | boundary (auth) |
| template-injection | 81 | 70 | yes | core (beacon over-scan) |
| jwt-alg-none | 19 | 80 | yes | boundary (auth) |
| css-injection | 14 | 70 | yes | core |
| jwt-time-forged | 13 | 70 | yes | boundary (auth) |
| path-traversal | 8 | 70 | yes | core |
| method-override-bypass | 5 | 50 | crit only | boundary |
| nosql-injection | 4 | 70 | yes | core/boundary |
| open-redirect | 3 | 50 | crit only | boundary |
| body-too-large | 1 | 30 | no (limit) | core |
| **TOTAL blocked** | **2,434** | | | |

> `recon-path` fired **557×** but **blocked 0** (score `PATH=25`, below every tier) — pure detect-only noise.
> Harmless to availability; correctly excluded from blocks. It *does* inflate "detect recall (rule-id≠none)"
> attribution, so the 70.56% detect-recall headline is slightly flattered by non-enforcing fires.

### 0a. Report/runner fixes (separate from detector fixes)

1. **Headline the enforced FP.** Promote **"FP (normal blocked) 2.43%"** to the top metric; demote/retitle the
   0.58% "regex detector" subset so it isn't read as the whole FP story. Drop the `✅` on 0.58%.
2. **List every blocking rule** in "Regex rules fired on normal traffic", not just the 3 `regex_detector`-tagged
   ones. Use the §0 table shape.
3. **Footnote control_endpoint.** `control_endpoint 0/7,226 (0%)` is **by design**, not a miss — `/__waf_control/*`
   is loopback-only and never proxied; a remote tester can't reach it. Mark it `N/A (by design)` so it doesn't
   read as a 0% recall regression.

---

## 1. P0 ENABLER — the FP logs can't attribute header/body-borne hits

The detail files log **only `method + url`**. But several top offenders fire on **request headers or bodies the
log never shows**:

- `header-injection` fires on `…/simplemodal.js?_=1728481127592` — no CRLF, no URL in the path/query ⇒ the
  trigger is a **header** (XFH / host-override / method-override / smuggling checks, `header_injection.rs:65-126`).
- `jwt-jku-external` fires on `/womens/accessories/bags` — no JWT in the URL ⇒ the trigger is a **cookie-borne**
  JWT (`jwt_inspection.rs:103-125`).
- `ssrf` fires on `POST /tr/`, `command-injection` on opaque `POST` paths — trigger is in the **body**.

You cannot tune a regex you can't see fire. **Before/alongside detector edits, extend the FP harness** to log,
per FP row: `waf_field` (uri/query/path/body/header:<name>/cookie:<name>), the **matched substring**, and the
**decoded variant** that matched. The WAF already tags `Signal.field`; surface it via an audit/debug header or
the live-feed the harness reads. This converts §2f/§2g from "instrument-then-tune" to "tune".

---

## 2. Root causes + per-rule fix specs

Each is reproduced against detector source, not inferred. All scores from
`crates/aegis-security/src/detectors/scores.rs`; tier ladder `critical=50 / high=60 / medium=70 / low=80`,
block when summed score ≥ tier threshold.

### 2a. Beacon over-scan — the shared root cause behind command-injection (427) + template-injection (81) + sqli/ssrf URI share

**Evidence.** `command_injection.rs:174` and `sqli.rs:82` gate the **body** scan on `body_is_scannable`
(`mod.rs:405`), which admits `text/*`, `application/json`, `*+json`, `*+xml`, and
**`application/x-www-form-urlencoded`**. Bot-management sensor beacons (Akamai `sensor_data=…`, PerimeterX,
F5) POST a single huge high-entropy value under exactly `application/x-www-form-urlencoded` (or `text/plain`),
so they **pass the gate** and the blob coincidentally matches shell/template/SQL shapes. The FP paths
(`POST /89SdLv43DcWJ/…`, `/3qtmli_SrwG6/…`) are classic sensor endpoints. The 2026-05-24 fix stopped
`application/octet-stream`/protobuf beacons but not form-encoded ones.

Secondary: the **URI** scan (`normalize_for_detection(raw_uri)`, `cmd:161 / sqli:70 / template`) has **no
opaqueness guard at all** and runs `url_decode_repeated(…, 3)` + `hex_blob_decode` on every path/query,
including opaque encoded segments.

**Fix spec.**
1. **Tighten `body_is_scannable` for form-urlencoded.** Treat a form body as scannable only when it *looks like*
   key/value form data (multiple `k=v&…` pairs, each value of bounded length / bounded entropy). A single
   `name=<very-long-high-entropy-blob>` value is a beacon, not parseable injection surface → skip. Add an
   entropy/length heuristic (e.g. value > N bytes with Shannon entropy > T ⇒ opaque) shared with §2a-2.
2. **Add a URI opaqueness guard** mirroring the body gate: before running the full injection pattern set on a
   decoded URI variant, skip path **segments** that are high-entropy/opaque (base64url-ish, no dictionary
   substring). Keep scanning the query and dictionary-ish path segments.
3. Keep `check_log4shell` on headers (real RCE) untouched.

**Tests:** corpus replay of the captured beacon POSTs (must go to 0 cmdi/template FP); positive fixtures for
`;cat /etc/passwd`, `$(id)`, `{{7*7}}`, `${T(java.lang.Runtime)}` in a *normal* form body must still fire.

### 2b. xss `on<event>=` with no HTML context (168)

**Evidence.** `xss.rs:16` — `on(?:load|error|click|…)\s*=` matches a bare `onload=` **anywhere** in the
URL-decoded URI/body, no tag/quote context required. FP samples: Cloudflare Turnstile `…/api.js?onload=KHGO2`,
`?onload=false&…` — legit JS callback params. Patterns 22-23 already cover the real cases
(`<svg … onload`, `<img … onerror=`).

**Fix spec.** Require HTML context for the standalone handler pattern: only fire `on<event>=` when preceded by a
tag/quote breakout — e.g. `(?i)<[a-z!/][^>]*\bon(?:load|error|…)\s*=` (handler inside a tag), or a
quote-then-handler form. Drop the context-free `on…=`. Keeps reflected-XSS coverage (`<img onerror=` /
`"><svg onload=`), kills `?onload=` query FPs. Add negative fixtures for `?onload=`, `?onclick=` query params;
positive fixtures for `"><svg/onload=alert(1)>`.

### 2c. mass-assignment via query string (574 — the single biggest offender)

**Evidence.** `body_abuse.rs:122-137` scans `req.uri.query()` with `MASS_ASSIGN_KEYS_FORM` over a 27-key set
(`body_abuse.rs:43-60`) that includes **`apiKey`, `api_key`, `access_token`, `accessToken`, `refresh_token`,
`refreshToken`, `scope`, `credit`, `verified`**. Those are ubiquitous benign query params (OAuth-token-in-URL,
mapbox `access_token=pk…`, `…?apiKey=…&userAttributes.host=…`). Privilege escalation via *query string* is an
authz/gateway concern; in a query these key names are far more likely legit auth params than an attack
(score 60 ⇒ solo-blocks on critical/high tiers).

**Fix spec (tune, not disable — per decision).** Split the key set into two surfaces:
- **JSON/form/multipart body surface (3a/3b/3c):** keep the full 27-key set — a `role`/`is_admin`/`access_token`
  *field* in a write body is the real mass-assignment shape.
- **Query surface (§2 / `body_abuse.rs:126`):** restrict to the unambiguous privilege-escalation keys only —
  `role|is_admin|isAdmin|is_superuser|isSuperuser|superuser|admin|privileges|grants|access_level|accessLevel`.
  **Drop credential/token/scope/financial/verified keys from the query scan** (`api_key|apiKey|access_token|
  accessToken|refresh_token|refreshToken|scope|credit|verified|balance|password_hash`) — these are normal in
  URLs and belong to the gateway's authz layer.

Define a second `MASS_ASSIGN_QUERY_KEYS` regex; leave `MASS_ASSIGN_KEY_NAMES` for the body surfaces.
**Tests:** negatives for `?access_token=pk…`, `?apiKey=…`, `?scope=read`, `?refresh_token=…`; positives for
`?role=admin`, `?is_admin=true` still fire; existing body fixtures (`body_abuse.rs:520-808`) unchanged.

### 2d. jwt-jku-external (389) + jwt-alg-none (19) + jwt-time-forged (13) — first-party cookie JWTs in strict mode

**Evidence.** `jwt_inspection.rs:103-125` inspects **every cookie value** with a JWT shape, identically to an
`Authorization: Bearer` — but a cookie JWT is almost always the **app's own first-party session token**.
`jku_host_allowed` (`:258-265`) returns `false` for *every* host when `jku_allowed_domains` is empty (the
default), so **strict mode flags every external `jku`/`x5u`** (score 80 ⇒ solo-block on any tier). Captured
real-browser cookies carry first-party JWTs ⇒ 389 blocks.

**Fix spec (tune — keep the attack value).**
1. **Empty allowlist ⇒ don't fire `jwt_jku_external`.** With no allowlist the WAF can't distinguish a legit
   first-party JWKS host from an attacker's; "flag everything" is the FP engine. Make jku/x5u enforcement
   require an explicitly configured allowlist (empty = observe/no-signal). Keep alg-none, x5c-inline, and
   kid-injection firing (those are context-free attack shapes).
2. **Down-rank first-party cookie JWTs.** Either emit cookie-sourced jwt signals at a corroborating score
   (so they stack, not solo-block) or gate the cookie-JWT scan behind a config flag. The `Authorization`-header
   path keeps full enforcement.
3. Re-check `alg-none`/`time-forged` FPs once instrumentation (§1) shows whether they ride first-party cookies
   too; if so, apply the same cookie down-rank.

**Tests:** negative — first-party cookie JWT with a `jku` to a normal host and empty allowlist ⇒ no
`jwt_jku_external`; positive — `Authorization: Bearer` with `jku:https://attacker.evil/…` ⇒ fires;
`alg:none` still fires from any source.

### 2e. cookie-injection (121) — `'` / `--` / `/*` standalone triggers vs base64url tokens

**Evidence.** `cookie_injection.rs:52-68` flags a session-named cookie value (`SESSION_COOKIE_NAMES` includes
`token|auth|access_token|refresh_token`) on **standalone** `'`, `--`, `/*`. Base64**url** tokens legitimately
contain `-`/`_` and frequently a `--` run; OAuth/opaque tokens occasionally contain `'`/`/`. The unit test
`opaque_session_token_is_clean` doesn't cover a `--`-containing base64url token. (Detector defaults OFF but was
enabled for this run.)

**Fix spec.** Drop the three context-free single-token triggers; require SQL/NoSQL **context**: `'` only when
followed by an SQL keyword/comment (`'\s*(or|and|union|;|--)`), `--` only as `';--` / `'\s*--`, keep the keyword
and `$op` patterns as-is. Add a negative fixture for `access_token=ab--cd_ef-gh` and a base64url value with
embedded `--`; keep all existing positives (`' OR 1=1--`, `{"$ne":…}`).

### 2f. header-injection (199) — header-borne, needs §1 first

**Evidence.** FP samples (`…/simplemodal.js?_=…`, analytics with encoded URLs) have **no** CRLF/URL in the
path/query, so the query/path CRLF scans (`header_injection.rs:38-61`) are not the trigger. It's one of the
header checks: XFH-suspicious (`:84-96`), URL-override (`:109`), method-override (`:115`), or h1-smuggling
backstop (`:126`). **Blocked on §1** — without the matched field/value we can't tell which.

**Fix spec (after §1).** Likely candidate: `xfh_is_suspicious` / url-override firing on benign CDN/proxy headers
(`X-Forwarded-Host`, `X-Original-URL` set by legit fronting infra). Once instrumented, narrow the suspicious-XFH
heuristic to require an actual attacker shape (control bytes, multiple hosts beyond a normal proxy chain, or a
keyword), not merely XFH ≠ Host (common behind real CDNs).

### 2g. ssrf (247) — internal-IP / userinfo URL in benign params, needs §1 first

**Evidence.** `ssrf.rs:79-89` scans url-decoded query/path/body. The broadest pattern is the userinfo form
`https?://[^@/\s]+@` (`:40`); internal-IP patterns (`:12-27`) also match URLs embedded in benign redirect/
analytics params. `POST /tr/` (Meta pixel) carries URLs in its body. Smallest core offender (0.25%).

**Fix spec (after §1).** Confirm via instrumentation whether FPs ride the userinfo pattern or internal-IP-in-
param. If userinfo: that pattern is the most FP-prone (legit `https://user@host` is rare but `@` appears in
encoded redirect chains) — consider scoping it to params the origin would actually fetch, or demoting it to a
corroborating score. Defer aggressive change until instrumented.

### 2h. Minor offenders (≤ 35 total)

`css-injection` (14), `path-traversal` (8), `method-override-bypass` (5), `nosql-injection` (4),
`open-redirect` (3), `body-too-large` (1). Backlog stubs — re-triage after §1 instrumentation; individually
below the noise floor. `open-redirect`/`method-override`/`nosql` are boundary detectors — narrow per the same
"require attack context, not benign shape" principle as §2c/§2e.

---

## 3. Genuine attack-recall gaps (not the focus here, but flagged while reviewing)

These are real misses worth a **separate** plan (this plan is FP-only):

- `traversal` **33.86%** (8,219/24,270) — large class, low recall. `path_traversal` (the other category) is
  80.37%, so the `traversal` corpus likely uses encodings/variants `path_traversal.rs` doesn't cover. Investigate.
- `cmdexe` **27.21%** (605/2,198) — low; many caught by `header-injection`/`path-traversal` rather than
  `command-injection`, suggesting attribution spread + a coverage gap.
- `xss` 99.6%, `sqli` 80.2%, `ssrf` 82.1% are healthy.
- `control_endpoint` 0% and `broken_access_control`/`dos_amplification`/`canary` 0% — by-design or
  out-of-scope-for-regex (see §0a-3); not detector regressions.

---

## 4. Sprint plan, ordering, and exit criteria

**Ordering** (by benign-block payoff and dependency):

| Step | Work | Blocks killed (est.) | Risk |
|------|------|--:|--|
| **S0** | §1 FP-harness instrumentation (field + matched substr + decoded variant) | 0 (enabler) | low |
| **S1** | §2c mass-assignment query key-set split | ~570 | low |
| **S2** | §2a beacon over-scan: form-urlencoded entropy gate + URI opaque-segment guard | ~510 (cmdi+template) | med |
| **S3** | §2d jwt empty-allowlist + cookie down-rank | ~420 | med (auth posture) |
| **S4** | §2b xss `onX=` HTML-context | ~168 | low |
| **S5** | §2e cookie-injection context requirement | ~121 | low |
| **S6** | §2f/§2g header-injection + ssrf (post-instrumentation) | ~446 | med (need S0) |
| **S7** | §2h minor offenders | ~35 | low |

**Exit criteria.** Re-run the 200k corpus; target **enforced FP (normal blocked) ≤ 0.5%** (from 2.43%) with
**no regression in attack block-recall** on the healthy classes (xss/sqli/ssrf/path_traversal/log4shell). Every
fix lands with detector-level negative fixtures for the exact benign shapes above **and** retains its existing
positive fixtures. Run the full `aegis-security` lib suite green after each step.

**Method note.** Per the prior plan, prefer the detector-fixture loop (reproduce the benign shape as a unit
test → fix → green) over corpus-only validation; corpus replay is the final gate, not the dev loop. Do NOT
blanket-disable boundary detectors (per decision) — narrow each so it fires on attack *context*, not benign
*shape*.

## 5. Risks

- **S2 entropy heuristic** could skip a genuinely malicious form value if an attacker pads to look opaque —
  keep the dictionary/keyword fast-path so known payload tokens (`select`, `sh -c`, `{{`, `$()`) are always
  scanned regardless of entropy.
- **S3 jwt** changes a security posture (strict jku). Document that jku/x5u enforcement now requires an
  allowlist; surface it in the config/runbook so an operator who *wants* strict mode sets one explicitly.
- **S6** is gated on S0 — do not guess at header/ssrf fixes from URL-only logs; that's how over-broad patterns
  were shipped before.
- Boundary detectors stay enabled (per decision); if narrowing proves insufficient to hit the 0.5% target, the
  fallback (log_only at the edge, deferring to the gateway) is a follow-up decision, not part of this plan.
