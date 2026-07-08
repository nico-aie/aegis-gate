# PLAN — Response-Filter False-Positive Reduction + Per-Request Filter Signal

**Date:** 2026-07-08
**Branch (proposed):** `feat/response-filter-fp-reduction`
**Status:** DRAFT — awaiting implementation
**Owner:** Nico

---

## 1. Problem (QC report)

The response-body redactor (`Pipeline::on_body_frame` → `dlp::redact`) is too eager and
hits false positives easily. Two distinct FP classes:

1. **Auth-token FP (explicit QC example).** Token-issuing endpoints — `/login`, `/signin`,
   `/auth`, `/refresh`, `/oauth/token`, … — legitimately return `access_token` /
   `refresh_token` / JWTs in the body. The WAF redacts them to `[REDACTED]`, which **breaks
   the login flow** (the client never receives its token).

2. **Broad-PII FP ("not login only").** The `email` and `phone` DLP patterns have **no
   validator and no gating** — they redact *every* email address and phone-shaped number in
   *every* 200 body. A profile API returning `{"email":"alice@example.com"}` becomes
   `[REDACTED]`. This is the single largest general FP source.

### How the FP arises (code map)

- `crates/aegis-security/src/pipeline.rs:261` — `on_body_frame` runs `dlp::redact(body)`
  over **every** 200 body, unconditionally, and **ignores the `RequestCtx`/`RouteCtx` it is
  handed** (`_rctx`, `_route` at `pipeline.rs:226-227`).
- `crates/aegis-proxy/src/data_plane.rs:3353` — the call site even builds an **empty**
  `RequestCtx` (no path), so the redactor has no idea it is looking at a token-issuing
  endpoint's *intended* payload.
- `crates/aegis-security/src/dlp/mod.rs`:
  - `jwt` whole-match (`:162`) — fires on any `eyJ…eyJ…` triple.
  - structural `json_secret`/`env_secret`/`yaml_secret`/`htaccess_setenv` (`:178-224`) —
    key stem includes `token` (`SECRET_KEY_STEM`, `:43`), so `access_token`/`refresh_token`
    values redact.
  - `email` (`:73`) and `phone` (`:80`) — no validator, no gate.

---

## 2. Confirmed decisions (from planning Q&A, 2026-07-08)

| # | Decision | Choice |
|---|----------|--------|
| A | Exempt token-issuing endpoints | **Request-path–aware skip** of token-class patterns on a configurable auth allowlist. Non-token secrets (AWS keys, PEM, `db_password`, config dumps) still redact **everywhere**, including auth paths. |
| B | Broad email/phone patterns | **Off by default (opt-in).** Keep credit_card/ssn/iban (validated) + distinctive credential patterns (AWS/PEM/JWT/etc.) ON. |
| C | Config surface | **Config-plane + dashboard.** New knobs on `ResponseFilterConfig` (fleet-propagated, editable at the Response-Filtering settings card) with safe defaults. |
| D | Redaction signal surface (new ask) | **Do NOT emit a separate Investigation row.** Instead: (a) add a **client-facing response header** when a body was filtered, and (b) fold the "filtered" signal into **that request's own** live-feed / investigation record. |

---

## 3. Design

### 3.1 Pattern taxonomy (drives the redaction policy)

| Class | Patterns | On auth path | email/phone OFF (default) |
|-------|----------|--------------|---------------------------|
| **Token** | `jwt`; structural key-stem `token`/`access_token`/`refresh_token`/`id_token` | **keep** | — |
| **Secret** | aws_key, aws_secret, github/stripe/slack/google, pem/ssh, password_hash; structural `password\|secret\|api_key\|private_key\|client_secret\|credential` | redact | — |
| **Financial** | credit_card (Luhn), ssn (validated), iban (mod97) | redact | — |
| **PII** | email, phone | redact | **skip** |

Key nuance: the auth-path skip is scoped to **token-class only**. `client_secret` still redacts
on `/login` (contains the non-token `secret` stem); `access_token` survives. An auth response
that leaks an AWS key / PEM / `db_password` is still scrubbed — that is never a legitimate
token-endpoint payload.

### 3.2 Policy-aware redactor — `dlp/mod.rs`

- Split `SECRET_KEY_STEM` into:
  - `TOKEN_KEY_STEM` = `token` (covers `access_token`, `refresh_token`, `id_token`, `token`).
  - `NON_TOKEN_SECRET_STEM` = `password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|db[_-]?pass|passphrase|client[_-]?secret`.
  - Structural regexes still compile against the **union** (unchanged match surface);
    classification happens per-match on the captured `pre` (key).
- Add `class: PatternClass` to `DlpPattern` (`Token` | `Secret` | `Financial` | `Pii`).
- Add:
  ```rust
  #[derive(Clone, Copy)]
  pub struct RedactPolicy {
      pub redact_email: bool,   // default false (opt-in)
      pub redact_phone: bool,   // default false (opt-in)
      pub keep_tokens: bool,    // true on auth paths
  }
  pub fn redact_with(text: &str, policy: &RedactPolicy) -> String;
  fn key_is_token_class(pre: &str) -> bool; // token stem present AND no non-token secret stem
  ```
  `redact_with` behavior:
  - `Pii::email` skipped unless `redact_email`; `Pii::phone` skipped unless `redact_phone`.
  - `Token` whole-match (`jwt`) skipped when `keep_tokens`.
  - structural closure: `if keep_tokens && key_is_token_class(pre) { return whole }`.
- **Keep the existing `pub fn redact(text)`** delegating to an "all-on / keep nothing"
  policy so every current dlp unit test stays green (incl.
  `rf1_oauth_response_preserves_metadata_redacts_tokens`, which calls the non-auth `redact`).
- `scan()` is **unchanged** (egress observability still sees everything).

### 3.3 Config surface — `aegis-core/src/config.rs` + `aegis-security` mirror

Extend **both** `ResponseFilterConfig` structs (core config ↔ security pipeline `ArcSwap`)
with `#[serde(default)]`:

```yaml
response_filter:
  scrub_stack_traces: true      # existing
  mask_internal_ips: true       # existing
  redact_dlp: true              # existing
  strip_response_headers: true  # existing
  redact_email: false           # NEW — opt-in
  redact_phone: false           # NEW — opt-in
  auth_paths:                    # NEW — token-class skip list
    - /login
    - /signin
    - /sign-in
    - /auth
    - /authenticate
    - /authorize
    - /token
    - /oauth/token
    - /oauth2/token
    - /connect/token
    - /refresh
    - /session
    - /sso
```

- Update the two mapping sites (`config.rs:445`, `:494`) + the `From`/clone glue.
- A YAML omitting the block ⇒ identical behavior to before for the on-by-default rungs;
  new fields take the safe defaults above.

### 3.4 Pipeline wiring — `pipeline.rs`

- `fn is_auth_path(path: &str, auth_paths: &[String]) -> bool` — query-stripped, lowercased,
  **segment-boundary** match (`/oauth/token` matches `/api/v1/oauth/token`; `/token` does
  **not** match `/tokenizer`).
- `on_body_frame`: read `rctx.fields.get("path")`, build `RedactPolicy` from
  `cfg.redact_email` / `cfg.redact_phone` / `is_auth_path(path, &cfg.auth_paths)`, call
  `redact_with`. Fix the explicit `ResponseFilterConfig { .. }` literal in the
  `on_body_frame_all_rungs_off_passes_through` test (add new fields / `..Default::default()`).

### 3.5 Call site — `data_plane.rs:3353`

- Populate `rctx_for_filter.fields` with `"path" → FieldValue::Str(path.clone())` so the
  filter sees it. (The existing comment at that site already anticipates exactly this.)

---

## 4. Redaction signal (Decision D) — header + per-request record, NOT a new row

### 4.1 Current behavior (to REMOVE)

`data_plane.rs:3386-3418` emits a **separate** `AuditEvent { class: Detection, action:
"redact", rule_id: "response_filter" }` on every `OutboundAction::Rewrite`. That shows up as
its own standalone row in Live Feed / Investigation.

### 4.2 New behavior

The redaction happens inside `forward_allow_to_upstream`, which returns
`(Response, DecisionTag)`. `DecisionTag` (`aegis-control/src/interop/headers.rs:143`) is the
carrier that the listener-side stamper turns into both the `X-WAF-*` response headers **and**
the per-request Access audit row. So:

1. **Carry the signal on `DecisionTag`.** Add:
   ```rust
   /// Set when the response-filter rungs rewrote the body. Feeds the
   /// X-WAF-Response-Filtered header + the request's own audit record.
   pub response_filtered: Option<ResponseFilterSignal>,
   // { redacted: true, bytes_before, bytes_after } — never the secret value.
   ```
   Default `None` (builder-compatible; keeps all existing `DecisionTag::allow()` call sites
   working via `..Default::default()` or an explicit `None`).

2. **Set it on Rewrite.** In `forward_allow_to_upstream`, when the body is rewritten, set
   `allow_tag.response_filtered = Some(..)` instead of emitting the standalone Detection
   event. **Delete** the `bus.emit(ev)` block at `data_plane.rs:3386-3418`.

3. **Client headers.** In the response stamper (`admin_dispatch.rs:1602`
   `stamp_interop_response`, the DecisionTag → header path), when `response_filtered.is_some()`:
   - emit `X-WAF-Response-Filtered: true` (and optionally `X-WAF-Filtered-Bytes: <delta>`).
     Add the header name(s) to the interop header module next to the other `X-WAF-*` constants.
   - **also stamp `X-WAF-Rule-Id: response_filter`** so the attribution field clearly names the
     filter, matching the `rule_id: "response_filter"` the deleted Detection row used to carry.
     **Guard:** only stamp it when there is no genuine rule attribution yet — i.e. `rule_id` is
     `None` or `"none"` (the unattributed-allow default). If a real allow/block rule already
     attributed this request, **keep** that id (don't clobber decision attribution); the
     `X-WAF-Response-Filtered: true` header still signals the scrub in that case.

4. **Per-request record.** In the Access-audit builder (same site that already folds
   `detector_score` / `risk_score` / `tier` from the DecisionTag into
   `AuditEvent.fields`), add `fields.response_filtered = { bytes_before, bytes_after }` when
   present. This makes the "response was filtered" signal appear in the **details of that
   request** in Live Feed / Investigation — no separate row.

> Note: the byte delta is a safe, value-free signal (never the redacted secret). The
> `egress_sensitive` / `egress_error_leak` observability detectors (run *before* redact) are
> **unchanged** — they remain audit-only and default-OFF.

### 4.3 Dashboard

- Live Feed / Investigation **request detail drawer**: render a "Response filtered"
  badge/line when `fields.response_filtered` is present (bytes before → after). No new
  top-level row type.
- Response-Filtering **settings card** (`pages.jsx`): add two toggles (Redact emails /
  Redact phone numbers) + an auth-paths editor (textarea, newline/comma list). Extend
  `ResponseFilterPatch` / `ResponseFilterView` (`api/response_filter.rs`) with the three
  fields. Rebuild the embedded `app.js` (esbuild) + run the acorn rules-of-hooks guard.

---

## 5. Phase / task breakdown

1. **Phase 1 — dlp policy** (`dlp/mod.rs`, TDD): stem split, `PatternClass`, `RedactPolicy`,
   `redact_with`, `key_is_token_class`; keep `redact()` back-compat.
2. **Phase 2 — config** (`config.rs` + security mirror): 3 new fields, defaults, `#[serde(default)]`, mapping sites.
3. **Phase 3 — pipeline** (`pipeline.rs`): `is_auth_path`, policy build in `on_body_frame`, fix test literal.
4. **Phase 4 — call site** (`data_plane.rs:3353`): thread `path` into `rctx_for_filter.fields`.
5. **Phase 5 — signal plumbing**: `DecisionTag.response_filtered`; set-on-Rewrite + **delete**
   the standalone Detection emit; `X-WAF-Response-Filtered` in `stamp_interop_response`;
   fold into the Access-audit `fields`.
6. **Phase 6 — dashboard**: settings-card toggles + auth-paths editor; request-detail
   "Response filtered" badge; rebuild `app.js`.

---

## 6. Test plan (TDD — RED → GREEN)

- **dlp:** auth policy keeps `access_token`/`refresh_token`/bare-JWT but still redacts
  `db_password` + AWS key in the *same* body; email/phone survive with default policy, redact
  when enabled; `key_is_token_class` boundary (`client_secret` redacts, `csrf_token` keeps).
- **auth-path matcher:** `/oauth/token`, `/api/v1/login` match; `/tokenizer`, `/authors`
  don't; query strings ignored; case-insensitive.
- **pipeline:** auth path in `rctx.fields` → tokens survive; non-auth path → tokens redacted;
  email-only body on non-auth path with `redact_email:false` → PassThrough; internal-IP /
  config-dump bodies still Rewrite on auth paths.
- **signal:** Rewrite sets `DecisionTag.response_filtered` (no separate Detection row emitted);
  stamper adds `X-WAF-Response-Filtered: true`; Access audit `fields.response_filtered` present.
- **rule-id stamping:** filtered + unattributed allow (`rule_id` None/`none`) → stamper emits
  `X-WAF-Rule-Id: response_filter`; filtered + a genuine allow/block rule id → that id is
  **preserved** (not clobbered), `X-WAF-Response-Filtered: true` still present; not-filtered
  request → `X-WAF-Rule-Id` unchanged (no `response_filter`).
- **regression:** existing `on_body_frame_*` tests + all `dlp` tests green;
  `cargo test --workspace` fully green (baseline is green — see memory).

---

## 7. Risks

| Level | Risk | Mitigation |
|-------|------|------------|
| MEDIUM | Auth-path allowlist is best-effort DLP, not access control. | Non-token secrets still redact on auth paths → small blast radius; documented. |
| MEDIUM | Behavior change on defaults (email/phone off; tokens survive on auth paths). | Opt-in re-enable, fleet-propagated config; `X-WAF-Response-Filtered` + audit field keep visibility of what *is* scrubbed. |
| LOW | `DecisionTag` new field ripples to every `::allow()`/builder site. | Field is `Option`, defaults `None`; use `..Default::default()` where a literal exists. |
| LOW | Config struct fan-out (core ↔ security ↔ patch/view). | Update the known mapping sites; existing structural guard tests catch omissions. |

## 8. Complexity: **MEDIUM** (dlp+config+pipeline ~3-4h · signal plumbing ~1-2h · dashboard ~1-2h · tests ~2h)

---

## 9. Out of scope / non-goals

- No change to `egress_sensitive` / `egress_error_leak` (stay observe-only, default-OFF).
- No content-type density heuristics for email/phone (rejected in favor of opt-in).
- No new Investigation row type for redaction (explicitly replaced by header + per-request field).
- No gzip/streaming redaction change (existing Accept-Encoding pin + non-UTF-8 passthrough unchanged).
