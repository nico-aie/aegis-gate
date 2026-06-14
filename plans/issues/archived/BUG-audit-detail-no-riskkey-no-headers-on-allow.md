# BUG / IMPROVE — Request Detail hides risk-key (always) and headers (on `allow`)

- **Type:** BUG (observability / audit detail) → improvement
- **Severity:** 🟡 Medium (diagnostic blind spot; no security regression)
- **Status:** ✅ Fix A + Fix B shipped 2026-06-14 (TDD). See Resolution below.

## Resolution (Fix A — 2026-06-14)

Done via the `fields` JSON bag (not a typed `AuditEvent` field — that would break all ~126 construction sites + the audit hash chain for no UI gain). New pure helper `risk_key_audit_value(&RiskKey)` (`data_plane.rs`) renders a privacy-safe object: `{ip, device_fp (already a hash), session_present (bool — raw session NEVER emitted), key_hash (16-hex blake3 of ip|device_fp|session)}`. Wired onto **every** decision:
- **allow** — `accept.rs` chokepoint (the reported case): key built from `peer.ip()` + request headers + `conn_tls_fp` before `handle_data_request` consumes the request, inserted as `fields.risk_key`.
- **block** (detector-block + risk-score-block) and **challenge** (`emit_challenge_audit` gained a `risk_key` param) — reuse one `risk_key_audit` rendered once from the gate's own `strike_key`, so the rendered bucket matches the one traffic accumulates under.
- **Dashboard:** Request Detail drawer (`pages.jsx`) renders `risk_key` (key_hash · device_fp · session) in the Network section on Live Feed + Investigation; excluded from the generic Extra-fields dump.

Tests (TDD): `risk_key_audit_value_*` (ip-only shape, never-leaks-raw-session, stable/distinct bucket hash) + `challenge_audit_emits_challenge_action_with_tier_and_score` extended to assert `fields.risk_key.ip`. All green; full `aegis-proxy` lib suite (884) passes.

### ✅ Resolution (Fix B — 2026-06-14)

Shipped via the **verbosity dial** (the lower-risk option vs a new per-IP toggle — no new config/state). `request_echo_fields()` is now made `pub(crate)` and attached to the **allow** audit in `accept.rs`, gated behind **`verbosity ≥ Debug`** (default is `Info`, so **OFF by default**). Captured headers-only (the body is consumed by `handle_data_request`; the user asked for headers), redaction unchanged (auth/cookie/token masked). It merges into the allow `fields` and therefore **flows to every audit sink automatically** — no sink change. The drawer already renders a "Request headers" section from `fields.request_headers`, so it shows with no dashboard change. Operators raise verbosity to `Debug` to capture allow-path headers; drop back to `Info` to stop the extra sink volume.

Tests: relies on the existing `request_echo_fields` redaction tests (incl. `body=None` headers-only shape) + `VerbosityLevel::is_at_least` tests; the wiring is integration-level (no isolated `accept.rs` request harness). Full `aegis-proxy` lib suite (884) green.

### Fix B scope clarification (Nico, 2026-06-14) — "display + log (audit sinks) headers for ALL requests"

Nico asked to surface request headers for **every** request, both in the dashboard drawer **and** in the audit-sink stream. That is exactly Fix B, with the sink dimension made explicit:
- **Mechanism already exists:** `request_echo_fields()` (correct redaction: auth/cookie/token masked, 2 KB body cap) is attached today only on detection/block paths behind `verbosity ≥ Info`. Wiring it onto the **allow** path (accept.rs, beside the `risk_key` capture from Fix A) makes it render in the drawer; **sinks need no change** — every sink (`audit/sinks/{splunk_hec,kafka,syslog,cef,leef,ocsf,ecs,jsonl}.rs`) serializes whatever is in `fields`, so the echo flows automatically once attached.
- **Why still default-off:** (1) hot-path cost + a large jump in audit-log/sink **volume + retention** (headers on every benign request, forwarded to Splunk/Kafka/syslog/…); (2) privacy/compliance — full headers on all traffic is a much bigger PII surface than on blocks. Gate behind a new elevated verbosity level (e.g. `Debug`) or a per-IP/CIDR "capture headers for allows" toggle, off by default, reusing the existing redaction unchanged.
- **Decision needed from Nico:** which gate (global verbosity dial vs per-IP capture), and the retention/PII posture for sinks, before coding.

---

- **Status (original):** 🟡 Open — reported 2026-06-14 (Nico), code-verified
- **Surfaces:** Live Feed + Investigation (Request Detail drawer)
- **Reported with:** a burst of `GET /<dir>/.git/config` recon from a single IP (`34.124.127.138` / `34.162.173.128`), each scored **25 / `recon_path` / ALLOW**, where cumulative IP risk did **not** climb across the burst. Operator could not see *why* (no headers, no risk-key) because the rows were `allow`.

## Symptom

For `allow` rows the Request Detail drawer is effectively empty — no request headers, no body preview — so an operator cannot tell **which risk-key bucket** a request landed in, nor inspect the headers that determined it. The risk-key is **never** shown, on any action. This makes it impossible to confirm the natural question the screenshots raise: *"same IP, many requests, score not summing — is each request keyed to a different bucket?"*

## Root cause (code-verified 2026-06-14)

1. **`risk_key` is never emitted into the audit event.** `aegis_core::audit::AuditEvent` (`crates/aegis-core/src/audit.rs:186`) has no risk-key field — only `client_ip`, `risk_score`, `rule_id`, `fields`, etc. So no surface (Live Feed, Investigation, or the `/api/audit/*` JSON) can display it for **any** action.
2. **The header/body echo is gated to detection/block paths.** `request_echo_fields()` (`crates/aegis-proxy/src/data_plane.rs:3407`, doc-comment at `:3394`: *"Only invoked on detection / block paths (not every request)"*) is attached only at the Detection-class emit sites (`:1011`, `:1292`, `:1408`) and rides a verbosity gate (`allow_verbose_fields = verbosity ≥ Info`) plus a load-mode gate (skipped in Critical). The `allow`/Access-class emit sites (`:2084`, `:2164`, `:2216`, `:3228`, `:3263`) attach no echo → empty drawer on `allow`.

### Why the score "doesn't sum" is *expected*, but invisible
The risk model is **max-per-request + decay**, not a running sum ([[feedback_two_score_model]]; `risk/tracker.rs`), so a burst of identical recon hits each worth 25 keeps cumulative ≈25 rather than climbing — even within **one** bucket. Separately, the bucket key is composite: `build_risk_key` (`data_plane.rs:3376`) = `ip` + `device_fp` (JA4+UA, **TLS-only**) + `session` (cookie). On plaintext `:8080` with no session cookie it collapses to a pure-IP key, so these *should* share a bucket. Surfacing the risk-key turns this from speculation into a one-glance check. Cross-ref [[project_config_plane_doc_vs_file]] is unrelated; see PRODUCTION_MISS_ANALYSIS §8 (composite-key / decay / XFF levers).

## Impact

- Operators can't validate cumulative-risk behaviour from the console (the exact confusion in the screenshots).
- Recon/low-score `allow` traffic — the bulk of real attack reconnaissance — is the least inspectable, despite being where triage is most needed.
- Cross-refs the cumulative-IP-risk confound called out in [`PLAN-sec-regression-2026-06-14-triage.md`](./PLAN-sec-regression-2026-06-14-triage.md); a visible risk-key would have answered "is it poisoning or keying?" without code spelunking.

## Suggested fix

**A. Always surface the risk-key (cheap, do first).** Add an optional `risk_key` (or a small `{ip, has_device_fp, has_session, key_hash}` triplet) to `AuditEvent` and populate it on **every** decision (allow/challenge/block). It is one short string — negligible volume/disk cost, unlike full header echo — and it directly answers the bucketing question. Render it in the Request Detail drawer on Live Feed + Investigation (`assets/dashboard/src/pages.jsx` / `data.jsx`).
  - Privacy: prefer the **components or a hash** over a raw composite if the session axis could carry a token; keep IP visible (already shown).

**B. Allow header/body echo for `allow` rows — but keep it gated.** Honour the existing volume/disk rationale: don't unconditionally echo every request. Options, in order of preference:
  1. Extend the existing **verbosity dial** so `verbosity ≥ Debug` (a new level above `Info`) attaches `request_echo_fields()` to Access-class events too — opt-in, off by default, bounded by the same redaction (`is_sensitive_header`, cookie masking, 2 KB body cap).
  2. Or a per-investigation "capture headers for allows" toggle scoped to an IP/CIDR, so the cost is paid only while actively triaging.
  - Reuse `request_echo_fields()` unchanged (redaction already correct); only the **gate** and the **call site** (wire it into the allow path) change.

**Scope guard:** A is the small win that resolves the report. B is the larger, cost-sensitive change — land A first, decide B with Nico (default-off either way).

## Verification / done criteria

- `risk_key` (or its components/hash) present on allow/challenge/block audit events and visible in the Request Detail drawer on both pages; a single-IP recon burst visibly shares one key.
- If B lands: with the elevated verbosity (or per-IP capture) on, `allow` rows show redacted headers; with it off, behaviour and volume are unchanged. Sensitive-header/cookie redaction asserted by test.
- No new PII in the default (gate-off) wire shape.

## Related

- [[feedback_two_score_model]] — max-per-request + decay (why the burst doesn't sum).
- [`PLAN-sec-regression-2026-06-14-triage.md`](./PLAN-sec-regression-2026-06-14-triage.md) — cumulative-IP confound this would have made self-evident.
- [`PRODUCTION_MISS_ANALYSIS.md`](./PRODUCTION_MISS_ANALYSIS.md) §8 — composite risk-key / decay / XFF escalation levers.
- [`BUG-ws-lifecycle-audit-missing-tier-path.md`](./BUG-ws-lifecycle-audit-missing-tier-path.md) — sibling audit-field-fidelity bug.
</content>
