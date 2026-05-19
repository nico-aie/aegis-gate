# Triage notes — LT-RUN-5 + cross-report

> Companion to `README.md`. Captures the verification evidence
> for the "hallucinated impact" + "real stub but unused" buckets
> so future audits don't re-raise them or so a fix planner
> doesn't burn a week on phantom incidents.

## Verified hallucinations / inflated impact

### CTL-26 + SEC-07 — "Production binary is a passthrough proxy"

**Claim:** `aegis-bin/main.rs` wires `NoopPipeline` so all WAF
inspection is skipped; detectors are dead code.

**Reality:** Both claims are literally true:
- `aegis-bin/main.rs:213-214` does wire `NoopPipeline` into the
  `Arc<dyn SecurityPipeline>` parameter passed to
  `aegis_proxy::run`.
- `aegis-security/src/pipeline.rs::Pipeline::inbound()` does
  only call `rules::evaluate()`.

**Why the impact claim is wrong:** the data plane bypasses the
`SecurityPipeline` trait entirely. The actual detector chain
invocation is in
`crates/aegis-proxy/src/data_plane.rs:504`:

```rust
let r = aegis_security::detectors::run_all_filtered_timed(
    /* &detectors, mask, &request_view, &observer */
);
```

`run_all_filtered_timed` walks every Detector implementation
(sqli / xss / ssrf / path_traversal / header_injection /
body_abuse / recon / brute_force / command_injection /
template_injection / nosql_injection / open_redirect / ai)
and produces signals. Signals feed the risk score which gates
the request via the per-tier `risk_threshold` field.

I verified this hands-on in this same session (2026-05-10) when
wiring the AI detector hot-enable path, the Option-B per-tier
cumulative thresholds, and the Strike-Block opt-in default —
all of which exercised `data_plane.rs` and the detector chain.

The `SecurityPipeline` trait + `Pipeline` impl is architectural
deadwood from a refactor that never completed. It's
referenced in tests but not in any hot path. The fix is to
either:
- decide the trait is keeper (e.g. for future outbound DLP /
  response filtering) and wire `inbound()` properly, OR
- remove the trait + `NoopPipeline` from the binary entry.

This is a **design cleanup**, not a security incident.

### SEC-02 — "CAPTCHA bypassed (CRITICAL)"

**Claim:** All three CAPTCHA providers (`Turnstile`, `HCaptcha`,
`ReCaptchaV3`) return `Ok(true)` unconditionally; the
bot-challenge mitigation provides zero protection.

**Reality:** the stubs exist exactly as described in
`crates/aegis-security/src/challenge/captcha.rs`. But:
- `grep -rn "CaptchaProvider\\|Turnstile\\|HCaptcha" crates/aegis-proxy/src/`
  returns **zero matches**. The proxy crate does not import or
  call these providers.
- The active challenge path uses Proof-of-Work
  (`pow_issuer.issue()` in `data_plane.rs` around the
  `RiskLevel::Challenge` arm). CAPTCHA vendors are not in the
  ladder.

The CAPTCHA module is paper-only today. Marking this Critical
implies an active bypass; in fact it's a **deferred feature
with a stub trait awaiting product decision**.

### SEC-04 — "JWT signature never verified (CRITICAL)"

**Claim:** `auth/jwt.rs` reads parts[0..2] then skips the
signature, so any JWT passes — auth bypass.

**Reality:** the stub exists. But:
- `grep -rn "jwt::\\|use.*jwt\\|JwtValidator" crates/aegis-proxy/src/`
  returns **zero matches**. The proxy doesn't reference JWT
  auth.
- The active admin auth path is session-cookie + CSRF +
  argon2id password (see `aegis-control::api::login`).

JWT is another deferred module. No active bypass.

### SEC-08 + SEC-20 — "DLP / ICAP never called from
`Pipeline::on_response_start()` and `on_body_frame()`"

**Same root cause as CTL-26 / SEC-07** — the `Pipeline` trait
is vestigial. Response filtering is implemented elsewhere
(`crates/aegis-control` or `aegis-security/src/response_filter`
depending on the path). DLP and ICAP are deferred features.

---

## Real stubs in unused code paths (deferred, not bugs today)

These exist as described but aren't on any active hot path.
They become real the day someone wires them in.

| Finding | Module | Status |
|---|---|---|
| SEC-02 | `aegis-security/src/challenge/captcha.rs` | Trait + 3 vendor stubs; trait unreferenced by proxy |
| SEC-04 | `aegis-security/src/auth/jwt.rs` | JWT validator stub; unreferenced by proxy |
| SEC-05 | `aegis-security/src/auth/opa.rs` | OPA stub returning HashMap decisions; unreferenced |
| SEC-08 | `aegis-security/src/pipeline.rs::on_response_start` | Returns PassThrough; trait vestigial |
| SEC-14 | `aegis-security/src/icap/` | Stub `Continue`; deferred |
| SEC-20 | `aegis-security/src/pipeline.rs::on_body_frame` | Same as SEC-08 |
| CTL-03 | `aegis-control/src/audit/sinks/splunk_hec.rs` | Buffers events, no HTTP delivery |
| CTL-04 | `aegis-control/src/audit/sinks/kafka.rs` | Buffers events, no Kafka producer |
| CTL-22 | `aegis-control/src/siem/*.rs` (QRadar, ArcSight) | Stubs |
| CTL-23 | `aegis-control/src/alerts/{pagerduty,opsgenie}.rs` | Stubs |
| PROXY-04 | `aegis-proxy/src/acme/` | Module is `#![allow(dead_code)]` |
| PROXY-23 | ACME auto-renewal | Same module as PROXY-04 |
| PROXY-18 | Jaeger tracing branch | `todo!()` in `init_tracing` |
| PROXY-16 | Redis rate-limit backend | `unimplemented!()` panic |
| CTL-18 | `LicenseValidator::verify` | Always returns Valid |

**Plan**: catalogue these in
`plans/future/unwired-stubs-catalog.md` (Phase 4 work).

---

## Findings that need a small code-read to grade

These are claims I haven't verified but didn't reject either.
Move them out of Phase 0 into Phase 3 once read.

| Finding | Where to look | Quick check |
|---|---|---|
| PROXY-02 (regex/glob fall-through) | `route/mod.rs::resolve_inner` | Does it have a regex-eval branch? |
| PROXY-08/09 (TierCache unwired) | grep `TierCache::` in `aegis-proxy/src/` | Zero call sites = dead |
| PROXY-10 (P2C counter) | `upstream/lb.rs::pick_p2c` | Is the index from a counter or RNG? |
| PROXY-11 (ConsistentHash modulo) | `upstream/lb.rs::pick_consistent_hash` | Modulo vs. ring lookup? |
| SEC-16 (nonce race) | `challenge/token.rs::issue`, `verify` | Two `subsec_nanos()` calls? |
| SEC-18 (CIDR HashMap) | `threat_intel/mod.rs::check_ip` | `HashMap.get(&ip.to_string())`? |
| SEC-21 (RateLimit action blocks) | `rules/eval.rs:107-119` | TODO + unconditional block? |
| CTL-19 (set_all wipes overrides) | `interop/mode.rs:91-97` | `ModeSnapshot::empty(mode)`? |
| CTL-20 (no session invalidation) | `api/admin.rs::change_password` | Calls `session_store.invalidate_*`? |

---

## Pattern-level observations

LT-RUN-5's author was doing static source analysis without
verifying call paths. Many findings are correct at the
statement level (`fn returns Ok(true)`) but wrong at the
system level (`but the function is never called`). For future
audits to be more actionable, the report should include a
**call-graph confirmation** step for every "CRITICAL" claim:

> "The function `X::y()` returns the stub `Z`. Verified
> reachable from the request hot path via the chain
> `data_plane.rs::handle_request → … → X::y()`."

Without that confirmation step, severity ratings drift toward
worst-case-imagined, which inflates the report and makes the
fix plan harder to scope.

The n-tester (functional QA against live UI) and LT-RUN-4
(aegis-core static audit) reports don't have this problem
because their findings are either (a) UI-observable behavior
or (b) scoped to a single small crate where call-path is
local. Their findings are mostly actionable as written.
