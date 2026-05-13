# Fix plan — Policy QA + Crate audits (2026-05-11)

> **Status:** Drafted 2026-05-11, awaiting user confirmation.
> **Inputs:**
> - `tests/n-tester/reports/policy-qa-findings.md` (8 findings)
> - `tests/l-tester/reports/2026-05-10-run4/LT-RUN-4-CORE-AUDIT.md` (12 findings)
> - `tests/l-tester/reports/2026-05-10-run5/LT-RUN-5-FULL-CRATE-AUDIT.md` (52 findings)
> - **Total raw findings:** 72.
> - **After triage:** see Phase 0 below — many LT-RUN-5 claims are
>   literal stubs in code paths the data plane does not call, with
>   inflated impact assertions. The fix plan acts on the verified
>   subset.

## Phase 0 — Triage (must-read before any fix work)

The raw count is misleading. I spot-checked the most-severe
LT-RUN-5 claims against the actual codebase and found a
consistent pattern: **literal claim true, impact claim wrong**.

### 0.1 — Verified hallucinations / inflated-impact claims

These either contradict the live codebase or describe stubs in
code paths that the production data plane does not call. They
should NOT be acted on as security incidents.

| Finding | Claim | Reality |
|---|---|---|
| **CTL-26** | "`aegis-bin/main.rs` wires `NoopPipeline` as `SecurityPipeline`; all WAF inspection silently no-ops" | Literally true that `NoopPipeline` is wired into the `Arc<dyn SecurityPipeline>` param. But the data plane bypasses `pipeline.inbound()` and calls `run_all_filtered_timed(&detectors, …)` directly (`data_plane.rs:504`). Detectors **do** run; the `SecurityPipeline` trait is vestigial. **Not a critical bug.** |
| **SEC-07** | "All 9 attack detectors disconnected; production binary is a passthrough proxy" | Same root cause as CTL-26. `Pipeline::inbound()` only runs rules — but `inbound()` is not in the request hot path. The detector chain is invoked through `run_all_filtered_timed` from `data_plane.rs`. Verified yesterday/today via direct edits to that path (Strike-Block + Option B + AI hot-enable). **Not critical; not actionable as stated.** |
| **SEC-02** | "All CAPTCHA providers return `Ok(true)` — CAPTCHA bypassed (CRITICAL)" | Literally true. `crates/aegis-security/src/challenge/captcha.rs` is a stub. **But** the `CaptchaProvider` trait is **not called from `aegis-proxy/src/`** — codebase-wide grep returns zero hits in the proxy crate. The data plane's challenge path uses PoW (`pow_issuer`), not CAPTCHA vendors. CAPTCHA module is paper-only today. **Real but downgrade to "deferred until CAPTCHA challenge type ships"** — not a runtime bypass. |
| **SEC-04** | "JWT signature never verified — auth bypass (CRITICAL)" | Same shape — `aegis-security/src/auth/jwt.rs` is stubbed, but the proxy crate doesn't reference it. JWT auth is not wired into request processing today. **Deferred, not critical.** |
| **SEC-08 / SEC-20** | "DLP + ICAP body scanner never called from `Pipeline::on_response_start()` / `on_body_frame()`" | Same `Pipeline`-trait-is-vestigial issue. DLP/ICAP aren't shipping features yet. |
| **SEC-21** | "`RuleAction::RateLimit` blocks all matching requests" | Need to verify whether `RuleAction::RateLimit` is a rule action operators can actually configure today vs. a parsed-only enum variant. Likely a real bug if the rule engine is hot, but impact depends on rule corpus. |

**Net for "Critical" claims in LT-RUN-5:** four of five trace to
the same vestigial-trait issue. They want a single architectural
fix or removal (Phase 3 below), not five emergency security
patches.

### 0.2 — Verified real bugs (act on these)

| Finding | Severity | Notes |
|---|---|---|
| **F-01 (n-tester)** | HIGH | Rules Simulator UI never renders the API response — real, blocks a documented workflow |
| **F-02..F-08 (n-tester)** | MEDIUM/LOW | UX bugs: silent validation, missing audit deep-link param, no AI ONNX preflight, native `window.confirm` instead of styled modal, etc. All real, all small fixes |
| **CORE-01** | HIGH | DdosConfig `observe_only` default contradicts WafConfig field doc — confirmed in code at `config.rs:129-141` vs `1774-1786` |
| **CORE-02** | HIGH | `UpstreamScheme::Tcp` passes validation but 502s at runtime — confirmed |
| **CORE-04** | MED | AI `extract_confidence` returns `None`; `confidence_threshold` is a no-op for sklearn-shaped ONNX | already-known issue, sees calibration note in `config/dev.yaml` |
| **CORE-05** | MED | `pool_snapshot_provider` hardcodes `healthy = total` — confirmed, dashboard health is fake |
| **CORE-06** | MED | `StateBackend::health()` default returns "disconnected" — confirmed; signal is misleading for new backends |
| **CORE-09 / CTL-08** | MED | `state.reconcile.mode = latest \| fail_safe` parses successfully then crashes at boot in `aegis-bin/state_select.rs`. `WafConfig::validate()` does NOT catch them — lint-time gap |
| **PROXY-02** | HIGH | `MatchType::Regex` and `MatchType::Glob` parsed + priority-sorted but `resolve_inner` only calls `trie.find_all_prefixes(path)` — needs verification but likely real |
| **PROXY-10 / 11** | MED | P2C uses a counter; ConsistentHash uses modulo — need to read `upstream/lb.rs` to confirm |
| **PROXY-08 / 09** | HIGH | `TierCache` not wired into the request pipeline — needs grep confirmation; if true, all cache config is dead |
| **CTL-19** | HIGH | `set_all(mode)` wipes operator overrides — needs verification; if true, contract §4.2 violation |
| **CTL-20** | MED | Password change doesn't invalidate sessions — needs verification |

### 0.3 — Deferred-stub / not-actionable-now

Real stubs that exist in the source but aren't on any hot path
today. They become real bugs the day someone wires them in.
**Action: catalog in `plans/future/` so the next person who
touches the area knows they need wiring.**

LT-RUN-5: SEC-02, SEC-04, SEC-08, SEC-20 (CAPTCHA, JWT, DLP, ICAP)
plus CTL-03, CTL-04 (Splunk HEC / Kafka audit sinks),
PROXY-04 / 23 (ACME), SEC-05 (OPA), SEC-14 (ICAP client),
CTL-18 (License validator), CTL-22/23 (PagerDuty / OpsGenie /
QRadar / ArcSight stubs), PROXY-18 (Jaeger), CORE-12 (network
secret providers).

### 0.4 — Findings that need bench-time verification

Some LT-RUN-5 claims need a small code-read I haven't done yet
because they're cheap but I want to confirm before scheduling:

| Finding | What to verify |
|---|---|
| PROXY-02 | Does `resolve_inner` actually skip regex/glob, or does it have a separate path? |
| PROXY-08 / 09 | Are there zero call sites of `TierCache` in handlers? |
| PROXY-10 / 11 | Read `upstream/lb.rs` — is P2C truly counter-based; is ConsistentHash truly modulo? |
| SEC-21 | Is `RuleAction::RateLimit` reachable via a rule the operator can save today? |
| CTL-19 | Read `interop/mode.rs:91-97` — does `set_all` really empty the override maps? |
| SEC-18 | Verify the CIDR-as-HashMap-key claim against the actual `threat_intel/mod.rs` |
| SEC-16 | Nonce race — is the issue path really two `subsec_nanos()` calls? |

These move from Phase 0 to Phase 2 or 3 once verified.

---

## Phase 1 — Policy QA quick wins (n-tester findings)

All eight findings from `policy-qa-findings.md` are dashboard-only
and small. Bundle into one PR; ~½ day total.

- [ ] **F-01** (HIGH) — Rules Simulator result panel doesn't render
      the API response. Fix the React state update in the
      `onSuccess` handler; bind the response to display state.
      Add a DOM-content test for `data-component` selectors.
- [ ] **F-02** (MED) — Silent validation: Add inline error +
      red-border + focus-first-invalid on Rules / Access Lists
      empty-submit. Apply to all required fields on the Policy
      section.
- [ ] **F-03** (MED) — Audit Log deep-link from Rules Stats tab
      loses context: append `?rule_id=<id>` to the link; have the
      Audit Trail page read it on mount.
- [ ] **F-04** (MED) — AI Enable shows no ONNX preflight: surface
      a warning when `model_path` set but model not loaded.
      (We already wired model-load fail-soft yesterday in
      `aegis-proxy/run.rs`; the API response can carry a
      `model_loaded: bool` field.)
- [ ] **F-05** (MED) — Compliance mode flip has no confirmation:
      caveat — compliance lock-by-mode is deferred today
      (`plans/future/compliance-profiles.md`). Reduce scope to
      "add confirmation dialog when modes are restored."
- [ ] **F-06** (LOW) — Detector Disable has no confirmation: add
      "Are you sure?" matching the Rules Delete pattern.
- [ ] **F-07** (LOW) — Access Lists Remove uses native
      `window.confirm()`: replace with the styled modal pattern.
- [ ] **F-08** (LOW) — "+ Add entry" button keeps `+` icon on
      Cancel state: change to `×` or drop the icon when in Cancel
      state.

**Tests:** dashboard polish suite stays green; add Playwright
or DOM-content assertions for F-01.

---

## Phase 2 — Verified aegis-core gaps (LT-RUN-4)

Real config / type / validation gaps. ~1 day.

- [ ] **CORE-01** — Resolve the `DdosConfig.observe_only` doc/impl
      conflict. Recommend: change `WafConfig.ddos` field doc to
      match the actual `Default` impl (`observe_only: false`) —
      enforce-by-default is the correct production posture, and
      the doc is wrong. **Decision needed**: confirm posture
      before changing doc vs. impl.
- [ ] **CORE-02** — `UpstreamScheme::Tcp` validates but 502s.
      Add a `validate()` guard in `WafConfig::validate()` that
      rejects `scheme: tcp` until Phase 4 ships. Loud-fail at
      boot instead of silent 502 at runtime.
- [ ] **CORE-09 / CTL-08** — Move the `reconcile.mode = latest |
      fail_safe` rejection from `aegis-bin/state_select.rs` boot
      path INTO `WafConfig::validate()`. Same for
      `state.backend = raft | redis_cluster`. Lint catches the
      error before boot.
- [ ] **CORE-05** — Wire real pool member health into the
      dashboard. The per-member `healthy: AtomicBool` already
      exists in `PoolRegistry`; just read it instead of returning
      `healthy = total`. ~20 lines.
- [ ] **CORE-06** — Change `StateBackend::health()` default
      from `unknown()` (`connected: false`) to a
      `{connected: true, backend: "unknown"}` shape. Dashboard
      health pill stops red-flagging new backends that haven't
      overridden the trait method.

**Deferred from CORE-04** (AI confidence threshold): the
sklearn-shape ONNX issue is a known calibration trade-off (see
`config/dev.yaml` ai block). Add a one-line note that
`confidence_threshold` is a no-op for sklearn-shape ONNX exports
+ link to the calibration doc. Don't try to fix
`extract_confidence` in this pass — that's a model-shape PR of
its own.

**Deferred from CORE-07** (gitops/witness/threat-intel not
spawned): the seam comment in `run.rs` is correct; the features
themselves aren't planned. Leave as-is.

**Deferred from CORE-10 / 11 / 12** (dead config_path field,
io_driver_fd_count no-op, network secret providers): low-value,
known limitations. Add to `plans/future/` index for
discoverability.

---

## Phase 3 — Verified aegis-proxy / aegis-security bugs (LT-RUN-5 subset)

Only the findings I either verified or believe are real-active-code.
~2-3 days depending on how many of the bench-time verifications
land in scope.

### Sub-phase 3a — Route resolver

- [ ] **Verify PROXY-02**: read `route/mod.rs:resolve_inner` end
      to end. If regex/glob really fall through to prefix:
      - Add a separate `RegexRouter` / `GlobMatcher` consulted
        after `find_all_prefixes` exhausts.
      - OR fail-loud at boot if `match_type: regex|glob` is
        configured and the resolver doesn't support it yet.

### Sub-phase 3b — Load balancer correctness

- [ ] **Verify PROXY-10** (P2C counter vs RNG): read
      `upstream/lb.rs::pick_p2c`. If deterministic-counter, swap
      to `fastrand` or `rand::thread_rng().gen_range(..)`. Add a
      property test that two consecutive picks are
      distinct-enough across many invocations.
- [ ] **Verify PROXY-11** (ConsistentHash modulo): read
      `pick_consistent_hash`. If modulo, replace with a
      virtual-node ring (~150-200 vnodes per member is standard).
      Same property test surface: members added/removed remap
      `~1/n` keys, not `~(n-1)/n`.

### Sub-phase 3c — TierCache removal (decision 2)

- [ ] Verified-zero call sites of `TierCache::` outside the
      module's own tests (Phase 0.4 spot-check). Action:
      **remove**.
- [ ] Delete `crates/aegis-proxy/src/cache/` module + any
      `mod cache;` declaration.
- [ ] Strip cache-related fields from `WafConfig` (search for
      `tier_cache`, `cache_ttl`, `cache_size` in
      `aegis-core/src/config.rs`).
- [ ] Drop the `Moka` dependency from `aegis-proxy/Cargo.toml`
      if it's only used here (verify before removing).
- [ ] Leave the contract's `POST /__waf_control/flush_cache`
      endpoint in place returning `{ok: true, supported: false}`
      — the contract §9 wording explicitly allows "caching not
      operational" reports.
- [ ] Audit `Implement-Progress.md` for cache claims that need
      updating to "removed 2026-05-11."

### Sub-phase 3g — Response filtering + Pipeline wire-up (decision 3) ★

This is the architectural piece that "decision 3 = keep + wire"
unlocks. ~1.5 days.

- [ ] **Backend**: replace `NoopPipeline` in
      `aegis-bin/main.rs:213-214` with
      `Pipeline::new(rules.clone())` (the existing impl in
      `aegis-security/src/pipeline.rs`). Boot won't change in
      behavior for inbound (data plane still calls
      `run_all_filtered_timed` directly), but now the
      `SecurityPipeline` trait has a real impl in scope.
- [ ] **Wire `Pipeline::on_body_frame`** to call
      `aegis_security::response_filter::filter_chunk(frame)`
      and the DLP scanner. Add a `DlpScanner` field on
      `Pipeline` constructed from `cfg.dlp` (or default-on with
      credit-card + SSN patterns).
- [ ] **Wire `Pipeline::on_response_start`** to inspect the
      upstream response headers — apply `X-Content-Type-Options`
      / `Strict-Transport-Security` etc. if not already
      stamped, and decide whether response-body filtering is
      enabled for this content-type (skip on `image/*`, `application/octet-stream`).
- [ ] **Data plane**: in
      `crates/aegis-proxy/src/data_plane.rs` where the upstream
      body is streamed back to the client, call
      `pipeline.on_body_frame(frame).await` for each chunk and
      apply the `OutboundAction` (PassThrough / Modified /
      Block-on-detection).
- [ ] **Config**: add `cfg.response_filter.{enabled,
      strip_stack_traces, dlp_patterns}` if not present.
      Audit-mutated PUT for runtime toggle.
- [ ] **Dashboard**: surface response-filter status on the
      Security Engine card (Settings or a new "Response
      Filtering" tile). Toggle for stack-trace scrub + DLP
      patterns.
- [ ] **Tests**:
      - Unit: `Pipeline::on_body_frame` redacts a credit-card
        number, scrubs a Python traceback, passes through clean
        JSON.
      - Integration: data-plane sends a synthetic 500 with a
        Python stack trace upstream; response to client has the
        traceback scrubbed.
      - DLP: synthetic JSON `{"card":"4111-1111-1111-1111"}`
        comes back as `{"card":"4111-****-****-****"}` (or
        `[REDACTED]` per action policy).
- [ ] **Docs**:
      - `docs/security/response-filtering.md` — new operator
        doc covering stack-trace scrub + DLP + Pipeline trait
        wiring.
      - Architecture.md §5 "Response filter" — was previously a
        forward-looking paragraph; now becomes shipped state.

### Sub-phase 3d — Rules engine + interop mode

- [ ] **Verify CTL-19**: read `interop/mode.rs:91-97`. If
      `set_all` really empties `feature_overrides` /
      `policy_overrides`, change `ModeSnapshot::empty(mode)` to
      preserve the existing override maps. Contract v2.3 §4.2
      compliance.
- [ ] **Verify SEC-21**: read `rules/eval.rs:107-119`. If
      `RuleAction::RateLimit` always blocks, either:
      - Connect to the existing IpRateLimiter / state-backend
        token bucket (audit-mutated); or
      - Reject the action at rule-validation time until wired.

### Sub-phase 3e — Threat intel CIDR (SEC-18)

- [ ] **Verify**: read `threat_intel/mod.rs:111-135`. If CIDR
      indicators are HashMap-keyed by string, replace with an
      `ipnet::IpNet`-keyed vec + linear scan (or a CIDR-tree
      lib). Adds a small dep (`ipnet`) which is fine.

### Sub-phase 3f — Session invalidation on password change (CTL-20)

- [ ] **Verify**: read `api/admin.rs::change_password`. If no
      `session_store.invalidate_all_for_user(...)` is called, add
      it after the password is persisted.

---

## Phase 4 — Document deferred / rejected findings

- [ ] Write `plans/future/unwired-stubs-catalog.md` listing every
      "real stub but not on active path" finding from LT-RUN-5,
      with the file location + the call-site grep that confirmed
      "not used today." Includes: CAPTCHA vendors (3 stubs),
      JWT validator, OPA stub, ICAP client, Splunk HEC sink,
      Kafka sink, QRadar/ArcSight SIEM, PagerDuty/OpsGenie
      alerters, License validator, Jaeger tracing branch,
      Redis rate-limit backend, ACME auto-renew, network secret
      providers (vault/aws/gcp/azure/hsm).
      Each entry: file path, "not called from <list>", contract
      status (required / not required / Phase-C deferred).
- [ ] **Remove** the actually-dead vendor stubs to stop them
      from re-appearing in static audits:
      - `aegis-security/src/challenge/captcha.rs` —
        `CaptchaProvider` trait + 3 vendor stubs. Drop entirely
        OR mark with `#![allow(dead_code)]` + module-level
        `//! 2026-05-11 — deferred; contract does not require
        CAPTCHA. See plans/future/unwired-stubs-catalog.md.`
      - Same call for `aegis-security/src/auth/jwt.rs` if
        truly unreferenced.
- [ ] In this directory's `TRIAGE.md` (companion to this README),
      keep the verified-hallucination list (CTL-26, SEC-07 impact
      claims) so future audits don't re-raise them.
- [ ] Update `plans/implementation-matrix.md` if any of the
      deferred items become hard "Not Implemented" entries.
- [ ] Update `Implement-Progress.md` to reflect Phase 3 changes:
      TierCache removed, Response Filtering shipped, DDoS
      `observe_only: false` documented as production default.

---

## Risk / impact summary

| Phase | Effort | Operator-visible impact |
|---|---|---|
| 1 — Policy QA | ½ day | Rules Simulator works; less-surprising UX across Policy section |
| 2 — aegis-core gaps | 1 day | Honest config validation (no parse-pass-boot-fail), accurate health UI, correct DDoS default doc |
| 3 — aegis-proxy/security (verified subset) | 3-4 days | Regex/glob routing parity, LB correctness, **TierCache removed**, mode-override safety, **response filtering wired (stack-trace scrub + DLP)** |
| 4 — Document + stub removal | 1 day | Stub catalogue in `plans/future/`; truly-dead vendor stubs deleted; implementation matrix updated |

**Total estimated effort:** 5-6 working days for verified-real
findings (increased from 4-5 because Phase 3 now includes the
response-filter wire-up + TierCache removal per decisions
2 + 3). Compare: treating every LT-RUN-5 finding as urgent
would burn ~3 weeks chasing inflated impacts.

## Decisions (locked 2026-05-11)

1. **DdosConfig default** (CORE-01) — **enforce by default is
   the production posture**. Keep `observe_only: false` in the
   `Default` impl; fix the `WafConfig.ddos` field doc + the
   operator-facing surface to match. This becomes a production
   feature (hardening pass): make sure the default behavior is
   defensible, audit-logged at first-trip, and well-documented.
   Phase 2 action.

2. **TierCache** (PROXY-08/09) — **remove**. Drop the cache
   module from `aegis-proxy/src/cache/`, strip any config
   surface that mentions cache tiers / TTLs, and remove
   `flush_cache` callback wiring if nothing else uses it
   (keep `POST /__waf_control/flush_cache` returning
   `supported: false` per existing contract §9 shape).
   Phase 3 action (combined with `SecurityPipeline` cleanup).

3. **`SecurityPipeline` trait + response filtering** — **keep
   the trait, actually wire it**. Response filtering is a real
   missing piece:
   - `crates/aegis-security/src/response_filter.rs` exists with
     stack-trace scrubbers for Python / Node.js / Java / Go
     (`scrub_stack_traces`, `filter_chunk`).
   - `crates/aegis-security/src/dlp/mod.rs` has
     credit-card / SSN regex + Luhn / SSN validators with
     Redact / Mask / Block / Monitor actions.
   - Neither is called from `aegis-proxy/src/` today (verified
     via grep). They're tested but vestigial.

   Action plan:
   - **Replace `NoopPipeline` in `aegis-bin/main.rs`** with a
     real `Pipeline::new(rules)` that the data plane can call.
   - **Wire `on_response_start` + `on_body_frame`** in the
     existing `Pipeline` impl to call `response_filter::
     filter_chunk` (stack-trace scrub) and the DLP scanner
     (credit-card / SSN redaction).
   - **Plumb `pipeline.on_body_frame(frame)` into the response
     path in `aegis-proxy/src/data_plane.rs`** where the
     upstream body is streamed back to the client.
   - This converts SEC-07 / SEC-08 / SEC-20 from "vestigial
     trait" to "real wiring path." Detector chain (inbound)
     still runs through `run_all_filtered_timed()` directly —
     the trait is for **response-side** work where the data
     plane needs an extension point.

4. **CAPTCHA / JWT / OPA / DLP / ICAP** — per contract:

   | Feature | Contract v2.3 status | Decision |
   |---|---|---|
   | **PoW / JS challenge** | Required (§3) | Already shipped (PoW). No change. |
   | **CAPTCHA vendors** | Not required (no mention of Turnstile / hCaptcha / reCAPTCHA in spec) | **Defer**. Move stubs to `plans/future/unwired-stubs-catalog.md`. Remove `CaptchaProvider` trait + 3 vendor stubs from `aegis-security/src/challenge/captcha.rs` if they're truly unreferenced, OR keep with a clear `#[deprecated]` + "deferred feature" doc note. |
   | **JWT auth** | Not required (admin auth already uses argon2 + session cookie + CSRF, contract §2.2 just requires *some* auth on control endpoints) | **Defer**. Move `aegis-security/src/auth/jwt.rs` to the deferred catalogue. The `aegis-control::api::login` admin auth path is contract-conformant on its own. |
   | **OPA** | Not required | **Defer**. Catalogue. |
   | **DLP** | Not required, but operator-valuable | **Ship as part of decision 3**: wire DLP redaction into `Pipeline::on_body_frame` alongside stack-trace scrub. |
   | **ICAP** | Not required (Phase-C feature per module doc) | **Defer**. Catalogue. |

   Contract evidence: §3 decision classes are `allow / block /
   challenge / rate_limit / timeout / circuit_breaker` — no
   CAPTCHA-specific action, no JWT-specific auth scheme. §3
   challenge: "client must solve a JS challenge OR
   proof-of-work" — `OR` means PoW alone satisfies the spec.

## Suggested PR sequence

1. **PR #1** — Phase 1 (Policy QA) as a single dashboard PR.
2. **PR #2** — Phase 2.1 + 2.2 (DdosConfig doc to match
   enforce-by-default impl, Tcp validate guard, reconcile.mode
   validate guard) — pure config / validation work.
3. **PR #3** — Phase 2.3 + 2.4 + 2.5 (real pool health,
   StateBackend default health, F-04 AI preflight signal) —
   small wiring changes.
4. **PR #4** — Phase 3a (PROXY-02 regex/glob route resolution).
5. **PR #5** — Phase 3b (LB correctness: P2C RNG, ConsistentHash
   ring) — needs property tests.
6. **PR #6** — Phase 3c (TierCache removal) — drops dead module +
   config surface + Moka dep.
7. **PR #7** — Phase 3g (Response filtering + Pipeline wire-up).
   **Largest PR** — replaces `NoopPipeline`, wires
   `on_body_frame` to `filter_chunk` + DLP, adds dashboard
   surface + operator doc. Decision-3 deliverable.
8. **PR #8** — Phase 3d/e/f (CTL-19 mode override safety,
   SEC-21 RuleAction RateLimit, SEC-18 CIDR threat intel,
   CTL-20 password→session invalidation) — security
   correctness pack.
9. **PR #9** — Phase 4 (documentation + stub catalogue + delete
   truly-dead vendor stubs).

PR #1 + #2 + #3 unblock everything else and are
near-independent. #4-#8 are parallelisable after that. #7 is
the biggest single PR — keep it focused on response filtering
to make review tractable.
