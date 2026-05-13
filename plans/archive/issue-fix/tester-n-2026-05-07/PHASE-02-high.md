# Phase 2 — HIGH fixes

> **Strict spec:** every fix follows `Hackathon_Doc/EN_waf_interop_contract_v2.3.md`.
> **Branch:** all changes target `develop`.

---

## H001 · SSRF detector false-positive on `Referer` header

**Source:** `tests/n-tester/reports/findings/2026-05-07/F-HIGH-001-ssrf-referer-false-positive.md`

### Verified state

`crates/aegis-security/src/detectors/ssrf.rs:61` — header scan list:

```rust
for name in &["referer", "x-original-url", "x-rewrite-url"] {
```

### Plan

**Step 1** — Drop `referer` from the scan list:

```rust
// Before:
for name in &["referer", "x-original-url", "x-rewrite-url"] {
// After:
for name in &["x-original-url", "x-rewrite-url"] {
```

**Rationale:** `Referer` describes where the user came from; it never represents a server-side fetch target. SSRF exploits go through query params, request bodies, or `X-Original-URL` / `X-Rewrite-URL` reverse-proxy directives — never via `Referer`. Browsers auto-set `Referer` to the page's own origin, which trips loopback patterns on any localhost-deployed WAF.

**Step 2** — Add a unit test as a negative case:

```rust
#[test]
fn clean_request_with_loopback_referer() {
    let view = req("GET", "/api/data")
        .header("Referer", "http://127.0.0.1:8080/")
        .build();
    let detector = SsrfDetector::default();
    let signals = detector.run(&view);
    assert!(signals.is_empty(), "Referer must not trigger SSRF");
}
```

**Step 3** — Confirm `X-Original-URL` / `X-Rewrite-URL` still trigger correctly:

```rust
#[test]
fn x_original_url_with_loopback_still_blocks() {
    let view = req("GET", "/api/data")
        .header("X-Original-URL", "http://127.0.0.1:8080/admin")
        .build();
    let detector = SsrfDetector::default();
    let signals = detector.run(&view);
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].tag, "ssrf");
}
```

### Acceptance

- [ ] `Referer` removed from the scan list
- [ ] Loopback-Referer negative case passes
- [ ] X-Original-URL positive case still passes
- [ ] Live dashboard at `127.0.0.1:8080` no longer self-blocks sub-resource requests
- [ ] All existing SSRF detector tests pass

**Effort:** ~15 min. Lowest risk fix in the plan.

---

## H002 · Investigation pivot link drops query params

**Source:** `tests/n-tester/reports/findings/2026-05-07/F-HIGH-002-investigation-pivot-query-params-dropped.md`

### Verified state

Frontend SPA hash-router — not deeply verified at the code level (would need to trace the router config). Trusting the report.

### Plan

**Step 1** — Reproduce.

1. Boot dev (`make run-dev` or `make bench-dev`)
2. Send `make mock-load-attacks` to populate the audit ring
3. Open dashboard → Live Feed → click a BLOCK row → click "Pivot to Investigation →"
4. Expected: Investigation page with `pivot=...&kind=...` populated in search input, results displayed
5. Actual: Overview renders (the bug)

**Step 2** — Locate the Investigation component in `crates/aegis-control/assets/dashboard/src/`.

```sh
grep -n "function PageInvestigation\|investigation" \
  crates/aegis-control/assets/dashboard/src/pages.jsx | head
```

**Step 3** — On mount, parse the hash-fragment query string:

```js
useEffect(() => {
  const hash = window.location.hash;
  const queryStart = hash.indexOf('?');
  if (queryStart === -1) return;
  const params = new URLSearchParams(hash.slice(queryStart + 1));
  const pivot = params.get('pivot');
  const kind = params.get('kind');
  if (pivot) {
    setPivotInput(pivot);
    if (kind) setKindOverride(kind);
    triggerPivot(pivot, kind);  // existing function
  }
}, []);
```

**Step 4** — Verify the SPA router actually matches `#/investigation?pivot=...`. If the router strips the query, fix the route matcher or normalise the URL to `#/investigation` and pass the params via `history.state`.

**Step 5** — Fix the fallback-to-Overview behaviour. An unmatched hash route should land on a clear "Page not found" surface, not silently re-render the Overview. This prevents future routing bugs from being invisible.

### Acceptance

- [ ] Click "Pivot to Investigation →" from a Live Feed detail drawer → Investigation page renders with the pivot input pre-filled and results visible
- [ ] Direct deep-link `#/investigation?pivot=req-abc&kind=request_id` produces the same behaviour
- [ ] Unmatched hash routes (e.g. `#/typo`) render a 404 view instead of Overview
- [ ] No regression in any existing pivot path (manual entry via the search input continues to work)

**Effort:** ~1 hour. Mostly reading the existing router config + adding a `useEffect` hook.

---

## H003 · `reset_state` evicts admin sessions

**Source:** `tests/n-tester/reports/findings/2026-05-07/F-HIGH-003-reset-state-evicts-admin-sessions.md`

### Spec citation (must satisfy)

§2.4 of v2.3:

> *"It SHOULD preserve long-term static config unless explicitly requested otherwise."*

Admin sessions are operator-state, not WAF temp state, and are not in §2.4's enumerated "MUST clear" list. Evicting them is a contract violation if reproduced.

### Operator hypothesis (2026-05-07)

> *"I think because we didn't implement api `__waf_control/**` for our waf (port 8080)"*

In other words: H003 may be a **side effect of C001**. The QA tester hit `reset_state` from a browser-driven flow. Without the data-plane endpoint wired, the path may have:

1. routed through the data plane → blocked by SSRF FP (C001) → an unrelated 403
2. confused the QA harness's session-tracking logic
3. been misattributed in the report as an "admin session evicted"

This is plausible but unverified. Plan: re-test **after** C001 lands.

### Verified state of `develop` (2026-05-07)

- `run.rs:1394–1403` — only two reset callbacks registered: `risk.reset_all()` and `ip_rate_limiter.reset_all()`.
- A third callback was added 2026-05-05 for `AttacksAggregator::reset()` (rolling window).
- **None touch the session store** — `aegis-control::api::auth::SessionStore` is not in any reset path.

The report's described failure mode (`handle_reset_state ... flushes Redis keys matching aegis_session:*`) does not match the code on `develop`. The reset machinery uses per-subsystem `reset_all()` methods, not a Redis key sweep.

### Plan (gated on C001)

**Step 1 — Land C001 first** (Phase 1). Cherry-pick + verify `/__waf_control/*` reachable on `:8080` via `make bench-dev`.

**Step 2 — Re-test H003 against the post-C001 build.**

```sh
make bench-dev    # boots dev with the C001 fix live
# In another terminal (browser): log into dashboard at http://127.0.0.1:9443/
# Then:
curl -ks -X POST -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" \
  http://127.0.0.1:8080/__waf_control/reset_state | jq

# Switch back to the dashboard tab — refresh:
#   - If still authenticated → H003 closes as N/A (it was the C001 side effect)
#   - If redirects to /admin/login → H003 is real, proceed to Step 3
```

Also re-run the QA harness's exact session-eviction probe sequence on the post-C001 build.

**Step 3 — If H003 still reproduces after C001**: trace the eviction.

```sh
# Add tracing temporarily — confirm which subsystem touches sessions on reset:
RUST_LOG=trace ./waf run --config ./waf.yaml 2>&1 | grep -iE "session|csrf|reset"
# Trigger reset_state, observe.
```

Likely-suspect subsystems if it does repro:
- `SessionStore::clear()` — search for unintended callers
- A Redis sweep using `KEYS *` that catches `aegis_session:*`
- A CSRF-secret rotation triggered indirectly by reset

**Step 4 — If real, fix.**

The intended behaviour per §2.4: clear WAF runtime state (rate-limit counters, risk scores, attack aggregators), preserve admin auth state. Recommended: scope the sweep (whitelist admin Redis prefixes) rather than re-architect key namespacing. ~1 hour if it goes this way.

**Step 5 — Regression test (only if real).**

```rust
#[tokio::test]
async fn reset_state_preserves_admin_sessions() {
    let services = build_test_services().await;
    let session_id = services.sessions.create_session("admin").unwrap();

    // Trigger reset_state via the control plane
    services.interop.unwrap().control.reset_state();

    // Session must still be valid (§2.4: preserve long-term config)
    let s = services.sessions.lookup(&session_id);
    assert!(s.is_some(), "reset_state must NOT evict admin sessions");
}
```

### Acceptance

- [ ] H003 re-tested on post-C001 build (live + QA harness rerun)
- [ ] **If C001 closes it**: mark H003 as "closed by C001" in the next QA report, no separate fix
- [ ] **If still real**: scoped fix + regression test
- [ ] Doc note in `STAGING-BENCHMARK.md §5.6` clarifying that `reset_state` is safe to call from a logged-in dashboard session

**Effort:** ~30 min if C001 closes it (most likely outcome). ~1.5 hours if real.

---

## Sequencing notes for Phase 2

- **H001 first** — 15 minutes, unblocks the entire dev-on-localhost workflow.
- **H002 next** — independent of H001, fixes the S3 SOC scenario.
- **H003 last** — gated on C001 landing first; expected to close as N/A.

## Phase 2 ships as

Two PRs (assuming H003 closes via C001):

1. `fix(detectors): drop Referer from SSRF scan + tests` (H001 alone — small, safe)
2. `fix(dashboard): Investigation pivot reads hash query params` (H002 alone, possibly +H003 if real)
