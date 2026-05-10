# Phase 1 — CRITICAL fixes (rerun)

> **Branch:** all changes target `develop`.

---

## NEW-1 · `risk.thresholds` not updated on hot-reload

**Source:** Run-2 §2 NEW-1.

### Verified state (2026-05-08, on `develop`)

- `crates/aegis-security/src/risk/tracker.rs:110` — `RiskTracker::set_thresholds(&self, t: RiskThresholds)` exists (the QA report calls it `update_thresholds` but the actual method is `set_thresholds`; same underlying bug).
- `crates/aegis-proxy/src/admin_mutate.rs:1881` — `tracker.set_thresholds(next_for_apply.clone())` is called from the audit-mutated `PUT /api/risk/thresholds` handler. So the runtime path through the dashboard's "Cumulative IP risk thresholds" card works.
- `crates/aegis-proxy/src/supervisor.rs` — `spawn_config_watcher` + `watch_loop` cover detector mask, route table, rate-limit, TLS certs, and mTLS trust. **No risk-threshold block.** Editing `risk.thresholds.challenge_at` in `config/dev.yaml` and triggering hot-reload does NOT propagate to the live tracker.

The QA's reproduction is correct. Editing `dev.yaml` to lower `challenge_at` and observing `config_reload` in logs gives no behavior change because the tracker's internal `ArcSwap<RiskThresholds>` was never re-stored.

### Plan

**Step 1 — extend `spawn_config_watcher` signature with an optional `Arc<RiskTracker>`.**

```rust
// crates/aegis-proxy/src/supervisor.rs:135
pub fn spawn_config_watcher(
    path: PathBuf,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    proxy_ctx: Option<Arc<crate::proxy::ProxyContext>>,
    ip_rate_limiter: Option<Arc<aegis_security::rate_limit::IpRateLimiter>>,
    tls_resolver: Option<Arc<crate::listener::tls::DynamicResolver>>,
    client_trust: Option<crate::listener::client_trust::ClientTrustStore>,
+   risk_tracker: Option<Arc<aegis_security::risk::RiskTracker>>,
) -> tokio::task::JoinHandle<()>
```

**Step 2 — in `watch_loop`, after the existing rate-limit block, add the risk-threshold update.**

```rust
// crates/aegis-proxy/src/supervisor.rs (inside watch_loop, after the rate-limit block)
if let Some(tracker) = risk_tracker.as_ref() {
    let new_thresholds = new_cfg.risk.thresholds.clone();
    let old_thresholds = tracker.thresholds();
    if new_thresholds != old_thresholds {
        tracker.set_thresholds(new_thresholds.clone());
        tracing::info!(
            challenge_at = new_thresholds.challenge_at,
            block_at     = new_thresholds.block_at,
            max          = new_thresholds.max,
            "config hot-reload: risk thresholds swapped",
        );
    }
}
```

**Step 3 — pass the tracker through from `run.rs`.**

```rust
// crates/aegis-proxy/src/run.rs:687 area
supervisor::spawn_config_watcher(
    config_path,
    cfg_swap.clone(),
    bus.clone(),
    Some(detector_mask.clone()),
    Some(proxy_ctx.clone()),
    Some(ip_rate_limiter.clone()),
    tls_resolver,
    client_trust,
+   Some(risk.clone()),
);
```

**Step 4 — RED test in `supervisor.rs` tests module.**

The supervisor's existing test infrastructure (e.g. `hot_reload_swaps_route_table`, `hot_reload_swaps_ip_rate_limit_cfg`) is the right shape to mirror. New test:

```rust
#[tokio::test]
async fn hot_reload_swaps_risk_thresholds() {
    let cfg = test_config_with_risk(40, 80, 100);          // helper → WafConfig with thresholds
    let cfg_swap = Arc::new(ArcSwap::from_pointee(cfg));
    let risk = Arc::new(RiskTracker::new(&cfg_swap.load().risk));
    let (bus, _rx) = AuditBus::new(64);
    let path = write_config_to_tmp(&cfg_swap.load());

    let handle = spawn_config_watcher(
        path.clone(), cfg_swap.clone(), bus, None, None, None, None, None,
        Some(risk.clone()),
    );

    // Snapshot the live thresholds — should match config
    assert_eq!(risk.thresholds().challenge_at, 40);

    // Edit the file: bump challenge_at to 50
    rewrite_config(&path, |c| c.risk.thresholds.challenge_at = 50);

    // Wait for the reload (notify::RecommendedWatcher fires within ~100 ms locally;
    // tests/cluster scripts allow 5 s — use the same backstop).
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let after = poll_until(|| risk.thresholds().challenge_at == 50, std::time::Duration::from_secs(5)).await;
    assert!(after, "risk thresholds did not propagate within 5 s");

    handle.abort();
}
```

If the test infrastructure already has a builder for "watcher with all overrides", reuse it; otherwise add the minimal helper. The watcher tests under `crates/aegis-proxy/src/supervisor.rs` lines 580+ already do this for routes / mask / rate-limit; pattern-match to that.

**Step 5 — confirm GREEN.** The test should fail before Step 2 and pass after.

### Acceptance

- [ ] `spawn_config_watcher` signature gains the new optional parameter
- [ ] `watch_loop` calls `tracker.set_thresholds(...)` when the new config differs from the live snapshot
- [ ] One info-level log line on every successful threshold swap
- [ ] New `hot_reload_swaps_risk_thresholds` test passes
- [ ] All existing supervisor tests pass
- [ ] Manual repro from QA's NEW-1 reproduction script no longer reproduces (challenge tier becomes reachable after editing `challenge_at` and observing reload)

**Effort:** ~1 hour. Mirrors a pattern that's already in this file 4 times.

---

## C002 follow-up · default-tighten AI in dev + prod profiles

**Source:** Run-2 §1 C002 (partial). Run-1 closed the v2.3 contract surface (toggleable policy, log_only path, threshold bumped 0.5 → 0.85). Model FP rate is still ~75 % at 0.85.

### Strict v2.3 reframing

The v2.3 contract gives us the runtime escape — `set_profile { policies: ["ai"], mode: "log_only" }` works correctly post-Run-1. What's left is the **default**: today the WAF ships with `ai.enabled: true` at threshold 0.85, which means out-of-the-box the AI detector blocks ~75 % of clean traffic.

The QA recommendation:
> Place `ai: enabled: false` (or `log_only` via `set_profile`) in all production profiles until the model is retrained on the specific upstream's clean traffic. Do not ship with `enabled: true` at any threshold below 0.95 without a per-deployment FP measurement.

We do not retrain the model in this PR (it's a data/ML problem; track separately). We DO ship a default that doesn't sink the SLO.

### Plan

**Step 1 — flip `config/dev.yaml` to `ai.enabled: false`.**

```yaml
# config/dev.yaml line 124-127 area
ai:
  enabled: false
  # 2026-05-08 — disabled by default in dev. The current ONNX model
  # over-fires at any threshold below 0.95 on benign traffic; QA
  # measured ~75% FP rate at 0.85. Operators can flip via the
  # Detectors page or via:
  #   POST /__waf_control/set_profile
  #   { scope: "policies", feature: "rules_engine",
  #     policies: ["ai"], mode: "log_only" }
  # to keep visibility without enforcement, OR set enabled: true
  # here after running a per-deployment FP calibration.
  model_path: data/ai_model/waf_model.onnx
  confidence_threshold: 0.85
```

**Step 2 — same in `config/profiles/prod-balanced.yaml` if AI is wired there** (verify; if not, no change needed).

**Step 3 — same in `config/profiles/prod-strict.yaml`.** Strict mode shouldn't auto-enable a high-FP detector either.

**Step 4 — document in `docs/security/detectors/ai-detector.md`** (if the file exists) the calibration workflow:

> Before enabling the AI detector in any environment, run a clean-traffic sample against the deployed model and measure FP rate. Acceptable FP rate at the chosen threshold should be < 5 %. The model that ships in this repo is a baseline; it is not calibrated to any specific upstream.

**Step 5 — no code changes needed.** Run-1's set_profile / log_only wiring is already shipped and verified (QA Run-2 confirms it's contract-compliant).

**Step 6 — manual verification.**

```sh
make bench-dev    # in another terminal
SECRET="waf-hackathon-2026-ctrl"

# 1. Default state — AI disabled
curl -ks http://127.0.0.1:8080/api/list  # expect 200, X-WAF-Action: allow

# 2. Operator opts in via set_profile
curl -ks -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["ai"]}' \
  http://127.0.0.1:8080/__waf_control/set_profile | jq

# 3. Now AI signals appear in audit but don't enforce
curl -ksi http://127.0.0.1:8080/api/list | grep -i '^x-waf-'
# Expect: x-waf-action: allow OR (block + x-waf-mode: log_only) — never enforce
```

### Acceptance

- [ ] `config/dev.yaml` ships `ai.enabled: false` with the calibration warning comment
- [ ] `config/profiles/prod-*.yaml` ship the same default (or no AI block at all)
- [ ] M009 SLO recovers in dev (verify after deploy + 24 h burn-window roll)
- [ ] `docs/security/detectors/ai-detector.md` calibration note added
- [ ] No code changes; Run-1's set_profile path stays the runtime escape

**Effort:** ~1.5 h (mostly the doc + verification, since the code is unchanged).

---

## Sequencing

NEW-1 ships first — it's a one-file fix with a clear regression test.
C002 follow-up ships second; it's config + docs only and has no test impact.

Both can ship in **one PR**: `fix(critical): hot-reload risk thresholds + tighten AI defaults (NEW-1 + C002 follow-up)`.
