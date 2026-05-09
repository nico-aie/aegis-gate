# DDoS wire-up plan (internal audit, 2026-05-09)

> **Trigger:** [`reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md`](../../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md)
>
> **Branch:** all changes target `develop`.
>
> **Goal:** turn the unwired `DdosDetector` stub into a working v1 single-node implementation, then update the doc to honestly describe what's shipped vs what's deferred.

---

## Why two phases (not one)

Wiring DDoS protection in one giant PR is risky: the request hot path is shared with rate-limiting, risk scoring, and the rules engine, and an early-return (503) is a behaviour change every operator's traffic encounters. Splitting reduces the blast radius:

1. **Phase 1 — config + telemetry surface** (no behaviour change). Add the `ddos:` YAML block, instantiate `DdosDetector` at boot, surface counters + dashboard panel + audit-event tag. Set `enforce: false` (observation mode) by default so the detector runs and logs but never blocks. Operators can flip the toggle once they trust the signal.

2. **Phase 2 — enforce path + 503 short-circuit** (behaviour-changing). Wire the `is_auto_blocked` short-circuit, return 503 on blocked IPs, broadcast spike-mode to the dashboard / SIEM. Default `enforce: true` here only after Phase 1's metrics confirm zero false-positive spike triggers in real traffic.

Splitting also keeps the doc-status update honest: after Phase 1 the doc moves to "**Partial — observe-only single-node**", and after Phase 2 it moves to "**Implemented (v1 single-node)**". The v2 cluster + per-tenant pieces stay deferred behind multi-tenancy.

---

## Phase 1 — Config + telemetry (observation only)

**Goal:** `DdosDetector` runs on every request, emits metrics + audit events, **never blocks**.

### Changes

1. **`aegis-core/src/config.rs`** — new `DdosConfig` field on root config:
   ```rust
   #[derive(Clone, Debug, Deserialize)]
   pub struct DdosConfig {
       #[serde(default = "default_true")]
       pub enabled: bool,
       /// Observation mode: detect + log + count, never 503.
       /// Default `true` until operators have validated the signal.
       #[serde(default = "default_true")]
       pub observe_only: bool,
       #[serde(default = "default_per_ip_limit")]
       pub per_ip_limit: u64,
       #[serde(default = "default_per_ip_window_s")]
       pub per_ip_window_s: u32,
       #[serde(default = "default_block_ttl_s")]
       pub block_ttl_s: u64,
       #[serde(default = "default_spike_multiplier")]
       pub spike_multiplier: f64,
   }
   ```
   Defaults match `aegis_security::ddos::DdosConfig::default()`. Wire into `RootConfig` with `#[serde(default)]` so old YAML still parses.

2. **`aegis-security/src/ddos.rs`** — extend the existing `DdosConfig` with `enabled` + `observe_only` flags. Keep the same field names so the YAML block deserialises cleanly. Add a `From<aegis_core::config::DdosConfig> for DdosConfig` impl.

3. **`aegis-proxy/src/run.rs`** — instantiate the detector at boot:
   ```rust
   let ddos = if cfg.ddos.enabled {
       Some(Arc::new(DdosDetector::new(cfg.ddos.clone().into())))
   } else {
       None
   };
   // Spawn the spike-detection ticker once.
   if let Some(d) = &ddos {
       let d = d.clone();
       tokio::spawn(async move {
           let mut iv = tokio::time::interval(Duration::from_secs(1));
           loop {
               iv.tick().await;
               d.tick_rps();
           }
       });
   }
   ```
   Thread the `Option<Arc<DdosDetector>>` through to the request-handling path the same way `mask` and `risk` are.

4. **Hot path (proxy request handler)** — call `ddos.check(state, peer_ip).await?` early in the pipeline (after TLS/HTTP parse, before rule engine). Always observe — never 503 in this phase. On `result.blocked`, emit:
   - audit event with `tag=ddos_observed`, `field=peer_ip`, `score=0` (observation, no risk add)
   - Prometheus counter `waf_ddos_blocks_total{reason}` (`burst` / `spike` / `auto_block`)

5. **Metrics** — new counters in `crates/aegis-control/src/metrics/`:
   - `waf_ddos_blocks_total{reason}` — Counter
   - `waf_ddos_spike_active` — Gauge (0/1)
   - `waf_ddos_baseline_rps` — Gauge
   - `waf_ddos_current_rps` — Gauge

6. **Dashboard panel** — new card on the **Health & SLOs** page showing:
   - Current RPS / baseline RPS / spike threshold
   - Spike-active indicator (green dot when normal, red pulse when spike)
   - Block-counter rolling 5-min sum, broken down by reason
   - One-line "currently in observe-only mode" disclaimer until Phase 2 lands

7. **Doc update** — `docs/security/ddos-protection.md`:
   - Status field → "**Partial — observe-only single-node** (Phase 1 of [wire-up plan])"
   - Explicit "what's shipped vs what's deferred" table
   - Operator action: how to switch `observe_only: false` once they trust the signal
   - Drop the per-tenant + cluster-coordinated paragraphs entirely (link them to multi-tenancy + ha-clustering as deferred dependencies)

8. **Score-catalog** — DDoS doesn't run through the detector chain (it's a request-level gate, not a `Detector` impl), so no `scores.rs` row needed. It does emit risk via `state.add_risk` at the strikes ladder; document the 100-point set on auto-block.

9. **Tests** — new integration test `crates/aegis-proxy/tests/ddos_observe.rs`:
   - Boot a real proxy with `cfg.ddos.enabled = true, observe_only = true`.
   - Send 200 requests from one IP within a window where `per_ip_limit = 100`.
   - Assert: every request returns the upstream response (no 503), audit log carries 100 `ddos_observed` events for the over-limit half, `waf_ddos_blocks_total` Prom counter is at 100.

### Acceptance

- [ ] `cargo build --workspace` green
- [ ] All workspace tests pass (1242+ security, 1045+ control, 18/18 binaries)
- [ ] Bench traffic in observe-only mode: zero 503s, audit-event count for `ddos_observed` matches the synthetic flood
- [ ] Dashboard panel renders the four metrics with sensible values
- [ ] Doc reflects observe-only state honestly

**Effort:** ~1 day.

---

## Phase 2 — Enforce path + 503 short-circuit

**Goal:** `observe_only: false` flips the WAF into actually-blocking mode. Operators choose to opt in once Phase 1 metrics show the signal is clean.

### Changes

1. **Hot path** — when `result.blocked && !cfg.ddos.observe_only`, short-circuit the request with HTTP 503, no upstream contact, no detector chain. Audit-event tag changes from `ddos_observed` to `ddos_blocked`.

2. **`StateBackend::is_auto_blocked` short-circuit** — even before `ddos.check()`, the request handler peeks `state.is_auto_blocked(peer_ip)`. If true, return 503 immediately. This is the path operators expect from the doc — a previously-blocked IP doesn't even reach the detector chain. Existing strikes-based auto-block (from `risk/tracker.rs`) starts blocking through the same path automatically — that's a free win.

3. **Spike-mode behaviour** — when `spike_active = true`:
   - Tighten per-IP threshold to `cfg.ddos.tightened_per_ip_rps` (new field, default 20)
   - Emit a single audit event when spike toggles on (not per-request)
   - Surface to dashboard as a yellow banner across the top of every page

4. **Risk integration** — when `result.blocked` (in enforce mode), `state.add_risk(RiskKey::Ip(peer_ip), 100, 100)` so the IP is also flagged in the risk-tracker view (the strikes ladder still operates independently — the two paths are complementary).

5. **Doc update** — `docs/security/ddos-protection.md`:
   - Status field → "**Implemented (v1 single-node)**"
   - Explicitly state the v2 / multi-tenant / cluster pieces are deferred behind `multi-tenancy.md` and `ha-clustering.md`
   - Update the "Response behavior" section to describe the actual 503 path

6. **Implementation-matrix update** — same status change.

7. **Tests** — extend the integration test:
   - Same setup but `observe_only = false`. Assert: requests after the 100-request limit return 503, body is the standard block envelope, Prom counter increments, audit tag is `ddos_blocked`.
   - Spike-mode test: inject a synthetic 4×-baseline burst across multiple IPs, assert `spike_active = 1`, all per-IP thresholds tighten, dashboard banner state changes.

### Acceptance

- [ ] Full integration test suite green (Phase 1 + Phase 2)
- [ ] Doc status accurately reflects "Implemented (v1)"
- [ ] Operator switch (`observe_only: false`) works without restart (audit-mutated; takes effect within one hot-reload tick — or document explicitly that it requires restart if hot-reload is too risky for this knob)
- [ ] No regression on existing 2,442 lib tests

**Effort:** ~1 day.

---

## What this plan does NOT solve

- **Per-tenant scoping** — depends on multi-tenancy (`docs/future/multi-tenancy.md` is DEFERRED). Don't fake it; explicitly remove from the doc.
- **Cluster-wide spike-mode broadcast** — depends on cluster state (`docs/operations/ha-clustering.md`). Phase 1 + 2 deliver per-process spike detection only; nodes coordinate **only** through the shared `StateBackend::is_auto_blocked` keyspace (which already works for redis backend).
- **Adaptive load-shedder integration** — works today via the load shedder reading the same state-backend; document the integration without adding new code.
- **Sub-modules `mode.rs` / `sweeper.rs`** — not built. The single `ddos.rs` file is enough for the v1 scope. If multi-tenancy lands later, refactor at that time.

---

## Sequencing

| Step | Phase | Order |
|---|---|---|
| 1. File bug + status update | Pre-work | **Done** (this PR) |
| 2. Phase 1 wire-up + observe-only mode | Phase 1 | Next |
| 3. Bake + collect metrics for ≥1 day on staging | Phase 1 | After step 2 ships |
| 4. Phase 2 enforce path + 503 | Phase 2 | After bake-in |
| 5. Doc moves to "Implemented (v1)" | Phase 2 | With step 4 |

---

## Cross-refs

- [`reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md`](../../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md) — bug report
- [`docs/security/ddos-protection.md`](../../../docs/security/ddos-protection.md) — doc with the (now-corrected) status field
- [`crates/aegis-security/src/ddos.rs`](../../../crates/aegis-security/src/ddos.rs) — existing detector logic to wire
- [`docs/operator/risk-tuning.md`](../../../docs/operator/risk-tuning.md) — adjacent doc explaining the risk-strikes auto-block (one of the partial backstops today)
- [`docs/data-plane/adaptive-load-shedding.md`](../../../docs/data-plane/adaptive-load-shedding.md) — actually-implemented feature DDoS should integrate with
- [`docs/future/multi-tenancy.md`](../../../docs/future/multi-tenancy.md) — deferred dependency blocking the per-tenant claims
