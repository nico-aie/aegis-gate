# BUG: DDoS protection is documented as implemented but is dead code

**Filed:** 2026-05-09
**Type:** Internal architectural audit (self-discovered, not QA-reported)
**Severity:** **HIGH** — operator-visible documentation lies about a security feature
**Status:** Open — fix plan in [`plans/issue-fix/internal-audit-2026-05-09-ddos/`](../../../plans/issue-fix/internal-audit-2026-05-09-ddos/)

---

## Summary

[`docs/security/ddos-protection.md`](../../../docs/security/ddos-protection.md) declares its status as **"Implemented — `aegis-security/src/ddos.rs`"** and walks the operator through a `ddos:` YAML config block, response semantics ("Blocked IP hits the WAF: HTTP 503"), and integration points (challenge engine, adaptive load shedding, cluster state). [`plans/implementation-matrix.md`](../../../plans/implementation-matrix.md) row 66 mirrors that claim.

**The actual implementation is a stub.** `crates/aegis-security/src/ddos.rs` defines `DdosConfig` + `DdosDetector` structs and 5 unit tests, but the detector is **never instantiated outside its own test module**. No code path runs DDoS detection on real traffic, no YAML field deserializes into `DdosConfig`, no `tokio::spawn` runs the spike-detection ticker, and the proxy hot path has no 503 short-circuit for blocked IPs.

A SOC operator following the doc — or any compliance auditor reviewing it — would conclude the WAF protects against volumetric / per-IP-flood / spike-mode attacks. **It does not, via this module.** Some adjacent primitives provide a partial backstop (see "What still works" below), but the architecture the doc describes is not present.

---

## Reproduction (verify the gap)

```bash
# 1. The module is exported.
grep -nE 'pub mod ddos' crates/aegis-security/src/lib.rs
#   crates/aegis-security/src/lib.rs:13:pub mod ddos;

# 2. Nothing outside the module's own file references DdosDetector / DdosConfig.
grep -rEn 'DdosDetector|DdosConfig' crates/ \
  | grep -v '^crates/aegis-security/src/ddos\.rs:'
#   (empty — zero hits)

# 3. No `ddos:` config block on the Rust side.
grep -nE '^\s*pub ddos|DdosConfig' crates/aegis-core/src/config.rs
#   (empty)

# 4. No 503 / auto-block short-circuit in the proxy hot path.
grep -nE 'is_auto_blocked' crates/aegis-proxy/src/lib.rs crates/aegis-proxy/src/run.rs
#   (empty — only the StateBackend trait method is implemented; nobody calls it from the request path)

# 5. tick_rps() is only called from #[test] — no production scheduler.
grep -rEn 'tick_rps\(\)' crates/
#   crates/aegis-security/src/ddos.rs:107:    pub fn tick_rps(&self) {
#   crates/aegis-security/src/ddos.rs:261:        detector.tick_rps();
#   crates/aegis-security/src/ddos.rs:267:        detector.tick_rps();
#   crates/aegis-security/src/ddos.rs:282:        detector.tick_rps();
#   crates/aegis-security/src/ddos.rs:287:        detector.tick_rps();
#   crates/aegis-security/src/ddos.rs:296:        detector.tick_rps();
```

Every line above is a doc-vs-code contradiction.

---

## What the doc claims vs what exists

| Doc claim | Reality |
|---|---|
| "Implemented — `aegis-security/src/ddos.rs`" | **File exists, contents are dead code** |
| Sub-modules `src/ddos/detector.rs`, `auto_block.rs`, `sweeper.rs`, `mode.rs` | **Single file `ddos.rs`** — multi-module structure was never built |
| YAML `ddos: enabled: true ...` config block with `per_ip`, `global`, `per_tenant_overrides` | **Zero `ddos:` field on the Rust config struct** — operators cannot configure it |
| "Blocked IP hits the WAF: HTTP 503, no backend contact" | **Proxy never calls `is_auto_blocked` on the request path; never returns 503 from a DDoS check** |
| "Per-IP burst detection in 1-second sliding window" | Logic exists in `DdosDetector::check`. Never invoked. |
| "Global rate spike detection" via `tick_rps()` | Method exists. **No tokio task spawns it in production.** |
| "Per-tenant scope, `waf:block:{tenant}:{ip}`" | Multi-tenancy is **explicitly DEFERRED** ([`docs/future/multi-tenancy.md`](../../../docs/future/multi-tenancy.md)). The keyspace doesn't exist. |
| "Cluster-wide DDoS mode" | `spike_active` is a per-process `AtomicU64`. Cluster-shared mode broadcast doesn't exist. |
| "Adaptive load shedder drops MEDIUM tier first" | Load shedder is implemented (`aegis-proxy/src/shed.rs`) but **not wired to DDoS** |
| "Dashboard alert on DDoS mode" | No dashboard surface, no metric, no audit event for DDoS-triggered blocks |
| "Risk score set to 100 for block duration" | `RiskTracker` does its own auto-block path on the strikes ladder; no DDoS-side hook |

---

## What still works (partial backstop)

The WAF is **not** completely defenseless against floods because adjacent features provide overlapping coverage:

| Primitive | Effect | Lives in |
|---|---|---|
| Per-IP rate limiting (token bucket) | Steady-state per-IP budget enforced by `rate_limit::bucket` | `crates/aegis-security/src/rate_limit/` |
| Velocity / login-flood limiter | Login-failure burst → temporary block | `crates/aegis-security/src/velocity.rs` |
| Risk-strikes auto-block | After N strikes (default 50) the IP is permanently blocked via `state.auto_block` | `crates/aegis-security/src/risk/tracker.rs` |
| Adaptive load shedding (Gradient2) | Under saturation, drops lowest-tier traffic first | `crates/aegis-proxy/src/shed.rs` |
| `is_auto_blocked` storage primitive | `StateBackend::is_auto_blocked` works (in_memory + redis backends) | `crates/aegis-proxy/src/state/` |

What's **missing** (the actual DDoS-protection use cases):

1. **Single-IP burst spikes** (e.g. an attacker hits 500 req/s for 10 s from one IP) — token bucket has steady budgets but no burst-window auto-block.
2. **Cluster-wide spike mode** — when aggregate RPS jumps 3× the baseline, the WAF doesn't tighten thresholds globally.
3. **Coordinated mitigation across nodes** — a flood spread across nodes is not caught faster than the per-IP token bucket on each individual node.
4. **DDoS-specific observability** — operators have no metric `waf_ddos_blocks_total`, no dashboard panel, no audit event tag.

---

## Severity rationale — why HIGH

- **Documentation lies.** Compliance frameworks (PCI 8.3, SOC 2 CC 6.6, ISO 27001 A.13.1) require accurate documentation of security controls. Claiming an unimplemented control is fraudulent in a regulated environment.
- **Operator trust.** A SOC team relying on the doc for incident response will misdiagnose floods (they'll grep for `ddos_blocked` in audit, find none even during an obvious flood, and conclude "the WAF didn't see it" rather than "the feature isn't wired").
- **No silent failure.** The behaviour today is "no signal" — there's no way to discover from telemetry that DDoS isn't running. Future readers debugging a flood will waste hours assuming the documented feature is active.
- **Easy to hide forever.** The unwired stub passes `cargo test` (its own unit tests are green) and `cargo build`, so neither CI nor automated audits flag it. Only manual code reading catches it.

---

## Recommendation

Wire the existing `DdosDetector` into the proxy hot path **honestly**: implement the v1 single-node feature set (per-IP burst detection, EWMA spike mode, in-memory + redis auto-block) and explicitly document the multi-tenant + cluster-coordinated pieces as deferred (since their dependencies are themselves deferred). Avoid the third option (delete it) because the existing detector logic is sound — only the wiring is missing — and DDoS protection is a baseline expectation for a WAF.

Plan: [`plans/issue-fix/internal-audit-2026-05-09-ddos/`](../../../plans/issue-fix/internal-audit-2026-05-09-ddos/).

---

## Acceptance criteria for "fixed"

- [ ] `DdosConfig` deserializes from YAML on `cfg.ddos.*`
- [ ] `DdosDetector` is instantiated in `aegis-proxy/src/run.rs` from the active config
- [ ] Proxy hot path checks `is_auto_blocked` on every request and short-circuits with HTTP 503 when blocked
- [ ] Per-IP burst exceeded → `state.auto_block` writes a TTL'd block entry
- [ ] Background `tokio::spawn` runs `tick_rps()` every 1 s for spike detection
- [ ] Spike mode increments a Prometheus counter and emits an audit event
- [ ] Per-tenant scope is **explicitly removed** from the doc until multi-tenancy lands (no fake feature claims)
- [ ] Documentation status field updated truthfully — "Partial (single-node v1)" until the cluster pieces land, then "Implemented (v2)" later
- [ ] Implementation-matrix row reflects the same status
- [ ] Integration tests cover the 503-on-blocked-IP path end-to-end (full request through proxy, not just the detector unit)
- [ ] No regression on existing tests (1242 security + 1045 control + workspace green)

---

## Cross-refs

- [`docs/security/ddos-protection.md`](../../../docs/security/ddos-protection.md) — doc with the false status field
- [`plans/implementation-matrix.md`](../../../plans/implementation-matrix.md) — row 66, same lie
- [`crates/aegis-security/src/ddos.rs`](../../../crates/aegis-security/src/ddos.rs) — the stub
- [`docs/operator/risk-tuning.md`](../../../docs/operator/risk-tuning.md) — adjacent doc that explains how the risk-strikes auto-block works (one of the partial backstops)
- [`docs/data-plane/adaptive-load-shedding.md`](../../../docs/data-plane/adaptive-load-shedding.md) — actually-implemented feature DDoS should integrate with
- [`docs/future/multi-tenancy.md`](../../../docs/future/multi-tenancy.md) — the deferred dependency that blocks the per-tenant claims in the DDoS doc
