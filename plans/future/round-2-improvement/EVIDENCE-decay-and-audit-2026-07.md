# Evidence pack — risk decay & audit coverage (committee round-2 🟡3)

> **AU-4** deliverable of [FEAT-audit-coverage-gaps](../../issues/archived/FEAT-audit-coverage-gaps-2026-07.md).
> Compiled 2026-07-05. Every claim carries a file:line anchor and a reproducible
> test; run commands from the repo root.

## 1. "Is risk decay implemented?" — Yes, and here is the proof

### Formula & defaults

Linear trust recovery: `recovered_points = elapsed_seconds × per_hour / 3600`,
floored ("`trust_decay_points`", `crates/aegis-security/src/risk/tracker.rs`).
Default rate **30 points/hour** (`aegis-core/src/config.rs`, `TrustRecoveryConfig`),
hot-tunable via `PUT /api/risk/thresholds` and cluster-propagated.

### Where decay applies (decay-on-read, one code path)

`decayed_slot()` ages the stored score by time-since-`last_seen` on **every**
read path — the gate decision, the `/api/risk` view, and the rebase step of
`record_malicious` — so all three always agree
(`crates/aegis-security/src/risk/tracker.rs`, `decayed_slot` /
`record_clean_at_with_key` / `record_malicious_at_with_key`).

### What deliberately never decays

**Strikes.** The lifetime repeat-offender counter only ever increments
(`entry.strikes.saturating_add(1)`); score decay cannot erase strike history.

### Reproduce

```sh
cargo test -p aegis-security --lib tracker::tests -- decay trust
# key tests: trust decay ramp, decay-on-read idempotence,
# interleaved_clean_does_not_reset_cumulative_for_shared_key
```

## 2. Decay caveats the committee should know (AU-3 dispositions)

| # | Caveat | Disposition (2026-07-05) |
|---|---|---|
| A | Idle eviction (1 h TTL) used to wipe strike state, so a **strike-blocked** source could un-block itself by going quiet | **Fixed.** Slots at/above `strikes.block_at` are exempt from idle eviction while the gate is enabled, with a 100 k safety cap (pathological blocked floods fall back to TTL; `MAX_TRACKED_KEYS` stays the hard memory ceiling). Under-threshold strikes still age out — that is the trust-recovery posture, now deliberate. Note the narrowing from the owner's "struck slots": *every* malicious record strikes, so exempting all struck slots would exempt every offender ever seen. Tests: `strike_blocked_slot_survives_idle_sweep`, `under_threshold_strikes_are_still_evicted_when_idle`, `strike_block_exemption_falls_back_to_ttl_past_safety_cap`. |
| B | At `MAX_TRACKED_KEYS` (1 M) new keys silently stop accumulating (fail-open) | **Made observable.** `saturation_rejects` counter + `is_saturated()` on the tracker; surfaced on `GET /api/risk` (`saturated`, `saturation_rejects`) and as gauges `waf_risk_tracker_saturation_rejects` / `waf_risk_tracker_saturated`. Test: `saturation_rejects_counter_increments_at_cap`. |
| C | `trust_per_hour: 0` disables decay entirely (sticky scores), reachable via config and API | **Explicit warning** at both wire points (boot + `set_trust_per_hour`); no validation floor — freezing decay mid-incident is a legitimate operator move. |

## 3. Audit coverage — what leaves a trail

- **Admin mutations (~40 call sites)**: every audit-mutated PUT/POST/DELETE flows
  through `AuditedMutate::apply` (`crates/aegis-control/src/api/mutation.rs`) —
  config activate/rollback, rules CRUD/toggle, mode/loadmode, risk
  resets/thresholds, white/blacklist, gates, zero-trust, AI routes.
- **Auth surface (AU-1, shipped 2026-07-04)**: `login_success` / `login_failure`
  (bucketed, flood-aggregated) / `logout` — `crates/aegis-control/src/api/login_audit.rs`.
- **Control-plane wipe (AU-1)**: `reset_state` emits an Admin-class event
  **before** the wipe (`ControlContext::reset_state_async`); order proven by
  `reset_state_emits_admin_audit_event_before_the_wipe`.
- **Tamper evidence**: SHA-256 hash chain, per-batch `fsync` (F-CRITICAL-013),
  offline verification via `waf audit verify`; 9 SIEM sink formats.
- **Delivery honesty (AU-2)**: best-effort bus by design; drops are counted on
  `waf_audit_events_dropped_total{consumer}` and per-sink delivery state is live
  at `GET /api/cold-tier`. Durability model: `docs/operator/usage.md` §6.

### Reproduce

```sh
cargo test -p aegis-control --lib login_audit          # taxonomy + aggregation
cargo test -p aegis-control --lib reset_state          # order-before-wipe
cargo test -p aegis-proxy   --lib au1_wiring           # events from the real login path
cargo test -p aegis-proxy   --lib pe3_route_guard      # no placeholder surface returns
```
