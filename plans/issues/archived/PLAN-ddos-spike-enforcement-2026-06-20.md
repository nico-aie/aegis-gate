# DDoS spike mode — wire enforcement + hysteresis (`tightened_per_ip_rps` is dead config)

**Status:** 🟢 P1–P4 shipped (TDD, `develop`, 2026-06-20)
**Filed:** 2026-06-20
**Reporter:** s-tester
**Severity:** 🔴 High (Finding #1 Critical) — surge-protection for Round 3 Attack Battle (DDoS L7 flood, BTC vector #01)
**Source report:** [`tests/s-tester/reports/20260620_ddos_spike_mechanism_report.md`](../../tests/s-tester/reports/20260620_ddos_spike_mechanism_report.md)
**Related:**
- [`PLAN-shed-per-pool-isolation-2026-06-20.md`](./PLAN-shed-per-pool-isolation-2026-06-20.md) + [`PLAN-conn-layer-dos-gaps-2026-06-20.md`](./PLAN-conn-layer-dos-gaps-2026-06-20.md) — the **distributed-flood** layer (per-pool shedder + accept-time conn cap). Spike-tighten is the **few-IP** layer; the three compose.
- [`runtime_gate_toggles_not_durable.md`](./runtime_gate_toggles_not_durable.md) — DDoS dashboard PUTs already have a durability caveat; orthogonal but same gate.

## TL;DR — report is accurate on all three findings

Re-verified against HEAD on `develop` (2026-06-20). The Spike mechanism **detects correctly**
(EWMA baseline + multiplier, 1s tick) but is **"observability theater"** — it raises a flag,
logs it, lights the dashboard, and **enforces nothing.**

| # | Finding | Sev | Verdict | Evidence |
|---|---|---|---|---|
| 1 | Spike detected but **never enforced** — `tightened_per_ip_rps` is dead config | 🔴 Critical | ✅ Confirmed | `check_local` ([ddos.rs:446](../../crates/aegis-security/src/ddos.rs#L446)) + Redis `check_with_tier` ([ddos.rs:~585](../../crates/aegis-security/src/ddos.rs#L585)) both use plain `cfg.limit_for(tier)` and block at that limit ([ddos.rs:461](../../crates/aegis-security/src/ddos.rs#L461)) with **no spike branch**. Every `is_spike_active()` consumer only populates telemetry (`DdosResult.spike_active` ddos.rs:315/349/395/612; audit JSON `ddos_spike_active` data_plane.rs:651/671). `grep tightened_per_ip_rps` → config schema / API gates / dashboard / validate only — **0 enforcement sites.** |
| 2 | Per-node, not cluster-wide | 🟡 Medium | ✅ Confirmed | `rolling_rps: AtomicU64` ([ddos.rs:177](../../crates/aegis-security/src/ddos.rs#L177)) is process-local; comment says "cluster-wide" ([ddos.rs:50](../../crates/aegis-security/src/ddos.rs#L50)); `dev.yaml:356` admits "cluster-wire deferred". |
| 3 | No hysteresis/dwell → flap | 🟡 Medium | ✅ Confirmed | `tick_rps` sets `spike_active = 1/0` on the instantaneous compare ([ddos.rs:638-642](../../crates/aegis-security/src/ddos.rs#L638)); no N-tick dwell, no cooldown. |

**Consequence:** in the Attack Battle, an HTTP flood lights `ddos_spike_active = true` on the
dashboard while the attacking IP keeps firing up to the *normal* `per_ip_limit` (dev.yaml:
60000/window). Same "declared-validated-surfaced-but-never-enforced" pattern as
`QuotaConfig.read_timeout` was (now fixed in the conn-layer plan).

### Unit semantics (must get right in the fix)
- `per_ip_limit` = **count over `per_ip_window_s`** (config.rs:4211 — e.g. 1000 req / 10s).
- `tightened_per_ip_rps` = **per-IP RPS** (config.rs:4218).
- Conversion: `tightened_window_limit = tightened_per_ip_rps × per_ip_window_s`
  (20 rps × 10s = 200 req/window, vs the normal 60000). Report's formula is correct.

### Corrections / nuances to fold in
- **Line drift:** the `ddos_spike_active` audit field is at **`data_plane.rs:651` + `:671`**,
  not `:623` as the report states. Everything else is file:line-accurate.
- **Collateral damage (under-weighted by the report):** `spike_active` is a **global** flag but
  tightening is **per-IP** — when it fires it clamps **every** IP, including legit users in a
  flash-crowd, to the tightened cap. This is *why* hysteresis (#3) is not cosmetic: a 1-tick
  blip must not throttle everyone. Argues for (a) dwell before engage, (b) an `observe_only`
  composition test, (c) keeping `tightened_per_ip_rps` sane (20–50, not single digits).
- **Layering (avoid overselling):** per-IP spike-tighten only stops **few-IP** floods. A
  highly-distributed flood (each IP < tightened cap) slips through — that is the per-pool
  shedder + accept-time conn-cap's job (sibling plans). State this so the fix isn't oversold.
- **Hot-reload is free:** `check_local` reads `self.config.load()` (ArcSwap) fresh per call, so
  a dashboard PUT to `tightened_per_ip_rps` takes effect live — no extra reload wiring needed.

---

## ✅ Shipped 2026-06-20 (`develop`, TDD)

- **P1** — spike tightening wired into **both** `check_local` and the Redis
  `check_with_tier` via a shared `spike_tightened_limit()` helper
  (`min(per_ip_limit, tightened_per_ip_rps × per_ip_window_s)`, tighten-only).
  Tests: `spike_active_tightens_check_local_block_threshold`,
  `spike_active_tightens_redis_check_with_tier`, `no_spike_leaves_per_ip_limit_untightened`,
  `observe_only_with_spike_still_only_observes` (composition — `should_enforce()` stays false).
- **P2** — hysteresis in `tick_rps`: two run-length counters
  (`spike_over_ticks`/`spike_under_ticks`) engage after `spike_engage_ticks` (default 2)
  consecutive over ticks, release after `spike_release_ticks` (default 8) under ticks. New
  knobs on both `DdosConfig` structs (serde defaults + `From` mapping); `reset()`/hot-disable
  zero them. Tests: `spike_engages_only_after_dwell_not_on_single_tick`,
  `spike_holds_through_brief_dip`, `spike_clears_only_after_release_cooldown` (deterministic,
  injected RPS); pre-existing instantaneous tests updated for dwell.
- **P3** — doc-fix: "cluster-wide"→**per-node** across `ddos.rs` + `dev.yaml`, breadcrumb at
  `rolling_rps` for deferred real aggregation. (Redis fleet-sum aggregation still deferred.)
- **P4** — `config.rs` + `dev.yaml` document the enforcement + RPS→window unit; new dwell
  knobs surfaced in `dev.yaml`. Validated via `aegis-bin validate --config config/dev.yaml`.

**Out of scope (as planned):** per-tier tightened cap (YAGNI), σ-band adaptive threshold,
true cluster-wide RPS aggregation. **Suites green:** aegis-security 1853/0, aegis-core 319/0,
aegis-control 1133/0.

---

## P1 — [🔴 Critical] Wire spike enforcement into the per-IP gate (TDD)

**Goal:** when `spike_active`, the per-IP block threshold drops to
`tightened_per_ip_rps × per_ip_window_s` (tighten-only, never loosen).

**Steps (TDD):**
1. **RED (proves #1):** force `spike_active = true` (drive `tick_rps` with a synthetic RPS
   sequence, or a test seam). One IP fires at a rate **between** `tightened×window` and
   `per_ip_limit` (e.g. tightened=20×10s=200, normal=60000, fire 300 in-window). Assert
   `NewlyBlocked`. This test **fails today**.
2. Companion test: with `spike_active = false`, the same IP at the same rate is `Allowed`
   (tightening engages **only** during spike).
3. **GREEN** — in `check_local`, right after `let (per_ip_limit, per_ip_window_s) =
   cfg.limit_for(tier);` ([ddos.rs:446](../../crates/aegis-security/src/ddos.rs#L446)):
   ```rust
   let mut per_ip_limit = per_ip_limit;
   if self.is_spike_active() {
       let tightened = cfg
           .tightened_per_ip_rps
           .saturating_mul(u64::from(per_ip_window_s)); // RPS → per-window count
       per_ip_limit = per_ip_limit.min(tightened);       // tighten, never loosen
   }
   ```
   `.min()` means a misconfigured `tightened×window > per_ip_limit` is a safe no-op.
4. **Parity:** apply the identical branch to the Redis `check_with_tier`
   ([ddos.rs:~585](../../crates/aegis-security/src/ddos.rs#L585)) so both enforcement paths
   behave the same regardless of which backend a config enables.
5. **Composition test:** `observe_only: true` + spike → request still **observed, not
   short-circuited** (enforce/observe is decided downstream of `check_local`; the tightened
   limit only changes *when* a would-be-block is recorded). Guards against spike silently
   turning a shadow gate into an enforcing one.

**Tier-override interaction:** `limit_for` already returns the per-tier limit; the `.min()`
tightens whatever it returns. A per-tier *tightened* cap is **out of scope** (YAGNI) — one
global `tightened_per_ip_rps` is enough for v1. Note it for later.

## P2 — [🟡 Medium] Hysteresis / dwell in `tick_rps` (TDD)

**Goal:** stop `spike_active` flapping when traffic oscillates around the threshold.

- Add two consecutive-tick counters (or one signed run-length):
  - **Engage:** require ≥ **2** consecutive over-threshold ticks before setting `spike_active`.
  - **Release:** require ≥ **8** consecutive under-threshold ticks (cooldown) before clearing.
- Defaults `2` / `8`; expose as `DdosConfig` knobs (`spike_engage_ticks`,
  `spike_release_ticks`) with serde defaults so existing configs keep working.
- **Tests (deterministic — inject the RPS sequence, no wall-clock):**
  1. Oscillation across the threshold → `spike_active` does **not** flap (engages only after
     the dwell, holds through brief dips).
  2. Sustained spike → engages within `engage_ticks`.
  3. Sustained calm after a spike → clears after `release_ticks`, not on the first quiet tick.
- Keep the existing hot-disable behaviour ([ddos.rs:625-629](../../crates/aegis-security/src/ddos.rs#L625)):
  a disabled gate zeroes the counters and clears `spike_active`.

## P3 — [🟡 Medium] Resolve the "cluster-wide" naming mismatch (decision + docs)

**Decision (recommended): doc-fix now, real aggregation deferred.** For single-node /
hackathon, per-node counting is sufficient. Re-word the misleading "cluster-wide" comments on
`rolling_rps`/`spike_multiplier`/`tightened_per_ip_rps` and `dev.yaml:356` to say **per-node**,
so operators don't assume fleet-wide surge detection that isn't there.

**Deferred (larger):** true cluster-wide RPS via Redis — `INCR` a per-tick key and read the
fleet sum in `tick_rps` — gated on whether multi-node spike detection is actually needed.
Leave a one-line TODO breadcrumb at the `rolling_rps` site pointing here.

> **Promoted to a future design doc (2026-06-20):**
> [`../future/ddos-cross-node-rps-aggregation.md`](../future/ddos-cross-node-rps-aggregation.md)
> — full design (per-second fleet bucket via existing `incrby`/`get_counter`, async tick seam,
> fail-safe to per-node, `spike_scope` config gate). Not scheduled.

## P4 — Config / doc sweep

- Update `config.rs` `DdosConfig` docs ([config.rs:4218](../../crates/aegis-core/src/config.rs#L4218))
  to state `tightened_per_ip_rps` is **enforced** (cross-ref P1) and document the RPS→window
  conversion so the unit difference vs `per_ip_limit` is unambiguous.
- Confirm dashboard already surfaces `current_rps` / `baseline_rps` / `spike_active` via the
  existing getters ([ddos.rs:386-395](../../crates/aegis-security/src/ddos.rs#L386)) — no new
  telemetry needed; the gap was enforcement, not observability.
- **Out of scope (research nice-to-have):** σ-band adaptive threshold (`baseline + k·σ`,
  k=3–4). Defer; the multiplier threshold is adequate for the Battle.

---

## Acceptance gates

- [ ] `aegis-security` lib green; **the P1 enforcement test that fails pre-fix now passes**,
      and the `spike_active=false` companion confirms tightening is spike-gated.
- [ ] Redis `check_with_tier` carries the same tightening (parity test).
- [ ] `observe_only + spike` still observes (no short-circuit).
- [ ] P2 hysteresis tests: no flap on oscillation; engages on sustained spike; clears after
      cooldown — all deterministic.
- [ ] `s-tester` end-to-end (multi-IP, per BTC §6 `127.0.0.x` = distinct clients): warm
      baseline ~1000 rps → 5× spike from many IPs → `ddos_spike_active=true` **and** attacking
      IPs throttled to the tightened cap (block-rate jumps); low-rate legit traffic still
      served; spike clears on cooldown. (Single-IP load would conflate with DashMap hot-shard
      contention — must spread source IPs.)

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Global flag + per-IP tighten clamps **all** IPs during a legit surge | Hysteresis/dwell (P2) so blips don't engage; `observe_only` escape hatch; keep `tightened_per_ip_rps` at 20–50 |
| LOW | Distributed flood (each IP < tightened cap) bypasses per-IP tighten | By design — covered by per-pool shedder + conn cap (sibling plans); documented, not oversold |
| LOW | Hysteresis knob churn confuses operators | Sensible serde defaults (2/8); existing configs unchanged |
| LOW | Test flake from wall-clock timing | Drive `tick_rps` with injected RPS sequences, never sleeps |

## Complexity: MEDIUM

P1 is small and surgical (≈6 lines × 2 paths + tests) and is the high-value fix. P2 adds a
little dwell state. P3 is a decision + comment fix. P4 is docs.
