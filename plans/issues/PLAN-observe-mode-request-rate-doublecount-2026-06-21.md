# Observe-mode request-rate double-count — `ddos_observed` inflates Requests/s

**Status:** 🟢 Phase 1 shipped (TDD, `develop`, 2026-06-21) — Phase 2 (Live Feed live/reload consistency) + Phase 3 (docs) still open
**Filed:** 2026-06-21
**Reporter:** pre-prod observation (operator enabled DDoS + observe-only, saw Requests/s jump)
**Severity:** 🟡 Medium — metric correctness; misleads capacity/threat reads during shadow validation (no data-plane / security impact)
**Related:**
- [`archived/PLAN-ddos-spike-enforcement-2026-06-20.md`](./archived/PLAN-ddos-spike-enforcement-2026-06-20.md) (observe/log_only fall-through path that emits the shadow event)
- Prior fix of the same class: `rate_limit` double-emit (listener + data-plane) → `interop::headers::listener_emits_audit` dedup (`develop`, 2026-06-21)

## TL;DR

The Overview **"Requests / s"** card (and the top-bar `REQ/S` chip, and the
per-second traffic chart) is **event-count-derived**, not a true per-request
counter. `StatsAggregator::record` pushes **every** audit event into the
request window with no action/class filter
([`stats.rs:157`](../../crates/aegis-control/src/api/stats.rs#L157)).

In **observe-only / log_only** DDoS mode, one inspected request emits **two**
audit events instead of one:

1. the data-plane **`ddos_observed`** (or `ddos_blocked`) shadow detection event
   ([`data_plane.rs:656`](../../crates/aegis-proxy/src/data_plane.rs#L656)), then the
   request **falls through** (no early return), and
2. the request's **terminal decision** event at the listener — `allow` /
   `circuit_breaker` / etc. ([`accept.rs:2206`](../../crates/aegis-proxy/src/accept.rs#L2206),
   gated by `listener_emits_audit` at [`accept.rs:2005`](../../crates/aegis-proxy/src/accept.rs#L2005)).

Both reach `StatsAggregator::record` via the same unfiltered bus drain
([`dashboard_services.rs:758`](../../crates/aegis-control/src/dashboard_services.rs#L758)),
so each observed request is counted **twice** → **~2× `request_rate`**.

| Mode | Audit events per breaching request | Counted as requests |
|---|---|---|
| Enforce | 1 — a single `block` (403 at the gate) | 1 ✅ |
| **Observe / log_only** | **2** — `ddos_observed` **+** terminal (`allow`/`circuit_breaker`) | **2 ❌ (double)** |

Same class of bug as the recently-fixed `rate_limit` double-emit — an extra
audit event that an event-derived metric naively treats as another request.

## Root cause (verified in code)

- **Metric is event-count-based.** `request_rate = count(events in last 10s) / 10`
  ([`stats.rs:220`](../../crates/aegis-control/src/api/stats.rs#L220),
  window [`stats.rs:28`](../../crates/aegis-control/src/api/stats.rs#L28)).
  Increment: `state.requests.push_back((now, was_block))` for **every** event
  ([`stats.rs:157`](../../crates/aegis-control/src/api/stats.rs#L157)); the per-second
  timeseries bucket likewise counts every event
  ([`stats.rs:188`](../../crates/aegis-control/src/api/stats.rs#L188)).
- **No filter on the bus → stats path.** `dispatch_event` calls `stats.record(ev)`
  for every event regardless of `class`/`action`
  ([`dashboard_services.rs:746-766`](../../crates/aegis-control/src/dashboard_services.rs#L746)).
- **Observe mode emits the extra event by design.** `ddos_observed` is the shadow
  signal; the request still proceeds to a terminal decision, which the listener
  also emits (`listener_emits_audit(Allow|CircuitBreaker) == true`,
  [`headers.rs:89`](../../crates/aegis-control/src/interop/headers.rs#L89)). The
  existing `block/challenge/rate_limit` dedup does **not** cover this case (the
  terminal action here is `allow`/`circuit_breaker`, which legitimately emits).
- Surfaces: Overview card [`pages.jsx:433`](../../crates/aegis-control/assets/dashboard/src/pages.jsx#L433),
  top-bar chip [`pages.jsx:2322`](../../crates/aegis-control/assets/dashboard/src/pages.jsx#L2322),
  both via `/api/stats`.

### Secondary (cosmetic) — Live Feed live-vs-reload inconsistency

The live SSE stream renders `ddos_observed` rows (correct for shadow validation),
but the backfill on reload (`/api/audit/since`) filters them out of `REAL_ACTIONS`
([`data.jsx:486-498`](../../crates/aegis-control/assets/dashboard/src/data.jsx#L486)).
So the feed shows **2 rows/request live, 1 after reload** — confusing but
harmless. Tracked here; fix is optional (see Phase 2).

## Scope / non-goals

- **In scope:** make `request_rate` + the per-second chart count **one event per
  request** (exclude the adjunct shadow detection events).
- **Not** changing the audit trail / Live Feed *content* — `ddos_observed` must
  still appear in the feed and durable audit (that's the whole point of observe
  mode). Only its contribution to the **request-volume metric** is wrong.
- **Not** touching block-rate semantics — block-rate keys on `action == "block"`,
  which the shadow events are not, so it stays correct once they're excluded.
- The Prometheus `waf_requests_total{action}` counter
  ([`metrics/decisions.rs`](../../crates/aegis-control/src/metrics/decisions.rs)) and
  the DDoS `current_rps` EWMA ([`api/gates.rs`](../../crates/aegis-control/src/api/gates.rs))
  are separate sources and out of scope (verify they're unaffected).

## Fix plan

### Phase 1 — exclude shadow detection events from request volume (the fix)

Define the set of **non-terminal "shadow" actions** that accompany (rather than
terminate) a request and must not count as request volume:
`ddos_observed`, `ddos_blocked`.

- In `StatsAggregator::record` ([`stats.rs:149`](../../crates/aegis-control/src/api/stats.rs#L149)),
  short-circuit *the request-volume bookkeeping* for those actions: skip the
  `state.requests.push_back` ([`:157`](../../crates/aegis-control/src/api/stats.rs#L157))
  **and** the per-second bucket increment ([`:188`](../../crates/aegis-control/src/api/stats.rs#L188)).
- Keep everything else intact (threat-set tracking keys on `risk_score`, which
  these events lack, so it's already a no-op for them — but make the skip explicit
  and early so intent is clear).
- Encode the predicate as a small named helper (e.g. `counts_as_request(action)`
  or `is_shadow_detection(action)`) so the policy is one obvious place — mirrors
  `listener_emits_audit`. Prefer an **allow-list of terminal actions**
  (`allow|block|challenge|rate_limit|timeout|circuit_breaker|websocket_frame_block`)
  over a deny-list, so a future shadow action can't silently re-inflate the metric.

**Files:** `crates/aegis-control/src/api/stats.rs`.

### Phase 2 (optional) — Live Feed live/reload consistency

Pick ONE so the feed reads the same live and after reload:
- **(a)** Add `ddos_observed` (and `ddos_blocked`) to the backfill `REAL_ACTIONS`
  set ([`data.jsx:486`](../../crates/aegis-control/assets/dashboard/src/data.jsx#L486))
  so shadow rows survive a reload (recommended — observe mode wants them visible), **or**
- **(b)** drop them from the live render too (hides the shadow signal — *not*
  recommended).

Recommendation: **(a)**. Requires a dashboard rebundle (`make dashboard-force`).

### Phase 3 — docs

- Note in [`docs/data-plane/`](../../docs/data-plane/) / the DDoS card help that
  observe-only emits an **extra audit row** for shadow validation but it does
  **not** count toward request volume (after Phase 1).

## TDD test plan (RED → GREEN)

- `stats.rs` unit tests on `StatsAggregator`:
  - `ddos_observed_does_not_count_as_request` — record 1 `allow` + 1
    `ddos_observed` (same logical request) → snapshot `total == 1`, `request_rate`
    reflects 1, not 2. **RED today.**
  - `ddos_blocked_shadow_does_not_count_as_request` — same for log-only.
  - `enforced_ddos_block_still_counts_once` — a single `block` event →
    `total == 1`, `blocked == 1` (no regression to block-rate).
  - `terminal_actions_all_count` — allow/challenge/rate_limit/timeout/
    circuit_breaker each count as 1 (locks the allow-list).
  - per-second bucket test: a `ddos_observed` does not bump `bucket.total`.
- Optional Phase 2: a small assertion that the backfill action set includes
  `ddos_observed` (JS — or just verify via the rebundled `app.js` smoke).

## Acceptance gates

- [ ] In observe-only mode under a single-IP flood, Overview "Requests / s" matches
      the true inbound rate (≈ enforce-mode rate for the same load), not ~2×.
- [ ] Block-rate and the threat-IP count are unchanged by the fix.
- [ ] `aegis-control` lib tests green incl. the new stats tests; 0 warnings.
- [ ] (If Phase 2) Live Feed shows the same rows live and after reload; bundle
      under the 600 KB budget.

## Risks

- **LOW:** under-counting if a future *terminal* action is added but omitted from
  the allow-list → it wouldn't count as a request. Mitigated by the
  `terminal_actions_all_count` test + an allow-list comment pointing at
  `Action::as_str`. (Symmetric to the `listener_emits_audit` exhaustiveness story.)
- **LOW:** the per-second chart and the 10s rate share the same skip, so they stay
  consistent — but double-check no other consumer relies on `state.requests`
  counting shadow events (none found).

## Estimated complexity: LOW

- Phase 1 (fix + tests): ~1–2 h. Phase 2 (feed consistency + rebundle): ~30 min.
  Phase 3 (docs): ~15 min.
