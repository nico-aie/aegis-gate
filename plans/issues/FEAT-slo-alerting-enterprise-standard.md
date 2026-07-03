# FEAT — SLO & Alerting: enterprise-standard burn-rate alerting + explainable Health page

> **Type:** FEAT (observability track) · **Status:** ◐ In progress — P1–P4a merged (#123 + build-fix `f898d2b`), P5 done 2026-07-03 (`feat/slo-enterprise-p5`) · **Remaining:** P4b config API + P6 dashboard · **Branch:** `feat/slo-enterprise-*` (per stage)
> **Track ID prefix:** `SLO-P1<–6>`
> **Code anchors:** engine `crates/aegis-control/src/slo.rs` · producers/eval loop `crates/aegis-proxy/src/accept.rs:1284-1379` · dispatch `slo/dispatch.rs` · UI `assets/dashboard/src/pages.jsx` (`PageTracking` :9062, `PageIncidents` :11742)
> **Honors:** [[project_health_signals_reported_not_gating]] (alerting reports, never fail-closes the data plane), [[project_dashboard_js_hook_safety]] (JSX has no runtime tests — rebuild binary, respect hook aliasing), [[project_docs_overstate_impl]] (several "(wired)" doc comments in `slo.rs` are stale — verified below against code)

**Goal (one line):** make `data_plane_availability` alerting *truthful* (origin 5xx counts, WAF blocks don't), *explainable* (Google-SRE multi-window burn rates with correct units), and *complete* (blackouts, slow burns, and the 9 unwired alert classes actually fire) — then make the Health & SLOs page explain itself to an operator.

---

## Current behavior — verified 2026-07-03, with the two complaints root-caused

### Why the logic is "hard to explain" — because the units are wrong

One SLI sample per audit-bus event: `1.0 if action == "allow" else 0.0` (`accept.rs:1291-1296`). Per burn window the engine computes `budget_consumed = (error_rate / budget) × 100` and fires when that ≥ `budget_pct` (2 / 5 / 10) (`slo.rs:672-680`).

That `budget_consumed_pct` is **not** "% of monthly budget consumed" — it has no time factor. It is `burn_rate × 100`. So "page at 2% budget in 1h" actually means **page when burn rate ≥ 0.02**, i.e. error rate ≥ 0.002% for the 99.9% target. Google-SRE fast-burn paging fires at burn **14.4** (= truly consuming 2% of a 30-day budget in 1h) — the current threshold is **720× more sensitive**. With a full 10k-sample buffer, **one** non-allow request (error rate 10⁻⁴ → burn 0.1) trips both the Page (0.02) and Ticket (0.05/0.10) thresholds. Nobody can explain that to on-call because it doesn't correspond to any budget statement.

### Why "still critical but did not alert" — four verified silent-failure classes

| # | Silent case | Root cause |
|---|---|---|
| 1 | **Origin returns 5xx** (app crash / DB down behind a healthy TCP origin) | SLI keys off the **WAF verdict**, not response status. A forwarded 500 is `action == "allow"` → recorded **1.0 = healthy** (`accept.rs:1291`). The status IS available: `fields.status` is stamped on every allow event (`accept.rs:2297`). |
| 2 | **Total blackout** (listener wedged, zero traffic → zero samples) | `average_in_window` → `None` → `continue` — window is skipped, never alerted (`slo.rs:667-670`). Absence of telemetry is treated as healthy. |
| 3 | **Slow burns invisible** | Ring buffer caps at 10,000 samples (`slo.rs:648`). At 100 rps that is ~100 s of history — the 6h and 72h windows silently evaluate over the last ~2 minutes. Slow burns can never trip; bursts self-"resolve" when the buffer flushes. The 30-day `budget_status` has the same truncation. |
| 4 | **9 of 11 `AlertEvent` classes have no producer** | Only `Slo` (`accept.rs:1340`) and `OperatorBriefing` (`accept.rs:1412`) are wired. `DdosModeEntered/Cleared` and `CertExpiringSoon` are doc-commented "(wired)" in `slo.rs:157-175` but have **zero** production construction sites. `UpstreamPoolDegraded`, `HotReloadFailed`, `StrikeBlockSurge`, `AuditChainBreak`, `GitOpsDrift` likewise dead. |

### Also broken/inverted (lower urgency)

- **WAF blocks count as unavailability.** `block`/`challenge`/`rate_limit` all record 0.0 — so **successfully stopping an attack wave burns the availability budget and can page on-call**. Enforcement is the WAF doing its job, not an outage.
- **`AuditDeliveryRate` is a tautology** — hardcoded `1.0` per observed event (`accept.rs:1297-1300`); it can never breach its 99.99% objective. Dead objective.
- **`WafOverheadP50/95/99`, `UpstreamAvailability`, `CertFreshnessDays`** are dead enum variants: no producer, no objective, and the engine's `error_rate = 1 − avg` arithmetic is meaningless for latency/day values anyway.
- **Objectives are hardcoded** (`SloEngine::new(default_objectives())`, `accept.rs:802`); no YAML/API surface. Receivers ARE configurable (YAML `alerting:` + `/api/alert-receivers`) with per-severity filters in the backend — but the UI never exposes severity routing (`pages.jsx:8589+`).
- **Dashboard:** `burn_rate` is fetched then never rendered (`pages.jsx:11786`); no timeline; SLI naming differs between Health (`${sli}-${window_hours}h`, :9193) and Incidents (regex `^(.+)-([0-9]+[smhd])$`, :11764); Health & SLOs card is node-local with no node selector while Incidents is fleet-scoped; "alert rules… editor isn't built yet" (:11991).
- **Fleet:** SLI sampling + burn evaluation are strictly node-local; fleet only merges *firing incidents* by `incident_uid` (`metrics/fleet_snapshot.rs:388`). That layering is fine — keep it (per-node burn is what you want; roll-up at the incident layer).

## Target design (the enterprise standard, in one paragraph)

Count **good vs bad events** in fixed time buckets. Bad = WAF-internal failure (`circuit_breaker`, `timeout`) **or** forwarded response with status ≥ 500. Excluded = security enforcement (`block`/`challenge`/`rate_limit` — tracked separately as an enforcement-rate signal). Burn rate over a window = `error_rate / (1 − target)`. Alert on **multi-window pairs** (Google SRE Workbook ch.5): Page when burn ≥ **14.4** over 1h AND over the last 5m; Page when burn ≥ **6** over 6h AND 30m; Ticket when burn ≥ **1** over 3d AND 6h. The short window makes alerts stop firing quickly once the incident ends and prevents stale re-fires. Every alert message reads: *"At this rate the 30-day error budget is gone in X hours (measured 99.4% vs target 99.9%)"*. Separately, a **telemetry-absent** watchdog alerts when a previously-serving node records zero events — closing the blackout hole.

## Staging (6 PRs, ordered so each ships standalone value)

### SLO-P1 — truthful error classification · **S** · START HERE
The drain task (`accept.rs:1284-1308`) reclassifies:
- bad = `timeout` | `circuit_breaker` | (`allow` && `fields.status >= 500`); good = other `allow`.
- `block`/`challenge`/`rate_limit` → **excluded** from availability; count into a new node-local enforcement counter (surfaced on `/api/slo` as an info series, NOT an objective).
- Drop the tautological `AuditDeliveryRate` sample+objective (real measurement is future work; today it is noise claiming 99.99% coverage).
- Keep everything else untouched — this alone fixes silent-case #1 and the blocks-page-on-call inversion.

### SLO-P2 — bucketed SLI store (honest windows) · **M**
Replace `SliRingBuffer` (10k samples) with per-SLI fixed-width counters: `good: u64, bad: u64` per 10s bucket, retained 72h (~26k buckets); 30-day budget from a per-minute rollup (43.2k buckets). O(1) record, exact window sums, no truncation. In-memory as today (restart loses history — same as now; persistence out of scope). `average_in_window` → `window_totals(window) -> Option<{good, bad}>` so "no data" is distinguishable from "healthy" (feeds P3's watchdog). Keep `SliSample`/`record()` signature; convert internally.

### SLO-P3 — multi-window multi-burn engine + blackout watchdog · **M** (the core)
- Burn thresholds per objective: `(long=1h, short=5m, burn≥14.4, Page)`, `(6h, 30m, ≥6, Page)`, `(72h, 6h, ≥1, Ticket)`. Fire only when BOTH windows exceed. Resolve when the short window recovers.
- **Min-traffic guard:** skip a window with fewer than `min_events` (default 60) total events — 1 bad request out of 3 at 04:00 must not page.
- **Telemetry-absent watchdog:** node has served ≥1 event since boot AND zero events for `absent_after` (default 10m) → fire `AlertEvent::TelemetryAbsent` (Ticket; new variant). This is the blackout alert — deliberately a distinct alert class, not a fake 0% availability.
- API additivity: keep `budget_consumed_pct` (now computed correctly: `burn × window/30d × 100`), add `burn_rate` (already in the JSON, now meaningful), `long_window`/`short_window`. Fingerprint/dedup keys unchanged (`sli, severity, window_hours`).
- Sanity-check the copilot consumer `active_slo_alert_labels()` (`tracking.rs:447`) against the new shapes.

### SLO-P4 — objectives configurable (YAML + API) · **M**
`WafConfig.slo: Option<SloConfig>` — objectives (target, window_days, burn thresholds), `min_events`, `absent_after`, classification toggles (`count_upstream_5xx`, `count_enforcement`), dedup window. `None` ⇒ compiled defaults (current behavior). Propagates via the shared config doc like `alerting:` did (N1 pattern); mind [[project_config_plane_doc_vs_file]] and the `apply_and_swap` helper-guard test ([[project_apply_and_swap_helper_guard]]) — engine objectives are boot-built, so config changes rebuild thresholds via ArcSwap, not the engine's buffers. `GET/PUT /api/slo/config` (CSRF + write scope).

### SLO-P5 — wire the dead alert producers · **M**
Producers for the classes whose subsystems already exist (each is a few lines at an existing seam):
- `UpstreamPoolDegraded/Recovered` ← passive-health marking transitions ([[project_passive_upstream_health_p2]] seam: `record_passive_failure/success` + monitor).
- `DdosModeEntered/Cleared` ← DDoS gate mode transitions (mode toggle shipped in PR #122 window).
- `CertExpiringSoon` ← the existing cert poll that feeds `/api/certs`.
- `HotReloadFailed` ← supervisor/watcher apply-error path.
- **Delete** `GitOpsDrift` (module removed 2026-05-17, `tracking.rs:490`); **defer** `StrikeBlockSurge` + `AuditChainBreak` (producers need new detection logic — note in `plans/future/`).
- Fix the stale "(wired)" doc comments on the enum as part of this PR.

### SLO-P6 — dashboard: an SLO page that explains itself · **M**
- **Burn gauges** per objective per window pair, with the plain-language line: *"burn 3.2× — budget exhausted in ~9 days at this rate"* (render the `burn_rate` the page already fetches and drops, `pages.jsx:11786`).
- **Error-budget timeline** — reuse the shipped `TimeseriesChart` widget ([[project_performance_page_ux_plan]]) over the P2 buckets (new `/api/slo/timeseries`).
- Unify SLI naming across Health/Incidents (single `sliLabel()` helper); copy explains the classification ("counts origin 5xx + gateway failures; excludes security blocks").
- Receiver **severity-routing UI** (backend filter exists, `slo.rs:467-476`); objective editor bound to `PUT /api/slo/config` (closes the ":11991 rule editor isn't built" note).
- Enforcement-rate strip (from P1) so operators see "blocks are up, availability is fine" as two separate truths.
- Node scope: add the `FleetNodeSelector` to the SLO card (pull-not-fan-out, same as [[project_dashboard_cluster_scope]]); incident roll-up stays as is.

## Tests (RED-first, per stage)

- **P1:** allow+`status:500` records bad; allow+200 good; `block`/`challenge`/`rate_limit` recorded in enforcement counter, absent from availability; timeout/circuit_breaker bad; no `AuditDeliveryRate` samples.
- **P2:** bucket boundary math (event at window edge); 72h window exact under >10k events (the old ring's failure); rollup consistency 10s↔1m; `None` vs zero-good distinction; memory bound (bucket count fixed).
- **P3 (table-driven outage scenarios — these encode the complaints):** (a) sustained 100% origin-5xx → Page within ~5m; (b) 0.05% error trickle → no page, Ticket only once 3d burn ≥1; (c) blackout after traffic → TelemetryAbsent at `absent_after`; (d) 1 bad of 3 requests → nothing (min-traffic); (e) attack wave, 90% blocked → **no availability alert**; (f) recovery → short window resolves fast; no re-fire under dedup.
- **P4:** YAML round-trip; config-doc propagation; `None` = compiled defaults; live threshold swap without engine-buffer reset.
- **P5:** each producer fires exactly once per transition (hysteresis), correct severity, dedup fingerprint stable; pool-recovered emits Info.
- **P6:** `build.sh` acorn hooks guard green ([[project_dashboard_js_hook_safety]]); manual smoke via rebuilt binary; label helper unit-tested in isolation.
- Suite stays green throughout ([[feedback_test_suite_green_baseline]] — expect stale-detection-test churn to be intended-behavior changes here, e.g. `alert_fires_on_high_error_rate` thresholds).

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | **Alert-behavior flip:** new thresholds are ~720× less sensitive — operators may perceive "alerts stopped working" | P3 ships a boot `tracing::info!` summary of active thresholds + the P6 page shows live burn vs threshold; scenario tests (a)–(f) document exactly when it fires |
| MEDIUM | **API consumers of `budget_consumed_pct`** (Incidents UI :11963, copilot snapshot, fleet merge `worst budget_consumed_pct`) see rescaled values | additive fields; keep key names; fleet `SnapIncident` unchanged (`incident_uid` scheme untouched) |
| LOW | **`fields.status` missing** on some allow paths (streamed/SSE) | classifier treats missing status as good (verdict-allow), matching today's behavior for those rows |
| LOW | **TelemetryAbsent false-positive** on genuinely idle dev nodes | fires only after first-served event, default 10m, configurable/disable-able in P4 |
| LOW | **Config-plane staleness** (P4) | validate against the config doc not the YAML; re-publish recipe documented ([[project_config_plane_doc_vs_file]]) |

## Acceptance

- [x] SLO-P1: origin 5xx burns budget; blocks/challenges don't; enforcement counter surfaced; dead AuditDeliveryRate gone. *(2026-07-03, `feat/slo-enterprise-p1`, rust-reviewer approved)*
- [x] SLO-P2: 72h/30d windows exact at ≥100 rps sustained (no ring truncation); no-data distinguishable. *(2026-07-03, same branch; two-tier 10s/72h + 1m/30d BucketStore, evaluate_at/record_at clock seam, rust-reviewer MEDIUMs addressed)*
- [x] SLO-P3: scenario table (a)–(f) green; alert text reads measured-vs-target + time-to-exhaustion; blackout alerts. *(2026-07-03, same branch; review hardening: silence never auto-resolves a fired alert — only confirmed recovery; short window volume-gated; fingerprint carries fired/resolved state)*
- [◐] SLO-P4: **P4a shipped 2026-07-03** — `slo:` YAML section (objectives + `telemetry_absent_after_secs`), boot consumption, fleet propagation via `apply_cfg_change_to_slo` (structural-guard-enforced), invalid sections rejected keeping previous set; defaults = compiled. **P4b remaining:** `GET/PUT /api/slo/config` — deliberately deferred to ride with the P6 editor that consumes it. Classification toggles (`count_upstream_5xx`/`count_enforcement`) deferred to future work (classifier is a pure fn; no operator demand yet).
- [x] SLO-P5: pool-degraded, DDoS-mode, cert-expiry, hot-reload-failed alerts fire from real transitions; GitOpsDrift deleted. *(2026-07-03, `feat/slo-enterprise-p5`; alert mpsc channel + single dispatch_and_record path; pool severity dynamic (0 healthy = Page); StrikeBlockSurge/AuditChainBreak stay placeholders needing new detection logic)*
- [ ] SLO-P6: burn gauges + timeline + unified naming + severity-routing UI + objective editor shipped; hooks guard green.
- [ ] Data plane never fail-closes on any of this (report-only contract intact).

## Out of scope

Real audit-delivery measurement (sink acks), latency SLO (`WafOverhead*` as a fast-request-ratio objective — natural follow-up once P2 buckets exist; keep enum variants), SLI persistence across restarts, fleet-level SLI re-aggregation (incident-layer merge stays), external Alertmanager/PagerDuty in-process delivery (stays operator-side `external`), StrikeBlockSurge/AuditChainBreak producers.
