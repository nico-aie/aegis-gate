# Performance page — chart quality, window honesty, card-scope clarity

**Status:** 🔴 Planned — not implemented
**Date:** 2026-07-02
**Reported by:** Nico (screenshot: Performance page, 1h window; "Requests over time
and Block ratio cards look not good UX, 24h default window too large; check the
other cards")
**Page:** `PageAnalytics` — `crates/aegis-control/assets/dashboard/src/pages.jsx:1650`

---

## Findings (verified in code, 2026-07-02)

### F1 — Default window (24h) exceeds backend retention by ~23× — ✅ CONFIRMED, root cause of "bad-looking" charts

- The page defaults to `'24h'` (`pages.jsx:1651`) and offers `1h/6h/24h/7d/30d`
  (`ANALYTICS_WINDOWS`, `pages.jsx:1642-1648`).
- The backend per-second bucket store retains **3700 s ≈ 62 min**
  (`TIMESERIES_RETENTION_SECS`, `crates/aegis-control/src/api/stats.rs:51,256`).
  `StatsAggregator::timeseries` zero-fills every bucket with no data
  (`stats.rs:330-379`).
- Consequence: at the 24h default, ≥23 of 24 hours are *structurally* zero.
  The chart renders as a flat line with all real traffic crammed into the right
  edge — exactly the screenshot. `7d`/`30d` are worse: ≥99.4 % of buckets can
  never contain data. Retention is also lost on restart (in-memory `BTreeMap`).
- Fleet view is tighter still: merged timeseries only covers
  `FLEET_TIMESERIES_MAX_WINDOW_SECS = 300` (`metrics/fleet_snapshot.rs:46`);
  wider windows silently fall back to node-local.

### F2 — "avg 0 req/s" while the chart clearly shows traffic — ✅ CONFIRMED

`avgReqPerSecond` divides total requests by `points.length × step`
(`pages.jsx:1667-1672`) — i.e. averages over the *whole selected window*
including the hours of forced zeros from F1, then `Math.round`s. Any realistic
dev traffic rounds to `0 req/s`. The header stat contradicts the visual.

### F3 — Sparkline is the wrong chart for a half-page card — ✅ CONFIRMED

Both big charts use `Sparkline` (`widgets.jsx:39-58`) at fixed `w=460 h=120`
(`pages.jsx:1719,1771`):

- **Not responsive** — fixed `width`/`height` attrs (no `viewBox`), so the SVG
  sits at 460 px inside a `col-6` card that is much wider on 1440+ screens;
  dead space right of the plot.
- **No axes, no gridlines, no time labels, no hover tooltip** — an operator
  cannot tell *when* the spike happened or *how big* it was without reading the
  subtitle's single "peak … at HH:MM" stat.
- **Min–max normalisation** (`Sparkline` maps `min..max` to full height) — the
  y-baseline is not zero, so background noise is amplified and two windows are
  not visually comparable.
- Meanwhile `TrafficChart` (`widgets.jsx:143-182`) already does most of this
  right for the Overview page: responsive `viewBox` + `width="100%"`, y-ticks,
  gridlines, zero baseline, total+blocked legend. The Performance page ignores
  it.

### F4 — Block-ratio series is volume-blind — ✅ CONFIRMED

`blockRatioPct` maps each bucket to `blocked*100/total`, `0` when empty
(`pages.jsx:1665`):

- A bucket with 1 request, 1 block renders the same 100 % spike as a real
  attack wave; the headline "peak 95.2 % at 19:03" stat is dominated by
  low-sample buckets (`pages.jsx:1674-1684`).
- Empty buckets render 0 % — visually indistinguishable from "traffic but no
  blocks".

### F5 — Cards silently ignore the window selector — ✅ CONFIRMED

Page subtitle says "Historical trends · {range} window" (`pages.jsx:1700`), but
only the two timeseries cards actually follow the selector:

- **Latency p50/p95/p99** (+ by-route, by-detector) read Prometheus cumulative
  histograms — *lifetime since process boot*, never windowed
  (`useLatencyApi` etc., `data.jsx:1170-1172`; `metrics/route_latency.rs` is a
  plain `HistogramVec`). The screenshot's `total p99 = 1015 ms` is almost
  certainly a single cold-start outlier that will be pinned there until
  restart — misleading on a "historical trends" page.
- **Error rate by route** reads the audit ring (`/api/analytics/routes`,
  10 s poll) — its own window, labelled with the jargon "audit-ring window".
- No card states its true time scope; changing the chip visually implies all
  six cards changed.

### F6 — Smaller card-level issues — ✅ CONFIRMED

- **Error rate by route:** header counts all rows ("15 routes") but the body
  renders `rows.slice(0, 10)` (`pages.jsx:1803`) with no "showing 10 of 15"
  cue. Same pattern in by-route latency (`slice(0, 15)`, `pages.jsx:1865`).
  (The by-detector card already fixed this class of bug — see comment at
  `pages.jsx:1916-1919`.)
- **"Error %" conflates blocked with 5xx** — `blocked` is the WAF working as
  intended, yet it drives the red/yellow "error" pill (`pages.jsx:1810`).
  An operator reading "/public 50.0 % error" thinks the origin is failing.
- **No cluster scope badges** — the page never calls `useScopeBadge()`
  (checked `pages.jsx:1650-1947`), even though the timeseries hook is
  fleet-scoped (`useApiScoped`, `data.jsx:700-702`) and the latency hooks are
  node-local (`useApi`) — mixed scopes, unlabelled, on cluster deployments.
  (Scope-badge convention shipped for other pages in PRs #102-104.)
- **Window choice not persisted** — `useStateP` is plain `useState`
  (`pages.jsx:2`); the range resets to the default on every visit and is not
  shareable via URL.

---

## Plan

Order: P1 fixes the complaint with zero backend work; P2 is the visual core;
P3–P4 are honesty/copy passes; P5 is the only backend-touching phase and is
severable.

> **Execution note (2026-07-02):** implemented as PRs C+D of the 3-track
> batch (A: live-feed self-node badge · B: investigation actions/risk-key ·
> C: this plan P1–P4 **plus P5.1 pulled forward** so chip gating is
> truth-driven from day one · D: P5.2–5.4 minute-tier, fully severable —
> skip if 1h/6h suffice after C).

### P1 — Window selector honesty (frontend only)

1. Default `range` to `'1h'` (matches retention; the screenshot itself was
   taken at 1h because 24h was useless).
2. Remove the `7d`/`30d` chips; keep `24h` **only if** P5 ships (else remove —
   a chip that can never show data is a broken promise). Until P5, cap the
   offering at `1h` + a `6h` chip gated the same way, and show a one-line
   caption under the chart when `window > retention`:
   "series retains ~60 min; older buckets are empty" (retention surfaced via
   the timeseries response, see P5.1).
3. Fix `avg req/s` (F2): compute over the span from the **first non-zero
   bucket** to now (or state "no traffic" when the series is all-zero), so the
   stat matches what the eye sees.
4. Persist the selected range to the URL (`?range=`) per the URL-as-state
   convention, so refresh/share keeps the view.

### P2 — Real timeseries chart (replaces Sparkline on this page)

1. Extract/extend `TrafficChart` into a reusable `TimeseriesChart` in
   `widgets.jsx`: responsive `viewBox` (no fixed 460 px), zero y-baseline,
   y-ticks + gridlines (already in TrafficChart), **time labels on the x-axis**
   (start / quarter marks / now, using the bucket `ts` the API already
   returns), and a **hover tooltip** (vertical crosshair + `HH:MM · value`)
   — SVG `onMouseMove` over the plot area, no library.
2. Requests over time: total area + blocked overlay in one chart (the data is
   already in each point; two half-cards showing the same x-axis twice wastes
   the operator's eye — but keep the two-card layout if Nico prefers;
   decision point at implementation).
3. Block ratio: render as **bars** (per-bucket ratio) rather than a smoothed
   line — ratio of a discrete bucket is a bar quantity; a line implies
   continuity between unrelated buckets.
4. Keep `Sparkline` untouched for the small stat-tile uses elsewhere.

### P3 — Volume-aware block ratio (frontend only)

1. Peak/avg stats ignore buckets below a minimum sample count
   (e.g. `total >= 5`); subtitle shows `peak 95.2 % at 19:03 (n=41)` so the
   number is auditable.
2. Tooltip shows `blocked/total` alongside the percentage.
3. Distinguish "no traffic" buckets from 0 %: render no bar (gap) instead of a
   zero bar.

### P4 — Card scope + copy clarity (frontend only)

1. Latency cards: caption "since boot · resets on restart" (uptime is already
   available via `/api/about`) instead of implying the selected window; drop
   the page-subtitle claim that everything follows the window (or move the
   chip row inside the two cards it actually controls).
2. Error rate by route: rename the metric or split the pill — blocked (WAF
   verdict, violet/neutral) vs 5xx (origin failure, red). "Error %" keeps only
   5xx; add a "Blocked %" column or fold blocked into a neutral pill.
3. Truncation cues: "showing 10 of 15 — sorted by total" on the route cards
   (or render all rows; route count is bounded by config, same argument as the
   detector card fix at `pages.jsx:1916`).
4. Wire `useScopeBadge()` on all six cards (fleet-capable: timeseries;
   node-local: latency histograms, audit-ring routes).
5. Replace "audit-ring window" with operator language ("recent requests
   window").

### P5 — Backend: retention to honestly serve 6h/24h (optional, severable)

1. Return `retention_seconds` in the `/api/stats/timeseries` response so the
   frontend can gate chips/captions from truth instead of a hardcoded copy
   (needed by P1.2 in its final form).
2. Extend `StatsAggregator` with a **downsampled tier**: keep per-second
   buckets for the last ~62 min (unchanged), fold expiring seconds into
   per-minute buckets retained for 24h (`1440 × 8 B` counters — trivial
   memory). `timeseries()` reads seconds for fine steps, minutes for coarse.
   All existing tests (`timeseries_*`, `stats.rs:980+`) must stay green;
   add: minute-fold correctness, cross-tier stitch at the boundary,
   restart behaviour unchanged (still in-memory; durable history is a
   non-goal here).
3. Re-add the `24h` chip (step 1200 s as today). `7d`/`30d` stay dropped —
   that's a durable-metrics-store feature (Prometheus/Redis), out of scope;
   note as follow-up candidate only if an operator asks.
4. Fleet view: leave `FLEET_TIMESERIES_MAX_WINDOW_SECS = 300` as-is, but P4's
   scope badge must make the node-local fallback visible (it exists today,
   silently).

---

## Test / verification strategy

- **Dashboard JSX has no runtime test coverage** (esbuild/cargo won't catch
  hook bugs) — rebuild the binary (`build.sh`, embeds `app.js`) and verify in
  the browser; `lint-hooks.mjs` guards rules-of-hooks. New chart component
  must use the `*W`-aliased hooks in `widgets.jsx` / `*P` in `pages.jsx`.
- Screenshot pass at 1024/1440/1920 for the responsive chart (fixed-width
  Sparkline is the current bug — verify the replacement actually flexes).
- P5: Rust unit tests in `stats.rs` (TDD) — minute-fold, stitch, retention
  response field; `cargo test --workspace` green baseline must hold.
- Manual: `make mock-load` + one attack burst, then check (a) avg req/s is
  non-zero and plausible, (b) block-ratio peak carries `n=`, (c) tooltip
  timestamps match the audit log, (d) 24h chip absent (pre-P5) or honest
  (post-P5).

## Non-goals

- Durable (restart-surviving / 7d+) metrics history.
- SLO / cert summaries returning to this page (removed 2026-05-10 by design,
  `pages.jsx:1658-1661`).
- Windowed latency percentiles (sliding-window histograms) — the "since boot"
  caption is the honest cheap fix; revisit only if operators ask for
  time-scoped percentiles.
