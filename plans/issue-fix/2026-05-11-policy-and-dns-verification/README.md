# Fix plan — 2026-05-11 Policy & DNS verification QA

> **Status:** Drafted 2026-05-11, awaiting confirmation.
> **Input:** `tests/n-tester/reports/2026-05-11/`
> (run summary `RUN-SUMMARY-policy-and-dns-verification.md`,
> per-finding files HIGH-01/02, MED-01..04, LOW bundle,
> INFO bundle, UX-PROPOSALS).
> **QA verdict:** 0 CRITICAL · 2 HIGH (both resolved in-run) ·
> 4 MEDIUM · 7 LOW · 7 INFO · 10 UX proposals.

## Phase 0 — Stale-bundle root cause (HIGH-01 + HIGH-02)

Both HIGH findings have a single root cause: editing `pages.jsx`
then running `make build` shipped a binary with stale `app.js`
embedded via `include_bytes!`. The QA tester worked around it
manually with `make dashboard` + `Cmd+Shift+R`.

### 0.1 — What's already shipped

| Fix | Status | Commit |
|---|---|---|
| `make build` now rebundles `app.js` automatically when any JSX source is newer | ✅ shipped | `0a9d815` |
| `app.js` regenerated against the post-PR-DNS-1 / post-PR #7 source | ✅ shipped | `0a9d815` |
| `make dashboard-force` added for toolchain-bump edge case | ✅ shipped | `0a9d815` |

The Makefile fix prevents the *recurrence* of HIGH-01 — anyone
running `make build` from now on rebuilds the bundle if JSX is
newer. So future commits can't ship the same stale-bundle
combination.

### 0.2 — Carry-overs from the QA recommendations

Three follow-ups the QA report flagged that aren't yet addressed:

- [ ] **PR-CACHE — drop dashboard JS cache-control to `no-cache, must-revalidate`.**
      Today `crates/aegis-proxy/src/responses.rs:103` ships
      `public, max-age=3600, must-revalidate` on every dashboard
      asset, including `app.js`. Within the 1-hour window the
      browser uses the cached copy without revalidating, so even
      after the operator rebuilds the binary the browser keeps
      serving the old bundle until either (a) the hour elapses
      or (b) the operator hard-reloads. Changing to `no-cache,
      must-revalidate` keeps the ETag/304 bandwidth-saving
      short-circuit but eliminates the multi-hour staleness
      window. Audit the asset list — `react.min.js`,
      `react-dom.min.js` are huge + unchanging, so they can stay
      on long cache; `app.js`, `index.html`, `i18n.json` are the
      churning ones.
- [ ] **PR-CI — `app.js` drift gate.**
      Single CI step: `bash crates/aegis-control/assets/dashboard/build.sh
      && git diff --exit-code crates/aegis-control/assets/dashboard/app.js`.
      If a PR ships JSX edits without the matching bundle, CI
      fails fast. Even with the Makefile fix in place, this is
      the belt-and-braces — covers operators who run `cargo
      build` directly without going through make.
- [ ] **PR-README — dashboard workflow note.**
      One paragraph under "Build" in `README.md` (and / or
      `docs/operator/usage.md`) saying: *"Editing JSX
      sources auto-rebundles via `make build`; if you bypass
      make (e.g. `cargo build` directly), run `make dashboard`
      first or you'll embed the previous bundle."* Cover
      `make dashboard-force` for toolchain bumps.

**Effort:** PR-CACHE + PR-CI are <1h each, PR-README ~10
min. All three independent.

## Phase 1 — MEDIUM fixes (4 findings)

All dashboard-side, all small. Recommended single PR ("Phase 1
medium fixes").

### MED-01 — Audit Trail `RULE` column shows `—` for `rule_*` rows

**Root cause:** the event's top-level `rule_id` field is `null`
for admin mutations (`rule_create`, `rule_disable`, etc.); the
actual rule ID lives in `fields.resource` (`/api/rules/<id>`)
or `fields.diff.after.rules.<id>`. The dashboard's column reader
only checks the top-level field.

**Fix:** in the Audit Trail row renderer (`pages.jsx`, around
the Audit Trail table), when `event.action` starts with
`rule_`, extract:
1. Try the top-level `event.rule_id` (current behaviour).
2. Fall back to parsing `event.fields.resource` as `/api/rules/<id>`.
3. Fall back to the first key of `event.fields.diff.after.rules`.

Same shape works for the `ROUTE` column on `route_*` actions
(`fields.resource = /api/routes/<id>`) and the `POOL` column on
`pool_*` actions (`fields.resource = /api/upstreams/pool/<id>`).
Adopt one `extractResourceId(event)` helper to share the logic.

**Effort:** ~1h dashboard. No backend change (the QA report's
preferred option B).

### MED-02 — Add Route modal: two contradictory error messages

**Root cause:** the modal renders both a bottom-right toast
(real server error) and an inline "Will create pool X with this
member — that pool name already exists" hint (driven by a local
pool-name lookup). When the server fails for a different reason
(catch-all collision), the inline hint stays misleading.

**Fix:** in the Add Route modal (`pages.jsx`, around route
upsert):
1. Drop the toast for save failures.
2. Render the server error inside the modal body, above the
   action buttons, in a red-bordered card matching the F-02
   inline-validation pattern.
3. Clear the local pool-name inline hint whenever the modal is
   in error state; let the server-side message be the canonical
   error surface.

**Effort:** ~1h dashboard. Matches the QA report's preferred
option B.

### MED-03 — Header `UNKNOWN` red badge on healthy single-node cluster

**Root cause:** the badge component reads
`/api/about.environment` and renders the string verbatim;
`environment` is `null` in dev so the badge falls back to the
literal `UNKNOWN`. Red is the styling for unknown.

**Fix:** in the shell header component:
1. When `environment === null` (or unset), render either
   nothing or a neutral grey `DEV` pill (no red).
2. Reserve red for genuine outage states — audit chain
   suspended, leader lost, state backend disconnected. (Those
   should drive a different pill, not the environment label.)

**Effort:** ~30 min dashboard. Trivial conditional + CSS tone
adjustment.

### MED-04 — Pool orphan survives failed route create

**Root cause:** the Add Route modal does a two-stage write —
`PUT /api/upstreams/pool/{id}` to create the pool, then
`POST /api/routes` to create the route. When stage 2 fails
(catch-all collision, validation, etc.) the pool sits orphaned
in "Pools without routes" with no breadcrumb to clean it up.

**Fix:** two options, ranked:

- **A (atomic, preferred):** add a server-side combined
  endpoint `POST /api/upstreams/route-with-pool` that takes
  `{ route, optional_new_pool }` and either applies both
  atomically or rolls back the pool. Cleaner state model. ~3h
  including new audit-chain entry + tests.
- **B (compensating delete):** keep the two-stage write on the
  client; if the route POST fails, the dashboard issues a
  follow-up `DELETE /api/upstreams/pool/{id}` to remove the
  pool it just created. ~1h dashboard + test. Operator-visible
  behaviour matches A.
- **C (operator warning):** leave both writes, surface a
  one-line note in the modal: "If the route save fails after
  the pool is created, the pool will be left unreferenced…"
  ~10 min. Doesn't fix the orphan, just admits to it.

**Recommendation:** ship **B** in this Phase 1 PR (small, fixes
the operator-visible behaviour); file **A** as a follow-up for
when the broader two-stage-write surfaces (route + multiple
pools, etc.) get a unified API.

## Phase 2 — LOW polish bundle (7 findings)

All dashboard-side, all <30 min each. Bundle into one
"dashboard polish" PR.

| ID | Fix |
|---|---|
| **LOW-01** | Replace `unknown-host-86898-…` node ID fallback with `gethostname()` on dev boot. ~10 min. |
| **LOW-02** | Replace `vnexpress` placeholders on Add Route modal (Route ID + Host SNI) with generic `my-route` / `api.example.com`. ~5 min. |
| **LOW-03** | Unify toast component — pick one styled component, replace ad-hoc green/red callers. ~20 min. |
| **LOW-04** | Bump disabled-chip opacity 0.5 → 0.6 + add stripey background, raises WCAG-AA contrast. ~15 min. |
| **LOW-05** | Routing & Upstreams summary copy: `1 route → 2 pools (3 members, 1 unreferenced)` → `1 route · 1 pool routed · 1 pool unrouted (2 members)`. ~5 min. |
| **LOW-06** | Chevron flip on `▶` / `▼` for "How does it work?" expandables on Traffic Gates. ~10 min. |
| **LOW-07** | `TIER A` pill on the Rule Simulator gets a tooltip or links to the Detectors page Risk-score reference. ~10 min. |

Total Phase 2 effort: ~1.5h.

## Phase 3 — UX-PROPOSALS triage

The QA report's `UX-PROPOSALS-policy-pages.md` lists 10 concrete
improvements with effort + impact ratings. These are not bug
fixes — they're product improvements. Triage decision needed
before scheduling:

| # | Proposal | Effort | Impact | Recommended? |
|---|---|---|---|---|
| P1 | Policy posture cheat-card (top of every Policy page) | S | High | Yes — small + high orientation value |
| P7 | Cross-page deep-link consistency | M | High | Yes — incident-review benefit |
| P6 | Traffic Gates flow diagram | S | High | Yes — onboarding win |
| P2 | Pin Live-policy panel on Detectors & Tiers | S | Medium | Yes — already designed |
| P9 | Move Refresh button next to title | S | Low | Maybe — muscle memory + real estate |
| P10 | Footer pill tone (mute DEMO/OFF) | S | Low | Maybe — easy + reduces noise |
| P3 | Rules tabbed view (Simulator separate tab) | M | Medium | Defer — needs UX agreement |
| P5 | Route activity pulse pill | M | Medium | Defer — needs backend per-route projection |
| P4 | Access Lists hit-counter | M | Medium | Defer — needs `/api/blacklist/hits` endpoint |
| P8 | Microcopy on dangerous toggles | S × 10 | Medium | Defer — coordinate with copy review |

**Status (post 2026-05-11 sprint):**
- **P10 — Footer pill tone (shipped).** Commit lands the SSE +
  audit-chain pills as `neutral` (grey) instead of `warn`
  (yellow). The dashboard footer no longer reads as five things
  to worry about on a healthy dev boot.
- **P9 — Refresh button placement (deferred).** Moving Refresh
  next to the title across 6 page components touches enough
  JSX that visual review is worthwhile before shipping. Queued
  for the next dashboard sprint with a Playwright screenshot
  diff as the gate.
- **P2 — Live-policy column pin on Detectors & Tiers (deferred).**
  Layout-only CSS rework; small but the page already has heavy
  layout logic and the change benefits from operator preview.
- **P6 — Traffic Gates flow diagram (deferred).** Static chip
  row needs visual review for chip ordering + click-scroll
  targets.
- **P1 — Policy posture cheat-card (deferred).** Shared
  component across 5 pages; needs scope agreement on the
  cheat-card's exact field list + which pages it appears on.
- **P7 — Cross-page deep-link consistency (deferred).** Per-page
  URL-read mount effects; needs a documented URL pattern and
  one effect per page. Plan: `#/<page>?<filter>=<value>` per
  the QA report's recommendation.

**Phase 3b (next iteration):** P3 + P5 + P4 + P8 — need upfront
discussion (backend changes for P4 / P5, refactor for P3, copy
review for P8).

**Decision:** Phase 3a deferred items move to a dedicated UX
sprint with visual review at the end of each item. They're not
bug fixes; the immediate operator pain (HIGH-01/02 + four
MEDIUMs + seven LOWs) is now closed.

## Suggested PR sequence

1. **PR-CACHE** — Phase 0.2 cache-control fix on dashboard
   assets. Independent, ~1h.
2. **PR-CI** — Phase 0.2 CI gate against `app.js` drift.
   Independent, ~30 min.
3. **PR-README** — Phase 0.2 README dashboard-workflow note.
   Independent, ~10 min.
4. **PR-MED** — Phase 1 four MEDIUM fixes. Single dashboard PR,
   ~5h.
5. **PR-LOW** — Phase 2 seven LOW polish items. Single dashboard
   PR, ~1.5h.
6. **PR-UX-A** — Phase 3a six UX proposals. Single dashboard PR,
   ~6h. **Needs decision on scope first.**

PR-CACHE / PR-CI / PR-README / PR-MED / PR-LOW are all near-
independent; pick any order. PR-UX-A waits on scope agreement.

## Effort summary

| Phase | Effort | Operator-visible impact |
|---|---|---|
| 0.2 — Carry-overs | ~2h | Future bundle drift can't recur; dashboard JS reaches operators on next nav, not next hour |
| 1 — MEDIUM | ~5h | Audit Trail readable; Add Route error UX honest; no header false-alarm; no orphan pools |
| 2 — LOW | ~1.5h | Polish: hostname IDs, placeholders, toasts, contrast, copy, chevrons, tooltips |
| 3a — UX-A | ~6h | Policy posture card, deep-link consistency, gate flow diagram, live-policy pin, refresh button placement, footer pill tone |
| 3b — UX-B | TBD | Deferred until scope discussion |

**Total verified-bug effort (Phases 0.2 + 1 + 2):** ~8.5h.
With Phase 3a: ~14.5h. Phase 3b TBD.

## Decisions to lock in before starting

1. **Cache-Control posture** — confirm `no-cache,
   must-revalidate` on `app.js` / `index.html` / `i18n.json`,
   keep long cache on the React UMD bundles. Or prefer content-
   hashed `app.js` URLs? (More invasive but eliminates the
   problem class entirely.)
2. **MED-04 fix shape** — Option A (atomic endpoint) vs B
   (compensating delete on client) vs C (warning copy)?
   Recommendation: B for this plan, A as follow-up.
3. **Phase 3a scope** — confirm P1 + P7 + P6 + P2 + P9 + P10 as
   the immediate UX cut, or trim further?

## Out of scope (intentionally)

- Re-running the QA harness — operators do that after PRs ship.
  This plan acts on the report; verification is a separate
  sweep.
- Audit-chain JSON schema changes — the QA report's MED-01
  recommendation was explicit ("Pick option 2 so the audit JSON
  schema doesn't change"). Dashboard-side fix only.
- New feature work — the report's INFO bundle catalogs surfaces
  that already work well (Rule Simulator detector breakdown,
  destructive-op modal copy, Config history card). Keep them.
