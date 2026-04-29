# Per-page Plans — index + template

> **Status:** Queued — supporting — Per-page redesign brief index.
>
> See [`README.md`](../../README.md) for the track status board.

> Each file in this directory is one milestone (M1..M10).
> They are *small* — each runs the
> [`../workflow.md`](../workflow.md) loop end-to-end and
> ships one page. Don't pad with content the workflow
> generates (the brief, the screenshots, the test additions).
> Plan = scope + acceptance + open questions.

## Index

| ID | Page | Plan file | Status |
|---|---|---|---|
| M1 | Overview | [`M1-overview.md`](./M1-overview.md) | seed |
| M2 | Live Feed | [`M2-live-feed.md`](./M2-live-feed.md) | seed |
| M3 | Attack Events | not yet written — copy template below | |
| M4 | Audit Log | not yet written | |
| M5 | Analytics | not yet written | |
| M6 | Rule Manager | not yet written | |
| M7 | Tier Config | not yet written | |
| M8 | Blacklist + Whitelist (combined) | not yet written | |
| M9 | Tracking | not yet written | |
| M10 | Settings | [`M10-settings.md`](./M10-settings.md) | seed |

> **Why some are seeded and others aren't.** The three
> seeded ones cover the visual bar (M1), the hardest
> interaction model (M2 SSE + drawer), and the
> P1–P8-touchpoint convergence (M10). The middle ones reuse
> patterns those three lock in — write them just-in-time
> when work begins so design questions don't go stale.

## Plan template

Copy this for any new milestone. Keep it short — anything
longer than a page is the workflow output, not the plan.

````markdown
# Mx — <page name>

> **Status.** seed / in-design / in-impl / shipped
>
> **Effort.** ~N days
>
> **Depends on.** M0 + (any other milestones whose
> components this page reuses)

## Inputs

- Design contract: [`docs/control-plane/enterprise/pages/<page>.md`](../../../docs/control-plane/enterprise/pages/<page>.md)
- API endpoints used: <list — see api.md>
- Components reused from M0: <list>
- New components introduced: <list — keep small, ideally 0–1>

## User goals (3 max)

1. <goal — one sentence>
2. <goal>
3. <goal>

## Scope

### In
- <bullet>
- <bullet>

### Out
- <bullet — defer with rationale>

## Acceptance

- Every user goal is reachable in ≤ 3 clicks.
- Page module raw size < 32 KB (per-file budget).
- Loading / empty / error / stale states each documented in
  the brief and rendered in code.
- WCAG 2.2 AA: keyboard reach for every interactive,
  contrast verified against tokens, no motion above
  `--motion-fast` for layout-altering changes.
- Both themes pass the screenshot review (workflow stage 4)
  at 1280 / 1440 / 1920.
- One Playwright spec or k6 user-journey script exercises
  the primary user goal.

## Open questions

- <question>
- <question>

## Out-of-scope drift log

> Append to this section any decision made during the
> milestone that diverges from the design contract or this
> plan. Keep doc + plan + code aligned at ship.
````

## What every milestone produces

Apart from the page module + CSS deltas:

1. `plans/dashboard-redesign/<id>.brief.md` — workflow
   stage 1 output. Keep this committed; it's the design
   record.
2. Updates to
   `docs/control-plane/enterprise/pages/<page>.md` if any
   contract decision diverged.
3. A test addition under `tests/dashboard_polish.rs`,
   `tests/api/`, or `tests/e2e/dashboard/`.
4. A "Last Completed" entry in `Implement-Progress.md`.

## What no milestone touches

- The data layer. Every page in this track consumes existing
  endpoints. If you find yourself wanting a new endpoint, **stop
  and write a separate plan** under `plans/` first. The
  redesign track must not silently expand the API surface.
- Auth flow. Login + session is in
  [`../../post-k6-followup.md`](../../post-k6-followup.md)
  (F-T1). The redesign assumes it lands first.

## Rolling SLA per milestone

Stage 1 brief + stage 2 critique should land within one
working day. Stage 3 implementation in two days. Stage 4
visual review in half a day. Stage 5 tests + ship in half a
day. If a milestone takes more than 5 days, the scope is
wrong — pull something into a follow-up plan.
