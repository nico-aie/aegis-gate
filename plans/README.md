# Plans

Cleaned up 2026-05-19. The top level holds tracking + reference
files only — every closed or paused plan lives in
[`archive/`](./archive/), and feature plans we've intentionally
deferred live in [`future/`](./future/).

## Layout

```
plans/
├── README.md                       ← this file (entry point)
├── plan.md                         ← AI-assistant guide for this repo
├── implementation-matrix.md        ← doc-by-doc Implemented / Partial / Designed status
├── future/                         ← deferred features (operator-confirmed, not yet built)
└── archive/                        ← closed / shipped / paused plans (read-only history)
```

## Active plans

None at top level. Pick up the next track from `future/` (each
file is self-contained — Status / Why deferred / Code anchor /
Future plan / Restoration checklist).

## Reference (kept at top level)

- [`plan.md`](./plan.md) — assistant protocol + repo conventions.
  Read this when picking up a new task.
- [`implementation-matrix.md`](./implementation-matrix.md) —
  status of every documented feature: Implemented / Partial /
  Designed / Deferred.

## `future/`

Features we've decided to defer. Each plan captures the
restoration spec so a future revisit doesn't have to recompose
context from scattered comments.

- [`smart-caching.md`](./future/smart-caching.md) — opt-in
  in-memory LRU response cache; flips `X-WAF-Cache: HIT/MISS`
  from the always-`BYPASS` baseline. Phase 1 (in-memory + GET
  allow-list) ≈ 3d. **Drafted 2026-05-19, designed only.**
- [`compliance-profiles.md`](./future/compliance-profiles.md) —
  per-regime detector pinning + clamp enforcement (FIPS / PCI /
  SOC 2 / GDPR / HIPAA). Modes still parse and surface as
  documentation tags today; the lock is a no-op until the pin
  list is repopulated. **Status: Deferred 2026-05-10.**
- [`audit-cold-tier-export.md`](./future/audit-cold-tier-export.md) —
  scheduled long-tail audit exports (S3 / SFTP) beyond the
  200-event ring cap. **Drafted, not started.**
- [`multi-node-metrics-aggregation.md`](./future/multi-node-metrics-aggregation.md) —
  cluster-wide Prometheus rollup once the multi-node deploy
  lands. **Drafted, not started.**
- [`risk-composite-key-data-plane.md`](./future/risk-composite-key-data-plane.md) —
  remaining JA4 device-FP fold-in for the composite-key risk
  bucket. Storage + most data-plane sites already landed.
  **Tracked, partial.**
- [`rule-non-block-actions.md`](./future/rule-non-block-actions.md) —
  rule actions beyond block/log (challenge, tarpit, mirror).
  **Drafted, not started.**
- [`unwired-stubs-catalog.md`](./future/unwired-stubs-catalog.md) —
  running catalogue of types / traits the rule engine declares
  but doesn't yet evaluate.

> **Adding a future plan**: new file in `future/<short-slug>.md`
> with sections "Status / Why deferred / Code anchor / Future
> plan / Restoration checklist". Mirror `smart-caching.md`.

## `archive/`

Closed plans kept for history. Files are individual feature
tracks that shipped or paused; subfolders bundle related work:

- [`archive/issue-fix/`](./archive/issue-fix/) — QA-driven fix
  plans (run-by-run; tester-n + tester-l + page-audit + DDoS
  internal audit).
- [`archive/phase-b-2026/`](./archive/phase-b-2026/) — Phase B
  production-packaging tracks (B1..B6).
- [`archive/multi-node-deployment/`](./archive/multi-node-deployment/) —
  multi-node proposal awaiting SA Team answers (paused, not
  rejected). Move to `future/` if a revisit is scheduled.
- [`archive/dashboard-enterprise/`](./archive/dashboard-enterprise/) —
  D-M1..D-M6 (superseded by DD-T\*).

Top-level archive files (one per shipped track, in alphabetical
order): `ai-assistant-testing-kickoff.md`, `ai-detector.md`,
`benchmark-mode.md`, `binary-handover-fd-pass.md`,
`cluster-ingress-lb.md`, `console-api-integration.md`,
`console-config-pages.md`, `console-fixups.md`, `console-qa.md`,
`console-soc-refactor.md`, `control.md`, `dashboard-redesign.md`,
`followups-rollback-and-sans.md`, `hackathon-readiness.md`,
`hackathon-stress-test.md`, `interop-contract.md`,
`interop-dry-run.md`, `mtls.md`, `post-k6-followup.md`,
`post-run-08.md`, `proxy.md`, `proxy-refactor.md`,
`scaling-config.md`, `security.md`, `tcp-forwarder-phase-4.md`,
`websocket-bridge.md`.

For the implementation log of what's shipped, see
[`../Implement-Progress.md`](../Implement-Progress.md).

## Working with plans

When picking up new work:

1. **Search `archive/` first** — existing-feature context is
   usually there.
2. **Check `future/`** — if the feature is deferred, the
   restoration checklist tells you what changes are needed.
3. **Active multi-step work** — drop a plan in `plans/`
   directly (e.g. `plans/<feature>.md`); promote to
   `archive/` once the work ships.
4. **Don't restart `archive/`** — closed plans are reference;
   if you need to extend old work, write a new plan that
   references the archived one.

## Recent cleanups

- 2026-05-19 — moved 13 closed issue-fix sprints (2026-05-11
  → 2026-05-18) into `archive/issue-fix/`; archived shipped
  `dns-upstream-resolution.md` (hickory-resolver + multi-A
  expansion landed); flipped smart-caching matrix row from
  Implemented to Deferred (TierCache removed 2026-05-11);
  drafted `future/smart-caching.md`.
- 2026-05-10 — folded ~25 top-level shipped plans into
  `archive/`; moved `issue-fix/`, `phase-b/`,
  `multi-node-deployment/` into `archive/`. Top level now
  has README + `plan.md` + `implementation-matrix.md` +
  `future/` + `archive/` only.
- 2026-05-10 — created `future/compliance-profiles.md`
  alongside the lock-by-mode deferral.
