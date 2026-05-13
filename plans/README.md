# Plans

Cleaned up 2026-05-10. The top level holds tracking + reference
files only — every closed or paused plan lives in
[`archive/`](./archive/), and feature plans we've intentionally
deferred live in [`future/`](./future/).

## Layout

```
plans/
├── README.md                       ← this file (entry point)
├── plan.md                         ← AI-assistant guide for this repo
├── implementation-matrix.md        ← doc-by-doc Implemented / Partial / Designed status
├── dns-upstream-resolution.md      ← active plan (2026-05-11)
├── future/                         ← deferred features (operator-confirmed, not yet built)
└── archive/                        ← closed / shipped / paused plans (read-only history)
```

## Active plans

- [`dns-upstream-resolution.md`](./dns-upstream-resolution.md) —
  Let operators address backends by hostname
  (`api.example.com:443`) instead of pinning a `SocketAddr`.
  Phase 1 (boot-time resolve) ≈ 2d, Phase 2 (background refresh
  via hickory-resolver) ≈ 3d, Phase 3 (dashboard polish) ≈ 1d.
  **Drafted 2026-05-11, not started.**

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

- [`compliance-profiles.md`](./future/compliance-profiles.md) —
  per-regime detector pinning + clamp enforcement (FIPS / PCI /
  SOC 2 / GDPR / HIPAA). Modes still parse and surface as
  documentation tags today; the lock is a no-op until the pin
  list is repopulated. **Status: Deferred 2026-05-10.**

> **Adding a future plan**: new file in `future/<short-slug>.md`
> with sections "Status / Why deferred / Code anchor / Future
> plan / Restoration checklist". Mirror `compliance-profiles.md`.

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

- 2026-05-10 — folded ~25 top-level shipped plans into
  `archive/`; moved `issue-fix/`, `phase-b/`,
  `multi-node-deployment/` into `archive/`. Top level now
  has README + `plan.md` + `implementation-matrix.md` +
  `future/` + `archive/` only.
- 2026-05-10 — created `future/compliance-profiles.md`
  alongside the lock-by-mode deferral.
