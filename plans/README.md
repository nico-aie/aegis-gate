# Plans

Simplified 2026-06-01 to focus on the **main plan**. The top level
holds the operating plan + the status matrix; forward-looking work is
the roadmap + the one active next track; everything closed or parked
lives in [`archive/`](./archive/).

## Layout

```
plans/
├── README.md                  ← this file (entry point)
├── plan.md                    ← MAIN PLAN — assistant protocol + repo conventions
├── implementation-matrix.md   ← doc-by-doc Implemented / Partial / Designed / Deferred
├── future/
│   ├── world-class-waf-roadmap.md       ← strategic ordering (Tiers 0–6)
│   ├── ai-operator-copilot.md           ← next active track
│   └── observability-otel-and-alerts.md ← OTel export + richer alerts
├── archive/                   ← closed / shipped / parked plans (read-only history)
└── issue-fix/                 ← active QA-driven fix plans
```

## Start here

1. **[`plan.md`](./plan.md)** — the main plan. Assistant protocol + repo
   conventions. Read this when picking up any task.
2. **[`implementation-matrix.md`](./implementation-matrix.md)** — what's
   actually shipped vs specified, per doc.
3. **[`../Implement-Progress.md`](../Implement-Progress.md)** — the
   living progress snapshot (current task, recent history, next task).

## `future/`

- **[`world-class-waf-roadmap.md`](./future/world-class-waf-roadmap.md)** —
  the ordering document: grades Aegis against the 2025–2026 WAAP leaders,
  names code-verified gaps, sequences them into Tiers 0–6. Read it before
  picking up new capability work.
- **[`ai-operator-copilot.md`](./future/ai-operator-copilot.md)** — the
  **next active track**: LLM situational summaries + smart-catch triage
  over the WAF's own telemetry (advisory-only, off the hot path,
  PII-redacted egress).
- **[`observability-otel-and-alerts.md`](./future/observability-otel-and-alerts.md)** —
  improve observation: (1) real OTLP export to an OTel Collector (traces
  + metrics + logs; backend suggestions inside) and (2) richer, "full"
  alert messages.

> **Trimmed 2026-06-01.** The per-feature backlog specs (alerts-refactor,
> bot-classifier-enforcement, compliance-profiles, smart-caching,
> audit-*, rule-non-block-actions, risk-composite-key-data-plane,
> unwired-stubs-catalog, advanced-features intake) were moved into
> [`archive/`](./archive/) to keep `future/` focused. They remain valid
> designs — the roadmap still references them by their archive paths. The
> API-security guard wire-up (old Tier 1A / B1) is **deprioritized**
> pending a WAF-vs-gateway boundary call (see the matrix `api-security`
> row).

## `archive/`

Closed, shipped, or parked plans kept for history — don't restart them;
write a new plan that references the archived one. Notable subfolders:
[`archive/issue-fix/`](./archive/issue-fix/) (older QA sprints),
[`archive/phase-b-2026/`](./archive/phase-b-2026/) (B1..B6 packaging),
[`archive/dashboard-enterprise/`](./archive/dashboard-enterprise/).

## Working with plans

1. **Search `archive/` first** — existing-feature context is usually there.
2. **New multi-step work** — drop a plan in `plans/` (or `plans/future/`
   for a net-new capability; also slot it into a tier in the roadmap),
   then move it to `archive/` once it ships.
3. **Don't restart `archive/`** — closed plans are reference only.
