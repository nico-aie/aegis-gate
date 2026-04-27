# Page — Rule Manager

> CRUD on rules with a diff-and-validate workflow. Wraps the
> existing `/api/rules` endpoints already implemented in
> `aegis-control`.

## Route

`GET /dashboard/rules`

## Data sources

| Widget | Source |
|--------|--------|
| Rule list | `GET /api/rules` |
| Rule detail | `GET /api/rules/{id}` |
| Match counts | `GET /api/rules/{id}/stats?window=1h` |
| Editor (diff/validate) | `POST /api/rules/validate` (new) |
| Save | `POST /api/rules` / `PUT /api/rules/{id}` / `DELETE /api/rules/{id}` |

`POST /api/rules/validate` is new — runs the parser + linter +
dry-run evaluator against a payload and returns a structured
result. It does **not** apply any change.

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Rule Manager                                  [+ New rule]   │
├────────────┬─────────────────────────────────────────────────┤
│ rules list │   editor / detail panel                          │
│ priority   │                                                  │
│ scope      │   [Edit] [Disable] [Delete]                      │
│ action     │                                                  │
│ count(1h)  │   ┌─ tabs: General | DSL | Diff | Stats ─┐      │
│ ───────    │   │                                       │      │
│ row 1 ✓    │   │  rule body editor (textarea + lint)   │      │
│ row 2 ✓    │   │                                       │      │
│ row 3      │   └───────────────────────────────────────┘      │
│ row 4      │                                                  │
│ …          │   [Validate]   [Save]   [Cancel]                 │
└────────────┴─────────────────────────────────────────────────┘
```

- Left panel: virtualized list, search box at top, sort by
  priority / hits / last fired.
- Right panel: detail / editor. Read-only by default; "Edit"
  toggles the editable mode.
- Tabs:
  - **General** — id, description, scope, priority, action, owner.
  - **DSL** — rule body in a `<textarea>` with monospace font and
    soft-wrap; gutter shows lint markers (errors red, warnings
    amber). The lint payload comes from `/api/rules/validate`.
  - **Diff** — unified diff between persisted and edited body.
    Auto-renders as the operator types (debounced 300ms).
  - **Stats** — match count over the last 1h, breakdown by route
    and decision; mini sparkline.

## Validate / Save flow

```
[Edit] → modify body → [Validate]
                        │
                        ▼
                /api/rules/validate
                        │
            ok  ────────┴────────  errors
             │                       │
             ▼                       ▼
    [Save] enabled              show inline markers
             │
             ▼
   PUT /api/rules/{id}    (CSRF + session)
             │
             ▼
   audit-chain entry written; reload list; toast "Saved"
```

A rule cannot be saved while validation has unresolved errors.
Warnings do not block save but show a confirm modal.

## Disable / Delete

- Disable sets `enabled: false` via PUT. Reversible.
- Delete requires confirm with the rule id typed back.
- Both write `AuditClass::Admin` entries.

## New rule wizard

- "+ New rule" opens a 3-step modal:
  1. Template (blank, SQLi pattern, IP block, rate-limit override).
  2. Fill in id/scope/priority.
  3. Validate + Save.
- Templates are static JSON snippets in the embedded asset bundle.

## Permissions / safety

- All mutating routes require valid session + CSRF as today.
- GitOps mode: instead of applying directly, Save opens the
  GitOps PR flow (see [`../../gitops-change-management.md`](../../gitops-change-management.md))
  and shows the resulting PR link in a toast.
- Break-glass override toggle in Settings → off by default.

## Telemetry

- Reuses existing `waf_admin_requests_total{endpoint="/api/rules"}`
  metric. No new metric.
