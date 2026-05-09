# Phase 4 — LOW fixes

> Source: `tests/n-tester/reports/findings/2026-05-07/F-LOW-ALL.md` (L001–L004)
>
> All four are dashboard polish — single-PR-able, ~1 hour total.

---

## L001 · Overview page has no in-page alert banner

**Where:** Dashboard — Overview page

**Today** — when SLO alerts are firing, the only cue is the bell badge in the header. SOC analysts who land on the dashboard during an incident may miss it.

**Proposed fix:** When `/api/alerts` returns one or more firing alerts, render a dismissible banner at the top of the Overview page:

```jsx
{firingAlerts.length > 0 && !dismissed && (
  <div className="alert-banner alert-banner-warn">
    ⚠ {firingAlerts.length} {firingAlerts.length === 1 ? 'alert' : 'alerts'} firing —
    {' '}{firingAlerts.slice(0, 2).map(a => `${a.name} (${a.severity})`).join(', ')}
    {firingAlerts.length > 2 ? `, +${firingAlerts.length - 2} more` : ''}
    {' · '}<a href="#/health">View in Health & SLOs →</a>
    <button onClick={() => setDismissed(true)} aria-label="Dismiss">×</button>
  </div>
)}
```

**Effort:** ~15 min.

---

## L002 · `UNKNOWN` badge in header is unexplained

**Where:** Dashboard — global header

**Today** — the header shows `● UNKNOWN` next to the logo with no tooltip or explanation. Day-1 operators have no context.

**Proposed fix:** Two-part — better default label + tooltip:

1. **Default label** — instead of `UNKNOWN`, show the more accurate operational state:
   - `STANDALONE` when GitOps is OFF and no peers are configured
   - `CLUSTERED · N/M` when in a cluster (N healthy / M total)
   - `DEGRADED` when peers report mismatched config
   - `UNKNOWN` only as a last-resort fallback
2. **Tooltip on hover** — explain what each state means. Example: *"Standalone — running as a single node, no GitOps source-of-truth configured."*

Source the state from `/api/cluster` + `/api/gitops/status`.

**Effort:** ~25 min.

---

## L003 · Dev-facing message in production empty state

**Where:** Dashboard — Top Attackers page (empty state)

**Today** — empty state currently reads:

> "No attackers ranked in the last 1h. Drive synthetic load with `make mock-load-attacks` to see the table populate."

The `make mock-load-attacks` reference is meaningless to end users.

**Proposed fix:** Replace with a user-facing message:

> "No blocked sources in the selected window. Try extending the time range or wait for traffic to be evaluated."

Optionally: include a link to the Help & Guide → "What is Top Attackers?" section.

**Effort:** ~5 min.

---

## L004 · `#/routing` URL alias *(closes alongside M003)*

**Where:** Dashboard SPA router + internal documentation

**Today** — see [M003](./PHASE-03-medium.md#m003) for the router-side alias fix. L004 is the *documentation* side of the same problem: any internal links / Help & Guide entries that reference `#/routing` should be updated to `#/upstreams`.

**Proposed fix:**

1. M003 ships the route alias (covers external bookmarks).
2. Within the same PR, grep the dashboard sources for `#/routing` and rewrite to `#/upstreams`:
   ```sh
   grep -rn '#/routing' crates/aegis-control/assets/dashboard/src/ docs/
   ```
3. Update any matches in `help.jsx`, `pages.jsx`, `README.md`, etc.

**Effort:** ~10 min. **Closes alongside M003.**

---

## Sequencing notes for Phase 4

All four ship as **one consolidated PR**: `chore(dashboard): polish — alert banner / cluster label / empty state copy / #/routing alias`. Total ~1 hour, single review pass.

**Order within the PR:** L001 (alert banner) is most-impactful, L004 piggy-backs on M003 (do that first), then L002 (cluster label) and L003 (copy fix) can land alongside.

---

## Summary across all phases

| Phase | Items | Effort | Risk | Sequencing |
|---|---|---|---|---|
| Phase 1 | C001, C002 (incl. mode field) | 2-3 hrs | LOW | First — blocks v2.3 |
| Phase 2 | H001, H002, H003 | 3-4 hrs | LOW (after H003 repro) | After Phase 1 |
| Phase 3 | M001-M009 | 6-8 hrs | MEDIUM (touches many files) | Parallelizable, M009 chains |
| Phase 4 | L001-L004 | ~1 hr | LOW | Last — polish |
| **Total** | **18** | **~12-16 hrs** | | |

## Definition of done

- [ ] All 18 findings have a closed acceptance checklist
- [ ] Re-run the QA report (`tests/n-tester/...`) — verify each finding either closes or moves to "won't-fix" with a documented reason
- [ ] Live test on `waf.hk-aegis-gate.com` confirms:
  - All 4 `/__waf_control/*` endpoints work on `:8080` AND `:8443`
  - Performance page block ratio < 5% on benign synthetic load
  - SOC scenario S3 (pivot from Live Feed to Investigation) works end-to-end
  - Logged-in dashboard sessions survive a `reset_state` call
- [ ] Updated `STAGING-BENCHMARK.md` if any operator step changes
- [ ] Updated `Implement-Progress.md` log
