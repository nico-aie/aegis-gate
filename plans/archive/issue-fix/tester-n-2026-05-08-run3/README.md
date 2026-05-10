# tester-n 2026-05-08 Run-3 — fix plan

> **Source:** [`tests/n-tester/reports/2026-05-07-regression/QA-RUN-3-SUMMARY.md`](../../../tests/n-tester/reports/2026-05-07-regression/QA-RUN-3-SUMMARY.md)
> **Status:** plan, awaiting confirmation. No code changes yet.
> **Branch target:** `develop` (operator merges to `Test/UI` for re-check after each phase)

---

## Run-3 outcome at a glance

All 5 carried-forward findings (NEW-1..NEW-5 + C002 + M009) are **VERIFIED FIXED** by Run-3. Three fresh findings opened.

| New | Severity | Verified against current code |
|---|---|---|
| **RUN3-NEW-1** `make bench-dev` doesn't refresh `waf.yaml` from `config/dev.yaml` | HIGH | ✓ confirmed — `Makefile:146` guard `if [ ! -e ./waf.yaml ]` skips the copy; stale `waf.yaml` keeps `ai.enabled: true` even after `dev.yaml` was fixed |
| **RUN3-NEW-2** `GET /__waf_control/healthz` returns 404 on data plane | MEDIUM | ✓ confirmed — `admin_dispatch.rs:699-755` dispatcher has no `healthz` arm. The Run-2 report mistakenly marked this green; Run-3 caught the mismatch |
| **RUN3-NEW-3** SPA redirects to `/admin/login` after `reset_state` | LOW | ⚠ verified mechanism but not reliably reproducible — global fetch interceptor at `data.jsx:563-591` redirects on any `fetch` returning 403 with `body.reason` starting with `csrf_`. `reset_state` itself doesn't touch sessions/CSRF; trigger is likely a coincidental CSRF cookie expiry on a parallel SPA polling fetch |

The QA report's wording is mostly accurate. Two clarifications worth flagging up-front:

- **RUN3-NEW-2 contract claim:** The QA cites v2.3 §1 as mandating `/__waf_control/healthz`. Reading the spec, §1 is just "Purpose" and §8 ("Health Check") says the benchmarker polls "the configured health endpoint" — endpoint path is operator-configured, not hardcoded. So this isn't strictly a contract violation, but adding `/__waf_control/healthz` is a natural completion of the namespace and matches what automated harnesses commonly probe. We close the finding by adding the endpoint.
- **RUN3-NEW-3 reproducibility:** The QA's described chain ("call reset_state → SPA dumps to login despite valid session") doesn't match any code path that's directly triggered by `reset_state`. The interceptor only fires on **fetch responses** (not arbitrary triggers), and `reset_state` ignores body params and doesn't touch SessionStore/CSRF. Most likely root cause: a parallel SPA polling fetch hit a 403 with a `csrf_*`-shaped body around the same time. Plan tightens the heuristic and adds diagnostics so the next occurrence captures actionable details.

---

## Phase plan

| Phase | Items | Approx effort | PR shape |
|---|---|---|---|
| [Phase 1 — HIGH](./PHASE-01-high.md) | RUN3-NEW-1 (bench-dev refresh + drift warning) | 30 min | One `fix(makefile)` PR |
| [Phase 2 — MEDIUM](./PHASE-02-medium.md) | RUN3-NEW-2 (`/__waf_control/healthz` data plane) | 30 min | One `feat(interop)` PR |
| [Phase 3 — LOW](./PHASE-03-low.md) | RUN3-NEW-3 (CSRF interceptor heuristic + diagnostic) | 30 min | One `fix(dashboard)` PR |

**Total estimated effort: ~1.5 hours**, three small independent PRs.

All five Run-2 findings stay closed per the QA verification matrix; nothing in Run-3 regressed Run-2 fixes.

---

## Sequencing

1. **RUN3-NEW-1 first** — without it, every CI run + every developer's `make bench-dev` boots with the over-firing AI detector, masking real signal in subsequent QA runs. Highest leverage.
2. **RUN3-NEW-2** — small, independent. Closes interop-harness compatibility for harnesses that probe `/__waf_control/healthz`.
3. **RUN3-NEW-3 last** — diagnostic improvement, not a behavior fix. Captures evidence so the next reported occurrence has actionable details rather than guesses.

The three are independent — could ship in parallel if reviewers can absorb three small PRs at once.

---

## What we're NOT doing in this round

- **Auto-refresh CSRF cookies in the SPA** when only the CSRF (not the session) expired. This is the proper fix for the broader RUN3-NEW-3 family of issues but requires a server-side refresh endpoint + client retry-on-csrf-expiry logic — a feature, not a fix. Track separately if RUN3-NEW-3 reoccurs after the diagnostic lands.
- **Force `waf.yaml` regeneration on every `make bench-dev`** without an opt-out. That would clobber operator-edited tunings between bench runs. The plan adds an opt-in `FORCE=1` flag + a drift warning instead.
- **Server-side `/__waf_control/healthz` heartbeat semantics** (e.g. checking Redis, upstream pools, audit sink). Returns the simplest "alive" shape; deeper readiness lives at admin `/healthz/ready`.
- **Browser-side blake3 PoW solve fixture** (Run-3 §NEW-2 verification gap — they couldn't run the positive 204 path because blake3 isn't a browser API). Add a node/wasm fixture in a follow-up; not blocking this round.

---

## Cross-cutting risks

| Risk | Mitigation |
|---|---|
| Operator with locally-tuned `waf.yaml` runs `make bench-dev FORCE=1` and loses their changes | Print a one-line warning before the copy: "FORCE=1 will overwrite ./waf.yaml; backup at ./waf.yaml.bak"; auto-create the .bak file |
| `/__waf_control/healthz` becomes a DDoS surface (no auth) | Match the existing `/healthz/live` pattern: 200 on every request, no body parsing, no DB hop. Trivial cost; same exposure as the existing admin healthz |
| RUN3-NEW-3 fix changes session-expiry UX in a way that confuses operators when CSRF actually does expire | Diagnostic-only changes in this round — no behavior change to the redirect logic. Heuristic tightening (require `ok: false`) is conservative |

---

## Acceptance for the whole round

- [ ] All 3 RUN3 findings have a fix or accepted-as-design close
- [ ] No regression in the Run-1 + Run-2 fixed findings (15 + 5 = 20 closed items)
- [ ] All workspace tests pass; new regression tests cover RUN3-NEW-2
- [ ] Manual verification: `make bench-dev FORCE=1` refreshes `waf.yaml` from `dev.yaml`; healthz endpoint returns 200 on `:8080`

---

## File map

```
plans/issue-fix/tester-n-2026-05-08-run3/
├── README.md             ← this file (index, sequencing, cross-check)
├── PHASE-01-high.md      ← RUN3-NEW-1 bench-dev waf.yaml refresh
├── PHASE-02-medium.md    ← RUN3-NEW-2 /__waf_control/healthz
└── PHASE-03-low.md       ← RUN3-NEW-3 SPA CSRF interceptor diagnostic
```
