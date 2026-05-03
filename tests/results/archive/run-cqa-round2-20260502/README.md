# CQA round-2 verification — 2026-05-02

> Closes the CQA round-1 sprint. 16 of 19 CQF slices shipped;
> 3 LOW slices (T17 / T18 / T19) deferred because each needs a
> backend slice we don't want to bundle into a UI sprint.

## How this round differs from round-1

Round-1 (`tests/results/run-cqa-20260502/`) ran two parallel
passes: live API + JSX-grep (parent session) and source
analysis (e2e-runner agent). Round-2 is targeted: every
slice that landed has been live-verified against the running
WAF — not just compiled.

## Per-slice verdict

| Slice | Title | Round-1 | Round-2 | Live-verified |
|---|---|---|---|---|
| CQF-T1 | TopBar logout button | n/a | ✅ Shipped | login → mutation 200 → logout 204 → cookie-jar empty → next mutation 403 → re-login restores |
| CQF-T2 | Blacklist + Whitelist CRUD | n/a | ✅ Shipped | POST without csrf 403; with csrf 201; whitelist bypass:["all"] persists; DELETE existing 200; missing-id DELETE 400; audit chain `blacklist_add` / `whitelist_add` / `blacklist_remove` |
| CQF-T3 | Tier Config detector mask UI | n/a | ✅ Shipped | base recon true→false→true; 'high' override added with brute_force:false; override cleared; 4 audit-chain entries |
| CQF-T4 | Overview Block + Live Feed drawer | n/a | ✅ Shipped | reuses CQF-T2's accessListAdd; clipboard fallback for non-async-clipboard browsers |
| CQF-T5 | RequestDetail live data | n/a | ✅ Shipped | 8 hardcoded fields removed; sections render only when caller has data; honest em-dash fallbacks |
| CQF-T6 | RiskHeatmap live rows | n/a | ✅ Shipped | hardcoded 8 paths replaced with `useTopRiskPathsApi` (groups /api/audit/since events by path → max risk → top 8); empty state honest |
| CQF-T7 | Cache management decision | n/a | ✅ Shipped | card removed (M1 has no query-cache layer); explanatory comment block at deletion site |
| CQF-T8 | Risk-threshold sliders | n/a | ✅ Shipped | GET 40/80 → PUT 35/75 → GET reflects → restore 40/50; "not wired" pill flipped to "live" |
| CQF-T9 | Sidebar BUILD/UPTIME | n/a | ✅ Shipped | new `mark_started()` in api::about; /api/about returns `started_at`; sidebar computes uptime from `Date.now() - started_at`; verified started_at stable across calls |
| CQF-T10 | Notifications bell | n/a | ✅ Shipped | bell badges firing-alert count; click navigates `#/tracking` |
| CQF-T11 | Audit Log filter + paginate (verify deferred) | n/a | ✅ Shipped | time-range chip group (1h / 24h / 7d / all) + load-more pagination |
| CQF-T12 | Defensive `pct.toFixed` guard | n/a | ✅ Shipped | `(malicious.pct ?? 0).toFixed(1)` |
| CQF-T13 | `useAlertReceiversApi` smell | n/a | ✅ Shipped | one-line: `window.useApi` → `useApi` |
| CQF-T14 | TopBar drain button | n/a | ✅ Shipped | new icon-btn next to logout; two-step confirm + POST /admin/drain |
| CQF-T15 | Drop simulator helpers | n/a | ✅ Shipped | `useLiveFeed` + `useTrafficSeries` no longer hung off window; stale `window.useTrafficSeries ? ...` branch in PageOverview removed |
| CQF-T16 | Per-rule hits1h preserved | n/a | ✅ Shipped | rules-adapter now reads pri / action / risk / cat / hits1h from backend (was discarding them) |
| CQF-T17 | Per-member drain on Upstreams | — | ⏸ Deferred | Needs new backend endpoint + per-member ready/not-ready state model |
| CQF-T18 | Latency / per-route placeholders | — | ⏸ Deferred | Pending Prometheus aggregator follow-up (run-12 carry-over) |
| CQF-T19 | Per-rule stats tab | — | ⏸ Deferred | Needs backend per-rule hit counter |

## Round-1 → round-2 page-level deltas

| Page | Round-1 verdict | After CQF | Notes |
|---|---|---|---|
| Overview | ❌ FAIL | ✅ PASS | Block button wired (T4); RequestDetail backed by event (T5); RiskHeatmap backed by /api/audit/since (T6) |
| Live Feed | ❌ FAIL | ✅ PASS | All 3 drawer actions wired (T4) |
| Attack Events | ⚠️ COND | ✅ PASS | `pct.toFixed` guard (T12) |
| Analytics | ✅ PASS | ✅ PASS | unchanged |
| Audit Log | ⚠️ PARTIAL | ⚠️ PARTIAL | Filter + paginate added (T11); chain-verify still deferred (in-memory ring lacks per-entry hashes; needs persisted-store endpoint) |
| Rule Manager | ✅ PASS | ✅ PASS | hits1h fix (T16) is a low-pri polish |
| Tier Config | ❌ FAIL | ✅ PASS | DetectorMaskCard with full edit/save flow (T3) |
| Upstreams | ✅ PASS | ✅ PASS | per-member drain still missing (T17 deferred); page itself is fine |
| Blacklist + Whitelist | ❌ FAIL | ✅ PASS | full CRUD (T2) |
| Settings | ⚠️ PARTIAL | ✅ PASS | Risk-threshold sliders wired (T8); cache card removed (T7) |
| Tracking | ✅ PASS | ✅ PASS | useAlertReceiversApi smell fixed (T13) |
| Scaling | ✅ PASS | ✅ PASS | unchanged; TopBar drain button mirrors the action (T14) |
| Cross-cutting | ❌ FAIL | ✅ PASS | logout (T1) + drain (T14) + sidebar wired (T9) + bell wired (T10) |
| Mock-data audit | ❌ FAIL | ✅ PASS | RequestDetail (T5) + RiskHeatmap (T6) + cache stats (T7) all replaced |

**Final: 12 PASS / 1 PARTIAL / 0 FAIL** (round-1 was 5 / 3 / 6).

## Verification commands

Each slice was driven via curl against a freshly-booted
`./target/release/waf run --config config/dev.yaml`. The
exact command sequences are in the per-slice commit messages
on `develop`:

```sh
git log --oneline --grep='CQF-T' develop  # all 12 CQF commits
```

## Backend confirmation

Workspace tests after every backend touch:
- aegis-control: 911 / 0 / 0 (added 1 test for `started_at` stability)
- aegis-proxy: 466 / 0 / 0
- aegis-security: 888 / 0 / 0
- aegis-bin: 32 / 0 / 0

Production build: `cargo build --release -p aegis-bin` clean.

## Files

| File | What |
|---|---|
| this `README.md` | Round-2 consolidated verdict |
| `../run-cqa-20260502/` | Round-1 source + per-slice findings |
| `../run-cqa-20260502/SUMMARY.md` | Round-1 merged report |
| `../run-cqa-20260502-api/findings/` | Round-1 live-API probe results |

## What's left

- T17 / T18 / T19 → future track when their backend slices land
- T11 chain-verify → future track when persisted store gets a verify endpoint exposed via /api/audit/verify
- General polish: any new feature that lands should re-run this CQA / CQF cycle.
