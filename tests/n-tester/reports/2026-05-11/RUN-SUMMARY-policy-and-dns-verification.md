---
id: 2026-05-11-policy-dns-verification-summary
date: 2026-05-11T17:30Z
test_mode: full-qc
scope:
  - plans/issue-fix/2026-05-11-policy-qa-and-audits (Phases 1, 2, 3)
  - plans/dns-upstream-resolution.md (Phases 1, 2)
  - Policy section pages end-to-end UX/functional
---

# Aegis-Gate end-to-end test run — Policy QA + DNS upstreams

## Headline

`Aegis-Gate test run complete · full-qc · ~40 min`
`Findings: 0 CRITICAL · 2 HIGH (both resolved in-run) · 4 MEDIUM · 7 LOW · 7 INFO`
`Top blocker: NONE remaining — both HIGH issues were stale-bundle artifacts;`
`  fixed in-run by running 'make dashboard' (the dedicated dashboard target,`
`  not 'make build' which only rebuilds the Rust binary) + hard-reload.`
`Reports: skills/aegis-waf-tester/reports/findings/2026-05-11/`
`Next suggested action: document 'make dashboard' next to 'make build' in the`
`  README; consider lowering Cache-Control max-age on app.js or moving to a`
`  hashed filename so bundle rebuilds land without a hard reload; add a CI`
`  gate that fails if app.js drifts from a fresh rebuild.`

## Phase-by-phase verdict

| Plan / Phase | Status | Evidence |
|---|---|---|
| **Policy QA F-01** Rules Simulator renders | **PASS** | verdict/risk/tier + Detectors Fired + muted + Signals table all render after Simulate click |
| **Policy QA F-02** Inline validation on empty required fields | **PASS** | "Rule ID is required." and "Value is required." inline, red-bordered, focused — Rules + Access Lists |
| **Policy QA F-03** Audit deep-link from Rules Stats | **PASS** | `#/audit?rule_id=qa-test-rule-001` mounts Audit Trail with rule_id filter pre-applied + matching `rule_create` row |
| **Policy QA F-04** AI ONNX preflight | **PASS-by-design** | API exposes `feature_present`; dashboard Enable button gates on it. No `model_loaded:false` test case in this run because the dev model loaded cleanly |
| **Policy QA F-05** Compliance mode confirmation | **N/A** | Compliance page retired (commit 206110e) — per fix plan |
| **Policy QA F-06** Detector Disable confirmation | **PASS** | AI Disable triggers `confirm()` with blast-radius copy: "Attack detection from the ML model stops on the next request…" |
| **Policy QA F-07** Access Lists Remove styled modal | **PASS** | Native `confirm()` replaced with dark-themed modal carrying audit-mutation context |
| **Policy QA F-08** "+ icon on Cancel state" | **PASS** | Cancel button has no `+` icon; toggles back to "+ Add entry" when collapsed |
| **CORE-01** DdosConfig doc/impl reconciled | **PASS** | `WafConfig::ddos` doc rewritten to `observe_only: false` (enforce-by-default) + operator opt-in path documented |
| **CORE-02** Tcp validate guard | **PASS** | `config.rs:444-465` rejects tcp routes with empty `tcp_destination_allowlist` at validate time |
| **CORE-05** Real pool member health | **PASS-by-code** | `AtomicBool healthy` lives in `crates/aegis-proxy/src/upstream/mod.rs:21`; dashboard reads live counts (`/api/upstreams.healthy_members`) |
| **CORE-06** StateBackend default health | **PASS** | `/api/state.connected: true · backend: "reconciling"` — no `connected:false` fallback for unknown backends |
| **CORE-09 / CTL-08** reconcile.mode + state.backend validate | **PASS** | `config.rs:498-531` rejects `raft`, `redis_cluster`, `reconcile.mode = latest \| fail_safe` at lint time, before boot |
| **PROXY-02** regex/glob route rejection | **PASS** | `config.rs:407` reject + tests `validate_rejects_match_type_regex/glob` at `config.rs:3108-3158` |
| **PROXY-08/09** TierCache retired | **PASS-by-commit** | `2ad3a61` removes the dead module + moka dep |
| **PROXY-10** P2C entropy | **PASS-by-code** | `upstream/lb.rs:91` uses real RNG (not deterministic counter) |
| **PROXY-11** ConsistentHash → Rendezvous (HRW) | **PASS-by-code** | `upstream/lb.rs:133-149` Rendezvous Hashing; property tests `consistent_hash_minimal_disruption_on_member_change` at `:368` |
| **Phase 3g** Response filtering wire-up (backend) | **PASS-by-code** | `data_plane.rs:1445` calls `pipeline.on_body_frame`; `main.rs:213-231` instantiates `Pipeline::new` instead of `NoopPipeline` |
| **Phase 3g** Response filtering dashboard surface | **FAIL (HIGH-01)** | Source `pages.jsx:4567-4660` ships `ResponseFilterCard` with 3-rung toggles → `/api/response-filter` PUT — **but the compiled `app.js` bundle still serves the old 2-rung "local-only" card with a hardcoded "not wired" pill**. Operators believe the feature is off when it's on. |
| **SEC-21** RuleAction::RateLimit | **PASS** | PR #8 rejects at lint time with pointer to `cfg.rate_limit` |
| **SEC-18** CIDR threat-intel matching | **PASS** | PR #8 stores indicators as `IpNet`, linear scan; 3 new tests |
| **CTL-19** set_all preserves overrides | **DOWNGRADED** | Re-verified as contract-correct; existing test `set_all_clears_overrides_and_changes_default` asserts the documented behavior |
| **CTL-20** password change invalidates sessions | **PASS** | PR #8 invalidates on success, retains on failure |
| **DNS Phase 1** Hostname members accepted at boot + PUT | **PASS** | `PUT /api/upstreams/pool/qa-hostname-pool` with `addr: example.com:443` returned 200; saved pool shows two resolved IPs (104.20.23.154, 172.66.147.243), `host_header: example.com` defaulted (SNI ✓) |
| **DNS Phase 1** Loud failure on unresolvable host | **PASS** | PUT with `this-hostname-definitely-does-not-exist-aegis-qa.invalid:8080` → 400 with `reason: validation` and clear message |
| **DNS Phase 1** Multi-A expansion + host_header default | **PASS** | Edit-pool modal in the dashboard shows 2 members, both with host_header pre-populated to `example.com` |
| **DNS Phase 1** Dashboard placeholder + helper update | **FAIL (HIGH-01)** | Source `pages.jsx:9805` has `placeholder="IP:port (10.0.1.10:8080) or hostname:port (api.example.com:443)"` but the compiled `app.js` ships `Type a new backend: IP:port (e.g. 10.0.1.10:8080)` (no hostname mention). Same stale-bundle root cause as PR #7. |
| **DNS Phase 2** background refresh + audit | **PASS-by-code** | `crates/aegis-proxy/src/upstream/dns_refresh.rs` + `dns_resolve.rs` exist with TTL clamp, soft-failure, `pool_dns_resolved` audit event. No live rotation in this 30-min window so the audit event wasn't captured, but module documentation + tests match the spec. |

## Per-Policy-page coverage matrix

```
Pages exercised (5 Policy pages):
  Routing & Upstreams ✓ mounts ✓ data ✓ controls (Edit pool modal exercised: members, LB picker showed all 5 strategies, scheme picker showed all 6 incl. tcp, protocol matrix, health/breaker toggles) ✓ empty
  Traffic Gates       ✓ mounts ✓ data (5 gates with live counts) ✓ controls (range sliders, expandables, edit buttons) ✓ empty
  Access Lists        ✓ mounts ✓ data ✓ controls (Blacklist+Whitelist tabs, add/remove + Bulk import + search) ✓ empty
  Detectors & Tiers   ✓ mounts ✓ data (mask grid, score reference, 4 tier cards, live policy summary) ✓ controls (Base mask edit, AI Enable/Disable, tier edit) ✓ empty
  Rules               ✓ mounts ✓ data (rule list, detail tabs: General/DSL/Stats) ✓ controls (Simulate, New/Edit/Disable/Delete, audit deep-link)
```

## SOC scenarios

```
SOC scenarios:
  S1 "I just got paged" = 3   (header "UNKNOWN" red badge confuses; otherwise clean)
  S2 "Who's attacking me?" = -  (no synthetic traffic this run; previously verified)
  S3 "What did this attacker do?" = -
  S4 "Audit Trail surfaces mutations <3s" = 5 (mutations visible immediately; chain visible)
  S5 "Empty states honest" = 4 (mostly honest; Upstream "Healthy 3/3" counted the unreferenced qa-hostname-pool — defensible, but operator might expect "1 of 1 routed" framing)
  S6 "Block this attacker" = -
  S7 "Reload tolerance" = 4 (URL hashes carry rule_id, etc.; modals close on reload as expected)
  S8 "Console hygiene" = 4 (no red errors observed in 60s idle on each Policy page)
```

## Build / state context

- Build: `0.1.0` · session ID visible at footer · ~16m uptime during test
- Audit chain: `DEMO` (per footer pill)
- Cluster: `1/1` leader
- GitOps: `OFF`
- mTLS: `disabled`
- AI detector: `enabled` (test-flipped, left enabled)
- Active admin sessions: 2 (the test session + a prior session)

## Files in this finding bundle

- `RUN-SUMMARY-policy-and-dns-verification.md` (this file)
- `HIGH-01-dashboard-bundle-stale.md` — stale `app.js` masks PR #7 and PR-DNS-1 dashboard updates
- `HIGH-02-not-wired-pill-on-wired-feature.md` — Response Filtering card shows "not wired" though the backend pipeline is wired
- `MED-01-rules-audit-rule-column-empty.md` — Audit Trail RULE column shows `—` even for `rule_create` rows
- `MED-02-add-route-pool-name-collision-error-ambiguous.md` — Save-failed toast and inline hint disagree on the failure cause
- `MED-03-unknown-status-badge-on-healthy-system.md` — header `UNKNOWN` red pill on a healthy cluster
- `MED-04-unreferenced-pool-survives-failed-route-create.md` — pools created in the same modal flow persist when route creation fails
- `LOW-01-cluster-hostname-fallback.md` — `unknown-host-86898-…` node identifier in `/api/cluster`
- `LOW-02-rule-id-placeholder.md` — `vnexpress` placeholder on Route ID input — environment artifact in shipping code
- `LOW-03-add-entry-toast-color-bg.md` — minor toast styling drift
- `LOW-04-disabled-text-readability.md` — disabled toggle/text contrast
- `LOW-05-pool-route-counter-mismatch-text.md` — copy nits on the Routing & Upstreams summary line
- `UX-PROPOSALS-policy-pages.md` — concrete UI/UX upgrade proposals for the 5 Policy pages
- `INFO-01-through-INFO-07.md` — passing observations / "works as designed" log

