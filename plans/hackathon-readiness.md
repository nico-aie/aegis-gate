# Hackathon-Readiness — `HACK-T*`

> **Status:** Active. **HACK-T1 + T2 ✅ shipped 2026-05-01.**
> T3..T5 (Tier A/B/C bonus features) next. Track ID prefix
> `HACK-T<n>`. Targets the v2.3 contract requirements
> documented in
> [`../Hackathon_Doc/EN_present_v2.3.md`](../Hackathon_Doc/EN_present_v2.3.md)
> + [`../Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](../Hackathon_Doc/EN_waf_interop_contract_v2.3.md).

---

## 0 · Why this track

The Hackathon v2.3 docs split scoring into three rounds:

| Round | Weight | Type | Risk for us |
|---|---|---|---|
| 1 — Functionality (Pass/Fail) | gate | elimination | **Mock-data penalty** on PageAttackEvents + PageAnalytics |
| 2 — Automated benchmark | 65% (≥ 70% gate) | strict contract | Already green per run-12 (32/32 OpenAPI; 8/8 round-1 acceptance; 0 nuclei matches) |
| 3 — Performance + Tier bonuses | 35% + bonus | head-to-head | **Tier A/B/C bonus features** unclaimed |

**The two real gaps** are (a) the Round-1 mock-data warning and
(b) Round-3 Tier-bonus features. Everything else is shipped or
parked behind explicit operator config.

---

## 1 · Round-by-round audit

### Round 1 — Functionality (Pass/Fail) gate

| Requirement (v2.3 §2.2) | Status | Evidence |
|---|---|---|
| WAF core in Rust, single binary | ✅ | `target/release/waf` (run-12: 20 MB) |
| `./waf run` starts + stable | ✅ | run-12 stability: 3/3 parallel boots |
| Reverse proxy: client → WAF → upstream → client | ✅ | run-12 k6: 37,600 req/s sustained |
| OWASP Top 5 detection | ✅ | run-12 attack probes: SQLi / XSS / path-traversal / SSRF / CRLF all 403 |
| Blacklist / rate-limit basics | ✅ | `/api/blacklist` + `IpRateLimiter` + audit-mutated PUT |
| Real-time monitor ≤ 5 s | ✅ | SSE feed on `#/live`; run-12 measured **55 ms** |
| Rule mgmt UI (CRUD) | ✅ | `#/rules` + audit-mutated `/api/rules` POST/PUT/DELETE |
| Hot-reload ≤ 10 s with UI indication | ✅ | run-12 measured **76 ms**; toast shows "applied in Xs" |
| Audit-log viewer with filters | ✅ | `#/audit` with time / IP / rule / request_id filters |
| Health / Status view | ✅ | TopBar uptime / nodes / mode pill; `/healthz/*`; new SC-T2 Scaling page |
| **No mock data** in features that claim to control the proxy | ⚠️ | **PageAttackEvents + PageAnalytics still use `Math.random`** with explicit "synthetic data" pills (run-12 followup item) |

**The only Round-1 risk is the `Math.random` synthetic data on
`#/attacks` and `#/analytics`.** The pages display the warning
honestly, but the Hackathon judges may still penalize them per
the v2.3 §2.2 rule:

> *Cases that may be penalized... The Dashboard uses mock data,
> local state, or simulated responses that make the UI state
> inconsistent with the real WAF-PROXY state.*

→ **HACK-T1** retires the `Math.random` calls.

### Round 2 — Automated Benchmark (65% / 70% gate)

| Requirement (v2.3 §3, §5, §6) | Status |
|---|---|
| `/__waf_control/{capabilities, reset_state, set_profile, flush_cache}` | ✅ shipped (IT-T1..T6, see [`interop-contract.md`](./interop-contract.md)) |
| `X-Benchmark-Secret` auth (default `waf-hackathon-2026-ctrl`) | ✅ shipped |
| Synchronous + atomic `reset_state` preserving audit log | ✅ shipped + DR-T verified |
| Required `X-WAF-*` headers on every response | ✅ shipped (Request-Id / Risk-Score / Action / Rule-Id / Cache / Mode) |
| Audit log JSONL with mandatory fields | ✅ shipped (request_id / ts_ms / ip / method / path / action / risk_score / mode) |
| Six decision classes: allow / block / challenge / rate_limit / timeout / circuit_breaker | ✅ shipped (`DecisionTag::*` + recommended HTTP status mapping) |
| `log_only` mode reports intended action without enforcing | ✅ shipped (`ModeStore` + per-policy override + header propagation) |
| TCP peer IP, not XFF, in `audit.ip` | ✅ shipped |
| Challenge response format (JSON or HTML with `challenge` token) | ✅ shipped (P3 challenge engine) |

**Round 2 is green.** Run-12 verified all 32 OpenAPI shape
checks + the 8/8 round-1 acceptance gates.

→ **HACK-T2** is a defensive re-run of the benchmark + an
automated "all v2.3 requirements pass" CI check that fails the
build if any contract drift creeps in.

### Round 3 — Performance + Tier bonuses (35% + bonuses)

**Performance targets** (v2.3 §2.4) are mostly opaque ("low
overhead", "stable under pressure"). Run-12 already shows
37,600 req/s sustained at p95 286 µs on a single node. Phase B
HA + cluster deploys for horizontal scaling.

**Tier-bonus features** (v2.3 §2.4):

| Tier | Description | What we have | Recommended next |
|---|---|---|---|
| **A — Security & Detection** | rule simulator, attack visualization, enriched data | PageAttackEvents (synthetic), `risk_score` per request, GeoIP enrichment via feature flag, threat-intel via `B3` | **HACK-T3** rule simulator (replay an audit event against the live ruleset) |
| **B — Advanced Operations** | config versioning, rollback, large-scale config deploy | hash-linked audit chain (`audit/witness`), GitOps (`B2-T2`), `waf snapshot/restore` CLI | **HACK-T4** Console rollback UI (browse audit chain, "rollback to revision N" button → re-applies the snapshot) |
| **C — System Integration** | log forwarding, alerts, metrics export | OpenTelemetry OTLP exporter, Prometheus `/metrics`, SLO `AlertReceiver` engine (Slack / PagerDuty / webhook), Jsonl audit sink | **HACK-T5** Syslog/CEF audit forwarder (connect existing Jsonl pipeline to a remote syslog sink — high signal for SIEM integrations, low complexity) |

The plan **deliberately recommends one item per Tier** because
Tier scoring has diminishing returns within the same Tier
(v2.3 §2.4):

> *Implementing multiple features within the same Tier will
> yield diminishing returns.*

---

## 2 · Slices (smallest first)

### HACK-T1 — Retire dashboard mock data — ✅ shipped 2026-05-01

**Goal:** every visible widget on `#/attacks` and `#/analytics`
shows real WAF data; no `Math.random` or static-fixture rows.

**Files:**
- `crates/aegis-control/assets/dashboard/src/pages.jsx`
  `PageAttackEvents` + `PageAnalytics`
- `crates/aegis-control/src/api/analytics.rs` — confirm the
  endpoint returns the histograms / time-series the page needs
- `crates/aegis-control/assets/dashboard/src/data.jsx` — add
  hooks if any are missing
- Remove the `synthetic data` pills once the data is live

**Specifically retire:**
- `pages.jsx:465` — `50 + Math.floor(Math.random() * 1800)` →
  read from `useAttacksDistributionApi` (already shipped) or
  Prometheus-backed `useAnalyticsApi`
- `pages.jsx:573-577` — `reqOverTime`, `blockRatio`, `latP50/95/99`
  → wire to `useTimeseriesApi` + the `request_duration` histogram
  exposed at `/metrics` (PROM-T1 shipped in run-10)
- `pages.jsx:1084` — random sparkline → wire to the same source

**Tests:**
- Unit test `aegis-control/src/api/analytics.rs` returns
  shape compatible with the dashboard hook expectations
- Integration test (`api_smoke.rs`) hits `/api/analytics/*`
  with a seeded `StatsAggregator` and verifies all expected
  fields are populated
- Browser screenshot via `tests/dashboard/capture-screenshots.mjs`
  — no "synthetic data" pill remains visible

**Definition of Done:**
- Bundle ≤ 256 KB
- All workspace tests green
- `#/attacks` + `#/analytics` screenshots show no warning pills
- run-13.5 acceptance pack re-run passes 32/32 + 8/8

### HACK-T2 — Automated v2.3 contract regression — ✅ shipped 2026-05-01

**Goal:** CI fails the moment any v2.3 contract requirement
breaks (header missing, JSON shape drift, `reset_state` not
atomic, etc.).

**Files:**
- New `tests/contract/v2.3_compliance.sh` — bash harness that
  spins up the binary, hits every required endpoint, asserts
  every required header, validates JSONL schema, checks
  audit-log preservation across `reset_state`.
- Hook into `tests/README.md` § 9 CI stages (already a
  scripted runner).

**Tests:**
- Each v2.3 requirement gets a numbered check with a clear
  failure message (e.g. "v2.3 §5.1.4 — `X-WAF-Cache` missing
  on /healthz/live").

**Definition of Done:**
- Script exits 0 against the current binary.
- Script exits non-zero if you intentionally break any
  contract (e.g. drop `X-WAF-Mode` from a hand-edit).
- Wired into CI matrix.

### HACK-T3 — Tier-A: Rule simulator (~6-8 h)

**Goal:** operators replay any historical audit event against
the *current* ruleset and see what would happen — without
sending real traffic. High-signal Tier A bonus per v2.3 §2.4.

**Files:**
- `crates/aegis-control/src/api/simulator.rs` (new) — POST
  `/api/rules/simulate` { request_id | raw_request_blob }
  returns `{ matched_rules: [...], action: "...", risk_score: N }`.
- `crates/aegis-security/src/pipeline.rs` — gain a
  `dry_run_evaluate(req_view) -> DecisionTag` that runs the
  full pipeline without any side effect (no risk increment,
  no rate-limit consumption, no audit emit).
- `assets/dashboard/src/pages.jsx::PageRuleManager` — add a
  "Simulate" tab. Pick an event from the audit log → click
  Simulate → see decision + matched detector tree.

**Tests:**
- Unit: `dry_run_evaluate` produces same decision as real
  pipeline on the same input but doesn't mutate `RiskTracker`
  / rate-limit counters.
- Integration: post a known-bad blob → response includes the
  expected rule_id.

**Definition of Done:**
- One-click replay from audit log → simulator pane.
- Documented in
  `docs/control-plane/enterprise/pages/rules.md`.

### HACK-T4 — Tier-B: Config versioning + rollback (~6-8 h)

**Goal:** every audit-mutated config change is browsable in
the UI with a one-click rollback. Tier B bonus (operations
lifecycle).

**Files:**
- `crates/aegis-control/src/api/config_versions.rs` (new) —
  `GET /api/config/versions` lists the audit chain entries
  whose `class = Config`. `POST /api/config/versions/{n}/rollback`
  re-applies the snapshot at version N (uses the existing
  `audit/witness` hash chain).
- `assets/dashboard/src/pages.jsx::PageSettings` — new
  "Versions" card under the page head listing the last 50
  config changes with a Rollback button (two-step confirm,
  same pattern as SC-T2 drain button).

**Tests:**
- Unit: rollback re-applies the snapshot AND emits a new
  `config_rollback` audit event linked to the original
  revision.
- Integration: change → rollback → state matches the original;
  audit chain is now N+1 entries (not destructive).

**Definition of Done:**
- Operators can browse the last 50 config edits.
- Rollback wires through the existing audit-mutated mutation
  path, so it cannot bypass authz / CSRF / chain.

### HACK-T5 — Tier-C: Syslog/CEF audit forwarder (~3-4 h)

**Goal:** stream the existing JSONL audit log to a remote
syslog endpoint (RFC 5424) or CEF receiver. Tier C bonus
(centralized log forwarding).

**Files:**
- `crates/aegis-control/src/audit/sinks/syslog.rs` (new) —
  `SyslogSink { endpoint, transport: udp | tcp | tls }`.
  Reuses the bus subscriber pattern from
  `audit::sinks::jsonl`.
- `crates/aegis-core/src/config.rs` — extend `AuditSinkConfig`
  with a `Syslog { endpoint, transport, format: rfc5424 | cef }`
  variant.
- `aegis-proxy::run` — spawn the new sink alongside the
  existing JsonlSink when configured.

**Tests:**
- Unit: encode an `AuditEvent` to RFC-5424; round-trip via
  a UDP loopback receiver.
- Integration: configure a TCP receiver in a test; emit
  events → assert receiver got them in order.

**Definition of Done:**
- Documented in
  `docs/operations/log-forwarding.md`.
- Example `waf.yaml` snippet showing dual-sink (jsonl +
  syslog).

---

## 3 · Sequencing

```
HACK-T1 (mock data retirement)
   ├── HACK-T2 (contract regression CI)
   └── HACK-T3 (rule simulator)        ← Tier A
         ├── HACK-T4 (versioning)      ← Tier B
         └── HACK-T5 (log forwarder)   ← Tier C
```

**T1 first** because it removes a Round-1 elimination risk.
**T2 next** because contract drift is the easiest way to lose
Round 2 points.
**T3..T5 in any order** — independent.

---

## 4 · Estimated effort

| Slice | Effort | Round impact |
|---|---|---|
| HACK-T1 | 3-4 h | Round 1 (de-risk) |
| HACK-T2 | 2 h | Round 2 (regression guard) |
| HACK-T3 | 6-8 h | Round 3 (Tier A) |
| HACK-T4 | 6-8 h | Round 3 (Tier B) |
| HACK-T5 | 3-4 h | Round 3 (Tier C) |
| **Total** | **20-26 h** | covers all three rounds |

---

## 5 · What's deliberately NOT in scope

- **More Tier-A items** (e.g. ML detector explainability,
  per-rule effectiveness panel) — diminishing returns within
  the same tier per v2.3 §2.4.
- **`/admin/login` mTLS bypass** — already on
  `plans/mtls.md` MTLS-T4 deferred list.
- **Hot-resize tokio** — explicitly impossible (v2.3 doesn't
  require it; SC-T documents the restart-only invariant).
- **Multi-tenancy** — not in v2.3 requirements; future track.

---

## 6 · Definition of Done (track-level)

- [ ] HACK-T1..T5 closed.
- [ ] `tests/contract/v2.3_compliance.sh` green.
- [ ] No `Math.random` / static fixtures on dashboard pages
      that claim to control the proxy.
- [ ] At least one feature in each of Tier A / B / C shipped.
- [ ] `docs/architecture/scaling-model.md` (already shipped)
      cross-linked from any new operator-facing pages.
- [ ] `Implement-Progress.md` § Last Completed reflects the
      track close per § 0.3 of `plans/plan.md`.
