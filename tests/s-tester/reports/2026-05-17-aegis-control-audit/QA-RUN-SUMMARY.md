---
id: 2026-05-17-aegis-control-audit
date: 2026-05-17T00:00Z
test_mode: source-review
scope:
  - Full audit of `crates/aegis-control/src/` — 102 files / ~35k LoC
    across 5 functional groups:
    A) Audit chain + 8 SIEM sinks + interop audit sink
    B) Read-only REST API + Live Feed (SSE) + dashboard asset serving
    C) Mutation REST API + GitOps + rollback
    D) Dashboard services + SLO + Prometheus metrics + health + identity
       tracker + compliance + residency + tiers
    E) Interop v2.3 deep-dive + admin-auth completeness
  - Cross-referenced into `crates/aegis-proxy/` where mutation handlers
    + listener wiring live.
  - Compliance gate: `Hackathon_Doc/WAF_Hackathon_2026_offical_rules.pdf`
    + `VN_waf_interop_contract_v2.3.md` + `VN_presen_v2.3.md`.
tester: Claude (5 parallel general-purpose audit agents +
                spot-verification via `grep` and direct file:line reads
                for the top 10 highest-impact findings)
---

# Aegis-Gate `aegis-control` full-crate audit — 2026-05-17

**Mode:** Source review only. 5 parallel agents took non-overlapping
functional groups; aggregated findings spot-verified by reading the
cited file:line and confirming via `grep` (especially for "dead-code"
claims — verified zero production callers across `crates/`).

**Scope reminder — what the hackathon grades** (PDF §6, 120 points total):

| Tiêu chí | Điểm | Mostly covered by this crate |
|---|---|---|
| Security Effectiveness | 40 / 120 | NO (aegis-security) |
| Performance | 20 / 120 | partial (request-duration metrics + SLO) |
| Intelligence & Adaptiveness | 20 / 120 | partial (SLO + identity tracker) |
| Architecture & Code Quality | 15 / 120 | **YES — audit chain, services bundle** |
| Extensibility | 10 / 120 | **YES — rule scopes, GitOps, rollback** |
| **Dashboard UI/UX & Realtime Config** | **10 / 120** | **YES — REST + SSE + assets** |
| Deployment & Operability | 5 / 120 | YES — health + metrics |

Plus the **Round-1 Pass/Fail dashboard mandates** (WAF-FE section of
official rules) ALL touch this crate:
- Real-time monitor ≤5s
- Audit log filterable by IP / Rule-ID / Request-ID / time
- Health/Status view (uptime, mode, active rule count)
- Hot-reload ≤10s with UI confirmation
- "**Tính hiệu lực**": UI feature MUST actually impact WAF-PROXY
  behavior. Mock data + workflow theater = "không đạt".

---

## Finding counts

| Severity | Count |
|---|---|
| CRITICAL | 16 |
| HIGH     | ~37 (bundled into 6 domain files) |
| MEDIUM   | ~48 (bundled) |
| Contract gaps (semantic) | 4 |
| **Total** | **105+** |

**Largest audit of the series**: data-plane 14, proxy-full-crate 64,
security 78, this 105+. The aegis-control crate is the dashboard +
control-plane surface — directly graded on Round-1 mandates AND a
10/120 dedicated rubric item.

---

## CRITICAL findings index — by Round-1 impact

### Round-1 Pass/Fail mandates UNMET

| ID | Title | Round-1 clause |
|---|---|---|
| F-CRITICAL-001 | Rule CRUD only mutates `services.rules` (RuleStore); live `Arc<RuleSet>` is NEVER rebuilt — operator clicks "Save rule" but real traffic behavior unchanged | "Tính hiệu lực" + Hot-reload ≤10s |
| F-CRITICAL-002 | `COMPLIANCE_PINNED = &[]` (empty) + compliance modes never read by TLS stack — FIPS/PCI/HIPAA dashboard toggles do NOTHING | "Tính hiệu lực" |
| F-CRITICAL-003 | `/healthz` missing uptime / mode / active-rule-count — Round-1 explicitly requires these 3 fields | Health/Status View |
| F-CRITICAL-004 | Audit search missing time-range filter — Round-1 names 4 dimensions (time, IP, Rule-ID, Request-ID), only 3 implemented | Audit Log Viewer |
| F-CRITICAL-010 | Capabilities response omits `open_redirect` policy while detector emits it — `set_profile` for that policy returns `unsupported` while rule still fires live | v2.3 §2.3 contract drift |
| F-CRITICAL-019 | `api/analytics.rs` returns hardcoded `0.0` for every key + `api/tracking.rs` returns 6 `placeholder()` constructors when providers unwired | §9 forbidden mock-data |

### Dead-code modules — advertised but never wired

| ID | Title |
|---|---|
| F-CRITICAL-005 | `GitOpsLoader::sync` dead code (zero production callers; `dry_run_validate` accepts `42` / `"hello"`) — §5.9 zero-downtime config sync bonus uncollected |
| F-CRITICAL-006 | `audit/witness.rs` dead code — README's "witness export" claim is false; HMAC key has no source at all |
| F-CRITICAL-007 | `residency.rs` (527 LoC) dead code — README's "GDPR region pin" never enforced |
| F-CRITICAL-008 | `tracing_init.rs` (305 LoC) dead code — `init()` is a stub returning `true`; `random_hex()` uses `blake3(timestamp:counter)` (predictable, F-CRITICAL-005 class) |
| F-CRITICAL-009 | `admin_auth/mtls.rs::verify_client_cert` dead code — defined but zero production callers; "optional mTLS layer" of auth chain is library-only |

### Live-system correctness

| ID | Title |
|---|---|
| F-CRITICAL-011 | `dashboard_services.rs:428` drain loop exits PERMANENTLY on `RecvError::Lagged` — under any burst, audit ring stops being fed, Live Feed freezes; §5.6 "≤5s" broken |
| F-CRITICAL-012 | `interop/audit.rs:86-95` does sync `std::fs::write_all` + `Mutex::lock` on the tokio async hot path WITHOUT `spawn_blocking` — every request stalls a worker thread on disk I/O |
| F-CRITICAL-013 | jsonl sink has NO `fsync`; chain on disk uses bare `AuditEvent` (not `ChainEntry`); cross-day chain linkage BROKEN (every daily file restarts at genesis → deleting a whole day is undetectable) |
| F-CRITICAL-014 | `api/rollback.rs::ROLLBACKABLE_ACTIONS` omits 13 of 25 mutation classes — rollback silently 422s for route/pool/alert/mtls-ca-bundle/ddos/rate_limit/upstreams_config |
| F-CRITICAL-015 | Unauthenticated SSRF via alert-receiver `bot_token` interpolated into URL path with no escaping or scheme validation — combined with F-CRITICAL-002 (admin no auth) → pivots HTTP client to AWS metadata `169.254.169.254` |
| F-CRITICAL-016 | `SliRingBuffer::push` does `Vec::remove(0)` (O(n) memcpy of 10k samples) under global `Mutex` — Performance 20/120 rubric collapse on 5k req/s data plane |

### High-cost theater

| ID | Title |
|---|---|
| F-CRITICAL-017 | `DEFAULT_VIPTALK_BOT_TOKEN = "xxx-dev-uat-bot-token-xxx"` hardcoded as default for receivers — production deployments that forget the env var POST every SLO alert (with SLI + severity payload) to a third-party Matrix room |

### HIGH bundles

| File | Mini-findings inside |
|---|---|
| F-HIGH-headers-contract.md | 3 items: `X-WAF-Request-Id` is 64-char blake3 hex NOT UUID v4 (strict graders reject every response) · `X-WAF-Rule-Id` uses underscores (`mtls_required`, `websocket_no_healthy_member`) NOT alphanumeric+hyphens · `X-WAF-Risk-Score` no `.min(100)` clamp (operator-config `risk.max` > 100 leaks) |
| F-HIGH-read-api.md | 8 items: audit ring cap 10k → search older events fails · SSE no `id:` line → Last-Event-ID broken · `attacks::top` IP-only key (cross-ref F-CRITICAL-001) · stats clock-skew evicts entire timeseries · stats upstream_provider double-fire · incidents alert_id collision on same-second fires · admin SessionInfo leaks IP+UA · audit search per-call O(ring) scan |
| F-HIGH-mutation-api.md | 7 items: `validate_rule_body` is stub (accepts "this is not a rule") · `validate_pool` no SSRF cap (operator can route to 169.254.169.254) · blacklist `bulk_insert` no cap + N mutex locks · simulator shares live mask + no body cap · rollback skips compliance clamp · mtls_mode PUT requires restart · ca-bundle no PEM size cap |
| F-HIGH-gitops.md | 4 items: `git clone` synchronous no timeout · `break_glass_edit` accepts X-Actor verbatim into git branch name + markdown PR body · poll driver `git show` operator-controlled `path` · GitOps signed-commit verification complete but unused |
| F-HIGH-slo-metrics.md | 7 items: `fired_history` Vec never trimmed · `BUCKETS_MS` only 1 bucket ≤1ms (p99 estimate at boundary ±25%) · `/healthz/live` returns 503 on draining → k8s SIGKILLs mid-drain · route_activity over-counts after idle gaps · per-tier rate-limit + per-tier detector pipeline "descriptive metadata only" (NOT enforced) · skipped_feature_off receivers never recorded · DashboardServices bundle not whole-struct ArcSwap |
| F-HIGH-auth-admin.md | 6 items: `password::generate_salt` from `blake3(now:counter)` NOT OsRng (defeats argon2 offline-attack resistance) · TOTP docstring says SHA-1 code uses SHA-256 (Google Authenticator lockout) · `session::base64url_encode` writes HEX not base64 (cookie 2x bigger, name lies) · password.rs Argon2 params not pinned · syslog sink drops audit data on slow remote, no metric · interop secret stored as plain String not zeroized |

### CONTRACT GAPS

| ID | Title |
|---|---|
| C-01 | Capabilities `open_redirect` policy drift (cross-ref F-CRITICAL-010) |
| C-02 | `reset_state` callbacks cover 4 of 6 enumerated classes (BehavioralAnalyzer not wired, acknowledged in code comment) |
| C-03 | `audit_log_preserved: true` hardcoded in reset_state response (not derived from any actual check) |
| C-04 | "8 SIEM sink formats" README claim — 8 formatters exist, only 2 actually transmit (jsonl + syslog). Splunk HEC, Kafka, CEF, LEEF, ECS, OCSF are stubs / format-only |

---

## Round-1 dashboard mandate compliance

| Mandate | Status | Top blocker |
|---|---|---|
| Real-time monitor ≤5s | ⚠️ Works at low load; FAILS under burst | F-CRITICAL-011 (Lagged exits drain) |
| Audit search by IP | ✅ | — |
| Audit search by Rule-ID | ✅ | — |
| Audit search by Request-ID | ✅ | — |
| **Audit search by time** | ❌ | F-CRITICAL-004 (no ts_from/ts_to field) |
| Audit search ≤30s | ⚠️ Works for events within ~2 min ring window | Ring cap 10k (F-HIGH-read-api) |
| Health/Status: uptime | ❌ | F-CRITICAL-003 |
| Health/Status: mode | ❌ | F-CRITICAL-003 |
| Health/Status: active rule count | ❌ | F-CRITICAL-003 |
| Hot-reload ≤10s rule | ❌ | F-CRITICAL-001 (no rebuild) |
| Hot-reload ≤10s detector mask | ✅ | ArcSwap, works |
| Hot-reload ≤10s upstream/routes (dashboard PUT) | ✅ | Works via dashboard; FILE-source still broken (F-CONTRACT-003 from proxy audit) |
| Hot-reload ≤10s mTLS mode | ❌ | F-HIGH-mutation-api (requires restart) |
| "Tính hiệu lực" on rules | ❌ | F-CRITICAL-001 |
| "Tính hiệu lực" on compliance modes | ❌ | F-CRITICAL-002 |
| "Tính hiệu lực" on mTLS toggle | ❌ | F-HIGH-mutation-api + F-CRITICAL-009 (verify_client_cert dead code) |
| §9 no mock data | ❌ | F-CRITICAL-019 (analytics + tracking) |

---

## Verdict

**The aegis-control crate fails Round-1 dashboard pass/fail mandates
in at least 4 places** (F-CRITICAL-001, -002, -003, -004) — each one
alone is enough to mark "không đạt" per the rules text. The dashboard
is well-architected (clean trait split, ArcSwap pattern, audit-mutated
flow) but multiple critical layers are either dead code or wired in a
way that doesn't actually affect data-plane behavior.

The **§9 "loại ngay" disqualification risk** is moderate: while no
hardcoded test-fixture patterns were found (unlike F-CRITICAL-012 in
the security audit), the COMBINATION of:
- analytics returning hardcoded `0.0`
- tracking returning `placeholder()` constants
- `DEFAULT_VIPTALK_BOT_TOKEN = "xxx-dev-uat-bot-token-xxx"`

...could be interpreted by judges as "mock data shipped to evaluation".

The **Dashboard UI/UX 10/120 rubric** is mostly recoverable — the
SPA itself is fine; the issues are server-side data plumbing.

### Top 5 smallest CRITICALs to fix first

1. **F-CRITICAL-017** (hardcoded VipTalk token) — 4 LoC, removes info-disclosure risk
2. **F-CRITICAL-004** (audit search time-range) — ~30 LoC, add 2 fields to `AuditFilter` + `matches` predicate
3. **F-CRITICAL-003** (`/healthz` fields) — ~40 LoC, extend `HealthResponse`
4. **F-CRITICAL-010** (open_redirect capability) — 1 LoC, add to rules_engine policy list
5. **F-CRITICAL-011** (Lagged exits drain) — 5 LoC, replace `while let Ok` with `match` (matches existing pattern in jsonl.rs:381-388)

### Biggest design-work fixes

- **F-CRITICAL-001** (rule CRUD live rebuild) — touches RuleStore, dashboard_services, aegis-bin boot, data plane. ~150 LoC.
- **F-CRITICAL-002** (compliance modes wire-in) — touches every TLS construction site + populates `COMPLIANCE_PINNED`. ~100 LoC.
- **F-CRITICAL-005..009** (dead-code wire-or-delete) — 5 modules, each is a "wire it (~200 LoC) or delete + update README". Design call.
- **F-CRITICAL-013** (audit chain on disk) — re-architect jsonl sink to persist `ChainEntry`, link cross-day via prev-file head. ~250 LoC.

---

## Files

```
QA-RUN-SUMMARY.md                                                       (this file)
F-CRITICAL-001-rule-crud-doesnt-rebuild-ruleset.md
F-CRITICAL-002-compliance-pinned-empty-tls-ignores-cfg.md
F-CRITICAL-003-healthz-missing-uptime-mode-rulecount.md
F-CRITICAL-004-audit-search-missing-time-range.md
F-CRITICAL-005-gitops-sync-dead-code.md
F-CRITICAL-006-audit-witness-dead-code.md
F-CRITICAL-007-residency-dead-code.md
F-CRITICAL-008-tracing-init-dead-code.md
F-CRITICAL-009-mtls-verify-client-cert-dead-code.md
F-CRITICAL-010-capabilities-omits-open-redirect-policy.md
F-CRITICAL-011-bus-drain-exits-on-lagged.md
F-CRITICAL-012-interop-audit-sync-fs-io-on-tokio-worker.md
F-CRITICAL-013-jsonl-no-fsync-chain-on-disk-broken.md
F-CRITICAL-014-rollback-dispatcher-13-of-25-classes-missing.md
F-CRITICAL-015-ssrf-via-alert-receiver-bot-token.md
F-CRITICAL-016-sli-ring-buffer-on-of-n-under-mutex.md
F-CRITICAL-017-viptalk-bot-token-hardcoded-default.md
F-CRITICAL-018-mock-data-violations-analytics-tracking.md
F-HIGH-headers-contract.md           (3 items)
F-HIGH-read-api.md                   (8 items)
F-HIGH-mutation-api.md               (7 items)
F-HIGH-gitops.md                     (4 items)
F-HIGH-slo-metrics.md                (7 items)
F-HIGH-auth-admin.md                 (6 items)
F-CONTRACT-GAPS.md                   (4 semantic gaps)
F-MEDIUM-ALL.md                      (~48 items)
```
