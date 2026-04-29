# Aegis-Gate Implementation Progress

> **How to maintain this file.** It is a *living snapshot*, not a
> changelog. The Completed Tasks Log at the bottom is the only
> append-only section. Every other section is overwritten in place.
> See [`plans/plan.md`](./plans/plan.md#03-progress-file-protocol-strict)
> §0.3 for the protocol; the rules in short:
>
> - **Last Completed** holds the *current* task in full detail.
> - **Recent History** holds the previous 5 tasks in 1–2 lines each.
> - **Next Task** holds the immediate next item.
> - All other sections (tracks, carry-overs, future phases) are
>   durable summaries — update only when the underlying state
>   changes, not on every task.
> - Append a row to **Completed Tasks Log** when a task closes.

---

## Status (snapshot)

- **As of:** 2026-04-29
- **Workspace tests:** 1,964 passing
- **Clippy:** clean (`cargo clippy --workspace -- -D warnings`)
- **Latest activity:** doc audit + Status banners on every feature
  doc (this turn).

---

## Last Completed

**Task:** Doc-by-doc implementation audit + lean Implement-Progress
rewrite.

**Outcome.** Every doc under `docs/` now carries a one-line
`> **Status:** ...` banner classifying it as Implemented / Partial /
Designed only / Deferred / Intake template; the master matrix lives
at [`plans/plan.md` § 1](./plans/plan.md#1-doc-by-doc-implementation-status)
with module paths so future audits start from evidence. Eleven
concrete Phase B candidates seeded into [§ 1.9](./plans/plan.md#19-phase-b-candidate-seeds-suggested).
This file was rewritten to a lean template that won't bloat as
future tasks land — the protocol is captured at the top so the
next author can follow it.

**Headline gaps surfaced (Phase B candidates):**
1. Real Redis state backend (currently `RedisBackendStub`).
2. Cross-node leader lease + ACME/GitOps/witness gating.
3. Service-discovery adapters (Consul / etcd / k8s).
4. GeoIP filter (no MaxMind reader anywhere).
5. STIX/TAXII fetch loop into `ThreatIntelStore`.
6. Concrete `IcapClient` TCP implementation.
7. Vault / AWS SM / GCP SM / Azure KV / HSM secret resolvers.
8. `waf snapshot` / `waf restore` CLI + `.tar.zst` writer.
9. HTTP/3 (no quinn / h3 today).
10. Concrete git poll-and-pull driver implementing `GitClient`.
11. Benchmark mode (`X-Aegis-*` headers + dashboard panels) —
    [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) is the
    open track.

**Files changed.**
- 58 doc files in `docs/` — banner inserted above any pre-existing
  intro blockquote (zero content lost).
- `plans/plan.md` — new § 1 implementation matrix and § 1.9 Phase B
  candidate seeds.
- `Implement-Progress.md` — full rewrite to the lean template.

**Verification.** `cargo check --workspace` clean; spot-checked
`rule-engine.md`, `ha-clustering.md`, `per-route-quotas.md` to
confirm banners added without removing existing topic blockquotes.

---

## Recent History

Last five tasks, compressed. For full detail see git history.

| Date | Task | Outcome |
|---|---|---|
| 2026-04-29 | Tests folder consolidation + new auth/TLS/rate-limit smoke coverage | `tests/README.md` is now a single playbook; new `tests/api/{auth,tls}.sh` + `tests/load/rate-limit.js` close P1/P4/rate-limit gaps. |
| 2026-04-28 | Documentation restructure — flat docs/ → 8-category taxonomy | `operator/`, `architecture/`, `data-plane/`, `security/{,detectors/}`, `control-plane/{,enterprise/}`, `observability/`, `operations/`, `future/`. 220 internal + 60+ external + 41 in-code refs rewritten. |
| 2026-04-28 | F-T6 / F-T7 / F-T8 / F-T9 / F-T10 — post-k6 polish bundle | host-vs-laptop perf docs, audit + cold-tier k6 coverage, per-stage latency histogram (`request_duration.rs`), Pebble container, AcmeManager wired into `run()`. 1,964 tests pass. |
| 2026-04-27 | Dashboard track close-out (D-M1..D-M6) | Enterprise SPA bundled into the binary; +275 tests; clippy clean. Re-design track now opens as the next dashboard phase. |
| 2026-04-27 | Security-toggle plan close-out (P1..P8) | AuditedMutate pipeline, detector mask + per-tier override, TLS hardening, ACME, risk strikes, LoadMode, verbosity gating. All 8 admin-API surfaces shipped. |

---

## Next Task

> Pick **one** of the open tracks below or take the highest-ranked
> Phase B candidate. No track is gated on another today.

**Open tracks (no clear owner yet):**

1. **Dashboard redesign — M0 foundations.**
   Plan: [`plans/dashboard-redesign/milestone-0-foundations.md`](./plans/dashboard-redesign/milestone-0-foundations.md).
   Highest-impact next move because it shapes every subsequent
   page redesign.

2. **Benchmark mode — B-T1.**
   Plan: [`plans/benchmark-mode.md`](./plans/benchmark-mode.md).
   Spec: [`docs/operator/benchmark-mode.md`](./docs/operator/benchmark-mode.md).
   B-T1..B-T3 (data plane) are unblocked; B-T4.5/T4.6 (dashboard
   panels) are gated on the dashboard redesign.

3. **Phase B intake.**
   Open [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   with one of the eleven candidate seeds in
   [`plans/plan.md` § 1.9](./plans/plan.md#19-phase-b-candidate-seeds-suggested).
   Score it (Impact / Reach / Cost / Confidence) and either accept
   or park.

**No active task in flight.** When you start one, replace this
section with the standard "Next Task" block from [`plans/plan.md`
§ 0.3](./plans/plan.md#03-progress-file-protocol-strict).

---

## Tracks in flight

| Track | Plan | State |
|---|---|---|
| Security toggles (P1..P8) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | **closed** — all 8 phases + F-T1..F-T10 follow-up shipped |
| Dashboard track (D-M1..D-M6) | [`plans/dashboard-enterprise/`](./plans/dashboard-enterprise/) | **closed** — SPA bundled, all 6 milestones shipped |
| Dashboard redesign (M0..M10) | [`plans/dashboard-redesign/`](./plans/dashboard-redesign/) | **open**, M0 unblocked |
| Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) | **open**, B-T1..B-T3 unblocked |
| Phase B advanced features | [`docs/future/advanced-features.md`](./docs/future/advanced-features.md) | **open intake**, 11 candidate seeds in `plans/plan.md` § 1.9 |

---

## Carry-overs / known limitations

Durable list of things that work but aren't fully shipped. Update
when the underlying state changes, not on every task.

- **HA clustering:** `aegis-bin` always wires `InMemoryBackend`.
  `RedisBackendStub` carries config + Lua scripts only — no real
  Redis I/O. No cross-node leader lease, no rehydrate phase.
  Single-node deployments are unaffected. See
  [`docs/operations/ha-clustering.md`](./docs/operations/ha-clustering.md).
- **Service discovery:** `file` watcher + churn safety in
  `aegis-proxy/src/sd/`; Consul / etcd / k8s adapters not
  implemented despite being mentioned in the module doc.
- **Secrets resolvers:** `env` + `file` work; Vault / AWS SM /
  GCP SM / Azure KV / HSM return `NotImplemented` stubs.
- **Threat-intel feeds:** in-memory `ThreatIntelStore` exists,
  no STIX/TAXII fetcher loop — feeds must be loaded externally.
- **Content scanning:** archive-bomb guard real, ICAP client is a
  trait + types stub (no concrete TCP client).
- **GitOps:** `GitClient` trait + signature verify + dry-run
  validate present; no concrete git poll-and-pull driver wired.
- **HTTP/3:** not implemented (no `quinn` / `h3` dependency).
- **GeoIP:** not implemented anywhere.
- **DR:** `SnapshotMeta` shape exists; `waf snapshot` / `waf
  restore` CLI + `.tar.zst` writer not wired.
- **Zero-downtime ops:** `supervisor.rs` + `hotbin.rs` + drain
  exist; no live binary-handover via fd-passing — restart is via
  supervised re-exec only.
- **Per-member pool health:** hardcoded to 0 in
  `pool_snapshot_provider` until the cluster runtime ships.
- **`/dashboard/sse`:** currently returns one event then closes
  (M1-era stub). T2.8 wired the pill; full streaming body needs
  AuditBus subscription wiring.
- **Production packaging:** no Dockerfile, no Helm chart, no
  GitHub Actions CI — `deploy/` ships dev/test compose only.

When one of these graduates to "shipped", remove the line and add
the matching row to the Completed Tasks Log.

---

## Future phases

Two big-shape phases queued, each with a planning track in `plans/`.
Phase B does not start until the dashboard redesign is at least
mid-flight.

1. **Dashboard redesign** —
   [`plans/dashboard-redesign/`](./plans/dashboard-redesign/).
   Eleven milestones (M0..M10), Claude Design–driven workflow
   documented in `workflow.md`. Implementation notes land under
   [`docs/control-plane/enterprise/`](./docs/control-plane/enterprise/)
   as the milestones close.
2. **Phase B advanced features** —
   [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   is the open intake; eleven concrete candidates seeded in
   [`plans/plan.md` § 1.9](./plans/plan.md#19-phase-b-candidate-seeds-suggested).
   Each accepted candidate moves out of `future/` into the
   appropriate category folder + opens its own track in `plans/`.

---

## Verification (last full run)

- `cargo test --workspace` → **1,964 passed** across 10 binary /
  lib / integration test targets, ~10 s wall.
- `cargo clippy --workspace -- -D warnings` → clean.
- `cargo check --workspace` → clean.

---

## Completed Tasks Log

Append-only. One row per closed task.

| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security, aegis-bin | 2026-04-22 |
| M1-T1.2 Config loader (figment + validation) | aegis-core | 2026-04-22 |
| M1-T1.3 Hot reload (notify + ArcSwap) | aegis-proxy | 2026-04-22 |
| M1-T1.4 Dual listener model | aegis-proxy | 2026-04-22 |
| M1-T2.1 Host matcher | aegis-proxy | 2026-04-22 |
| M1-T2.2 Path trie | aegis-proxy | 2026-04-22 |
| M1-T2.3 RouteTable::build + resolve | aegis-proxy | 2026-04-22 |
| M1-T2.4 Upstream Pool + LB strategies | aegis-proxy | 2026-04-22 |
| M1-T2.5 Active health checks | aegis-proxy | 2026-04-22 |
| M1-T2.6 Circuit breaker | aegis-proxy | 2026-04-22 |
| M1-T2.7 Wire routing + upstream into proxy.rs | aegis-proxy | 2026-04-22 |
| M1-T3.1 DynamicResolver + CertStore | aegis-proxy | 2026-04-24 |
| M1-T3.2 HTTP/2 on both sides | aegis-proxy | 2026-04-24 |
| M1-T3.3 WebSocket upgrade passthrough | aegis-proxy | 2026-04-24 |
| M1-T3.4 gRPC trailer-preserving forward | aegis-proxy | 2026-04-24 |
| M1-T3.5 mTLS to upstream | aegis-proxy | 2026-04-24 |
| M1-T3.6 ACME (feature acme) | aegis-proxy | 2026-04-24 |
| M1-T3.7 OCSP stapling | aegis-proxy | 2026-04-24 |
| M1-T4.1 Per-route quotas | aegis-proxy, aegis-core | 2026-04-24 |
| M1-T4.2 Transformations + CORS | aegis-proxy | 2026-04-24 |
| M1-T4.3 Canary split + header/cookie steering | aegis-proxy | 2026-04-24 |
| M1-T4.4 Retries with budget | aegis-proxy | 2026-04-24 |
| M1-T4.5 Shadow mirroring | aegis-proxy | 2026-04-24 |
| M1-T4.6 Session affinity | aegis-proxy | 2026-04-24 |
| M1-T4.7 Worker supervisor + graceful drain | aegis-proxy | 2026-04-24 |
| M1-T4.8 Hot binary reload (SIGUSR2) | aegis-proxy | 2026-04-24 |
| M1-T4.9 Tier-aware smart cache | aegis-proxy | 2026-04-24 |
| M1-T5.1 InMemoryBackend polish | aegis-proxy | 2026-04-24 |
| M1-T5.2 RedisBackend stub (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver (env + file) | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore types | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery (file watcher) | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership (in-process) | aegis-proxy | 2026-04-24 |
| M2-T1.1 Rule AST + parser | aegis-security | 2026-04-24 |
| M2-T1.2 Linter | aegis-security | 2026-04-24 |
| M2-T1.3 Evaluator | aegis-security | 2026-04-24 |
| M2-T1.4 RuleSet hot reload | aegis-security | 2026-04-24 |
| M2-T1.5 Tier classifier | aegis-security | 2026-04-24 |
| M2-T2.1 Sliding window rate limit | aegis-security | 2026-04-26 |
| M2-T2.2 Token bucket | aegis-security | 2026-04-26 |
| M2-T2.3 DDoS per-IP burst + cluster spike | aegis-security | 2026-04-26 |
| M2-T2.4 OWASP detectors (SQLi, XSS, PathTraversal, SSRF, HeaderInjection, BodyAbuse, Recon) | aegis-security | 2026-04-26 |
| M2-T3.1 JA4/JA3 parser | aegis-security | 2026-04-26 |
| M2-T3.2 HTTP/2 fingerprint | aegis-security | 2026-04-26 |
| M2-T3.3 Composite device id | aegis-security | 2026-04-26 |
| M2-T3.4 RiskEngine (scoring + decay) | aegis-security | 2026-04-26 |
| M2-T3.5 Challenge ladder | aegis-security | 2026-04-26 |
| M2-T3.6 Challenge tokens (HMAC + nonce) | aegis-security | 2026-04-26 |
| M2-T3.7 CAPTCHA providers (Turnstile, hCaptcha, reCAPTCHA) | aegis-security | 2026-04-26 |
| M2-T3.8 Behavioral analyzer | aegis-security | 2026-04-26 |
| M2-T3.9 Transaction velocity | aegis-security | 2026-04-26 |
| M2-T4.1 CIDR lists + XFF walker | aegis-security | 2026-04-26 |
| M2-T4.2 MaxMind ASN classifier | aegis-security | 2026-04-26 |
| M2-T4.3 Bot classifier | aegis-security | 2026-04-26 |
| M2-T4.4 Threat intel feeds (in-memory store) | aegis-security | 2026-04-26 |
| M2-T5.1 Streaming response filter | aegis-security | 2026-04-26 |
| M2-T5.2 DLP patterns + actions | aegis-security | 2026-04-26 |
| M2-T5.3 FPE (AES-FF1) | aegis-security | 2026-04-26 |
| M2-T5.4 OpenAPI schema enforcement | aegis-security | 2026-04-26 |
| M2-T5.5 ForwardAuth | aegis-security | 2026-04-26 |
| M2-T5.6 JWT validation | aegis-security | 2026-04-26 |
| M2-T5.7 ICAP antivirus (trait + types stub) | aegis-security | 2026-04-26 |
| M2-T5.8 Magic-byte + archive-bomb | aegis-security | 2026-04-26 |
| M2-T5.9 GraphQL guard | aegis-security | 2026-04-26 |
| M2-T5.10 HMAC request signing | aegis-security | 2026-04-26 |
| M2-T5.11 API-key management | aegis-security | 2026-04-26 |
| M2-T5.12 Basic Auth | aegis-security | 2026-04-26 |
| M2-T5.14 OPA callout | aegis-security | 2026-04-26 |
| M2-DoD Red-team suite + benign corpus + fixture expansion | aegis-security | 2026-04-26 |
| M3-T1.1 MetricsRegistry init | aegis-control | 2026-04-26 |
| M3-T1.2 Prometheus exporter | aegis-control | 2026-04-26 |
| M3-T1.3 Health endpoints (live/ready/startup) | aegis-control | 2026-04-26 |
| M3-T1.4 Dashboard shell + SSE stub | aegis-control | 2026-04-26 |
| M3-T1.4b Dashboard overview page | aegis-control | 2026-04-26 |
| M3-T1.5 GET /api/config | aegis-control | 2026-04-26 |
| M3-T2.2 Tracing init + W3C Trace Context | aegis-control | 2026-04-26 |
| M3-T2.4 Access log writer (combined/JSON/template) | aegis-control | 2026-04-26 |
| M3-T3.1 Audit chain writer (SHA-256 hash chain) | aegis-control | 2026-04-26 |
| M3-T3.2 Audit verify (chain walk + recompute) | aegis-control | 2026-04-26 |
| M3-T3.3 Audit sinks (JSONL, syslog, CEF, LEEF, OCSF, Splunk HEC, ECS, Kafka) | aegis-control | 2026-04-26 |
| M3-T3.4 Admin change log | aegis-control | 2026-04-26 |
| M3-T3.5 Witness export (blake3 signing) | aegis-control | 2026-04-26 |
| M3-T3.6 State snapshot tracker | aegis-control | 2026-04-26 |
| M3-T4.1 Password verify + PHC (argon2id) | aegis-control | 2026-04-26 |
| M3-T4.2 HMAC session cookie + SessionRecord | aegis-control | 2026-04-26 |
| M3-T4.3 CSRF double-submit | aegis-control | 2026-04-26 |
| M3-T4.4 Login rate limit + lockout | aegis-control | 2026-04-26 |
| M3-T4.5 IP allowlist (in mtls module) | aegis-control | 2026-04-26 |
| M3-T4.6 TOTP (RFC 6238) + recovery codes | aegis-control | 2026-04-26 |
| M3-T4.7 Admin mTLS | aegis-control | 2026-04-26 |
| M3-T5.1 Compliance profiles (FIPS, PCI, SOC2, GDPR, HIPAA) + conflict detection | aegis-control | 2026-04-26 |
| M3-T5.2 Residency / retention sweep / right-to-erasure | aegis-control | 2026-04-26 |
| M3-T5.3 GitOps loader (poll, sig verify, dry-run, break-glass) | aegis-control | 2026-04-27 |
| M3-T5.5 SLO / SLI + multi-burn alerts (5 SLIs, 3 windows, 5 receivers) | aegis-control | 2026-04-27 |
| M3-DoD Integration tests (login flow, audit verify, SIEM ≥3 sinks, FIPS, SLO) | aegis-control | 2026-04-27 |
| Cross-crate wiring (audit verify, admin set-password, admin enroll-totp, validate + compliance) | aegis-bin | 2026-04-27 |
| README.md full rewrite | project-wide | 2026-04-27 |
| deploy/GUIDE.md deployment guide | project-wide | 2026-04-27 |
| docs/operator/usage.md operator runbook | project-wide | 2026-04-27 |
| Data-plane detector wiring (7 OWASP detectors run on every request) | aegis-proxy | 2026-04-27 |
| Admin listener wiring (dashboard, SSE stub, health, metrics, config API on :9443) | aegis-proxy | 2026-04-27 |
| config/README.md configuration guide | project-wide | 2026-04-27 |
| **D-M1 milestone** (SPA shell + assets + router + chrome + security headers + legacy carve-out + dev hot-reload + i18n) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M2 milestone** (6 endpoints + Overview page wired end-to-end) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M3 milestone** (4 operator pages + 11 endpoints) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M4 milestone** (5 config-management pages + 11 endpoints + 5 stores) | aegis-control, aegis-proxy | 2026-04-28 |
| **D-M5 milestone** (tracking page — 6 endpoints + snapshot aggregate) | aegis-control, aegis-proxy | 2026-04-28 |
| **D-M6 milestone** (a11y/contrast/headers/budget tests + legacy removal + docs) | aegis-control, aegis-proxy, docs | 2026-04-28 |
| **Dashboard track complete** (D-M1..D-M6, +275 tests) | project-wide | 2026-04-28 |
| **P1** AuditedMutate pipeline (CSRF + audit chain + ArcSwap) | aegis-control | 2026-04-28 |
| **P2** Class toggles + hot-path bitfield mask + Settings UI | aegis-security, aegis-control | 2026-04-28 |
| **P3** Per-detector toggles + per-tier override (SharedDetectorMask) | aegis-security, aegis-control | 2026-04-28 |
| **P4** TLS hardening (TLS 1.2+ minimum, security headers, redirect) | aegis-proxy | 2026-04-28 |
| **P5** ACME — InstantAcmeProvider + AcmeManager + scheduler | aegis-proxy | 2026-04-28 |
| **P6** Risk-scoring upgrades (strikes + trust recovery + reset) | aegis-security, aegis-control | 2026-04-28 |
| **P7** LoadMode + bounded caches + degraded logging | aegis-core, aegis-security, aegis-proxy, aegis-control | 2026-04-28 |
| **P8** Verbosity gating + cold-tier surface | aegis-core, aegis-control | 2026-04-28 |
| **F-T1** Wire `POST /admin/login` + `/admin/logout` end-to-end | aegis-control | 2026-04-28 |
| **F-T2** Wire per-IP rate limiting | aegis-security, aegis-proxy | 2026-04-28 |
| **F-T3** No-op (was test contamination, not a real bug) | — | 2026-04-28 |
| **F-T4 + F-T5** k6 contract tests for security toggles + risk strikes | tests/load | 2026-04-28 |
| **F-T6** host-vs-laptop perf calibration docs | tests/load/README-perf.md | 2026-04-28 |
| **F-T7** Pebble container + ACME smoke | deploy, tests/api/acme.sh | 2026-04-28 |
| **F-T8** AcmeManager + InstantAcmeProvider wired into `run()` | aegis-proxy | 2026-04-28 |
| **F-T9** k6 audit-since + cold-tier inventory contracts | tests/load | 2026-04-28 |
| **F-T10** RequestStageHistogram (per-stage WAF latency) | aegis-control, aegis-proxy | 2026-04-28 |
| Documentation restructure — flat docs/ → 8-category taxonomy | docs/, plans/, crates/ | 2026-04-28 |
| Tests folder consolidation + new auth/TLS/rate-limit smoke coverage | tests/ | 2026-04-29 |
| Doc-by-doc implementation audit + Status banners + Phase B candidate seeds | docs/, plans/plan.md | 2026-04-29 |
| Implement-Progress.md rewritten as lean future-proof template | Implement-Progress.md | 2026-04-29 |
