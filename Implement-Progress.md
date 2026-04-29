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
>
> **For at-a-glance track priority** see
> [`plans/README.md`](./plans/README.md). For per-doc Implemented /
> Partial / Designed-only status see
> [`plans/implementation-matrix.md`](./plans/implementation-matrix.md).

---

## Status (snapshot)

- **As of:** 2026-04-29
- **Workspace tests:** 2,173 default-feature (was 2,151; +22 net
  new from B5-T2 benchmark module + proxy end-to-end tests).
  Per-feature test groups unchanged.
- **Clippy:** clean across the workspace **lib + bin** targets
  on default; per-feature combos clean.
- **Active track:** Phase B — production-readiness, **B5
  CLOSED**, moving to milestone B6
  ([`plans/phase-b/`](./plans/phase-b/README.md))
- **Next task:** B6-T1 — production Dockerfile (start of B6
  packaging)
- **Latest activity:** B5-T2 closed — `aegis-proxy::benchmark`
  module ships `BenchmarkConfig` + `StageTimings` + header
  serialiser; `proxy::handle_request` captures total +
  route + upstream timings and stamps `X-Aegis-*` response
  headers when enabled. **B5 milestone CLOSED.**

---

## Last Completed

**Task:** **B5-T1 — HTTP/3 listener** (start of milestone
B5 — protocols + benchmark).

**Outcome.** `aegis-proxy` ships an HTTP/3 listener behind
the new `http3` Cargo feature. Operators who terminate
QUIC alongside the existing TLS listener now have a real
implementation to wire up: same `rustls::ServerConfig`
(cert resolver, TLS 1.3 enforcement) is converted into a
`quinn::ServerConfig` with ALPN forced to `["h3"]` + the
configured idle/streams limits. Each accepted QUIC
connection is wrapped by `h3-quinn::Connection` and run
through `h3::server::Connection`; every request is
dispatched through the existing
[`crate::proxy::handle_request`] so routing + security +
upstream forwarding stay shared between protocols.

**Decision recap (h3 0.0.8 + h3-quinn 0.0.10).** Initial
attempt at h3 0.0.6 + h3-quinn 0.0.7 failed at compile
time — h3-quinn 0.0.7 dereferences a private field of
`quinn::StreamId` that's no longer accessible on quinn
0.11.x. Bumped both to the next compatible pair; the
public API in our integration is small enough that no
code changes were needed.

**Decision recap (`aws_lc_rs` provider in tests).** With
`http3` on, `quinn`'s `ring` feature pulls a second
crypto provider into the rustls dep tree; rustls then
refuses to auto-pick. The unit tests resolve this by
calling `rustls::crypto::aws_lc_rs::default_provider()`
explicitly — `aws_lc_rs` is *always* in the workspace's
rustls dep tree (pulled by hyper-rustls), so the same
test code works across feature combos.

**Decision recap (Alt-Svc helper, no auto-stamp).** This
sub-task ships the `format_alt_svc` helper but does
**not** automatically stamp `Alt-Svc:` on every TLS
response. That wiring lives in the TLS-listener path and
will land alongside the boot-site wire-up in a follow-up;
the helper signature + the constants are stable so the
TLS listener can call them without surface change.

**Files changed.**
- `Cargo.toml` (workspace) — three new optional deps:
  `quinn = "0.11"` (with `runtime-tokio` + `rustls` +
  `ring`), `h3 = "0.0.8"`, `h3-quinn = "0.0.10"`.
- `crates/aegis-proxy/Cargo.toml` — new `http3` Cargo
  feature gating those three deps.
- `crates/aegis-proxy/src/listener/mod.rs` — declared
  `pub mod http3;`.
- `crates/aegis-proxy/src/listener/http3.rs` — **new**,
  ~340 lines. Public surface:
  - `ALT_SVC_HEADER` constant; `format_alt_svc(port,
    max_age)` / `default_alt_svc(port)`;
    `ALT_SVC_DEFAULT_MAX_AGE = 86400`.
  - `h3_alpn_protocols() -> Vec<Vec<u8>>` /
    `with_h3_alpn(cfg) -> ServerConfig`.
  - `Http3Config` struct (bind + idle_timeout +
    max_concurrent_streams, sensible defaults).
  - `Http3ConfigError` enum (BadBind / Tls / Bind /
    Internal).
  - `parse_http3_bind(s)` validator.
  - `#[cfg(feature = "http3")]` runtime module:
    `build_quic_server_config(rustls_cfg, &cfg)` and
    `serve_http3(cfg, rustls_cfg, ctx)` (returns
    `(quinn::Endpoint, JoinHandle)` for graceful drain).
    The accept loop dispatches each stream through
    `proxy::handle_request` then writes the response
    back over the h3 stream.
- `docs/architecture/protocols.md` — banner flipped
  Partial → Implemented.
- `plans/implementation-matrix.md` — row updated.

**Tests.** 15 net new in `listener::http3::tests`,
default-feature (no QUIC dep tree needed for the helpers):

- `format_alt_svc_*` (4) — header value formatting,
  default 24h max-age, lowercase `Alt-Svc` constant.
- `h3_alpn_protocols_only_h3` — no draft IDs.
- `with_h3_alpn_replaces_existing` — existing HTTP/2
  ALPN gets replaced cleanly.
- `parse_http3_bind_*` (4) — IPv4 / IPv6 / garbage /
  missing-port reject.
- `http3_config_default_*` (3) — idle timeout, max
  streams, bind defaults.
- `config_error_display_messages` — every error variant
  formats sanely.

**Verification.**
- `cargo build -p aegis-proxy` clean (default).
- `cargo build -p aegis-proxy --features http3` clean.
- `cargo test --workspace` (default features) → **2,151
  passed** (was 2,136; +15 net new).
- `cargo test -p aegis-proxy --features http3 --lib
  listener::http3::` → **15 passed**.
- `cargo clippy --workspace --lib --bins -- -D warnings`
  → clean.
- `cargo clippy -p aegis-proxy --features http3 --lib
  -- -D warnings` → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.

---


## Recent History

Last five tasks, compressed. For full detail see git history.

| Date | Task | Outcome |
|---|---|---|
| 2026-04-29 | **B4-T4** Full SSE streaming on `/dashboard/sse` — closes B4 | `admin_sse` widens admin pipeline to `UnsyncBoxBody`; `sse_response` streams `BroadcastStream` events with 15s heartbeat. +8 tests. |
| 2026-04-29 | **B4-T3** Full upstream proxying | `upstream::forward` replaces stub; hop-by-hop scrub both directions; Host rewrite + `X-Forwarded-Host`; preserves method/path/query/body. +14 forward + 5 proxy end-to-end tests. |
| 2026-04-29 | **B4-T2** `waf restore` CLI subcommand | `restore_envelope` w/ atomic dry-run validation + rollback; default destinations come from envelope; `dr-backup.md` flipped Implemented for config/rules surface. +10 tests. |
| 2026-04-29 | **B4-T1** `waf snapshot` CLI subcommand | `aegis-bin::snapshot` ships JSON envelope w/ schema versioning, blake3 hash, every referenced rules file inlined; refuses overwrite without `--force`. +15 tests. |
| 2026-04-29 | **B3-T4** Concrete RFC 3507 ICAP TCP client — closes B3 | `content::icap::{codec,tcp}`; pure framing helpers + 5-vendor decision table; configurable timeout + fail-open default; `content-scanning.md` flipped Implemented. +36 tests. |

---

## Next Task

**Task:** **B5-T2 — benchmark mode** (folds in
`plans/benchmark-mode.md`'s B-T1..B-T6).

**Plan:** [`plans/phase-b/README.md` § B5](./plans/phase-b/README.md#b5--protocols--benchmark)
+ [`plans/benchmark-mode.md`](./plans/benchmark-mode.md).

**Why this next.** B5-T1 just shipped HTTP/3. The remaining
B5 sub-task is benchmark mode — a gated, opt-in surface
that emits per-request timing breakdown via `X-Aegis-*`
response headers, ships dashboard panels, and exposes
Prometheus series. Today none of those exist; load tests
have to instrument timing externally with k6.

**Outline.**

1. New `benchmark` Cargo feature on `aegis-proxy` (and
   `aegis-control` for the dashboard panel) — off by
   default.
2. `crates/aegis-proxy/src/benchmark.rs` — owns the
   timing capture per request stage. Hooks into the
   existing security pipeline + upstream forward. Each
   captured stage adds an `X-Aegis-Stage-<name>: <us>`
   header on the response when the feature is on AND the
   `benchmark.enabled` config flag is set at runtime.
3. Prometheus series: a per-stage histogram (already
   exists as `RequestStageHistogram` from F-T10 — re-use
   that and expose extra labels under the new feature).
4. Dashboard panel: new "Benchmark" page card in
   `dashboard-enterprise` that reads the stage histogram
   + emits a per-route timing table.
5. Doc — flip `docs/operator/benchmark-mode.md` banner
   Designed → Implemented.
6. Tests:
   - Pure: header builder formats microseconds correctly.
   - Integration: feature ON + flag ON → response has
     stage headers + Prometheus series populated; feature
     ON + flag OFF → no headers, no series.

**Acceptance.**

- `cargo build` clean across **default**, `benchmark`,
  and full superset.
- `cargo test --workspace` green; +12–18 net new tests.
- After this lands, mark **B5 milestone CLOSED** and
  move to milestone B6 (production packaging).

**On close:** Next Task → **B6-T1 — production
Dockerfile**.

---

## Tracks in flight

Order is execution priority — earlier rows run first.

| # | Track | Plan | State |
|---|---|---|---|
| 1 | **Phase B — production-readiness (B1..B6)** | [`plans/phase-b/README.md`](./plans/phase-b/README.md) | **active**; B1-T1 unblocked |
| 2 | Dashboard redesign (M0..M10) | [`plans/dashboard-redesign/`](./plans/dashboard-redesign/) | **queued** — runs after Phase B closes |
| — | Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) | folded into Phase B as B5-T2 |
| — | Security toggles (P1..P8) + post-k6 (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | closed |
| — | Dashboard track (D-M1..D-M6) | [`plans/dashboard-enterprise/`](./plans/dashboard-enterprise/) | closed |
| — | Phase B intake | [`docs/future/advanced-features.md`](./docs/future/advanced-features.md) | open — for items NOT covered by `plans/phase-b/` |

---

## Carry-overs / known limitations

Durable list of things that work but aren't fully shipped. Each row
is grouped under the Phase B milestone that closes it, so when a
milestone ships you can see exactly which lines to delete. See
[`plans/phase-b/README.md`](./plans/phase-b/README.md) for the task
breakdown.

**B1 — HA & multi-node** ✅ **CLOSED** 2026-04-29 — single-node
+ Redis-primary + local-fallback ships;
`docs/operations/ha-clustering.md` is Implemented. Two minor
follow-ups deliberately deferred from B1: counter merge-back
on partition heal (sliding-window can't be cleanly merged
without a wire-format change), and the GitOps / witness /
threat-intel lease gates (those subsystems aren't running as
background tasks today; their boot sites carry TODOs pointing
at `spawn_with_lease`). Per-member pool health is still
hardcoded to 0 in `pool_snapshot_provider` — depends on
membership-driven cluster runtime, not on the lease layer.

**B2 — Operational integrations** ✅ **CLOSED** 2026-04-29 —
the cloud-secrets quartet (vault/aws/gcp/azure) and the
service-discovery trio (consul/etcd/k8s) all ship. Both
`docs/control-plane/secrets-management.md` and
`docs/data-plane/service-discovery.md` are now Implemented.
HSM (B6-T4) and DNS SRV remain on the deferred list.
- **Service discovery:** `file` watcher + churn safety in
  `aegis-proxy/src/sd/`; Consul / etcd / k8s adapters not
  implemented despite being mentioned in the module doc.

**B3 — Data feeds + filtering** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B3-T1 GitOps poll driver
(`aegis-control/gitops/poll_driver`); B3-T2 TAXII fetch loop
(`aegis-security/taxii` feature); B3-T3 GeoIP MaxMind reader
(`aegis-security/geoip` feature); B3-T4 ICAP TCP client
(`content::icap::tcp`). `threat-intelligence.md`,
`geoip-filtering.md`, and `content-scanning.md` all flipped
Partial → Implemented. `gitops-change-management.md` banner
stays Partial until the boot-site lease wrap (`aegis-bin` /
`aegis-proxy::run`) lands — same constraint as ACME.

**B4 — Operator tooling** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B4-T1 `waf snapshot` (JSON envelope,
schema versioning, blake3 hash), B4-T2 `waf restore`
(atomic dry-run validation + rollback), B4-T3 full upstream
proxying (`upstream::forward` w/ hop-by-hop scrub on both
directions + Host rewrite + X-Forwarded-Host), and B4-T4
streaming SSE (`admin_sse::sse_response` w/ 15s heartbeat,
boxed body type, lag handling). `dr-backup.md` flipped
Implemented for the config/rules surface. Body forwarding
is currently buffered — true streaming forwarding (no
collect) is a deeper refactor that touches every listener
+ the SecurityPipeline body-frame hooks; deferred to a
future stream-through change.

**B5 — Protocols + benchmark**
- ✅ **HTTP/3 listener shipped** (B5-T1) —
  `aegis-proxy/http3` Cargo feature ships
  `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn
  0.0.10; reuses operator's rustls cert; dispatches
  through `proxy::handle_request`. Boot-site wire-up
  (auto-stamping `Alt-Svc` on every TLS response) is a
  follow-up.
- **Benchmark mode:** `plans/benchmark-mode.md` exists; no
  `benchmark/` module wired. `X-Aegis-*` response headers and
  dashboard panels not present.

**B6 — Production packaging**
- **Production packaging:** no Dockerfile, no Helm chart, no
  GitHub Actions CI — `deploy/` ships dev/test compose only.
- **Zero-downtime ops:** `supervisor.rs` + `hotbin.rs` + drain
  exist; no live binary-handover via fd-passing — restart is via
  supervised re-exec only.

When a milestone closes, delete the rows above it and append a
"**Bx milestone**" row to the Completed Tasks Log.

---

## Future phases

Order is execution priority — earlier phases run first.

1. **Phase B — production-readiness (active).**
   [`plans/phase-b/README.md`](./plans/phase-b/README.md).
   Six milestones (B1..B6) that close every Partial /
   Designed-only banner currently in `docs/`. Each milestone close
   removes the matching block of carry-overs above and flips the
   matching `> **Status:**` banners.
2. **Dashboard redesign (queued).**
   [`plans/dashboard-redesign/`](./plans/dashboard-redesign/).
   Eleven milestones (M0..M10), Claude Design–driven workflow
   documented in `workflow.md`. **Does not start until Phase B
   closes.** Implementation notes will land under
   [`docs/control-plane/enterprise/`](./docs/control-plane/enterprise/)
   as the milestones close.
3. **Open intake.**
   [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   for proposals NOT covered by Phase B (e.g. multi-tenancy,
   RBAC/SSO, anything new). Scored against the Impact / Reach /
   Cost / Confidence rubric.

---

## Verification (last full run)

- `cargo test --workspace` (default features) → **2,151 passed**
  (was 2,136; +15 net new from B5-T1 listener::http3 tests).
- `cargo test -p aegis-proxy --features http3 --lib
  listener::http3::` → **15 passed** (helper layer
  unchanged across feature combos).
- `cargo test -p aegis-proxy --lib admin_sse::` → **8 passed**.
- `cargo test -p aegis-proxy --lib upstream::forward::` →
  **14 passed**.
- `cargo test -p aegis-proxy --lib proxy::` → **8 passed**
  (3 pre-existing + 5 new end-to-end).
- `cargo test -p aegis-bin --bin waf -- snapshot` → **25
  passed** (15 from B4-T1 + 10 from B4-T2).
- `cargo test -p aegis-security --lib content::icap::` →
  **44 passed** (35 new + 9 pre-existing stub).
- `cargo test -p aegis-security --features geoip --lib
  geoip::` → **10 passed**.
- `cargo test -p aegis-security --features taxii --lib
  threat_intel::taxii::` → **38 passed**.
- `cargo test -p aegis-control --lib gitops::poll_driver::`
  → **9 passed**.
- `cargo test -p aegis-proxy --features consul --lib sd::consul::`
  → **16 passed**.
- `cargo test -p aegis-proxy --features etcd --lib sd::etcd::`
  → **18 passed**.
- `cargo test -p aegis-proxy --features k8s --lib sd::k8s::`
  → **24 passed**.
- `cargo test -p aegis-control --features alerts --lib slo::dispatch::`
  → **4 passed** (VipTalk routing).
- `cargo clippy --workspace --lib -- -D warnings` → clean.
- `cargo clippy --workspace --bins -- -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features http3 --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-security --features geoip --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-security --features taxii,geoip --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features
  redis,vault,aws,gcp,azure,consul,etcd,k8s --lib --
  -D warnings` → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.
- `waf snapshot --output /tmp/x.json --config
  config/waf.dev.yaml` → 7,143-byte envelope, JSON
  round-trips through `python -c "json.load(...)"`.
- `waf snapshot ... --output snap.json --force` → `waf
  restore --from snap.json --config-out restored.yaml` →
  `waf validate --config restored.yaml` → all clean
  (full snapshot/restore CLI round-trip).

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
| Phase B promoted to active track — `plans/phase-b/` formalised, dashboard redesign queued | plans/, Implement-Progress.md | 2026-04-29 |
| `plans/` cleanup — README status board + extracted implementation-matrix.md + 21 Status banners + AI-guide-only `plan.md` | plans/, Implement-Progress.md | 2026-04-29 |
| **B1-T1** Real Redis state backend (`deadpool-redis` + Lua scripts + per-call timeout + live parity vs InMemoryBackend) | aegis-proxy | 2026-04-29 |
| **B1-T2** Backend selection in `aegis-bin` (`state_select::select` + boot log line + feature-gated redis branch + actionable errors) | aegis-bin | 2026-04-29 |
| **B1-T3** Cross-node leader lease (`LeaseStore` trait + `InProcessLease` + `RedisLease` + `spawn_heartbeat` + 7 live parity tests) | aegis-core, aegis-proxy | 2026-04-29 |
| **B1-T4** Lease gate on leader-only tasks (`run_with_lease` runner + `lease_select` + ACME gated; gitops/witness/threat-intel TODOs marked) | aegis-proxy, aegis-bin | 2026-04-29 |
| **B1-T5** Rehydrate + readiness gate (`state::rehydrate` probe + `state.reconcile.readiness_warm_ms` config + 5s default deadline; never permanently 503) | aegis-core, aegis-proxy | 2026-04-29 |
| **B1-T6** Partition-safe merge — closes B1 (`ReconcilingBackend` wrap; block-list union on heal; counters fall through; `ha-clustering.md` flipped Implemented) | aegis-proxy, aegis-bin, docs | 2026-04-29 |
| **B1 milestone CLOSED** — HA & multi-node ships single-node + Redis-primary + local-fallback | project-wide | 2026-04-29 |
| **B2-T1** Vault secret resolver (`aegis-proxy/vault` feature, KV-v2 client, token + AppRole auth, env-var config) | aegis-proxy | 2026-04-29 |
| **B2-T2** AWS Secrets Manager resolver (`aegis-proxy/aws` feature, `aws-sdk-secretsmanager`, full credential chain, JSON-field extraction) | aegis-proxy | 2026-04-29 |
| **B2-T3** GCP Secret Manager resolver (`aegis-proxy/gcp` feature, REST + `gcp_auth`, ADC chain, shared `json_field` helper) | aegis-proxy | 2026-04-29 |
| **B2-T4** Azure Key Vault resolver (`aegis-proxy/azure` feature, REST + hand-rolled SP/IMDS auth) — closes the cloud-secrets quartet | aegis-proxy | 2026-04-29 |
| **B2-T5** Consul service discovery (`aegis-proxy/consul` feature, blocking-query watcher, env-driven config, ACL/multi-DC/mTLS support) | aegis-proxy | 2026-04-29 |
| Side-quest: VipTalk default alert routing (`aegis-control/alerts` feature, `slo::dispatch::send_alert`, env override; doc updated) | aegis-control, docs | 2026-04-29 |
| **B2-T6** etcd service discovery (`aegis-proxy/etcd` feature, REST gateway range-polling, basic auth + mTLS, configurable poll interval) | aegis-proxy | 2026-04-29 |
| **B2-T7** Kubernetes service discovery — closes B2 (`aegis-proxy/k8s` feature, EndpointSlice streaming watch, in-cluster + override auth) | aegis-proxy | 2026-04-29 |
| **B2 milestone CLOSED** — operational integrations (cloud-secrets quartet + service-discovery trio) ship | project-wide | 2026-04-29 |
| **B3-T1** Built-in git poll-and-pull `GitClient` (`gitops::poll_driver::GitPollDriver` shells out to system `git`; signature parse via `verify-commit --raw`; read-only by design; +9 tests) | aegis-control | 2026-04-29 |
| **B3-T2** STIX/TAXII fetch loop into `ThreatIntelStore` (`aegis-security/taxii` feature; TAXII 2.1 client + paginated fetcher loop; STIX 2.1 pattern decoder for IPv4/IPv6/domain/URL/SHA-256; +38 tests) | aegis-security | 2026-04-29 |
| **B3-T3** GeoIP MaxMind reader + rule-engine `country` / `asn` conditions (`aegis-security/geoip` feature; `MaxMindReader` w/ atomic hot-reload + `EvalContext`-threaded rule eval; `geoip-filtering.md` flipped Implemented; +18 default-feature + 5 feature-gated tests) | aegis-security | 2026-04-29 |
| **B3-T4** Concrete RFC 3507 ICAP TCP client — closes B3 (`content::icap::{codec,tcp}`; pure framing helpers + 5-vendor decision table; configurable timeout + fail-open default; `content-scanning.md` flipped Implemented; +36 tests) | aegis-security | 2026-04-29 |
| **B3 milestone CLOSED** — Data feeds + filtering (GitOps + TAXII + GeoIP + ICAP) ship | project-wide | 2026-04-29 |
| **B4-T1** `waf snapshot` CLI subcommand (`aegis-bin::snapshot::SnapshotEnvelope`; bundles config + rules files + blake3 integrity + schema versioning into JSON; refuses overwrite without `--force`; `decode`/`validate_envelope` ready for B4-T2; +15 tests) | aegis-bin | 2026-04-29 |
| **B4-T2** `waf restore` CLI subcommand (`restore_envelope` w/ atomic dry-run validation + rollback; `dr-backup.md` flipped Implemented for config/rules surface; +10 tests) | aegis-bin | 2026-04-29 |
| **B4-T3** Full upstream proxying (`upstream::forward` replaces stub; hop-by-hop scrub both directions; Host rewrite + `X-Forwarded-Host`; preserves method/path/query/body; +14 forward + 5 proxy end-to-end tests) | aegis-proxy | 2026-04-29 |
| **B4-T4** Full SSE streaming on `/dashboard/sse` — closes B4 (`admin_sse::sse_response` returns `UnsyncBoxBody` driven by `BroadcastStream` merged w/ 15s idle heartbeat ticker; preamble + per-event frames + lag handling; +8 tests) | aegis-proxy, aegis-control | 2026-04-29 |
| **B4 milestone CLOSED** — Operator tooling (snapshot + restore + upstream + SSE) ships | project-wide | 2026-04-29 |
| **B5-T1** HTTP/3 listener (`aegis-proxy/http3` feature; `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10; pure helpers for Alt-Svc + ALPN + bind parse + config; runtime path dispatches QUIC streams through `proxy::handle_request`; `protocols.md` flipped Implemented; +15 tests) | aegis-proxy | 2026-04-29 |
