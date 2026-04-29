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
- **Workspace tests:** 2,021 default-feature (unchanged — B2-T6
  is feature-gated; +6 in default were the VipTalk + dispatch
  tests that landed in the side-quest) + 16 consul + 18 etcd
- **Clippy:** clean across every feature combo, including the
  full `redis,vault,aws,gcp,azure,consul,etcd` superset.
- **Active track:** Phase B — production-readiness, milestone
  B2 ([`plans/phase-b/`](./plans/phase-b/README.md))
- **Next task:** B2-T7 — Kubernetes service discovery (closes
  the discovery half + milestone B2)
- **Latest activity:** B2-T6 closed — etcd v3 REST gateway
  range-polling watcher behind `aegis-proxy/etcd` emits
  `DiscoveryEvent`s on an mpsc; basic-auth + mTLS support;
  configurable poll interval.

---

## Last Completed

**Task:** **B2-T6 — etcd service discovery.**

**Outcome.** Operators running etcd as their service registry
can now have aegis-proxy watch a key prefix and emit
`DiscoveryEvent`s on member changes. The new
`aegis-proxy::sd::etcd::watch(prefix)` returns an
`mpsc::Receiver<DiscoveryEvent>` whose sender is owned by a
spawned tokio task that POSTs `/v3/kv/range` against the
configured endpoints every `poll_interval` (default 5s),
diffs the result against its last view via
`sd::diff_members`, and emits `Added`/`Removed` events.

**Why range polling, not gRPC Watch.** Pulling `tonic` +
`prost` for one Watch RPC would dominate the dep tree. The v3
REST gateway exposes the same operations over JSON; we POST
to `/v3/kv/range`, base64-decode the values into `addr:port`
strings, and compare. Trade-off is up to `poll_interval`
extra latency on a member change versus the cleaner dep tree.
A future task can add `etcd_grpc` if real-time membership
matters more.

**Auth + mTLS.** Basic auth via etcd's `/v3/auth/authenticate`
endpoint (returns a token sent in subsequent requests'
`Authorization` header). mTLS via three env vars
(`AEGIS_ETCD_CA_CERT_PATH`, `_CLIENT_CERT_PATH`, `_CLIENT_KEY_PATH`)
— reqwest's `Identity::from_pem` consumes the concatenated
cert + key.

**Files changed.**
- `crates/aegis-proxy/Cargo.toml` — new `etcd` feature gating
  `reqwest` + `base64` (both already optional from earlier
  features). Independent of every other feature.
- `crates/aegis-proxy/src/sd/mod.rs` — declared
  `#[cfg(feature = "etcd")] pub mod etcd;`. No other changes
  — `DiscoveryEvent` + `diff_members` reused as-is.
- `crates/aegis-proxy/src/sd/etcd.rs` — **new**, 540 lines.
  `EtcdConfig::from_env()` reads the 7 supported env vars
  (`AEGIS_ETCD_ENDPOINTS` + `_USER` + `_PASSWORD` +
  `_CA_CERT_PATH` + `_CLIENT_CERT_PATH` + `_CLIENT_KEY_PATH`
  + `_POLL_INTERVAL_MS`). `watch(prefix)` spawns the loop;
  `poll_once` does one round-trip with cached auth token,
  401/403 → `WatcherError::Auth` (no retry), everything else
  → `WatcherError::Transient` (exponential backoff
  500ms→30s). Pure helpers `prefix_to_range_end(prefix)`
  (computes etcd's open-ended range end by incrementing the
  last byte) and `parse_response(body)` (base64-decode +
  socket-addr parse) are fully unit-testable.

**Tests.** 18 net new in `sd::etcd::tests`:

- `config_defaults_when_no_env`,
  `config_parses_comma_separated_endpoints`,
  `config_filters_empty_endpoints_and_strings`,
  `config_parses_poll_interval`,
  `config_invalid_poll_interval_falls_back_to_default` — env
  parsing.
- `prefix_to_range_end_simple`,
  `prefix_to_range_end_increments_last_ascii_byte`,
  `prefix_to_range_end_unicode_terminator`,
  `prefix_to_range_end_empty_string_yields_empty_range` —
  range-end algorithm.
- `parse_empty_kv_set`, `parse_single_member`,
  `parse_multiple_members` — happy-path JSON.
- `parse_value_not_addr_port_errors`,
  `parse_value_not_base64_errors`,
  `parse_value_not_utf8_errors`,
  `parse_invalid_json_errors` — error paths.
- `diff_first_observation_is_all_added` — proves the watcher's
  inner-loop diff produces the right shape.
- `live_etcd_watch` — gated by
  `AEGIS_ETCD_INTEGRATION_TEST=1`; the dev compose's etcd
  service at `127.0.0.1:2379` is the natural target.

**Verification.**
- `cargo build` clean across **default**, `etcd`, and
  `redis,vault,aws,gcp,azure,consul,etcd` (every feature
  combo).
- `cargo test --workspace` (default features) → **2,021
  passed** (unchanged — etcd module is feature-gated).
- `cargo test -p aegis-proxy --features etcd --lib sd::etcd::`
  → **18 passed**.
- `cargo clippy --workspace --lib -- -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features
  redis,vault,aws,gcp,azure,consul,etcd --lib -- -D warnings`
  → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.

---

## Recent History

Last five tasks, compressed. For full detail see git history.

| Date | Task | Outcome |
|---|---|---|
| 2026-04-29 | **B2-T5** Consul service discovery + VipTalk default alert routing | `aegis-proxy/consul` Consul blocking-query watcher (16 tests); side-quest landed `aegis-control/alerts` with VipTalk default routing (9 tests). |
| 2026-04-29 | **B2-T4** Azure Key Vault resolver — closes the cloud-secrets quartet | `aegis-proxy/azure`; REST + hand-rolled SP/IMDS auth; reuses `json_field`. +14 tests. |
| 2026-04-29 | **B2-T3** GCP Secret Manager resolver | REST + `gcp_auth` behind `aegis-proxy/gcp`; ADC chain; shared `json_field` helper extracted. +9 tests. |
| 2026-04-29 | **B2-T2** AWS Secrets Manager resolver | `aws-sdk-secretsmanager` behind `aegis-proxy/aws`; full credential chain; JSON-field extraction. +13 tests. |
| 2026-04-29 | **B2-T1** Vault secret resolver | KV-v2 client behind `aegis-proxy/vault`; token + AppRole auth; env-var config. +12 tests. |

---

## Next Task

**Task:** **B2-T7 — Kubernetes service discovery** (closes
the discovery half of milestone B2).

**Plan:** [`plans/phase-b/README.md` § B2](./plans/phase-b/README.md#b2--operational-integrations).

**Why this next.** B2-T5 (consul) and B2-T6 (etcd) ship; k8s
closes the trio. Once this lands, B2 milestone closes — every
"Partial" / "Designed-only" doc banner under `secrets/` and
`sd/` flips to Implemented (modulo HSM, which is B6-T4).

**Outline.**

1. New `aegis-proxy/src/sd/k8s.rs` (feature-gated `k8s`).
   Watches an `EndpointSlice` (or `Endpoints`) for a service
   in a namespace and emits `DiscoveryEvent`s.
2. **Decision in-task** between the official `kube-rs` crate
   (full controller-runtime, big dep tree) vs. hand-roll
   against the k8s REST API. The kube-rs ecosystem is
   excellent but heavy; for one watch endpoint a hand-roll
   keeps with the B2-T5/T6 pattern. Likely choice: hand-roll
   using `reqwest` + service-account JWT bearer auth.
3. In-cluster auth: read service-account token from
   `/var/run/secrets/kubernetes.io/serviceaccount/token`
   and CA cert from `.../ca.crt`. Default API server is
   `https://kubernetes.default.svc`. Out-of-cluster (`kubectl`-
   style): respect `KUBECONFIG` or `~/.kube/config` via env
   override.
4. Watch endpoint: `GET /apis/discovery.k8s.io/v1/namespaces/<ns>/endpointslices?labelSelector=kubernetes.io/service-name=<svc>&watch=true`.
   Streams JSON-line events; parse each `EndpointSlice` and
   diff via `sd::diff_members`.
5. Config from env: `AEGIS_K8S_NAMESPACE` (default `default`),
   `AEGIS_K8S_API_SERVER` (default `https://kubernetes.default.svc`),
   `AEGIS_K8S_TOKEN_PATH` + `_CA_CERT_PATH` (defaults to the
   in-cluster paths).
6. Tests: EndpointSlice parsing, member diff, env handling,
   live test gated by `AEGIS_K8S_INTEGRATION_TEST=1`.

**Acceptance.**

- `cargo build` clean across **default**, `k8s`, and the full
  feature superset.
- `cargo test --workspace` green; +6–10 net new tests.
- After this lands: flip `docs/data-plane/service-discovery.md`
  banner Partial → Implemented; update
  `plans/implementation-matrix.md`; mark B2 closed in
  `plans/phase-b/README.md`.

**On close:** Next Task → **B3-T1 — built-in git poll-and-pull
GitClient** (start of milestone B3 — data feeds + filtering).

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

**B2 — Operational integrations (active)**
- **Secrets resolvers:** the cloud quartet ships — `env`,
  `file`, `vault`, `aws`, `gcp`, `azure`. **HSM still returns
  `NotImplemented`** (Phase B-6 follow-up).
- **Service discovery:** `file` + churn safety in
  `aegis-proxy/src/sd/`, plus `consul` and `etcd`. **k8s
  adapter still TBD** (B2-T7) — that's the last task in this
  milestone.
- **Service discovery:** `file` watcher + churn safety in
  `aegis-proxy/src/sd/`; Consul / etcd / k8s adapters not
  implemented despite being mentioned in the module doc.

**B3 — Data feeds + filtering**
- **GitOps:** `GitClient` trait + signature verify + dry-run
  validate present; no concrete git poll-and-pull driver wired.
- **Threat-intel feeds:** in-memory `ThreatIntelStore` exists,
  no STIX/TAXII fetcher loop — feeds must be loaded externally.
- **GeoIP:** not implemented anywhere (no MaxMind reader).
- **Content scanning:** archive-bomb guard real, ICAP client is a
  trait + types stub (no concrete TCP client).

**B4 — Operator tooling**
- **DR:** `SnapshotMeta` shape exists; `waf snapshot` / `waf
  restore` CLI + `.tar.zst` writer not wired.
- **Full upstream proxying:** currently stub "OK" for clean
  requests — needs real TCP connect to pool members.
- **`/dashboard/sse`:** currently returns one event then closes
  (M1-era stub). Full streaming body needs AuditBus subscription
  wiring.

**B5 — Protocols + benchmark**
- **HTTP/3:** not implemented (no `quinn` / `h3` dependency).
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

- `cargo test --workspace` (default features) → **2,021 passed**
  (unchanged — B2-T6's etcd module is feature-gated).
- `cargo test -p aegis-proxy --features consul --lib sd::consul::`
  → **16 passed**.
- `cargo test -p aegis-proxy --features etcd --lib sd::etcd::`
  → **18 passed**.
- `cargo test -p aegis-control --features alerts --lib slo::dispatch::`
  → **4 passed** (VipTalk routing).
- `cargo test -p aegis-proxy --features
  vault,aws,gcp,azure,consul,etcd --lib` → all green.
- `cargo clippy --workspace --lib -- -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features
  redis,vault,aws,gcp,azure,consul,etcd --lib -- -D warnings`
  → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.

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
