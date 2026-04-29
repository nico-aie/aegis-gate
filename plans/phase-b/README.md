# Phase B — Production-Readiness Track

**Goal.** Close every "Partial" / "Designed only" row in
[`plans/plan.md` § 1](../plan.md#1-doc-by-doc-implementation-status).
The current scope (P1–P8 + F-T1..F-T10 + dashboard track D-M1..D-M6)
is closed; this track turns the remaining stubs into shipped
features so Aegis-Gate can be deployed multi-node, behind real
secret managers, with real threat-intel + GeoIP + content scanning.

**Why before dashboard redesign.** Operators can run a usable
single-node WAF today. They cannot run a multi-node deployment, plug
in Vault, fetch a STIX feed, or block by country. Closing those gaps
is higher-impact than a dashboard refresh, so this track runs first.
Dashboard redesign ([`../dashboard-redesign/`](../dashboard-redesign/))
follows.

**Task ID convention.** `B<n>-T<x>` where `<n>` is the milestone
number (B1..B6) and `<x>` is the sub-task within it.

---

## Milestones

The order below is the recommended execution order — earlier
milestones unblock later ones. Within a milestone the sub-tasks are
mostly independent and can be parallelised.

### B1 — HA & multi-node (unblocks everything else)

The `StateBackend` trait + `InMemoryBackend` are already shipped;
this milestone makes the cluster claim in
[`docs/operations/ha-clustering.md`](../../docs/operations/ha-clustering.md)
real.

| Task | Outcome |
|---|---|
| **B1-T1** Real Redis backend | Replace `RedisBackendStub` (`aegis-proxy/src/state/redis.rs`) with a `deadpool-redis` impl that satisfies `aegis_core::StateBackend`. Use the existing Lua scripts (already defined as constants). Add reconnect + timeout. |
| **B1-T2** Backend selection in `aegis-bin` | `aegis-bin/src/main.rs:83-84` always wires `InMemoryBackend`. Read `cfg.state.backends` + `routing` and select per-keyspace; fall back to in-memory if the config doesn't ask for Redis. |
| **B1-T3** Cross-node leader lease | Redis `SET NX EX` lease with heartbeat renewal (`aegis-core::cluster` already defines the contract). Replace `aegis-proxy/src/cluster.rs::InProcessCluster` lease with a Redis-backed impl behind the same trait. |
| **B1-T4** Lease gate on leader-only tasks | Wrap ACME issuance, GitOps poll, threat-intel fetcher, and witness export so they only run on the lease holder. Lose the lease → stop the task within one heartbeat. |
| **B1-T5** Rehydrate + readiness gate | New `aegis-proxy/src/state/rehydrate.rs`. Block `/healthz/ready` (return 503) until the essential keyspaces (rate limits, block lists, challenge nonces) have been warmed from Redis. `reconcile.readiness_warm_ms` is the deadline. |
| **B1-T6** Partition-safe merge | `max(local_fallback, remote)` reconciliation for rate-limit counters when a partition heals. Block lists are strictly additive. New `aegis-proxy/src/state/reconcile.rs`. |

**Doc updates on close:** flip
[`docs/operations/ha-clustering.md`](../../docs/operations/ha-clustering.md)
banner from **Partial** to **Implemented**; remove the corresponding
carry-over from `Implement-Progress.md`.

---

### B2 — Operational integrations

Production deployments need real secret managers and real service
discovery. The trait surface exists; concrete drivers do not.

| Task | Outcome |
|---|---|
| **B2-T1** Vault secret resolver | Replace `NotImplemented` in `aegis-proxy/src/secrets.rs` for `${secret:vault:<path>#<field>}`. AppRole or Kubernetes auth method. |
| **B2-T2** AWS Secrets Manager resolver | `${secret:aws:<arn>#<field>}` via `aws-sdk-secretsmanager`. IAM role from instance metadata. |
| **B2-T3** GCP Secret Manager resolver | `${secret:gcp:<resource>#<field>}` via `google-cloud-secretmanager`. Workload-identity preferred. |
| **B2-T4** Azure Key Vault resolver | `${secret:azure:<vault>:<secret>#<field>}` via `azure_security_keyvault`. Managed identity preferred. |
| **B2-T5** Consul service discovery | New `aegis-proxy/src/sd/consul.rs`. Watches a service name, emits `DiscoveryEvent::{Added,Removed}`. Token + TLS support. |
| **B2-T6** etcd service discovery | `aegis-proxy/src/sd/etcd.rs`. Watch on a key prefix. mTLS support. |
| **B2-T7** Kubernetes service discovery | `aegis-proxy/src/sd/k8s.rs`. EndpointSlice watch via `kube-rs`. Works in-cluster. |

**Doc updates on close:** flip
[`docs/control-plane/secrets-management.md`](../../docs/control-plane/secrets-management.md)
and
[`docs/data-plane/service-discovery.md`](../../docs/data-plane/service-discovery.md)
banners from **Partial** to **Implemented**.

---

### B3 — Data feeds + filtering

Closes the remaining security-policy gaps surfaced by the audit.

| Task | Outcome |
|---|---|
| **B3-T1** Built-in git poll-and-pull driver | Concrete `GitClient` impl using `gix` or `git2`. Polls a remote repo, pulls signed commits, runs the existing `dry_run_validate`, applies on success. Fits behind the existing `gitops::GitOpsLoader`. |
| **B3-T2** STIX / TAXII fetch loop | Background task that pulls STIX 2.1 from a TAXII collection and feeds `ThreatIntelStore::insert_indicator`. Configurable interval, leader-only (gated by B1-T4). |
| **B3-T3** GeoIP MaxMind reader | New `aegis-security/src/geoip/`. Reads `GeoLite2-Country.mmdb` + `GeoLite2-ASN.mmdb`. New rule-engine condition `Country(<code>)` and `Asn(<num>)`. Hot-reload on file change. |
| **B3-T4** Concrete ICAP TCP client | Implement `IcapClient` (`aegis-security/src/content/icap.rs`) — RFC 3507 REQMOD/RESPMOD over TCP. Configurable scan timeout, fail-open on timeout (configurable). |

**Doc updates on close:** flip banners on
[`gitops-change-management.md`](../../docs/control-plane/gitops-change-management.md),
[`threat-intelligence.md`](../../docs/security/threat-intelligence.md),
[`geoip-filtering.md`](../../docs/security/geoip-filtering.md),
and [`content-scanning.md`](../../docs/security/content-scanning.md).

---

### B4 — Operator tooling

`waf snapshot` / `waf restore` already have a `SnapshotMeta` shape
in `aegis-proxy/src/dr.rs`; this milestone wires them as real CLI
subcommands. Adds the upstream-proxying maturity that the audit
flagged.

| Task | Outcome |
|---|---|
| **B4-T1** `waf snapshot` CLI | New subcommand in `aegis-bin`. Writes effective config + rules + version stamp into a `.tar.zst` with an embedded `SnapshotMeta`. |
| **B4-T2** `waf restore` CLI | Reads a snapshot, runs `dry_run_validate`, then applies via the existing hot-reload path. Refuses to restore across a major-version break. |
| **B4-T3** Full upstream proxying | Replace the "OK" stub in `aegis-proxy/src/proxy.rs` with a real TCP/HTTP client that proxies to selected pool members, honors retry/circuit-breaker policy. |
| **B4-T4** Full SSE streaming on `/dashboard/sse` | Replace the one-event-then-close stub with a streaming hyper body that subscribes to the `AuditBus` and writes events as they arrive, with backpressure + heartbeat. |

**Doc updates on close:** flip
[`dr-backup.md`](../../docs/operations/dr-backup.md) to
**Implemented**; remove the upstream-proxy + SSE rows from the
carry-overs list.

---

### B5 — Protocols + benchmark

| Task | Outcome |
|---|---|
| **B5-T1** HTTP/3 listener | Add `quinn` + `h3` deps, terminate QUIC alongside the existing TLS listener. Reuse the same routing + security pipeline. Negotiate via Alt-Svc. |
| **B5-T2** Benchmark mode (folds in existing `plans/benchmark-mode.md`) | B-T1..B-T6 already specced. Land `X-Aegis-*` response headers + dashboard panels + Prometheus series. Gated, opt-in, default off. |

**Doc updates on close:** flip
[`protocols.md`](../../docs/architecture/protocols.md) and
[`benchmark-mode.md`](../../docs/operator/benchmark-mode.md).

---

### B6 — Production packaging

Last in the order because it's the easiest to defer; everything
above is a code change, this is mostly YAML + workflows.

| Task | Outcome |
|---|---|
| **B6-T1** Production Dockerfile | Multi-stage build, distroless runtime, non-root, signed image. |
| **B6-T2** Helm chart | `deploy/helm/aegis-gate/` with values for the listeners, state backend, secret resolver, and ingress. |
| **B6-T3** GitHub Actions CI | Workflow runs the four CI stages from [`tests/README.md` § 9](../../tests/README.md). Caches cargo. |
| **B6-T4** HSM secret resolver | Last secret-manager driver. PKCS#11 against a real HSM. |
| **B6-T5** Binary-handover via fd-passing | Replace the supervised re-exec pattern with `SO_REUSEPORT` + fd handoff so in-flight connections survive a restart. |

**Doc updates on close:** flip
[`zero-downtime-ops.md`](../../docs/control-plane/zero-downtime-ops.md)
banner; close the production-packaging carry-over.

---

## Definition of Done (Phase B as a whole)

- Every `> **Status:** Partial` banner currently in `docs/` is
  flipped to **Implemented** OR explicitly re-classified as
  Designed-only with a stated reason.
- The carry-overs list in `Implement-Progress.md` is empty.
- `cargo test --workspace` still green.
- A multi-node deployment of two `waf` processes pointed at a
  shared Redis instance can:
  1. Share rate-limit counters (proven by k6).
  2. Run ACME / GitOps / threat-intel / witness on exactly one
     node (proven by killing the leader and observing failover).
  3. Survive a Redis partition without losing counter
     monotonicity (proven by `iptables` partition test).
- `/healthz/ready` returns 503 during rehydrate.
- A snapshot taken from one node restores cleanly on a fresh node.

When all six milestones close, this track is done and the
[Dashboard redesign](../dashboard-redesign/) track moves up.

---

## Out of scope

Multi-tenancy and RBAC/SSO remain
[Deferred](../../docs/future/) — they have their own design docs and
will not be picked up as part of Phase B unless an explicit
candidate is opened in
[`docs/future/advanced-features.md`](../../docs/future/advanced-features.md)
with a customer / compliance trigger attached.
