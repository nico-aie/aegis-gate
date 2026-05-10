# Phase B — Production-Readiness Track

> **Status:** Active — Production-readiness — six milestones (B1..B6) closing every Partial / Designed-only doc banner. Runs **before** dashboard redesign.
>
> See [`README.md`](../README.md) for the track status board.

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

### B1 — HA & multi-node (unblocks everything else) — ✅ CLOSED 2026-04-29

All six sub-tasks shipped:
[`docs/operations/ha-clustering.md`](../../docs/operations/ha-clustering.md)
flipped Partial → Implemented; `aegis-bin` wires single-node
in-memory **or** Redis primary + in-memory fallback from
config; ACME issuance is gated on a Redis-backed leader lease;
`/healthz/ready` waits for state-backend rehydrate; partition
falls through transparently to local with block-list union on
heal.

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

### B2 — Operational integrations — ✅ CLOSED 2026-04-29

All seven sub-tasks shipped: cloud-secrets quartet (vault,
aws, gcp, azure) + the three production service registries
(consul, etcd, k8s).
[`docs/control-plane/secrets-management.md`](../../docs/control-plane/secrets-management.md)
and
[`docs/data-plane/service-discovery.md`](../../docs/data-plane/service-discovery.md)
both flipped Partial → Implemented; HSM (B6-T4) and DNS SRV
remain on the deferred list.

#### Original B2 plan (preserved for reference)

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

#### Side-quest landed during B2: VipTalk default alert routing

Out-of-band addition (2026-04-29) — added a `VipTalk` variant
to `aegis-control::slo::ReceiverKind` plus a real
HTTP-delivery `slo::dispatch::send_alert` behind the new
`aegis-control/alerts` Cargo feature. `default_receivers()`
seeds a single VipTalk receiver pointed at the project's
dev/UAT bot; operators override via
`AEGIS_VIPTALK_BOT_TOKEN` / `AEGIS_VIPTALK_ROOM_IDS` /
`AEGIS_VIPTALK_API_BASE` env vars. Doc:
[`docs/observability/slo-sli-alerting.md`](../../docs/observability/slo-sli-alerting.md)
§"Alert routing".

---

### B3 — Data feeds + filtering — ✅ CLOSED 2026-04-29

All four sub-tasks shipped:

| Task | Outcome |
|---|---|
| **B3-T1** Built-in git poll-and-pull driver | `aegis-control/gitops/poll_driver.rs` — `GitPollDriver` shells out to system `git` for clone/fetch/show/verify-commit; signature parser; read-only by design. +9 tests. |
| **B3-T2** STIX / TAXII fetch loop | `aegis-security/taxii` Cargo feature; TAXII 2.1 client + paginated fetcher + STIX 2.1 pattern decoder feeding `ThreatIntelStore`. +38 tests. |
| **B3-T3** GeoIP MaxMind reader | `aegis-security/geoip` Cargo feature; `MaxMindReader` w/ atomic hot-reload; rule engine grew `country` / `asn` conditions threaded via new `EvalContext`. +23 tests. |
| **B3-T4** Concrete ICAP TCP client | `content/icap/{codec,tcp}.rs` — RFC 3507 REQMOD/RESPMOD TCP client; pure framing helpers; decision table for 5 vendor infection-header forms; configurable timeout + fail-open default. +35 tests. |

**Doc updates on close:**
[`threat-intelligence.md`](../../docs/security/threat-intelligence.md),
[`geoip-filtering.md`](../../docs/security/geoip-filtering.md),
and [`content-scanning.md`](../../docs/security/content-scanning.md)
all flipped Partial → Implemented.
[`gitops-change-management.md`](../../docs/control-plane/gitops-change-management.md)
banner stays Partial until the boot-site lease-gate wrap lands —
the driver itself ships, but multi-node deployments need
`spawn_with_lease("leader:gitops", …)` at `aegis-bin` /
`aegis-proxy::run` to avoid double-applying commits.

---

### B4 — Operator tooling — ✅ CLOSED 2026-04-29

All four sub-tasks shipped:

| Task | Outcome |
|---|---|
| **B4-T1** `waf snapshot` CLI | `aegis-bin::snapshot` writes a JSON envelope (config + rules + blake3 hash + schema versioning); refuses overwrite without `--force`. +15 tests. |
| **B4-T2** `waf restore` CLI | `restore_envelope` w/ atomic temp-write + `aegis_core::load_config` dry-run + rollback on failure. +10 tests. |
| **B4-T3** Full upstream proxying | `upstream::forward` replaces the stub: hop-by-hop scrub on both directions, `Host` rewrite + `X-Forwarded-Host`, body byte-for-byte. +14 forward + 5 proxy end-to-end tests. |
| **B4-T4** Full SSE streaming on `/dashboard/sse` | `admin_sse::sse_response` returns `UnsyncBoxBody<Bytes, Infallible>` driven by a `BroadcastStream` merged with an idle heartbeat tick; preamble + per-event `data:` frames + 15s heartbeat + lag handling. +8 tests. |

**Doc updates on close:**
[`dr-backup.md`](../../docs/operations/dr-backup.md) flipped
Partial → Implemented for the config/rules surface (B4-T1 +
B4-T2). Upstream-proxy + SSE carry-overs removed.

---

### B5 — Protocols + benchmark — ✅ CLOSED 2026-04-29

Both sub-tasks shipped:

| Task | Outcome |
|---|---|
| **B5-T1** HTTP/3 listener | `aegis-proxy/http3` Cargo feature ships `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10; pure helpers for Alt-Svc + ALPN; runtime path dispatches QUIC streams through `proxy::handle_request`. +15 tests. |
| **B5-T2** Benchmark mode (core slice) | `aegis-proxy::benchmark` ships `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser, wired into `proxy::handle_request` with per-request total + route + upstream timings, plus tier + decision. IP allowlist / HMAC tokens / per-detector timing / dashboard panel deferred to follow-ups. +21 unit + 2 proxy end-to-end tests. |

**Doc updates on close:**
[`protocols.md`](../../docs/architecture/protocols.md) and
[`benchmark-mode.md`](../../docs/operator/benchmark-mode.md)
both flipped Designed/Partial → Implemented.

**Carry-over:** auto-stamping `Alt-Svc` on every TLS
response (the helper exists, the wire-up at the TLS
listener does not yet) and the full benchmark-mode plan
(B-T1..B-T6) — IP allowlist, HMAC tokens, per-detector
timing, dashboard panel — remain open.

---

### B6 — Production packaging

Last in the order because it's the easiest to defer; everything
above is a code change, this is mostly YAML + workflows.

| Task | Outcome |
|---|---|
| **B6-T1** ✅ Production Dockerfile | Multi-stage build, distroless runtime, non-root, signed image. |
| **B6-T2** ✅ Helm chart | `deploy/helm/aegis-gate/` with values for the listeners, state backend, secret resolver, and ingress. Chart `lint` + `template` clean; `appVersion` synced to Cargo.toml. CI-gated. |
| **B6-T3** ✅ GitHub Actions CI | Workflow runs lint + test (matrix) + smoke + **v2.3 contract gate** (Round-2 official regression) + helm lint + dockerfile (slow lane). All five gate `ci-pass`. |
| **B6-T4** HSM secret resolver | Last secret-manager driver. PKCS#11 against a real HSM. *(Deferred)* |
| **B6-T5** Binary-handover via fd-passing | FDP-T1..T6 shipped — library primitives + boot-path wiring (adopt-or-bind, spawn_successor, perform_handover, ReadinessPipe, SIGUSR2 listener). One gap: the accept-loop drain refactor that lets SIGUSR2 actually invoke `perform_handover`. See [`plans/binary-handover-fd-pass.md`](../binary-handover-fd-pass.md). |

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
