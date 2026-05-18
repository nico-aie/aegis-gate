# Storage Layout & v2.3 Contract Mapping

> **What this doc is.** A focused reference on where each piece of
> runtime data lives — Redis, etcd, local disk — and how that
> layout maps to the requirements in
> [`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](../../Hackathon_Doc/EN_waf_interop_contract_v2.3.md).
> Read this before changing any storage tier or audit sink; the
> benchmarker grades against the §3 / §5 / §6 expectations and the
> three tiers each carry different invariants.

## Three-tier split

| Tier | Backing store | Latency | Durability | Cluster role |
|---|---|---|---|---|
| **Hot state** | Redis | ~1 ms | volatile (optional AOF) | shared across N nodes |
| **Config / control plane** | etcd | ~10 ms | Raft-replicated | shared, strongly consistent |
| **Audit trail** | Local disk (JSONL) | <1 ms (buffered) | persistent, node-local | **per-node** |

The split is deliberate. Hot state needs sub-ms shared reads/writes
that tolerate loss of the last few hundred ms. Config needs strong
consistency across nodes but changes rarely. Audit needs append-only
durability with strict ordering — disk is the right tool, but it
becomes per-node by default.

## Hot state — Redis

Behind the `aegis_core::state::StateBackend` trait
([`crates/aegis-core/src/state.rs:135`](../../crates/aegis-core/src/state.rs)).
Implemented by `aegis_proxy::state::RedisBackend`
([`crates/aegis-proxy/src/state/redis.rs`](../../crates/aegis-proxy/src/state/redis.rs))
with a `ReconcilingBackend` wrapper that falls back to
in-memory on `WafError::State` (split-brain safe).

| Data | Redis command | Why Redis |
|---|---|---|
| Sliding-window rate limits | `ZADD` + `PEXPIRE` (atomic Lua) | atomic incr-and-test in <1 ms |
| Token buckets | `HMSET tokens, ts` (Lua refill) | same |
| Risk scores per `RiskKey{ip, device_fp, session, tenant}` | `INCRBY` w/ cap + TTL | aggregated across N nodes |
| Auto-block flags per IP | `SET key TTL` | TTL is native |
| CSRF / replay nonces | `SET NX` (consume-once) | atomic compare-and-set |
| Cluster leader lease | `SET NX PX` ([`cluster_lease/redis.rs`](../../crates/aegis-proxy/src/cluster_lease/redis.rs)) | leader election without external coordinator |

**Why everything here is ephemeral.** Every entry in the Redis tier is
covered by `POST /__waf_control/reset_state` (§3 of the contract).
That endpoint clears rate-limit state, risk state, cache state,
challenge/session state, and temporary enforcement state — all of
which map 1:1 to keys above. See **Reset-state coverage** below.

## Config / control plane — etcd

`aegis_proxy::config_source::etcd_source`
([`crates/aegis-proxy/src/config_source/etcd_source.rs`](../../crates/aegis-proxy/src/config_source/etcd_source.rs)).
Opt-in via `AEGIS_CONFIG_SOURCE=etcd`.

| Data | Key shape | Why etcd |
|---|---|---|
| `WafConfig` YAML blob | `/aegis/config/waf` (single key) | read once at boot + watch; must be identical across nodes |
| Service discovery | per-pool member keys ([`sd/etcd.rs`](../../crates/aegis-proxy/src/sd/etcd.rs)) | Raft-backed membership |
| Admin sessions | `admin_auth/session.rs` | linearizable history needed for audit |
| Config version history | `api/config_versions.rs` | linearizable history needed for audit |

**Why YAML-as-blob.** The same YAML the file loader accepts, verbatim.
Single validation surface (`WafConfig::validate`), and operators can
move between file ↔ etcd by copying the contents. A future split into
`/aegis/config/rules/<id>` keys is documented in
`deploy/etcd/README.md` but not implemented.

## Audit trail — local disk

Two parallel sinks subscribe to the in-process `AuditBus` broadcast:

### 1. Minimal contract sink — `./waf_audit.log`

[`crates/aegis-control/src/interop/audit.rs`](../../crates/aegis-control/src/interop/audit.rs) —
`MinimalJsonlSink`.

- **Single file**, append-only, one JSON object per line.
- 8 fixed fields (`request_id`, `ts_ms`, `ip`, `method`, `path`,
  `action`, `risk_score`, `mode`) + optional `rule_id` + `tier`.
- Path defaults to `./waf_audit.log` — configurable in
  `cfg.interop.audit_path`.
- **Boot-time fail-fast** if the path is unwritable (F-CRITICAL-003
  fix, 2026-05-17). Pre-fix the gateway booted with no audit sink
  and silently failed every Phase-2 correlation clause.

This is the file the benchmarker reads. The schema is contract-locked.

### 2. Forensic chain — daily-rotated NDJSON + hash chain

[`crates/aegis-control/src/audit/sinks/jsonl.rs`](../../crates/aegis-control/src/audit/sinks/jsonl.rs)
+ [`crates/aegis-control/src/audit/chain.rs`](../../crates/aegis-control/src/audit/chain.rs).

- Files named `audit-YYYY-MM-DD.ndjson` keyed off event timestamp.
- Daily rotation, `retention_days` TTL pruning (default 30).
- Per-node SHA-256 hash chain: `hash = sha256(prev_hash || canonical_json(event))`.
- Background tokio task drains the bus; data-plane never blocks on disk.

This runs alongside the minimal sink for operator forensics — not
contract-mandated but useful for tamper evidence and long-term retention.

### 3. Optional fan-out sinks

Configured via `Vec<AuditSinkConfig>` in
[`crates/aegis-core/src/config.rs:2738`](../../crates/aegis-core/src/config.rs):

- `Syslog` — RFC 5424 / CEF over UDP / TCP / TLS
- `Splunk` — HTTP Event Collector
- `Kafka` — broker list + topic

Fire-and-forget: each sink is a `AuditBus` subscriber. If a sink
falls behind, broadcast `Lagged(_)` logs a warn and continues —
no data-plane impact.

## v2.3 contract compliance matrix

| Contract clause | Where it lives | Status |
|---|---|---|
| **§3 `/__waf_control/reset_state`** clears rate-limit, risk, cache, challenge/session, temporary enforcement | `ControlContext::reset_state` callback chain ([`interop/control.rs:264`](../../crates/aegis-control/src/interop/control.rs)) | **OK** — `RiskTracker::reset_all`, `IpRateLimiter::reset_all`, `AttacksAggregator::reset` all registered |
| **§3 reset_state MUST NOT modify audit log** | `MinimalJsonlSink` is opened append-only; no callback truncates it | **OK** — verified by `interop::audit::tests::reset_does_not_truncate` |
| **§5 X-WAF-* headers** match audit `request_id` | Headers emitted from the same `DecisionTag` that constructs the `AuditEvent` | **OK** |
| **§6 audit file** is JSONL at `./waf_audit.log` (configurable) | `MinimalJsonlSink` writes single-file JSONL to `cfg.interop.audit_path` | **OK** |
| **§6 audit IP field** = TCP peer, not XFF | `MinimalAuditEntry.ip` set from peer socket in the data plane | **OK** |
| **§6 audit action** ∈ `{allow, block, challenge, rate_limit, timeout, circuit_breaker}` | Typed via `AuditAction` enum (F-CRITICAL-004) — `is_wire_action()` distinguishes wire vs admin tags | **OK** — type-safe since 2026-05-18 |
| **§2.4 `log_only` mode** still reports intended action | `X-WAF-Mode: log_only` + intended `X-WAF-Action` set before the bypass branch | **OK** |

**Status: full match.** Every clause the contract checks has a
backing implementation, and the two-sink design cleanly separates
the contract-locked file (`./waf_audit.log`, single file, fixed
schema) from the operator forensic chain (daily-rotated, hash-chained,
optional fan-out).

## Multi-node implications

### Works correctly across N nodes

- **Risk + rate-limit aggregation.** Redis is the shared source —
  an attacker hitting node A then node B accumulates one risk
  score, not two independent ones.
- **Config propagation.** etcd watch fans out config changes to
  every node within ms.
- **Leader-only tasks.** `SET NX PX` lease in Redis guarantees at
  most one node runs hourly snapshots, threat-feed refresh, etc.
- **Service discovery.** etcd-backed pool member registration.
- **Reset-state.** Each node has its own runtime state to clear,
  but the Redis-shared bits (rate-limit windows, risk scores)
  are cleared by whichever node receives the call; other nodes
  see the cleared state immediately because Redis is shared.

### Caveats — audit trail is per-node by default

The contract assumes a single-node deployment writing one
`./waf_audit.log`. Scaling to N nodes introduces three issues:

1. **Each node writes its own `./waf_audit.log`.** The benchmarker
   correlates `X-WAF-Request-Id` against the audit file on the
   responding node — for a single-VIP cluster, that means the
   benchmarker either reads N files or expects the LB to pin
   sessions to one node. Today's `tests/cluster/HA-TEST-METHODOLOGY.md`
   addresses this by running per-node test runs.

2. **Hash chains are per-node.** Each `ChainWriter` starts from
   `sha256("genesis")` and chains *that node's* events. The
   cryptographic ordering proof is per-node, not global. An
   attacker who compromises node A and rewrites its log is
   detectable from node A's chain; the cluster does not produce
   a single tamper-evident timeline.

3. **No central query API.** `/api/audit/*` on each control plane
   reads its local files only. Cluster-wide queries
   ("all blocks for IP X across all nodes") require external
   aggregation.

### Recommended multi-node audit topology

- **Production**: enable Kafka or Splunk sink alongside `Jsonl`.
  Sinks are `Vec<AuditSinkConfig>`, not mutually exclusive — events
  fan out to every configured sink. The central SIEM becomes the
  source of truth for cluster-wide audit queries.
- **Air-gapped**: ship `./waf_audit.log` files off-node via
  vector / fluentbit / filebeat into Loki / Elasticsearch / S3.
- **Single-pane-of-glass**: add a central Postgres or ClickHouse
  sink (not implemented; planned in `plans/` if needed).

The contract-mandated `./waf_audit.log` stays node-local in all
scenarios — the benchmarker reads it per-node, which is correct
behavior given the contract's per-instance scope.

## Carry-over / future work

- **Graceful Degradation §5.8** (deferred — see
  `plans/issue-fix/2026-05-17-fix-plan.md`). A panicking detector
  currently can crash the data-plane task; `catch_unwind` wrap
  plus `degraded=true` audit field is the remaining fix.
- **Central audit query API.** If a customer asks for cluster-wide
  audit queries without external SIEM, design a Postgres / ClickHouse
  sink with an HTTP query layer.
- **Cross-node hash chain witnessing.** `audit::witness` exists but
  is per-node today. Cross-node witness exchange would give a
  cluster-global tamper-evident timeline; not currently scoped.

## See also

- [`docs/operations/ha-clustering.md`](../operations/ha-clustering.md) — HA cluster topology and state sharing
- [`docs/architecture/scaling-model.md`](./scaling-model.md) — three-layer scaling model (CPU / nodes / shared state)
- [`docs/operations/dr-backup.md`](../operations/dr-backup.md) — disaster recovery and snapshot policy
- [`docs/operations/data-residency-retention.md`](../operations/data-residency-retention.md) — audit retention policy
- [`Architecture.md`](../../Architecture.md) §"State & persistence" — the system-shape view
