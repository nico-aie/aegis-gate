# HA Clustering & Distributed State (v2, enterprise)

> **Status:** Implemented (single-node + Redis primary +
> local-fallback). Two cluster nodes against one Redis primary
> share rate-limit counters (named buckets via
> `StateBackend`), block lists, challenge nonces, control-plane
> modes, and risk scores. Split-brain safe via
> `ReconcilingBackend` (block lists strictly additive on heal,
> counters fall through to local on `WafError::State`).
>
> **Leaderless (2026-06-10).** There is no cluster leader: every
> node is equal, `/api/cluster` returns a flat peer roster + `our_node`
> (no `is_leader`/`leader_node`), and `/healthz/ready` is purely
> node-local. Singleton side-tasks (ACME, GitOps) still coordinate via
> per-task leases — leaderless distributed mutexes, not a global leader.
> Cross-node console sync: live events via `cluster.fleet_events`
> (Phase 2, Redis pub/sub) and merged traffic metrics via
> `cluster.fleet_view` (Phase 3, TTL'd `fleet:snap:*` snapshots). See
> [`plans/future/cluster-mode-multinode-sync.md`](../../plans/future/cluster-mode-multinode-sync.md).
>
> **Not yet implemented:** `redis_cluster` slot-hashing,
> `raft` (`openraft`-based), `foca_swim` gossip, the front-of-cluster
> load balancer (today's deploy still expects an *external*
> L4/L7 LB; see "Cluster topology" below for the recommended
> shape).
>
> **Open carry-over:** the cluster perf harness routes traffic
> per-node (see [`tests/cluster/HA-TEST-METHODOLOGY.md`](../../tests/cluster/HA-TEST-METHODOLOGY.md)).
> Recommended fix: HAProxy in front. Plan is in §"Roadmap" below.

> **Enterprise addendum.** Multiple WAF nodes share security
> state so an attack mitigated on one node is mitigated
> everywhere. Split-brain safety is non-negotiable.

## Purpose

Let the WAF scale horizontally behind a load balancer without
weakening any security guarantee. A rate limit of 10 rps/IP must
mean 10 rps/IP across the fleet, not 10 rps/IP × N nodes.

This document covers **Layer 2** of Aegis-Gate's three-layer
scaling model:

| Layer | Mechanism | Doc |
|---|---|---|
| 1 — In-node | Tokio worker threads, optional CPU pin | [`runtime-tuning.md`](./runtime-tuning.md) |
| 2 — Across nodes | This document — HA cluster behind a VIP | here |
| 3 — State | Redis-backed shared state | [`Architecture.md` §12](../../Architecture.md) |

Per-node scaling (Layer 1) and cluster scaling (Layer 2) are
orthogonal: tune workers per pod, then add more pods.

## Cluster topology

```text
            ┌───────────────────────┐
   clients  │  L4 / L7 load balancer│   ← terminates client TLS
       ────▶│  (HAProxy / Envoy /   │     (or end-to-end TLS to backends)
            │   Nginx / k8s ingress)│   ← health-checks each backend
            └──────────┬────────────┘   ← pulls dead nodes within `inter`
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
     ┌────────┐  ┌────────┐  ┌────────┐
     │ WAF n0 │  │ WAF n1 │  │ WAF n2 │      ← each node identical
     └────┬───┘  └────┬───┘  └────┬───┘     ← same `WafConfig`,
          │           │           │            different node_id
          └───────────┼───────────┘
                      ▼
            ┌────────────────────┐
            │  Redis primary     │  ← shared state: rate-limit counters,
            │  (+ optional       │     task leases, block lists,
            │   replica for HA)  │     challenge nonces, fleet snapshots
            └────────────────────┘
                      │
                      ▼
            ┌─────────────────────┐
            │  upstream pools     │  ← real backends the WAF protects
            │  (services, APIs)   │
            └─────────────────────┘
```

Operators are responsible for:

- Standing up the LB. The WAF does not embed one. Patterns
  for the three common deployment shapes are spelled out in
  §"Load balancer patterns" below.
- Standing up Redis (or one of the future backends). Single
  primary + replica is the published HA recipe today.
- Stamping every node with a stable `node_id` (today derived
  from hostname + PID; future versions will accept a
  `node.id` config knob).

**Operator visibility.** The Console exposes the cluster
roster + Layer-3 backend health side-by-side on the
**Scaling** page (Tracking → Scaling). `GET /api/cluster`
returns the peers list; `GET /api/state` returns the
configured `StateBackend`'s reachability + telemetry. The
same page also shows L1 (in-node workers) so operators can
verify all three layers in one view. See
[`architecture/scaling-model.md`](../architecture/scaling-model.md)
for the full three-layer reading.

## State backends

Pluggable via a `StateBackend` trait. Abbreviated to the security-relevant
ops — see `aegis-core/src/state.rs` for the full surface (`incrby`, `expire`,
`scan_prefix`, `cas_set`, `reset_ephemeral`, `health`, …):

```rust
pub trait StateBackend: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()>;
    async fn del(&self, key: &str) -> Result<()>;

    // Cluster-shared rate limiting.
    async fn incr_window(&self, key: &str, window: Duration, limit: u64) -> Result<SlidingWindowResult>;
    async fn token_bucket(&self, key: &str, rate_per_s: u32, burst: u32) -> Result<bool>;

    // Shared risk + auto-block.
    async fn get_risk(&self, key: &RiskKey) -> Result<u32>;
    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32>;
    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()>;
    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool>;

    // Challenge nonces.
    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool>;
    async fn consume_nonce(&self, nonce: &str) -> Result<bool>;

    // Reachability + telemetry for /api/state.
    async fn health(&self) -> BackendHealth;
}
```

| Backend | Latency | Consistency | Status |
|---|---|---|---|
| `in_memory` | ns | local only | **shipped** — single-node dev/test |
| `redis` | sub-ms | strong within primary, eventual cross-AZ | **shipped** — production default |
| `redis_cluster` | sub-ms | slot-hashed | not yet — Phase B follow-up |
| `raft` | ms | linearizable | not yet — Phase B follow-up |
| `foca_swim` | ms | eventual | not yet — Phase B follow-up |

## Two limiter contracts (read this before configuring rate limits)

Aegis-Gate ships **two distinct rate-limit surfaces** with
deliberately different semantics. The `2026-04-29` cluster
smoke surfaced confusion about this; documenting the split
explicitly:

- **Per-IP volumetric guard** — `IpRateLimiter` runs first
  in `handle_data_request`. Per-node, local-only,
  `DashMap`-backed. Designed to drop a flooding source
  *fast* without a state-backend round-trip — under DDoS
  every node should reject locally, not contend on Redis.
  With N nodes and budget B, the fleet admits up to N×B
  per-IP-per-window worst case — that's the contract.
- **Named-bucket limiter** — `rate_limit::sliding::check`
  takes a `&dyn StateBackend`. Configured via
  `rate_limit.buckets[*]` in YAML. **This** is the cluster-
  shared surface — one counter per `(key, bucket)` for the
  whole fleet. Use this when you want strictly cluster-wide
  rate limits.

See [`docs/security/rate-limiting.md`](../security/rate-limiting.md)
for the full schema.

## Per-task singleton leases (no cluster leader)

Some side-tasks must run on exactly one node at a time. These are
**per-task leases** — leaderless distributed mutexes (whoever grabs the
key first runs that one task), **not** a global cluster leader. The
old `leader:cluster` "I am the leader" lease was removed (2026-06-10):
nothing gated on it, `/api/cluster` is a flat roster, and `/healthz/ready`
is node-local.

| Lease key | Task | Today |
|---|---|---|
| `acme` | ACME cert issuance + renewal scheduler. | shipped |
| `gitops` | GitOps poll-and-pull driver wrap (per `B3-T1` carry-over). | code lives, wrap not yet wired at boot site |
| `taxii` | STIX/TAXII fetcher loop wrap (per `B3-T2` carry-over). | code lives, wrap not yet wired at boot site |
| `witness` | Audit-chain witness export. | shipped behind feature flag |

Lease acquisition uses Redis `SET NX PX` with heartbeat renewal
(half-TTL) and a fence counter (monotonic per acquire).
Losing the lease → the wrapped task receives a
`tokio::Notify` and exits cleanly. The runner re-acquires
after a half-TTL backoff. On a Redis partition these leases are
**deliberately not reconciled** (`ReconcilingBackend` invariant) — an
unreachable Redis *pauses* ACME/GitOps rather than risk two nodes both
"winning" (double cert issuance). Cert renewal pausing for a Redis blip
is safe — certs have weeks of validity.

## Cross-node console sync + fleet logs

| Surface | Mechanism | Config | Redis down |
|---|---|---|---|
| **Config / modes / risk / block-list** | versioned doc + shared `g:*` keys, polled | (always on with Redis) | local fallback; converges on heal |
| **Live events** (≤ 5 s SLA) | Redis pub/sub fanout → each node's dashboard SSE | `cluster.fleet_events.enabled` | cross-node feed stops; each dashboard shows its **own** events (still ≤ 5 s) |
| **Traffic metrics** (RPS, p50/95/99, top-attackers, by-detector, bot-mix) | TTL'd `fleet:snap:<node>` snapshots, scan + merge on read | `cluster.fleet_view.enabled` | `SCAN` empty → panels fall back to **local** ("This node") |
| **Forensic audit log** | per-node `waf_audit.log` (+ SigNoz), correlated by `request_id` | (always) | unaffected — local files are the source of truth |

The fleet-event feed is a **lossy live monitor**, not the durable record.
For the complete fleet audit trail, every response carries
`X-WAF-Request-Id` and every node stamps it into `waf_audit.log`; merge
all nodes' files with [`deploy/collect-audit.sh`](../../deploy/collect-audit.sh)
(scp + time-order by `ts_ms`) and join on `request_id`, or query SigNoz.

The data plane never blocks on any of this — every cross-node mechanism
is a background task + best-effort write + local-fallback read. **Losing
Redis costs monitoring completeness for the outage window, never
protection.** See knob reference: [`config/REFERENCE.md`](../../config/REFERENCE.md)
§`cluster`.

## Identity reconciliation

On restart, nodes rehydrate from the state backend before
serving traffic. `/healthz/ready` returns 503 until either
the essential keyspaces have warmed OR
`state.reconcile.readiness_warm_ms` elapses, whichever comes
first. After the deadline readiness flips to ready
regardless — we never return permanent 503.

## Split-brain safety

`ReconcilingBackend` wraps the primary with an in-memory
fallback. On `WafError::State` from the primary:

- **Counters** (rate-limit windows, risk scores) fall
  through to local during the partition so the data plane
  keeps enforcing. They are **not** merged back on heal:
  the primary resumes from its pre-partition value and the
  wrapper logs the divergence so operators can see it. A
  `max(local, primary)` back-merge is a Phase B follow-up,
  not today's behaviour. Net effect during a partition:
  shared limits enforce *per-node* until Redis returns.
- **Block lists** are strictly additive: a block written
  during the partition is replayed to the primary on heal.
  Delist requires an explicit admin action.
- **Leader lease** expires on the partitioned side
  (heartbeat fails); a node on the surviving side acquires.
  When the partition heals, the previous leader notices the
  lost lease via the next renewal CAS and exits its task.

## Configuration

The actual YAML schema (matching the implementation, not the
old design-doc placeholder):

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8080"
      tls: false
    # …or HTTPS:
    # - bind: "0.0.0.0:8443"
    #   tls: true
  admin:
    bind: "127.0.0.1:9443"

# State backend — single block, not a list.
state:
  backend: redis
  redis:
    urls: ["redis://waf-redis-0:6379"]
    cluster: false           # set true for `redis_cluster`
                             # (not yet implemented)
    pool_size: 8
    timeout: "1s"
  reconcile:
    readiness_warm_ms: "5s"
    mode: max                # only `max` honored today

# Optional TLS data plane (carry-over 5, post 2026-04-29).
tls:
  certificates:
    - cert_path: "/etc/aegis/certs/cluster.crt"
      key_ref:   "/etc/aegis/certs/cluster.key"
      hosts:     ["edge.example.com"]
  min_version: "1.2"
```

`config/cluster-{a,b}.yaml` are the test fixtures both
nodes use; `config/prod.yaml` is the HTTPS fixture.

## Load balancer patterns

The WAF doesn't embed an LB. These are the three patterns
operators ship with today; Aegis-Gate is wire-compatible
with all of them.

### Pattern A — k8s Ingress

```yaml
# values.yaml — your ingress controller of choice (nginx,
# traefik, contour). Reverse-proxy paths through to
# aegis-gate Service which fronts the StatefulSet.
controller:
  config:
    use-forwarded-headers: "true"
    forwarded-for-header: X-Forwarded-For
    use-proxy-protocol: "false"   # or true if you terminate at L4

# Service in front of WAF pods.
apiVersion: v1
kind: Service
metadata:
  name: aegis-gate
spec:
  type: ClusterIP
  selector: { app: aegis-gate }
  ports:
    - { name: http,  port: 80,  targetPort: 8080 }
    - { name: https, port: 443, targetPort: 8443 }
    - { name: admin, port: 9443, targetPort: 9443 }   # internal-only
```

The ingress controller terminates TLS (or hands off via SNI
to the WAF for end-to-end TLS) and round-robins / least-conn
across pods. WAF replicas read `X-Forwarded-For` to recover
the original client IP — same chain Nginx + the WAF use today.

Health checks: hit `GET /healthz/ready` on each pod's admin
port. Readiness drives Pod readiness drives endpoint removal.

### Pattern B — Nginx upstream block

```nginx
upstream aegis_cluster {
    least_conn;
    server waf-0.internal:8080 max_fails=3 fail_timeout=10s;
    server waf-1.internal:8080 max_fails=3 fail_timeout=10s;
    server waf-2.internal:8080 max_fails=3 fail_timeout=10s;
    keepalive 32;             # reuse connections — cuts handshake cost
}

server {
    listen 443 ssl http2;
    server_name edge.example.com;

    ssl_certificate     /etc/nginx/certs/cluster.pem;
    ssl_certificate_key /etc/nginx/certs/cluster.key;

    location / {
        proxy_pass         http://aegis_cluster;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   X-Forwarded-Host  $host;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
    }
}
```

Why `least_conn` over `round_robin`: under bursts, longer-lived
connections (e.g., one client with a large upload) skew
round-robin's per-connection fairness. `least_conn` keeps
the per-backend load even.

`keepalive 32` is the number Nginx reuses to reach each
WAF backend. Without it Nginx opens a fresh TCP per request
and the WAF spends most cycles on handshakes — the same
trap the run-04 perf table fell into when k6 fired one
short-lived conn per VU iteration.

### Pattern C — HAProxy (recommended for the local test rig)

```text
defaults
  mode http
  timeout connect 5s
  timeout client  60s
  timeout server  60s

frontend in
  bind *:80
  bind *:443 ssl crt /certs/cluster.pem alpn h2,http/1.1
  default_backend cluster

backend cluster
  balance roundrobin
  option httpchk GET /healthz/ready
  http-check expect status 200
  default-server check inter 2s fall 2 rise 1
  server waf0 waf-0.internal:8080
  server waf1 waf-1.internal:8080
  server waf2 waf-2.internal:8080
```

`fall 2 rise 1` is the failover budget — two failed health
checks pull a node out, one success puts it back. With
`inter 2s` that bounds detection at ~4 s.

This is the pattern the recommended local test rig
(carry-over 6) will adopt — see "Roadmap" below.

## Observability

Every node exposes the same surfaces, scrape every node:

| Endpoint | What it tells you |
|---|---|
| `GET /healthz/live` | Process alive — used by Pod liveness. |
| `GET /healthz/ready` | Ready to serve — used by Pod readiness + LB health checks. 503 during state-backend rehydrate. |
| `GET /healthz/startup` | Boot complete — used by k8s `startupProbe`. |
| `GET /metrics` | Prometheus counters + histograms. Scrape every node and aggregate fleet-wide via `sum(...)` / `histogram_quantile(...)`. |
| `GET /api/cluster` | Flat leaderless roster: `peers[]` + `our_node`. Drives the dashboard's peer list + "this node" label (no leader badge). |

## Roadmap

Open work, in priority order. Each item links to the carry-over
or B-track milestone that owns it.

| # | Item | Status | Owner |
|---|---|---|---|
| 1 | **HA load-balancer reference deploy** — drop an `aegis-lb` HAProxy container into `deploy/docker-compose.dev.yml` per pattern C; add `tests/cluster/05-single-vip-baseline.sh` + `06-mid-burst-failover.sh`. Closes the test-methodology gap surfaced 2026-04-29. | open (carry-over 6) | — |
| 2 | **Boot-site lease wraps for GitOps + TAXII** — code drivers exist (B3-T1 + B3-T2); wire `cluster_lease::spawn_with_lease("leader:gitops" / "leader:taxii", …)` in `aegis-bin::main`. | open (B3 carry-over) | — |
| 3 | ~~**`node.id` config knob**~~ — ✅ **done** (HA-T3, verified 2026-05-27). `aegis-bin::lease_select::derive_node_id` resolves `cfg.node.id` → `AEGIS_NODE_ID` → `${HOSTNAME}-${PID}-${NANOS}`. Set `node.id: "${POD_NAME}"` for a restart-stable identity. | closed | — |
| 4 | **Redis Sentinel / replica failover** — current single-Redis primary is a SPOF. Document the Sentinel topology + verify the WAF reconnects on primary swap. | open | — |
| 5 | **`redis_cluster` backend** — slot-hashed shards for fleets > ~50 k req/s where one Redis primary becomes the bottleneck. Pulls the existing Lua scripts onto a cluster-aware connection pool. | open | — |
| 6 | **`raft` backend** — embed `openraft` so the WAF cluster doesn't depend on an external state store at all. Targets sites where running Redis isn't acceptable (regulated air-gapped envs). | open | — |
| 7 | **`foca_swim` gossip layer** — for soft state (device fingerprints, bot confidence). Out-of-band of the security path. | open | — |
| 8 | **Per-member health surfacing on `/api/cluster.peers`** — the membership registry **is built** (HA-T4, verified 2026-05-27): `accept.rs` runs a `members:<node_id>` heartbeat lease + a 5s poller (`lease_store.list_keys_with_prefix("members:")` → `LeaderView::set_members`) that populates `peers` with `{id, version, last_heartbeat}`. **Remaining:** enrich `ClusterPeer.addr` + `leases` (empty today) and per-member health. The earlier "always `[]`" claim is stale. | partial | — |

## Implementation map

```
crates/aegis-core/src/
  cluster.rs              ← LeaseStore trait, NodeId
  state/                  ← StateBackend trait

crates/aegis-proxy/src/
  state/
    redis.rs              ← deadpool-redis + Lua, with timeout
    rehydrate.rs          ← warm-up gating /healthz/ready
    reconcile.rs          ← local-fallback counters (no back-merge yet) + additive blocks
  cluster_lease/
    in_process.rs         ← single-node InProcessLease (default)
    redis.rs              ← RedisLease (CAS Lua scripts + heartbeat)
    runner.rs             ← run_with_lease / spawn_with_lease wrapper
    heartbeat.rs          ← TTL/2 renewal + lost-lease Notify

crates/aegis-control/src/api/
  tracking.rs             ← LeaderView + /api/cluster shape

config/
  cluster-a.yaml      ← node A test fixture
  cluster-b.yaml      ← node B test fixture
  prod.yaml            ← HTTPS data-plane fixture (carry-over 5)
```

## Performance notes

Numbers from `tests/results/run-04-2026-04-29-cluster-https/`:

- Single-node baseline (real upstream): 31.5 k RPS, 504 µs
  median allow path, 1.04 ms p95.
- Two-node cluster (k6 against each node separately):
  identical per-node — ~31.7 k RPS, ~510 µs median, ~1.10 ms
  p95.
- HTTPS (TLS 1.3 + AES-256-GCM-SHA384, ALPN forced to
  http/1.1): 31.8 k RPS, handshake p95 2.12 ms,
  request p95 1.03 ms.

The numbers above are per-port; cluster-wide RPS through a
single VIP is **not yet measured** (carry-over 6). Expect
~1.8× single-node on a healthy LB with `keepalive` /
upstream connection pooling tuned, modulo the rate-limit
ceiling each node honours independently for the per-IP
volumetric guard.

## See also

- [`tests/cluster/HA-TEST-METHODOLOGY.md`](../../tests/cluster/HA-TEST-METHODOLOGY.md)
  — the test-side companion that names the harness gap
  this doc's "Roadmap §1" closes.
- [`tests/cluster/README.md`](../../tests/cluster/README.md)
  — per-script contracts the smoke harness exercises today.
- [`docs/security/rate-limiting.md`](../security/rate-limiting.md)
  — the dual-surface rate-limit contract referenced above.
- [`Implement-Progress.md`](../../Implement-Progress.md)
  — current carry-over slate + which items in §"Roadmap"
  are gating B6 vs deferred.
