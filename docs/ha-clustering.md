# HA Clustering & Distributed State (v2, enterprise)

> **Enterprise addendum.** Multiple WAF nodes share rate-limit counters,
> DDoS block lists, challenge nonces, risk scores, device fingerprints,
> and session state so an attack mitigated on one node is mitigated
> everywhere. Split-brain safety is non-negotiable.

## Purpose

Let the WAF scale horizontally behind an L4 load balancer without
weakening any security guarantee. A rate limit of 10 rps/IP must mean
10 rps/IP across the fleet, not 10 rps/IP times N nodes.

## State backends

Pluggable via a `StateBackend` trait:

```rust
#[async_trait]
pub trait StateBackend: Send + Sync {
    async fn incr(&self, key: &str, ttl_ms: u64) -> Result<u64>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set_nx(&self, key: &str, val: &[u8], ttl_ms: u64) -> Result<bool>;
    async fn del(&self, key: &str) -> Result<()>;
    async fn watch(&self, prefix: &str) -> WatchStream;
    async fn script_eval(&self, script_id: ScriptId, keys: &[&str], argv: &[&[u8]]) -> Result<ScriptResult>;
}
```

| Backend | Latency | Consistency | Notes |
|---|---|---|---|
| `in_memory` | ns | local only | Single-node dev/test |
| `redis` | sub-ms | strong within primary, eventual cross-AZ | Shipped default for clusters |
| `redis_cluster` | sub-ms | slot-hashed | Horizontal scale |
| `raft` | ms | linearizable | Built-in, `openraft`-based |
| `foca_swim` | ms | eventual | Gossip for soft state only |

## Identity reconciliation

On restart, nodes rehydrate from the state backend before serving
traffic. Readiness probe (`/healthz/ready`) returns 503 until the
essential keyspaces (rate limits, block lists, challenge nonces) have
been warmed.

## Split-brain safety

Rate-limit counters use `max(local_fallback, remote)` on reconciliation
so a network partition that forces local-only mode never **lowers** a
counter when the partition heals. Block lists are strictly additive;
delist requires an explicit admin action.

## Gossip layer (optional)

For soft state (device-fingerprint cache, bot-confidence hints), a
SWIM gossip layer (`foca` crate) spreads updates without blocking the
hot path:

```yaml
state:
  gossip:
    enabled: true
    bind: "0.0.0.0:7946"
    seeds: ["waf-0.internal:7946", "waf-1.internal:7946"]
```

Gossip is advisory only — never the source of truth for a security
decision.

## Leader tasks

Some tasks must run on exactly one node:

- Threat-intel feed fetcher
- ACME cert issuance / renewal
- GitOps repo sync
- Hash-chain witness export

Leader election uses a lease key in the state backend
(`SET NX EX` with heartbeat renewal). Losing the lease → stop the task.

## Configuration

```yaml
state:
  backends:
    - name: primary
      type: redis
      endpoints: ["redis://waf-redis-0:6379", "redis://waf-redis-1:6379"]
      tls: true
      password: "${secret:env:REDIS_PASSWORD}"
      pool_size: 32
    - name: local_fallback
      type: in_memory
  routing:
    rate_limit: primary
    ddos:       primary
    challenge:  primary
    risk:       primary
  reconcile:
    mode: max    # max | latest | fail_safe
    readiness_warm_ms: 5000
  leader_election:
    lease_key: "waf:leader"
    ttl_s: 15
```

## Implementation

- `src/state/backend.rs` — `StateBackend` trait
- `src/state/{in_memory,redis,redis_cluster,raft,foca_swim}.rs`
- `src/state/reconcile.rs` — partition-safe merge
- `src/state/leader.rs` — lease-based election
- `src/state/rehydrate.rs` — warm-up on startup

## Performance notes

- Redis ops are pipelined; typical hot-path RTT ≤ 500 µs on same AZ
- Lua scripts for atomic sliding-window rate limits (one RTT per check)
- `raft` is slower but removes Redis as a separate tier
- Fallback to local is wait-free — an atomic bool flip per op
