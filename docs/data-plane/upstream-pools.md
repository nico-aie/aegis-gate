# Upstream Pools & Load Balancing (v2, new)

> **Status:** Implemented — `upstream/{lb,health,circuit,tls,mod}.rs` — 5 LB strategies, health checks, circuit breaker.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **New in v2.** Replaces v1's single upstream. Each route points at a
> **pool** of backend members with a load-balancing strategy, active and
> passive health checks, and a per-member circuit breaker.

## Purpose

Distribute traffic across multiple backends with health awareness,
sticky-session support, per-pool TLS/mTLS, and graceful member drain.

## Pool model

```rust
pub struct Pool {
    pub name: String,
    pub members: Vec<Member>,
    pub lb: LbStrategy,
    pub health: HealthConfig,
    pub tls: Option<UpstreamTls>,
    pub draining: Vec<Member>,    // finishing in-flight only
}

pub struct Member {
    pub addr: SocketAddr,
    pub weight: u32,
    pub zone: Option<String>,
    pub state: AtomicMemberState,  // healthy | degraded | ejected
}
```

## Load-balancing strategies

| Strategy | Use case | Notes |
|---|---|---|
| `round_robin` | Uniform members | Default |
| `weighted_rr` | Mixed capacity | Smooth WRR (nginx-style) |
| `least_conn` | Long/varied request times | Requires in-flight counters |
| `consistent_hash` | Sticky routing, cache affinity | Ring via `hashring` crate |
| `random_two_choices` | Low-overhead balance | P2C algorithm |

Consistent-hash key sources: client IP, cookie, header, JWT claim.
See [`session-affinity.md`](./session-affinity.md).

## Active health checks

Per-pool background task:

- HTTP `GET /healthz` (configurable path, method, headers)
- Interval (default 2 s), timeout (default 1 s)
- Expected status / body regex / TLS verify
- Unhealthy → `degraded` → `ejected` after N consecutive failures

## Passive health

Real traffic updates member state:

- Count 5xx / connect errors / read timeouts in a sliding window
- Exceed threshold → `ejected` for cooldown
- Feeds the per-member circuit breaker in
  [`graceful-degradation.md`](./graceful-degradation.md)

## Circuit breaker

`closed → open → half-open → closed`, per member. See
[`graceful-degradation.md`](./graceful-degradation.md).

## Drain on remove

Removing a member from config puts it in `draining`:

- No new requests routed to it
- In-flight requests finish
- After `drain_timeout` or when in-flight is zero, the member is dropped

## mTLS to upstream

Each pool can carry a dedicated `rustls::ClientConfig`:

```yaml
tls:
  sni: "internal.svc.local"
  ca_bundle: "/etc/waf/certs/internal-ca.pem"
  client_cert: "/etc/waf/certs/waf-client.pem"
  client_key:  "${secret:vault:kv/data/waf#upstream_key}"
  min_version: tls1_3
```

## Configuration

```yaml
upstreams:
  api_pool:
    lb: least_conn
    members:
      - { addr: "10.0.1.10:8443", weight: 2, zone: us-east-1a }
      - { addr: "10.0.1.11:8443", weight: 2, zone: us-east-1b }
      - { addr: "10.0.1.12:8443", weight: 1, zone: us-east-1c }
    health:
      path: /healthz
      interval_s: 2
      timeout_ms: 1000
      unhealthy_threshold: 3
      healthy_threshold: 2
    tls:
      sni: "api.internal"
      ca_bundle: "/etc/waf/certs/internal-ca.pem"
  cdn_origin:
    lb: consistent_hash
    hash_key: { source: header, name: "x-cache-key" }
    members: [...]
```

### Hostname-addressed members (PR-DNS-1, 2026-05-11)

`addr:` accepts either an IP literal (`10.0.1.10:8443`) or a
hostname (`api.example.com:443`). Hostnames are resolved at
config-load + dashboard-PUT time via `tokio::net::lookup_host`;
multi-A records expand into one synthetic member per resolved
IP, so the LB strategies above distribute across all of them.

```yaml
upstreams:
  api-elb:
    members:
      - addr: api.example.com:443
    connection:
      scheme: https
```

Wire shape after expansion (illustrative):

```text
api-elb.members
  ├── 52.84.150.17:443   weight=1  host_header=api.example.com  (from A)
  ├── 52.84.150.42:443   weight=1  host_header=api.example.com  (from A)
  └── 52.84.150.99:443   weight=1  host_header=api.example.com  (from A)
```

`host_header` defaults to the hostname when unset — TLS SNI +
outbound `Host:` align automatically. An explicit `host_header`
in the YAML still wins.

**Background refresh (PR-DNS-2).** Every pool with at least one
hostname member spawns a `dns_refresh` task at boot, backed by
`hickory-resolver` (pure-Rust, TTL-aware). Refresh cadence is
`min(TTL, refresh_seconds, 60 s)` clamped to `[10 s, 1 h]`. On
each tick the task diffs the resolved IP set against the
last-applied set; only an actual change triggers
`PoolRegistry::apply` + a `pool_dns_resolved` audit event.
Resolver outages soft-fail (keep last-known IPs, retry).

Boot is also soft-failure as of Phase 2: a hostname that can't
resolve at startup logs a warn and the pool starts without those
members; the refresh task fills them in once DNS recovers.
Dashboard PUTs stay strict — typos surface immediately.

## Implementation

- `src/upstream/pool.rs` — `Pool`, `Member`, state machine
- `src/upstream/lb/{round_robin,weighted_rr,least_conn,consistent_hash,p2c}.rs`
- `src/upstream/health_active.rs` — background probe task
- `src/upstream/health_passive.rs` — sliding-window counters
- `src/upstream/circuit.rs` — per-member circuit breaker
- `src/upstream/drain.rs` — graceful removal
- `src/upstream/tls.rs` — per-pool `rustls::ClientConfig`

## Performance notes

- Round-robin pick: single atomic `fetch_add`
- Consistent hash: binary search on a pre-built ring
- Least-conn: one atomic load per member, pick min
- Zero allocation on the hot path

## Editing via the Console (CC-T1.\*)

Pools can be inspected, added, edited, and deleted via the
dashboard's **Upstreams** page (`/dashboard/#/upstreams`).
The page consumes the audit-mutated CRUD endpoints; every
change is recorded in the audit chain and the proxy hot-swaps
the live pool table on the same request — in-flight requests
finish on the previous pool, new requests see the new one.

| Endpoint | Purpose |
|---|---|
| `GET /api/upstreams/config` | Full pool detail incl. `referenced_by_routes` |
| `PUT /api/upstreams/config` | Whole-map replace |
| `PUT /api/upstreams/pool/{id}` | Single-pool upsert |
| `DELETE /api/upstreams/pool/{id}` | Delete; refuses with **409 + `referenced_by_routes`** when any route still targets the pool |

The DELETE refusal is operator-friendly: the delete-confirm
modal renders the route-reference list directly so you know
what to fix before retrying. Validation rejections (empty
members, weight 0, health timeout ≥ interval, circuit-breaker
threshold outside `[0, 1]`) return the standard
`{ok:false, reason, message}` envelope with a stable
`reason_code` the dashboard maps to a targeted toast.

Schemas + 4xx/409 contracts: see
[`docs/control-plane/api.openapi.yaml`](../control-plane/api.openapi.yaml).
