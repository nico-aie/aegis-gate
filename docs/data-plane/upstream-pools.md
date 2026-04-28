# Upstream Pools & Load Balancing (v2, new)

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
