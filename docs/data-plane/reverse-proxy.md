# Reverse Proxy Core (v2)

> **Status:** Implemented — `aegis-proxy/src/{lib,proxy,supervisor}.rs`.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **v1 → v2:** The proxy is no longer a single-upstream forwarder. It now fronts
> a route table, multiple upstream pools, multi-protocol adapters, and TLS
> termination with SNI. See [`routing-ingress.md`](./routing-ingress.md),
> [`upstream-pools.md`](./upstream-pools.md), and [`tls-termination.md`](./tls-termination.md).

## Purpose

The foundation of the WAF: a transparent, high-performance reverse proxy that
sits between clients and backends. Every byte flowing in either direction
passes through this layer, giving all security modules a single chokepoint.

## Requirements

- **Transparency**: backends require no code changes
- **Bidirectional**: inspect inbound and outbound traffic
- **Streaming**: large bodies never fully buffered unless inspection requires it
- **Protocols**: HTTP/1.1, HTTP/2 (ALPN auto-negotiated), WebSocket upgrade, gRPC passthrough
- **TLS**: rustls termination with SNI + dynamic cert resolver
- **Performance**: ≥ 5,000 RPS per worker, p99 overhead ≤ 5 ms

## Design

Built on `hyper 1.x` + `hyper-util` + `tokio`. The listener is held by the
[worker supervisor](../control-plane/zero-downtime-ops.md) and shared across N workers via
`SO_REUSEPORT`. Each accepted TCP connection is handled in its own tokio task:

1. **TLS terminate** (if configured) through `tokio-rustls` with the dynamic
   SNI resolver.
2. **Protocol negotiate** via `hyper::server::conn::auto::Builder` — ALPN
   picks h1 or h2 automatically.
3. **Request parse** and handoff to `handle_request`.
4. **Admission control** (see [`adaptive-load-shedding.md`](./adaptive-load-shedding.md))
   rejects with 503 under pressure before the pipeline runs.
5. **Route match** against the `RouteTable` (host + path → `Route`).
6. **Tenant governor** (see [`multi-tenancy.md`](../future/multi-tenancy.md)) enforces
   per-tenant quotas.
7. **Security pipeline** — the v1 pipeline stages (rules, detectors, risk,
   rate limits, challenge) run unchanged against the resolved route.
8. **Auth** — ForwardAuth / JWT / HMAC per route (see [`external-auth.md`](../security/external-auth.md)).
9. **API schema guard** — OpenAPI / GraphQL validation (see [`api-security.md`](../security/api-security.md)).
10. **DLP inbound** scanning.
11. **Transforms** — header/URL rewrite, CORS (see [`transformations-cors.md`](./transformations-cors.md)).
12. **Upstream selection** via the route's `Pool`, with LB + health awareness.
13. **Forward** using the pool's dedicated `hyper` client.
14. **Outbound filters**: DLP response scan, redactor, header strip, CORS.
15. **Audit emit** + metrics + access log.

## Protocol adapters

| Protocol | Handling |
|----------|----------|
| HTTP/1.1 | Native `hyper` h1 |
| HTTP/2   | Native `hyper` h2 (ALPN `h2`) |
| WebSocket| Handshake runs through the pipeline; approved upgrades are tunneled via `hyper::upgrade::on` + `tokio::io::copy_bidirectional` |
| gRPC     | HTTP/2 + trailer propagation; no transcoding. Pipeline preserves `Trailer` headers |
| HTTP/3   | Feature-gated (`--features http3`) via `quinn` + `h3` (bonus) |
| CONNECT  | TCP tunneling on routes with `scheme: tcp`. See § "TCP tunneling via CONNECT" below |

## TCP tunneling via CONNECT

The data plane terminates HTTP CONNECT requests on routes
configured with `scheme: tcp` and bridges them to a literal
TCP destination from the request's authority. Reuses the same
`hyper::upgrade::on` + `tokio::io::copy_bidirectional` primitive
the WebSocket adapter uses; no parallel listener path.

See [`plans/tcp-forwarder-phase-4.md`](../../plans/tcp-forwarder-phase-4.md)
for the full design — lifecycle, security gates, audit shape,
test matrix.

### When CONNECT dispatch fires

Four-cell decision matrix:

| method   | pool.scheme | outcome                          |
|----------|-------------|----------------------------------|
| CONNECT  | tcp         | tunnel admit → 200 + bridge      |
| CONNECT  | non-tcp     | 502 `connect_to_non_tcp_route`   |
| non-CON  | tcp         | 502 `non_connect_to_tcp_route`   |
| non-CON  | non-tcp     | normal HTTP forward (unchanged)  |

### Configuration

```yaml
routes:
  - id: redis-tunnel
    path: "/"
    upstream: tcp-mesh
    tcp_destination_allowlist:
      - "10.0.0.0/8:6379"          # Redis private mesh
      - "192.168.1.0/24:443"       # HTTPS to that subnet
    max_concurrent_tunnels_per_ip: 8

upstreams:
  tcp-mesh:
    members: [{ addr: "127.0.0.1:6379" }]   # ignored for tcp pools
    connection: { scheme: tcp }
```

`tcp_destination_allowlist` entries take the shape
`<cidr>:<port-spec>`. Port spec is a single number, a range
(`8000-8999`), or `*`. Empty allowlist = closed; every CONNECT
to that route is rejected. The config validator rejects empty
allowlists on tcp routes at boot — operators get a fast
failure with the offending route ID instead of a 502 on first
request.

### Security gates (in order)

1. **Authority parse** — must be `host:port`. Missing or empty
   → 400 `connect_authority_missing`.
2. **DNS resolution** — only when the authority isn't a literal
   IP. Failure → 503 `connect_dns_failed`; no records → 403
   `connect_dns_no_records`.
3. **SSRF gate** — loopback, link-local, unspecified, multicast,
   broadcast are hardcoded-deny. 403 `connect_destination_internal`.
   Bypass via `AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1` (intentionally
   awkward).
4. **Allowlist** — the destination's `(IP, port)` must match at
   least one rule. 403 `connect_destination_denied`.
5. **Per-IP cap** — `max_concurrent_tunnels_per_ip` (default 16).
   429 `connect_concurrent_tunnel_cap`.
6. **Upgrade availability** — HTTP/2 clients without extended
   CONNECT get 405 `connect_no_upgrade_support`. (Extended
   CONNECT support is queued for later; the field population
   today is plain HTTP/1.1.)

Each error path emits an `x-waf-rule-id` response header so
contract-aware clients can branch.

### Audit shape

Two events per tunnel, sharing the same `request_id`:

- `tcp_tunnel_open` — class `Access`, `rule_id: tunnel_admitted`,
  fields carry `destination`.
- `tcp_tunnel_close` — class `Access`, `rule_id` one of
  `tunnel_closed_normal` / `tunnel_closed_error` /
  `tunnel_upstream_unreachable`, fields carry `duration_ms`,
  `bytes_to_upstream`, `bytes_from_upstream`, `close_reason`.

Orphan-prevention guarantee: every `tcp_tunnel_open` is paired
with a `tcp_tunnel_close` even when the post-200 hyper upgrade
itself fails (the bridge task emits a synthetic close on that
path).

### What's explicitly out of scope

- **TLS-MITM inspection of tunnel bytes.** The whole point of a
  CONNECT tunnel is end-to-end privacy. Operators wanting WAF
  inspection should use `scheme: https` (where the WAF
  terminates TLS), not `scheme: tcp`.
- **HTTP/2 extended CONNECT** (RFC 8441). Rare in the wild; h1
  CONNECT covers the operator population. The dispatch returns
  405 with `connect_no_upgrade_support` until this lands.
- **Per-tunnel bandwidth shaping.** `copy_bidirectional` doesn't
  take rate limits today; deferred until an operator asks.

## Hop-by-hop header handling

Per RFC 7230, these headers are stripped on both ingress-to-upstream and
response-to-client legs:

`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`,
`Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`

`Upgrade` is preserved for WebSocket negotiation before tunneling begins.

## Client IP extraction

The TCP peer is the immediate hop. The `XffValidator` walks the
`X-Forwarded-For` chain, verifying each hop against the trusted-proxy list
(see [`ip-reputation.md`](../security/ip-reputation.md)) and stopping at the first
untrusted hop — that IP becomes `RequestContext.client_ip`.

## Implementation

- `src/proxy/server.rs` — listener loop + worker integration
- `src/proxy/handler.rs` — `handle_request`, top-level pipeline orchestration
- `src/proxy/upstream.rs` — thin wrapper; real pools live in `src/upstream/`
- `src/proxy/tls.rs` — rustls `ServerConfig` builder using the dynamic resolver
- `src/proxy/protocol.rs` — ALPN / WS upgrade handling

## Performance notes

- `mimalloc` global allocator
- `Bytes` / `Arc<[u8]>` for zero-copy body forwarding
- Streaming: bodies pass through in frames; buffering only when a stage
  explicitly requests it (e.g. DLP or OpenAPI body validation)
- Per-pool keepalive client avoids head-of-line blocking across unrelated backends
- No synchronous locks on the hot path: `ArcSwap`, `DashMap`, atomics
