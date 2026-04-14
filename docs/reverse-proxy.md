# Reverse Proxy Core (v2)

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
[worker supervisor](./zero-downtime-ops.md) and shared across N workers via
`SO_REUSEPORT`. Each accepted TCP connection is handled in its own tokio task:

1. **TLS terminate** (if configured) through `tokio-rustls` with the dynamic
   SNI resolver.
2. **Protocol negotiate** via `hyper::server::conn::auto::Builder` — ALPN
   picks h1 or h2 automatically.
3. **Request parse** and handoff to `handle_request`.
4. **Admission control** (see [`adaptive-load-shedding.md`](./adaptive-load-shedding.md))
   rejects with 503 under pressure before the pipeline runs.
5. **Route match** against the `RouteTable` (host + path → `Route`).
6. **Tenant governor** (see [`multi-tenancy.md`](./multi-tenancy.md)) enforces
   per-tenant quotas.
7. **Security pipeline** — the v1 pipeline stages (rules, detectors, risk,
   rate limits, challenge) run unchanged against the resolved route.
8. **Auth** — ForwardAuth / JWT / HMAC per route (see [`external-auth.md`](./external-auth.md)).
9. **API schema guard** — OpenAPI / GraphQL validation (see [`api-security.md`](./api-security.md)).
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

## Hop-by-hop header handling

Per RFC 7230, these headers are stripped on both ingress-to-upstream and
response-to-client legs:

`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`,
`Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`

`Upgrade` is preserved for WebSocket negotiation before tunneling begins.

## Client IP extraction

The TCP peer is the immediate hop. The `XffValidator` walks the
`X-Forwarded-For` chain, verifying each hop against the trusted-proxy list
(see [`ip-reputation.md`](./ip-reputation.md)) and stopping at the first
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
