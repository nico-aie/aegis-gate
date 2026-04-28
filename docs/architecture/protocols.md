# Protocol Support (v2, new)

> **New in v2.** HTTP/1.1 + HTTP/2 + HTTP/3 (optional), WebSocket upgrade
> passthrough, and gRPC transit. v1 shipped HTTP/1.1 only.

## Purpose

Serve the protocols real-world clients use. The security pipeline is
protocol-agnostic wherever possible; only the transport adapters differ.

## HTTP/1.1

Baseline. `hyper` server with keep-alive, pipelined request handling
disabled (nginx-compatible), configurable `max_header_size`,
`max_request_line`, `max_body_size`.

## HTTP/2

Enabled via `hyper` `h2` feature. Supports:

- ALPN-negotiated `h2` on TLS listeners
- Plain `h2c` on explicitly enabled listeners (not recommended)
- Stream-level flow control, `SETTINGS_MAX_CONCURRENT_STREAMS` bound
- Header list + HPACK table caps (mitigate CVE-2023-44487 rapid reset)
- Per-connection stream budget + reset-flood detector

Rapid-reset mitigation: track stream `RST_STREAM` rate; exceeding a
threshold closes the connection with `ENHANCE_YOUR_CALM`.

## HTTP/3 (optional, `--features h3`)

Via `quinn` + `h3`:

- UDP listener on the same port as HTTPS (443)
- Alt-Svc advertisement on h1/h2 responses
- Connection migration supported
- Same security pipeline applied as h1/h2

## WebSocket upgrade

Detected by `Upgrade: websocket` + `Connection: Upgrade`. Flow:

1. Request runs the full security pipeline (headers, rate limit, rules)
2. On allow, a tunnel task is spawned: raw TCP copy both ways
3. Per-message inspection is **not** attempted (out of scope)
4. Idle timeout + total lifetime cap enforced
5. Drops on WAF shutdown are announced with a close frame `1001`

Per-route config can disable upgrade (`allow_upgrade: false`).

## gRPC

gRPC is HTTP/2 + trailers; the WAF treats it as h2 with:

- Trailer propagation (both directions)
- `grpc-status` aware error mapping to audit events
- Per-method routing: `path = "/package.Service/Method"` matches via
  the standard path trie
- Optional `grpc-web` (`application/grpc-web`) is passed through

No transcoding. No protobuf inspection (that's the application's job).

## Configuration

```yaml
listeners:
  public:
    bind: "0.0.0.0:443"
    protocols: [h1, h2]
    h3:
      enabled: false
      bind: "0.0.0.0:443/udp"
    h1:
      max_header_bytes: 65536
      max_request_line: 8192
    h2:
      max_concurrent_streams: 128
      reset_flood:
        enabled: true
        threshold_per_sec: 100
    websocket:
      enabled: true
      idle_timeout_s: 120
      max_lifetime_s: 3600
```

## Implementation

- `src/listener/h1.rs` — plain HTTP/1.1
- `src/listener/h2.rs` — HTTP/2 adapter + rapid-reset guard
- `src/listener/h3.rs` — HTTP/3 via quinn (feature-gated)
- `src/listener/ws_tunnel.rs` — WebSocket tunnel task
- `src/listener/grpc.rs` — gRPC-aware matching + trailer propagation

## Performance notes

- HPACK decoding is bounded; oversized headers 431
- WebSocket tunnel is a zero-copy `tokio::io::copy_bidirectional`
- HTTP/3 reuses the same rustls config; no extra cert load
