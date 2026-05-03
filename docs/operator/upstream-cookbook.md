# Upstream Cookbook — config recipes per protocol

> Pair this with the **reference**:
> [`../data-plane/upstream-pools.md`](../data-plane/upstream-pools.md)
> covers the schema + LB algorithms. This file is the **practical
> recipes** — copy-paste-ready blocks for each protocol you'd put
> behind the WAF.

Every recipe assumes `make run-dev` (or one of the production
profiles). Edit the upstream block in `config/dev.yaml` (or your
profile of choice), restart the WAF, and verify with curl.

---

## Quick decision

| Your backend speaks… | Pick `connection.scheme:` | Notes |
|---|---|---|
| Plain HTTP/1.1 | `http` | The most common path. Auto-bridges WS upgrades on this scheme. |
| TLS-terminated HTTPS | `https` | Auto-bridges WSS. Use `host_header:` if your backend dispatches on Host. |
| HTTP/2 cleartext (h2c) | `h2c` | Forces h2 prior-knowledge framing. Service-mesh sidecars. |
| HTTP/2 TLS for gRPC | `grpc` | ALPN h2 only — no h1 fallback. gRPC strict. |
| Both h1 and h2, decided by ALPN | `auto` | Default. Mirrors the legacy `tls` flag. |
| Raw TCP (no HTTP framing) | `tcp` | Requires the **CONNECT** method from the client. SSH-over-WAF, custom protocols, etc. |

WebSocket and WSS are detected automatically on `http` / `https` / `auto` — no separate scheme. The bridge code reads `Upgrade: websocket` + `Connection: Upgrade`, opens a raw TCP forward to the resolved member, and `copy_bidirectional`s after the upstream returns 101.

---

## Recipe 1 — plain HTTP backend (the simplest case)

Your backend is a single nginx / express / FastAPI / Go service on `:3001`.

```yaml
# config/dev.yaml
routes:
  - id: api
    path: "/"
    upstream: api-pool

upstreams:
  api-pool:
    members:
      - addr: "127.0.0.1:3001"
    lb: round_robin
    connection:
      scheme: http
      keep_alive: true
      max_idle_per_host: 32
      idle_timeout: "30s"
```

```bash
make run-dev
curl -i http://localhost:8080/        # forwards to 127.0.0.1:3001
```

Adding more members for HA:

```yaml
upstreams:
  api-pool:
    members:
      - addr: "10.0.1.10:3001"
      - addr: "10.0.1.11:3001"
      - addr: "10.0.1.12:3001"
    lb: least_conn      # or weighted_round_robin / consistent_hash / p2c
```

---

## Recipe 2 — HTTPS backend with auto-bridged WebSocket / WSS

Your backend is a TLS-terminated service. WebSocket upgrades that arrive on this WAF route automatically bridge through to the same upstream — no separate config.

```yaml
upstreams:
  app-pool:
    members:
      - addr: "10.0.1.50:443"
    connection:
      scheme: https
      keep_alive: true
```

```bash
# HTTP forwards normally
curl -ik https://localhost:8443/api/users

# WebSocket upgrade auto-bridges
websocat wss://localhost:8443/socket
# or: wscat -c wss://localhost:8443/socket
```

The audit chain pairs `websocket_open` + `websocket_close` events; the dashboard's Live Feed shows `Proto = ws-open` / `ws-close` pills; `aegis_websocket_active` Prometheus gauge tracks in-flight bridges.

---

## Recipe 3 — multi-vhost / public-TLS upstream

Your backend dispatches on the `Host` header (Cloudflare-fronted services, GitHub Pages, multi-tenant nginx, your own VPS hosting many vhosts). Without `host_header:` the WAF rewrites `Host` to the IP and the backend returns 404.

```bash
dig +short example.com    # → e.g. 23.215.0.136
```

```yaml
upstreams:
  example-com:
    members:
      - addr: "23.215.0.136:443"
        host_header: "example.com"   # ← drives Host header AND TLS SNI
    connection:
      scheme: https
```

What this does:
- Upstream sees `Host: example.com`.
- Original client `Host:` rides as `X-Forwarded-Host`.
- TLS SNI for the upstream handshake = `example.com` (so the cert validates).
- A process-global pinned DNS resolver routes the `example.com` connection back to `23.215.0.136`, bypassing system DNS.

This combination unlocks pointing the WAF at any public TLS service without a sidecar.

---

## Recipe 4 — gRPC backend

gRPC needs HTTP/2 only — no h1 fallback. Set `scheme: grpc` and the WAF forces ALPN to `h2`.

```yaml
upstreams:
  grpc-payments:
    members:
      - addr: "10.0.2.10:443"
    connection:
      scheme: grpc          # HTTPS, ALPN h2 only
      keep_alive: true
```

For an internal cleartext gRPC sidecar (no TLS), use `h2c`:

```yaml
upstreams:
  internal-payments:
    members:
      - addr: "127.0.0.1:9090"
    connection:
      scheme: h2c           # HTTP/2 cleartext
```

Test with `grpcurl`:

```bash
grpcurl -plaintext localhost:8080 list      # for h2c
grpcurl localhost:8443 list                 # for grpc/TLS
```

---

## Recipe 5 — raw TCP tunneling (CONNECT)

Forwarding non-HTTP traffic — SSH, custom binary protocols, WebSocket-over-anything-but-HTTP. Client must use the HTTP `CONNECT` method.

```yaml
routes:
  - id: ssh-tunnel
    host: "*"
    path: "/"
    methods: ["CONNECT"]
    upstream: ssh-pool

upstreams:
  ssh-pool:
    members:
      - addr: "10.0.3.50:22"
    connection:
      scheme: tcp
    tcp_destination_allowlist:
      - "10.0.3.0/24:22"      # SSRF gate — only allow these dests
```

Usage:

```bash
# CONNECT through the WAF; upstream is 10.0.3.50:22
curl -x localhost:8080 ssh://10.0.3.50:22
```

The data plane checks the destination against `tcp_destination_allowlist` before opening the tunnel; non-CONNECT methods on a `tcp`-scheme pool return `502 non_connect_to_tcp_route`.

---

## Recipe 6 — health checks + circuit breaker

Every member can carry an active health probe and a passive circuit breaker.

```yaml
upstreams:
  api-pool:
    members:
      - addr: "10.0.1.10:3001"
      - addr: "10.0.1.11:3001"
    connection:
      scheme: http
    health:
      path: "/healthz"
      interval: "10s"
      timeout: "3s"
    circuit_breaker:
      error_rate_threshold: 0.5     # 50 % errors trips
      open_duration: "30s"           # cooldown
```

Member health flips visible at `/api/upstreams` and on the dashboard's "Routing & Upstreams" page. Health flap audits land on the chain.

---

## Recipe 7 — sticky sessions (consistent hash by header)

```yaml
upstreams:
  sticky-pool:
    members:
      - addr: "10.0.1.10:3001"
      - addr: "10.0.1.11:3001"
      - addr: "10.0.1.12:3001"
    lb: consistent_hash
    hash_on:
      header: "x-tenant-id"           # or `cookie: session-id` etc.
    connection:
      scheme: http
```

Sticky requires `lb: consistent_hash` and a `hash_on:` block — see [`upstream-pools.md`](../data-plane/upstream-pools.md) for the full set.

---

## Recipe 8 — per-zone weighted distribution

```yaml
upstreams:
  multi-zone:
    members:
      - addr: "10.0.1.10:3001"
        weight: 3
        zone: "us-east-1a"
      - addr: "10.0.1.11:3001"
        weight: 3
        zone: "us-east-1a"
      - addr: "10.0.2.20:3001"
        weight: 1
        zone: "us-east-1b"            # standby zone gets 14 % of traffic
    lb: weighted_round_robin
```

---

## Doing this from the dashboard

The same fields are editable from the **Routing & Upstreams** page:

- **Members** table now carries an explicit `Host header (vhost)` column for vhost / SNI override.
- The **Scheme** dropdown surfaces the same six options as YAML, with a **Protocol matrix** card underneath that maps each scheme to which protocols it carries (HTTP/1.1, HTTP/2, WebSocket, gRPC, raw TCP).
- Pool changes go through the audit-mutated PUT path — every save lands as a `pools_updated` audit chain entry, hot-swaps within ~5 s, no restart.

---

## Verifying

```bash
# Pool config the proxy is currently using:
curl -s -b cookies http://localhost:9443/api/upstreams/config | jq

# Live member health (per-pool, per-member healthy flag):
curl -s -b cookies http://localhost:9443/api/upstreams | jq

# A request through the data plane:
curl -i http://localhost:8080/your/path

# What the audit chain saw:
curl -s -b cookies "http://localhost:9443/api/audit/since?limit=5" \
  | jq '.events[] | {ts, action, fields: (.fields | {method, path, status})}'
```

---

## Operator footguns (designed-out, but worth knowing)

- **Pinning a `host_header` for HTTPS is now self-consistent.** The WAF builds the URL with the override hostname so SNI + cert both validate against the same name; the pinned resolver routes the TCP connect to your `addr`. You don't need `/etc/hosts` tricks.
- **`scheme: tcp` requires CONNECT.** Other methods get a 502 `non_connect_to_tcp_route` — by design.
- **A stalled health probe DOES NOT keep killing connections.** Members ejected by the breaker get re-probed when `open_duration` elapses; once one passes, traffic returns.
- **Hot-swap is one-shot per save.** Successive PUTs to `/api/upstreams/config` queue at the audit-mutation layer; in-flight requests on the old Arc finish, new ones see the new pool.
