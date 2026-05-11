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

**Addressing the backend.** Every recipe below writes `addr: IP:port`, but as of 2026-05-11 (PR-DNS-1) `addr: hostname:port` also works — the WAF resolves hostnames at config-load + dashboard-PUT time and expands multi-A records into one member per resolved IP. See **Recipe 3.7** for the full pattern; the IP-pinned recipes still work unchanged.

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

Your backend dispatches on the `Host` header (Cloudflare-fronted services, GitHub Pages, multi-vhost nginx, your own VPS hosting many vhosts). Without `host_header:` the WAF rewrites `Host` to the IP and the backend returns 404.

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

## Recipe 3.7 — hostname-addressed upstream (DNS-resolved)

> **Since 2026-05-11 (PR-DNS-1, Phase 1).** Skip the manual
> `dig`-and-pin dance from Recipe 3 when the backend's IP can
> change — cloud load balancers (`*.elb.amazonaws.com`,
> `*.cloudfront.net`), Kubernetes Services
> (`svc.cluster.local`), Consul services. Just write the
> hostname and the WAF resolves it at config-load time.

```yaml
upstreams:
  api-elb:
    members:
      - addr: "api.example.com:443"
    connection:
      scheme: https
```

What this does:
- At config load (boot or dashboard PUT) the WAF runs
  `tokio::net::lookup_host("api.example.com:443")` and expands
  the result into one member per resolved A/AAAA record. A
  hostname returning three IPs becomes three members; the
  pool's LB strategy (round-robin, p2c, consistent-hash)
  distributes across them.
- `host_header` defaults to the hostname — TLS SNI and outbound
  `Host:` automatically line up, so HTTPS upstreams "just
  work" without you having to repeat the hostname in
  `host_header:`.
- Mixed IP + hostname members are fine — IP members pass
  through untouched; only `Hostname` entries get expanded.

```yaml
upstreams:
  mixed:
    members:
      - addr: "api.example.com:443"   # → expands to N
      - addr: "10.0.1.10:8080"        # → passes through as-is
    connection:
      scheme: auto
```

When this is the wrong choice:
- **Backend IP rotates within a session.** Phase 1 resolves
  once at config load. If the LB rotates IPs *mid-session*
  faster than your YAML hot-reload cadence, you'll bind to
  stale IPs until the next reload. Phase 2 (planned, separate
  PR) adds background DNS refresh on TTL.
- **You need DNS-01 ACME against the hostname.** That's a
  separate ACME-side decision; the upstream resolver here
  doesn't interact with cert issuance.
- **Hostname is unresolvable at boot.** Today's behaviour is
  loud-fail: boot aborts with a stable
  `dns: failed to resolve …` error. Phase 2 will soften to
  "start with the pool empty, retry in the background".

Override the SNI when the hostname you connect to differs from
the SNI the backend expects (rare):

```yaml
upstreams:
  api-elb-internal:
    members:
      - addr: "internal-elb.example.com:443"
        host_header: "api.example.com"   # explicit override wins
    connection:
      scheme: https
```

---

## Recipe 3.5 — route by **incoming** host header

Sister recipe to Recipe 3. That one rewrites the host on the **upstream** side; this one matches incoming requests by their `Host` header so different vhosts go to different pools.

Use case: you front several services behind one WAF and dispatch by hostname — `vnexpress.localhost`, `payments.localhost`, `staging.example.com`, etc.

### From the dashboard

**Routing & Upstreams** → **+ Add route** with:

| Field | Value |
|---|---|
| Route ID | `vnexpress` |
| Path | `/` *(or any prefix you only want under that host)* |
| **Host** | `vnexpress.localhost`  ← this is the matcher |
| Match type | `prefix` |
| Forward to | pick a pool, or create `vnexpress` inline |

Order it **above** the catch-all (the route table is first-match-wins, top to bottom).

### From YAML

```yaml
routes:
  - id: vnexpress
    host: "vnexpress.localhost"          # exact host match (case-insensitive)
    path: "/"
    match_type: prefix
    upstream: vnexpress-pool

  - id: catch-all                        # leave this last
    path: "/"
    match_type: prefix
    upstream: stub-pool
```

### Host-pattern syntax

The `host:` field accepts four shapes (see `crates/aegis-proxy/src/route/host.rs`):

| Pattern | Type | Matches | Tie-break priority |
|---|---|---|---|
| `vnexpress.localhost` | Exact (case-insensitive) | `Host: vnexpress.localhost` and `Host: vnexpress.localhost:8080` | **0 (highest)** |
| `*.example.com` | Wildcard suffix | any `*.example.com` (any sub-domain) | 2 |
| `/api-[0-9]+\.example\.com/` | Regex (slash-delimited, anchored) | `api-1.example.com`, `api-42.example.com` | 1 |
| `*` *or omit the field* | Catch-all | any host | 3 (lowest) |

Port is **stripped before matching** — `vnexpress.localhost:8080` and `vnexpress.localhost` both match the exact pattern. Both HTTP/1.1 (`Host:`) and HTTP/2 (`:authority`) are normalised before the matcher runs.

### Make `vnexpress.localhost` resolve to the WAF

```sh
echo "127.0.0.1  vnexpress.localhost" | sudo tee -a /etc/hosts
```

### Verify

```sh
# Route 'vnexpress' wins because the Host header matches.
curl -i http://vnexpress.localhost:8080/

# Anything else hits the catch-all.
curl -i http://localhost:8080/
```

The original client `Host:` is preserved in `X-Forwarded-Host` regardless of any `host_header:` rewrite on the upstream side. So Recipe 3 (override outgoing host) and this recipe (match incoming host) **compose** — common pattern: incoming `vnexpress.localhost` → forwarded with `Host: vnexpress.net` so the upstream's vhost dispatcher sees the real name.

### TLS for vhost on `:8443`

The dev cert SAN list is hard-coded to `localhost / 127.0.0.1 / aegis-gate.local`. Browsing `https://vnexpress.localhost:8443/` will show a cert mismatch warning. Two ways out:

1. **Dev**: add the vhost to the dev cert SAN list (edit `config/gen-cert.sh`, then `make reset-cert && make run-dev`).
2. **Prod**: configure `tls.certificates:` with one cert per host (or a wildcard). The TLS resolver picks the right cert via SNI:
   ```yaml
   tls:
     certificates:
       - cert_path: certs/vnexpress.crt
         key_ref:   certs/vnexpress.key
         hosts:     ["vnexpress.localhost", "*.vnexpress.localhost"]
       - cert_path: certs/stub.crt
         key_ref:   certs/stub.key
         hosts:     ["localhost", "127.0.0.1"]
   ```

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
      header: "x-customer-id"         # or `cookie: session-id` etc.
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
- Pool changes go through the audit-mutated PUT path — every save lands as a `pool_upsert` audit chain entry, hot-swaps within ~5 s, no restart.

**Routes** are now editable from the same page (RT-T3, shipped 2026-05-04). The Routes table at the top of **Routing & Upstreams** has `+ Add route`, **Edit**, and **Delete** controls:

- **Add / Edit** opens a form with ID, host (optional), path, match type (`exact` / `prefix` / `regex` / `glob`), HTTP methods, upstream pool dropdown, tier override, and required auth kinds. Validation happens server-side — unknown upstream returns 400, the modal surfaces the toast.
- **Delete** is hot. Refused with 409 if you try to remove the last catch-all (the route whose path is `/` with no host) — add another catch-all first.
- Every save / delete lands as a `route_upsert` / `route_delete` audit-chain entry. Endpoints: `PUT /api/routes/{id}` and `DELETE /api/routes/{id}` — full schema in [`../control-plane/api.openapi.yaml`](../control-plane/api.openapi.yaml).

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
