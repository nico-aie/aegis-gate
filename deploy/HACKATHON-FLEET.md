# Aegis-Gate — Multi-Node Fleet Deployment (nginx LB + WAF fleet)

> **Audience:** an AI assistant (or operator) standing up a production-shaped
> Aegis-Gate deployment — one **infra host** (Redis, multi-protocol mock
> upstream, observability, nginx load balancer) and **N WAF nodes** behind
> the LB, sharing state via Redis. Built for the hackathon next-round
> simulation, but the topology is the real production one.
>
> **Read first:** [`GUIDE.md`](./GUIDE.md) §3 (multi-node), [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md),
> [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).
> This doc is the *fleet* layer on top of those. **Verify every claim against
> the running binary** — config schema moves.

---

## 0. Architecture — and is the plan sound?

Your plan (infra on one host + WAF on many, nginx routing) is **sound and
matches the WAF's intended cluster model**. Recommended topology:

```
                 ┌──────────────── infra host ────────────────┐
   clients ──▶ nginx LB ──┐                                    │
   (L7, TLS    (:443)     │   Redis (:6379)  ← shared state    │
    terminate)            │   mock upstream  (http/ws/grpc/tcp)│
                          │   SigNoz/OTel collector (:4317)    │
                          └────────────────────────────────────┘
                          │ private network (RFC1918), XFF injected
              ┌───────────┼───────────┐
              ▼           ▼           ▼
          WAF node A   WAF node B   WAF node C      ← data :8080/:8443, admin :9443
              └───────────┴───────────┘  all → Redis (state + config plane + leases)
                          │
                          ▼
                   mock upstream (infra host)
```

### Three decisions to make up front (they change the config)

1. **Client-IP preservation — THE make-or-break.** The WAF's per-IP
   security (rate-limit, cumulative risk, DDoS, strike-block) keys on the
   resolved client IP. Behind a load balancer the WAF sees the **LB's** IP
   unless it trusts the LB's `X-Forwarded-For`. Two hard facts in the code:
   - The WAF honors XFF **only from trusted-proxy CIDRs**, and that set is
     currently **hardcoded to RFC1918 + loopback** (`aegis-proxy/src/
     data_plane.rs::default_trusted_proxies`; an operator override is a
     known TODO). → **The nginx→WAF hop MUST be on a private (10/8,
     172.16/12, 192.168/16) network**, with nginx injecting
     `X-Forwarded-For`. On a public/non-RFC1918 hop, XFF is ignored and
     every request looks like it came from the LB → per-IP logic collapses
     (you'll see all traffic attributed to one IP, mass false blocks).
   - There is **no PROXY-protocol support**. So L4/TCP passthrough cannot
     recover the client IP — **use L7 nginx (terminate TLS at nginx, inject
     XFF)**, not `stream{}` passthrough.

2. **TLS termination — a trade-off you must accept.**
   - **L7 (recommended for this sim):** nginx terminates TLS, forwards
     HTTP + XFF to the WAF. ✅ correct per-IP security. ❌ the WAF's **JA3/JA4
     TLS fingerprinting** sees nginx, not the client (fingerprint-based bot
     scoring is effectively disabled behind the LB).
   - **Edge-direct (if JA3/JA4 matters):** put the WAF nodes at the TLS edge
     (DNS round-robin or L3/ECMP that preserves the client IP) and use nginx
     only for the mock upstream + Redis host. ✅ JA3/JA4 + real client IP.
     ❌ no single L7 VIP. Pick this only if fingerprinting is scored.

   For the hackathon sim, **L7 nginx** is the right default — per-IP
   rate-limit/risk/DDoS correctness outweighs JA3/JA4.

3. **Redis is a single point of failure** in this layout. Fine for the sim;
   for real prod use Redis Sentinel/Cluster and set `state.redis.urls[]`
   accordingly. The WAF degrades to local-only fallback on a Redis
   partition (block-list union + local counters), so a Redis blip is
   survivable but loses cross-node coordination while down.

---

## 1. Host inventory

| Host | Role | Listens |
|---|---|---|
| `infra` | Redis + mock upstream + OTel/SigNoz + **nginx LB** | `:443` (public VIP), `:6379` `:9999±` `:4317` (private) |
| `waf-a/b/c` | Aegis-Gate data plane | data `:8080`/`:8443`, admin `:9443` (all on the **private** net) |

All WAF↔infra traffic stays on the private network. Only nginx `:443` is
public. Admin `:9443` is **never** exposed publicly (the `/__waf_control/*`
namespace is loopback-gated; the dashboard is for operators on the private
net / VPN).

---

## 2. Phase 1 — infra host

### 2.1 Redis (shared state, config plane, leases)
```sh
docker run -d --name aegis-redis --restart unless-stopped \
  -p 0.0.0.0:6379:6379 redis:7-alpine \
  redis-server --save 60 1 --appendonly yes
# bind 6379 to the PRIVATE interface only; firewall it off the public NIC.
```

### 2.2 Multi-protocol mock upstream
See [§5](#5-multi-protocol-mock-upstream) for the spec. Build + run:
```sh
go build -o /usr/local/bin/aegis-mock deploy/mock/mock-upstream.go
aegis-mock --http :9991 --ws :9992 --grpc :9993 --tcp :9994 &
```
(Or keep the single HTTP mock `tests/hackathon/upstream/fast-upstream.go` on
`:9999` if you only test HTTP this round.)

### 2.3 Observability — SigNoz on the infra host
```sh
make signoz-up           # SigNoz on the infra host; collector on :4317
# point every WAF node's WAF_OBSERVABILITY__OTEL__ENDPOINT at infra:4317
```
Import the WAF dashboard after first-run onboarding:
[`signoz/dashboards/waf-overview.json`](./signoz/README.md).

> **Sizing caveat (co-location).** SigNoz is heavy — it ships ClickHouse +
> otel-collector + query-service + ZooKeeper. Co-locating it with the public
> **nginx LB** on one box means a ClickHouse CPU/IO spike (ingest, compaction)
> can add latency to client traffic. For the sim it's fine; give the infra
> host real headroom (≥ 4 vCPU / 8 GB, SSD) or, better, put SigNoz on its own
> host and keep only Redis + mock + nginx on the LB box. The bind to `:4317`
> stays private — only nginx `:443` is public.
>
> **First-run gotcha:** SigNoz ingests nothing until you create the admin
> org in its UI (the collector rejects OTLP with `cannot create agent
> without orgId` until then). Do the onboarding before expecting spans. See
> [`signoz/README.md`](./signoz/README.md).

### 2.4 nginx load balancer — L7, TLS-terminating, XFF-injecting
`/etc/nginx/conf.d/aegis.conf`:
```nginx
upstream aegis_waf {
    least_conn;                              # right for keep-alive clients
    server 10.0.0.11:8080 max_fails=2 fail_timeout=4s;   # waf-a (data, plaintext)
    server 10.0.0.12:8080 max_fails=2 fail_timeout=4s;   # waf-b
    server 10.0.0.13:8080 max_fails=2 fail_timeout=4s;   # waf-c
    keepalive 64;
}

server {
    listen 443 ssl;
    http2 on;
    server_name _;
    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;

    location / {
        proxy_pass http://aegis_waf;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        # CRITICAL — let the WAF see the real client IP (trusted because the
        # hop is RFC1918). Without these, per-IP security keys on nginx's IP.
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        # WebSocket upgrade passthrough (the WAF bridges WS upstream):
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 75s;
    }
}
# map for the Connection upgrade header (put in http{} scope):
# map $http_upgrade $connection_upgrade { default upgrade; '' ''; }
```
> **gRPC note:** gRPC is HTTP/2 end-to-end. If you front gRPC through nginx,
> use a dedicated `grpc_pass` server block (`listen 443 http2; location / {
> grpc_pass grpc://aegis_waf_grpc; }`) pointing at the WAF's gRPC data port —
> mixing `proxy_pass` and `grpc_pass` on one block doesn't work. Simplest for
> the sim: a second nginx server block / port per protocol family.

Health: nginx open-source has no active health checks; `max_fails`/`fail_timeout`
gives passive ejection. For active probes against the WAF's `/healthz/ready`
(admin `:9443`), use nginx Plus, or keep the HAProxy reference
([`haproxy/haproxy.cfg`](./haproxy/haproxy.cfg)) which already does
admin-port health checks.

### 2.5 nginx multi-protocol limitations (read before relying on one VIP)

nginx **can** load-balance every protocol the WAF speaks, but **not through a
single block** — and one choice breaks WAF inspection if you get it wrong:

| Protocol | nginx directive | Caveat |
|---|---|---|
| HTTP/1.1 | `proxy_pass` (http) | none |
| WebSocket | `proxy_pass` + `Upgrade`/`Connection` headers | works; it's an HTTP/1.1 upgrade |
| **HTTP/2 & gRPC** | **`grpc_pass`** (own `http2` block) | **`proxy_pass` downgrades client h2 → h1 to the backend** — so the WAF would receive *HTTP/1.1*, never h2/gRPC, and couldn't inspect it as gRPC. gRPC **must** use `grpc_pass` on a dedicated `listen … http2` block/port |
| Raw TCP (`scheme:tcp`) | `stream{}` (L4) | L4 = no HTTP headers → **no XFF injection**, and the WAF has **no PROXY-protocol support** → the WAF sees the nginx IP, not the client. Per-IP security is degraded on this path |
| HTTP/3 (QUIC) | `listen … quic` (nginx ≥ 1.25, experimental) | h3 is terminated at nginx; backend hop is h1/h2. The WAF's own h3 + JA3/JA4 are bypassed (same TLS-edge caveat as §0.2) |

**Consequences for the design:**
- You can't multiplex HTTP + gRPC + raw-TCP on one nginx `server` block. Use
  **one listener/port per protocol family** (e.g. `:443` http+ws via
  `proxy_pass`, `:8443`→a `grpc_pass` block, a `stream{}` port for raw TCP).
- **gRPC/h2 fidelity:** only `grpc_pass` preserves h2 to the WAF, so the WAF
  inspects real gRPC. With `proxy_pass`, the WAF sees downgraded h1.
- **Raw-TCP client IP is lost** behind any LB here (no PROXY-proto in the
  WAF). Test the raw-TCP path by hitting a WAF node directly, or accept
  LB-IP attribution for it.

**When to prefer HAProxy / Envoy instead:**
- **HAProxy** (shipped: [`haproxy/haproxy.cfg`](./haproxy/haproxy.cfg)) —
  `mode http` covers HTTP/WS/gRPC(h2), `mode tcp` covers raw TCP, **active**
  health checks, cleaner h2. Best balance for this fleet; still no client-IP
  on the L4 path (WAF lacks PROXY-proto).
- **Envoy** — best native multi-protocol (h2/gRPC/h3, L7 routing,
  content-type routing, health checks) but heavier config.

For the sim: **nginx is fine for HTTP + WS + gRPC** with per-family blocks;
reach for HAProxy if you want active health checks with minimal config. If
JA3/JA4 or raw-TCP client-IP is scored, put those WAF nodes at the **edge**
(§0.2) rather than behind any LB.

### 2.6 If not nginx — LB options (and why L4 often beats L7 for a WAF)

**Key insight:** Aegis-Gate is *itself* a full L7 security reverse proxy that
wants to terminate TLS (for JA3/JA4) and inspect every protocol. Putting an
**L7** LB (nginx/Envoy/ALB) in front means it re-terminates — obscuring
JA3/JA4, downgrading h2, and forcing per-protocol config. An **L4 /
TCP-passthrough** LB that **preserves the client source IP** is usually the
better fit: the WAF sits at the edge and transparently gets **real client IPs
+ JA3/JA4 + every protocol** with *zero* per-protocol LB config.

But beware the client-IP rule (§0.1): the WAF has **no PROXY-protocol** and
trusts XFF only from RFC1918. So an L4 LB must **preserve the source IP at L3**
(DSR / direct-routing / `externalTrafficPolicy: Local` / cloud client-IP
preservation) — an L4 LB that SNATs hides the client and breaks per-IP
security just like a misconfigured L7 hop.

| Option | Layer | Client IP to WAF | JA3/JA4 | Multi-proto | Notes |
|---|---|---|---|---|---|
| **Cloud L4 NLB** (AWS NLB / GCP TCP LB / Azure LB) w/ client-IP preservation | L4 | ✅ real | ✅ (WAF at edge) | ✅ transparent | **Best on cloud** — simple, robust, all protocols pass through |
| **IPVS/LVS (DR)** or **Cilium eBPF (DSR)** | L4 | ✅ real | ✅ | ✅ | Best bare-metal; high perf; preserves source IP |
| **HAProxy `mode tcp` + transparent (TPROXY)** | L4 | ✅ (needs TPROXY) | ✅ | ✅ | Shipped config is `mode http`; switch to tcp + transparent for edge-WAF |
| **DNS round-robin** (no LB in path) | — | ✅ real | ✅ | ✅ | Dead simple for a sim; coarse balance; failover = DNS TTL |
| **HAProxy `mode http`** (shipped) | L7 | ⚠ XFF (private hop) | ❌ | h1/ws/gRPC | Active health checks, clean h2; raw-TCP needs a `mode tcp` block |
| **Envoy** | L7 | ⚠ XFF | ❌ | best L7 (h2/gRPC/h3) | Most capable L7; heavier config |
| **Traefik** | L7 | ⚠ XFF | ❌ | h1/h2/ws/gRPC | k8s-native, easy; no raw TCP without entrypoints |
| **nginx** | L7 | ⚠ XFF | ❌ | per-family blocks (§2.5) | Fine; the limitations in §2.5 apply |
| **nginx `stream{}` / L4 SNAT** | L4 | ❌ LB IP | ✅ | ✅ | SNATs → **client IP lost** (no PROXY-proto in WAF). Avoid |

**Recommendation:**
- **Cloud:** an **L4 NLB with client-IP preservation** → WAF at the edge. Cleanest; everything just works.
- **Bare metal / VM sim:** **IPVS-DR / Cilium**, or **HAProxy `mode tcp` transparent**; or **DNS round-robin** for the simplest sim.
- **Only choose an L7 LB** (nginx/HAProxy-http/Envoy/Traefik) if you specifically want L7 routing/WAF-behind-gateway and can live without JA3/JA4 — and keep the hop RFC1918 for XFF.
- **Avoid** any L4 LB that SNATs (incl. nginx `stream{}` default) — it hides the client IP and the WAF can't recover it.

---

## 3. Phase 2 — WAF nodes

Each node runs the **same binary + same base profile**
(`config/profiles/prod-balanced.yaml`), differing only by `node.id` and
pointing at the shared Redis. Per-node config via the `WAF_…__…` env overlay
(no per-node YAML edits needed):

```sh
# waf-a  (repeat on waf-b/c with NODE id b/c)
WAF_NODE__ID=waf-a \
WAF_STATE__BACKEND=redis \
WAF_STATE__REDIS__URLS='["redis://10.0.0.10:6379"]' \
WAF_OBSERVABILITY__OTEL__ENDPOINT=http://10.0.0.10:4317 \
LLM_API_KEY="$(cat /etc/aegis/llm.key)"   # only if copilot is enabled \
  ./waf run --config config/profiles/prod-balanced.yaml
```

Key per-node requirements:
- **Unique `node.id`** — drives the leader lease, per-node ACK, and metrics
  aggregation. Duplicate ids corrupt the cluster view.
- **Same `state.redis.urls`** on every node — that's what makes them one
  fleet (shared rate-limit counters, leader lease, **config plane**,
  block-list union).
- **Upstream pool** points at the infra mock (`10.0.0.10:9991` etc.) — set
  in the profile or via the dashboard (config plane propagates it to all
  nodes).
- Bind admin to the **private** interface; never expose `:9443` publicly.

Production-ize with systemd (see [`GUIDE.md`](./GUIDE.md) §2) or the
distroless image + Helm ([`GUIDE.md`](./GUIDE.md) §1).

### Config once, converge everywhere
With shared Redis, edit detectors / rules / tiers / **upstream pools** /
AI-toggle on **any** node's dashboard (or `PUT /api/config`) and it converges
on every node within one watcher poll (~3 s), surviving restart + leader
failover. **Do not hand-edit each node's YAML.** See
[`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md).

---

## 4. Phase 3 — verification (per protocol)

From a client *outside* the private net, through the nginx VIP:

```sh
VIP=https://<infra-public-ip>

# HTTP/1.1 + HTTP/2
curl -k  $VIP/                       # expect 200 from the mock (allowed)
curl -k --http2 $VIP/api/health

# Client-IP correctness — the make-or-break check:
#   drive an attack from one source, then a request from ANOTHER source;
#   only the attacker should accrue risk. If BOTH get blocked, XFF isn't
#   trusted (check the nginx→WAF hop is RFC1918).
curl -k "$VIP/?q=1'%20OR%20'1'='1"   # SQLi → 403 block
curl -k $VIP/                        # legit, different client → still 200

# WebSocket  (WAF bridges WS upstream)
#   wscat -c wss://<vip>/ws   → echo round-trip
# gRPC       (via the grpc server block)
#   grpcurl -insecure <vip>:443 mock.Echo/Say
# Raw TCP    (CONNECT tunnel)
#   per tests/protocols/

# Fleet health — both/all nodes serving + one config version:
for n in 10.0.0.11 10.0.0.12 10.0.0.13; do
  curl -s http://$n:9443/healthz/ready -o /dev/null -w "$n ready %{http_code}\n"
  curl -s http://$n:9443/api/config | jq .version    # should match across nodes
done
```
Reuse the protocol smoke scripts in [`../tests/protocols/`](../tests/protocols/)
(01-http1 … 05-grpc) pointed at the VIP.

---

## 5. Multi-protocol mock upstream

The WAF proxies **HTTP/1.1, HTTP/2, WebSocket, gRPC, raw TCP** (and HTTP/3).
The bundled mock (`tests/hackathon/upstream/fast-upstream.go`) is HTTP-only —
extend it to a single Go binary that serves every family so each forwarding
path is exercised. Spec for the AI to build (`deploy/mock/mock-upstream.go`):

| Flag | Protocol | Behaviour |
|---|---|---|
| `--http :9991` | HTTP/1.1 + h2c | `GET /` 200 echo; `/api/health` 200; `/products`, `/login` (mirror the existing fast-upstream API surface so detector tests still work) |
| `--ws :9992` | WebSocket | upgrade + echo every frame back; close on `bye` |
| `--grpc :9993` | gRPC (HTTP/2) | a tiny `Echo` service: `rpc Say(EchoReq) returns (EchoResp)` returning the message |
| `--tcp :9994` | raw TCP | line echo (for CONNECT-tunnel / `scheme:tcp` upstreams) |

- Single static binary (`go build`), no deps beyond `google.golang.org/grpc`
  + `nhooyr.io/websocket` (or gorilla). Logs each connection's protocol so
  you can confirm the WAF routed correctly.
- Keep the existing `:9999` HTTP fast-upstream for the 5k-RPS stress runs;
  the multi-protocol mock is for *coverage*, not throughput.
- Wire WAF routes/pools (one per protocol) via the dashboard or profile:
  `/` → http pool, `/ws` → ws pool (`scheme: auto`), `/grpc` → grpc pool
  (`scheme: grpc`), a `scheme: tcp` route for the raw-TCP tunnel.

> I can implement this mock as a follow-up — say the word.

---

## 6. Operate

- **Scale out:** boot another node with a new `node.id` + the same Redis;
  add its `:8080` to the nginx `upstream` block; `nginx -s reload`.
- **Drain a node** (zero-drop): `curl -X POST http://<node>:9443/admin/drain`
  → readiness flips 503 → nginx ejects it after `fail_timeout` → stop the
  process. (See [`GUIDE.md`](./GUIDE.md) §3.)
- **Rolling upgrade:** drain → replace binary → start → wait `/healthz/ready`
  200 → next node. Config plane keeps policy consistent across mixed versions
  during the roll.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All traffic attributed to one IP; mass false blocks | nginx→WAF hop not RFC1918, or XFF not injected | put the hop on a private net; set `proxy_set_header X-Forwarded-For` |
| Bind `Address already in use` | a WAF already on the ports | stop it first (`make restart-copilot` locally; `systemctl restart` on a node) |
| `port 6379 already allocated` | a Redis already running | reuse it; don't start a second |
| Nodes show different `/api/config` versions | a node can't reach Redis | check `state.redis.urls` + firewall; node falls back to local-only |
| JA3/JA4 fingerprint always empty | TLS terminated at nginx (L7) | expected in L7 topology — use edge-direct if fingerprinting is scored |
| gRPC 502 through nginx | `proxy_pass` used for gRPC | use a `grpc_pass` server block on its own port |

---

## 8. AI-assistant execution checklist

1. Provision infra host: Redis (private), multi-protocol mock (§5), SigNoz
   (`make signoz-up`), nginx (§2.4) with TLS cert + the XFF headers.
2. For each WAF node: deploy binary + `prod-balanced.yaml`, set
   `WAF_NODE__ID` (unique), `WAF_STATE__REDIS__URLS`, OTLP endpoint; start;
   confirm `/healthz/ready` 200.
3. Wire the upstream pools (one per protocol) **once** via the dashboard /
   `PUT /api/config`; confirm `/api/config` version matches on all nodes.
4. Add every node's `:8080` to nginx `upstream`; reload nginx.
5. Run §4 verification — **especially the two-source client-IP check** and a
   per-protocol smoke (`tests/protocols/`).
6. Confirm spans from all `node.id`s land in SigNoz and Prometheus metrics
   aggregate fleet-wide.

**Stop-and-ask gates:** TLS strategy (L7 vs edge-direct), whether to enable
the copilot (external LLM egress), and the public exposure of any port other
than nginx `:443`.
