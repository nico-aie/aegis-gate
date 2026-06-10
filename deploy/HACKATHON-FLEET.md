# Aegis-Gate — Multi-Node Fleet Deployment (HAProxy L4/TPROXY + WAF fleet)

> **Audience:** an AI assistant (or operator) standing up a production-shaped
> Aegis-Gate deployment — one **infra host** (Redis, multi-protocol mock
> upstream, SigNoz, **HAProxy load balancer**) and **N WAF nodes** behind the
> LB, sharing state via Redis. Built for the hackathon next-round simulation;
> the topology is the real production one.
>
> **LB choice:** **HAProxy in `mode tcp` with transparent proxying (TPROXY).**
> This is an **L4 passthrough** — HAProxy forwards raw TCP and **does not
> terminate TLS**, so the **WAF sits at the edge**: it terminates TLS (JA3/JA4
> fingerprinting works), inspects every protocol natively (h1/h2/ws/gRPC/raw
> TCP), and — thanks to TPROXY — sees the **real client IP** as the connection
> peer. No `X-Forwarded-For` trust games. The one cost is the TPROXY
> **return-routing** setup (§2.4). Other LB options + the rationale are in the
> [appendix](#appendix--load-balancer-options).
>
> **Read first:** [`GUIDE.md`](./GUIDE.md) §3, [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md),
> [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md),
> the shipped [`haproxy/haproxy.cfg`](./haproxy/haproxy.cfg) (a `mode http`
> reference — this doc uses `mode tcp`). **Verify claims against the running
> binary** — config schema moves.

---

## 0. Architecture

```
                ┌─────────────────── infra host ───────────────────┐
  clients ─▶ HAProxy :443 ──┐  (mode tcp, transparent / TPROXY)     │
   (raw TCP,  preserves     │   Redis (:6379)   ← shared state      │
    TLS intact) client IP   │   mock upstream   (http/ws/grpc/tcp)  │
                            │   SigNoz / OTel collector (:4317)     │
                            └───────────────────────────────────────┘
                            │ private net; HAProxy spoofs client src IP
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          WAF node A     WAF node B     WAF node C   ← terminate TLS on :8443
              │  (real client IP as peer; JA3/JA4 ✓; all protocols native)
              └──────┬──────┴──────┬──────┘   all → Redis (state + config plane + leases)
                     │  return path routes back THROUGH HAProxy (§2.4)
                     ▼
              mock upstream (infra host)
```

> ### ⭐ If JA3/JA4 is a hard requirement (with or without an LB)
> JA3/JA4 are computed from the **client's TLS ClientHello**, so **the WAF
> must terminate TLS itself** — anything that terminates TLS *before* the WAF
> (any L7 LB: nginx, Caddy, Traefik, HAProxy `mode http`, cloud ALB,
> Cloudflare) makes the WAF see the LB's TLS and **fingerprinting is gone**.
> The WAF cannot currently read a fingerprint from a header either.
>
> **Therefore, to keep JA3/JA4:**
> - **No LB** (single node, or **DNS round-robin** across WAF IPs) — the WAF
>   is the edge → JA3/JA4 + real client IP **natively**. Simplest.
> - **With an LB** — use an **L4 / TCP-passthrough LB that preserves the
>   client source IP**: **HAProxy `mode tcp` + TPROXY** (this guide), a
>   **cloud L4 NLB** with client-IP preservation, or **IPVS-DR / Cilium**.
>   The LB forwards raw TLS bytes → the WAF terminates TLS → JA3/JA4 works.
> - **Never an L7 LB** here, and **don't** let the LB "handle ACME" by
>   terminating TLS (that's the L7 path). The cost of staying at the edge is
>   the cert story: the WAF terminates TLS on every node, so **provision certs
>   out-of-band + set `tls.acme.auto_renew: false`** (§3.1) — or single-node
>   ACME when there's no LB.

### Why this topology (and what changes vs an L7 LB)

Aegis-Gate is *itself* a full L7 security reverse proxy. With an **L4
passthrough** LB it does the L7 work (the LB stays dumb), which means:

- **TLS terminates at the WAF** → JA3/JA4 + h2/h3 fingerprinting all work
  (they're impossible behind an L7 LB that re-terminates).
- **Every protocol passes through transparently** — `mode tcp` doesn't parse
  HTTP, so HTTP/1.1, HTTP/2, WebSocket, gRPC, and raw TCP all reach the WAF
  intact with **zero per-protocol LB config**. (HTTP/3 is UDP/QUIC — see the
  note below.)
- **Client IP is the real client** (TPROXY spoofs the source on the backend
  connection), so per-IP rate-limit / risk / DDoS key on the true client. No
  `X-Forwarded-For` and no trusted-proxy concern — the WAF's peer *is* the
  client. (Certs move to the WAF nodes; HAProxy holds none.)

### The three things to get right

1. **TPROXY return routing (the one real cost).** With `source 0.0.0.0
   usesrc clientip`, HAProxy connects to a WAF node using the **client's**
   source IP. The WAF's reply is therefore addressed to the client — it
   **must route back through the HAProxy host**, or the client sees a reply
   from the WAF's IP (not the VIP) and the connection breaks. Fix with one of
   (§2.4): (a) WAF nodes use the HAProxy host as their **default gateway**, or
   (b) **policy routing** on the WAF nodes that sends reply traffic via
   HAProxy, or (c) a **docker-compose** network where the HAProxy container is
   the WAF containers' gateway (easiest for the sim).

2. **HTTP/3 / QUIC is UDP** — `mode tcp` is TCP-only, so h3 isn't balanced by
   this HAProxy. For the sim, test h3 **directly against a WAF node** (the
   WAF's h3 listener needs `--features http3`), or add a separate UDP LB
   (LVS/nftables) later. h1/h2/ws/gRPC/raw-TCP are all TCP and covered.

3. **Redis is a single point of failure** here. Fine for the sim; for real
   prod use Redis Sentinel/Cluster + `state.redis.urls[]`. On a Redis
   partition the WAF degrades to local-only (block-list union + local
   counters) — survivable, but cross-node coordination pauses while down.

---

## 1. Host inventory

| Host | Role | Listens (all private except HAProxy :443) |
|---|---|---|
| `infra` | HAProxy LB + Redis + mock upstream + SigNoz | `:443` public VIP; `:6379` `:999x` `:4317` private |
| `waf-a/b/c` | Aegis-Gate (terminates TLS) | data `:8080`/`:8443`, admin `:9443` (private) |

Only HAProxy `:443` is public. Admin `:9443` is never exposed publicly
(`/__waf_control/*` is loopback-gated; the dashboard is for operators on the
private net / VPN). Certs live on the **WAF nodes** now (HAProxy passes TLS
through) — provision them in the profile or via the WAF's ACME.

---

## 2. Phase 1 — infra host

### 2.1 Redis (shared state, config plane, leases)
```sh
docker run -d --name aegis-redis --restart unless-stopped \
  -p <private-ip>:6379:6379 redis:7-alpine \
  redis-server --save 60 1 --appendonly yes
# bind 6379 to the PRIVATE interface only; firewall it off the public NIC.
```

### 2.2 Multi-protocol mock upstream
See [§5](#5-multi-protocol-mock-upstream). Build + run:
```sh
(cd deploy/mock && go build -o /usr/local/bin/aegis-mock .)   # or: make mock-build
aegis-mock --http :9991 --ws :9992 --grpc :9993 --tcp :9994 &
```

### 2.3 Observability — SigNoz on the infra host
```sh
make signoz-up           # ClickHouse + collector (:4317) + UI; onboard the admin org first
# every WAF node points WAF_OBSERVABILITY__OTEL__ENDPOINT at infra:4317
```
Import [`signoz/dashboards/waf-overview.json`](./signoz/README.md) after
onboarding. **Sizing caveat:** SigNoz is heavy (ClickHouse). Co-located with
the public LB it can add latency under ingest spikes — give the infra host
≥ 4 vCPU / 8 GB SSD, or put SigNoz on its own box. `:4317` stays private.

### 2.4 HAProxy — `mode tcp` + transparent (TPROXY)

`/etc/haproxy/haproxy.cfg`:
```haproxy
global
    log stdout format raw local0 info
    maxconn 16384
    # TPROXY (spoofing the client source IP) needs CAP_NET_ADMIN/RAW.
    # Run as root, OR: setcap cap_net_admin,cap_net_raw+ep /usr/sbin/haproxy

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 5s
    timeout client  60s
    timeout server  60s
    retries 2

# ── TLS VIP (passthrough — the WAF terminates TLS on :8443) ──
frontend tls_in
    bind *:443
    default_backend waf_tls

backend waf_tls
    balance leastconn                 # right for keep-alive / h2 clients
    source 0.0.0.0 usesrc clientip    # TPROXY: connect to WAF as the client IP
    # Health-check the WAF's readiness over HTTP on the ADMIN port, while
    # traffic flows to the data TLS port:
    option httpchk GET /healthz/ready
    server waf-a 10.0.0.11:8443 check port 9443 inter 2s fall 2 rise 2
    server waf-b 10.0.0.12:8443 check port 9443 inter 2s fall 2 rise 2
    server waf-c 10.0.0.13:8443 check port 9443 inter 2s fall 2 rise 2

# ── (optional) plaintext VIP → WAF :8080, same transparent pattern ──
frontend http_in
    bind *:80
    default_backend waf_http
backend waf_http
    balance leastconn
    source 0.0.0.0 usesrc clientip
    option httpchk GET /healthz/ready
    server waf-a 10.0.0.11:8080 check port 9443 inter 2s fall 2 rise 2
    server waf-b 10.0.0.12:8080 check port 9443 inter 2s fall 2 rise 2
    server waf-c 10.0.0.13:8080 check port 9443 inter 2s fall 2 rise 2

# raw-TCP / any other protocol port: add another frontend/backend pair —
# mode tcp forwards anything (e.g. a :5000 frontend → WAF tcp upstream).
```

**Host prep on the HAProxy box:**
```sh
sysctl -w net.ipv4.ip_nonlocal_bind=1     # allow binding the spoofed client IP
# grant the caps (or run haproxy as root):
setcap cap_net_admin,cap_net_raw+ep "$(command -v haproxy)"
```

**Return routing — pick ONE (this is the TPROXY requirement):**
- **(a) Default gateway** — set each WAF node's default route to the HAProxy
  host. Replies to the (spoofed) client IP then traverse HAProxy, which
  restores the VIP connection. Simplest on VMs you control.
- **(b) Policy routing** on each WAF node — mark the WAF's reply traffic and
  route it via HAProxy:
  ```sh
  ip rule add fwmark 0x1 lookup 100
  ip route add default via <haproxy-private-ip> dev <iface> table 100
  iptables -t mangle -A OUTPUT -p tcp --sport 8443 -j MARK --set-mark 0x1
  iptables -t mangle -A OUTPUT -p tcp --sport 8080 -j MARK --set-mark 0x1
  ```
- **(c) docker-compose (easiest for the sim)** — put the WAF containers on a
  user-defined network whose **gateway is the HAProxy container**; return
  traffic flows through it automatically. No host routing changes.

> If TPROXY routing is impractical in your environment, fall back to **DNS
> round-robin** (no LB in the path — WAF nodes are the edge, real client IP,
> JA3/JA4, all protocols; coarse balancing, DNS-TTL failover). See the
> appendix.

---

## 3. Phase 2 — WAF nodes (now the TLS edge)

Same binary + base profile (`config/profiles/prod-balanced.yaml`), differing
by `node.id` + the shared Redis, via the `WAF_…__…` env overlay:

```sh
# waf-a  (repeat on b/c with a unique NODE id)
WAF_NODE__ID=waf-a \
WAF_STATE__BACKEND=redis \
WAF_STATE__REDIS__URLS='["redis://10.0.0.10:6379"]' \
WAF_OBSERVABILITY__OTEL__ENDPOINT=http://10.0.0.10:4317 \
LLM_API_KEY="$(cat /etc/aegis/llm.key)"   # only if copilot enabled \
  ./waf run --config config/profiles/prod-balanced.yaml
```

Per-node requirements:
- **Unique `node.id`** — surfaces in `/api/cluster.our_node`, the `members:<id>`
  heartbeat, per-node ACK, and fleet snapshots. Duplicates corrupt the cluster
  view. The cluster is **leaderless** — every node is equal.
- **Same `state.redis.urls`** on every node — that's what makes one fleet
  (shared rate-limit, per-task leases, **config plane**, block-list union,
  fleet events + merged metrics).
- **TLS certs on the node** (the WAF now terminates TLS): the profile's
  `tls.certificates`, or the WAF's ACME. HAProxy holds no certs.
- **Upstream pools** point at the infra mock (`10.0.0.10:9991` etc.) — set in
  the profile or once via the dashboard (config plane propagates to all).
- Bind admin to the **private** interface; never expose `:9443` publicly.
- Ensure the **return route** (§2.4) is in place so TPROXY replies work.

### 3.1 TLS certificates across the fleet (ACME caveat — read this)

In this topology every WAF node terminates TLS, so **every node needs the
cert**. The WAF's built-in ACME is **not fleet-aware** (verified in code):

- It's **HTTP-01 only** and runs on **one node** (whichever holds the `acme`
  task lease — a leaderless distributed mutex, *not* a cluster leader), the
  challenge token lives in an **in-process** store, and the issued cert is
  persisted **locally on that node**.
- Behind an **L4 (`mode tcp`) LB this breaks two ways:** (1) the CA's
  `http://domain/.well-known/acme-challenge/<token>` request is round-robined
  and may hit a **different node** that doesn't have the token → validation
  fails (and L4 can't path-route the challenge to the renewing node); (2) even
  when that node renews, the new cert is **not distributed** to the others,
  which keep serving the old one.

**So: don't rely on in-WAF ACME in a load-balanced fleet.** Pick one:

- **(Recommended for the sim) Provision one shared cert on all nodes.** Issue
  a wildcard / multi-SAN cert out-of-band (certbot/cert-manager on the infra
  host, or self-signed for the sim) and deploy the **same** PEM to every WAF
  node via `tls.certificates` (or a `${secret:...}` ref). Renew out-of-band
  and re-push. No single-renewer node, no challenge routing, no distribution problem.
- **Terminate TLS at the LB instead** — only if you switch to HAProxy
  `mode http` (L7), which gives one cert in one place + LB-side ACME, **but
  loses JA3/JA4** (you're no longer at the edge). Conflicts with this guide's
  goal; listed for completeness.
- **(Roadmap) Redis-backed ACME** — the lease-holding node renews, writes the
  challenge token **and** the issued cert to Redis; the other nodes serve the
  challenge + hot-load the cert. The right fleet design, **not implemented today**.

**Turn the in-WAF renewal off explicitly:** set `tls.acme.auto_renew: false`
(2026-06). The WAF then **never contacts the ACME directory** — it only serves
certs you provision via `tls.certificates` — and logs a boot NOTICE. Use this
for any of the above (LB-terminated TLS, or out-of-band issuance) so a doomed
renewal loop doesn't run on the lease-holding node. Default is `true` (single-node / edge
keeps auto-renewing); a **load-balanced fleet should set it `false`** (or omit
the `tls.acme` block entirely).

```yaml
tls:
  acme:
    auto_renew: false        # LB / out-of-band owns ACME; WAF only loads provisioned certs
  certificates:
    - cert: "${secret:file:/etc/aegis/fullchain.pem}"
      key:  "${secret:file:/etc/aegis/privkey.pem}"
```

**Two ways to "let the LB handle ACME":**
- **LB terminates TLS (L7).** If you front the fleet with an **L7** LB
  (Caddy / Traefik — both auto-ACME; or HAProxy `mode http` / nginx + certbot;
  or a cloud LB with managed certs), the LB owns the cert + renewal, and the
  WAF receives plaintext on `:8080` (no `tls.acme`, no `tls.certificates`).
  **This is the simplest cert story** — one cert at the edge, renewal
  automatic. ⚠️ **But it's no longer `mode tcp` passthrough**: the WAF is not
  at the TLS edge, so **JA3/JA4 fingerprinting is off** (the §0 trade-off).
- **LB host issues out-of-band, WAF still terminates TLS (keeps `mode tcp` +
  JA3/JA4).** Run certbot/cert-manager on the infra host (it owns `:80` for
  the challenge, or uses DNS-01), then push the same PEM to every WAF node
  (`tls.certificates`) and set `auto_renew: false`. Keeps fingerprinting;
  costs you a cert-distribution step on renewal.

> **Does one node "need to renew"?** Yes — ACME renewal runs on a single node
> (the `acme` task-lease holder) — but that renewal **alone is not sufficient**
> in a fleet (challenge routing + cert distribution gaps above). For the sim, a
> shared provisioned cert sidesteps all of it.

> **Should HAProxy live on a WAF node?** **No.** The cluster is leaderless, but
> the `acme` task-lease holder is still **dynamic** (the Redis lease moves on
> restart), so pinning the LB to "the renewing node" breaks the moment the lease
> shifts. Co-locating the LB with a WAF node also couples lifecycles
> (draining/upgrading that node takes the whole fleet's ingress down) and
> contends for resources. **Keep HAProxy on the infra host, independent of every
> WAF node**, and solve certs with a shared provisioned cert (above) — not by
> moving the LB.

### Config once, converge everywhere
With shared Redis, edit detectors / rules / tiers / **upstream pools** /
AI-toggle on **any** node (dashboard or `PUT /api/config`) — it converges on
every node within ~3 s (or ms with `cluster.pubsub_nudge`), surviving restart.
**Don't hand-edit each node's YAML.** See [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md).

### Cross-node console sync (leaderless)
Every node's dashboard shows the **whole fleet**, so an operator hitting any node
(or a VS Code port-forward) sees the same picture:
- **Live events** — `cluster.fleet_events.enabled`: each node's security
  decisions fan out via Redis pub/sub to every node's SSE feed (≤ 5 s SLA).
- **Merged traffic metrics** — `cluster.fleet_view.enabled`: RPS / latency
  percentiles / top-attackers / by-detector / bot-mix merged across nodes;
  `/api/stats` carries `fleet_nodes` and the banner shows "Fleet view (N nodes)".
- **`cluster.pubsub_nudge`** — control changes converge in ms.
- **`/api/cluster`** — flat leaderless roster (`peers` + `our_node`).
- Forensic audit stays per-node; merge with [`collect-audit.sh`](./collect-audit.sh)
  (orders by `ts_ms`, joins by `request_id`). The live event feed is a lossy
  monitor — local `waf_audit.log` + SigNoz remain the source of truth.

See [`config/REFERENCE.md`](../config/REFERENCE.md) §`cluster` +
[`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).

---

## 4. Phase 3 — verification (per protocol)

From a client *outside* the private net, through the HAProxy VIP:

```sh
VIP=https://<infra-public-ip>

# HTTP/1.1 + HTTP/2 (WAF terminates TLS → JA3/JA4 captured)
curl -k  $VIP/                       # 200 from the mock (allowed)
curl -k --http2 $VIP/api/health

# Client-IP correctness — the make-or-break check (TPROXY edition):
#   the WAF's peer IP MUST be your real client IP, not the HAProxy IP.
curl -k "$VIP/?q=1'%20OR%20'1'='1"   # SQLi from client X → 403 block
#   then from a DIFFERENT client → still 200 (only X accrued risk).
#   Confirm on a node: GET /api/top-attackers shows real client IPs, not 10.0.0.10.

# WebSocket   wscat -c wss://<vip>/ws        → echo round-trip
# gRPC        grpcurl -insecure <vip>:443 mock.Echo/Say
# raw TCP     nc <vip> 5000                  → line echo (if a tcp frontend is wired)
# HTTP/3      test directly against a WAF node (UDP not via HAProxy tcp)

# Fleet health — all nodes serving + one config version:
for n in 10.0.0.11 10.0.0.12 10.0.0.13; do
  curl -s http://$n:9443/healthz/ready -o /dev/null -w "$n ready %{http_code}\n"
  curl -s http://$n:9443/api/config | jq .version     # equal across nodes
done
```
Reuse [`../tests/protocols/`](../tests/protocols/) (01-http1 … 05-grpc)
against the VIP.

---

## 5. Multi-protocol mock upstream

The WAF proxies **HTTP/1.1, HTTP/2, WebSocket, gRPC, raw TCP** (and HTTP/3).
The bundled mock (`tests/hackathon/upstream/fast-upstream.go`) is HTTP-only —
extend it to one Go binary serving every family. **Built:** [`mock/`](./mock/)
(`make mock-build`):

| Flag | Protocol | Behaviour |
|---|---|---|
| `--http :9991` | HTTP/1.1 + h2c | `GET /` 200 echo; `/api/health` 200; mirror the existing fast-upstream API surface (`/login`, `/products`) so detector tests still fire |
| `--ws :9992` | WebSocket | upgrade + echo every frame; close on `bye` |
| `--grpc :9993` | gRPC (HTTP/2) | `Echo` service: `rpc Say(EchoReq) returns (EchoResp)` returns the message |
| `--tcp :9994` | raw TCP | line echo (for `scheme:tcp` / CONNECT-tunnel upstreams) |

- Single static binary (`go build`); deps `google.golang.org/grpc` +
  `nhooyr.io/websocket` (or gorilla). Log each connection's protocol so you
  can confirm the WAF routed correctly.
- Keep the `:9999` HTTP fast-upstream for 5k-RPS stress; this mock is for
  *coverage*.
- Wire one WAF route/pool per protocol (dashboard or profile): `/` → http,
  `/ws` → ws (`scheme: auto`), `/grpc` → grpc (`scheme: grpc`), a `scheme:
  tcp` route for raw TCP.

Per-path verification + the gRPC `echo.proto` are in [`mock/README.md`](./mock/README.md).

---

## 6. Operate

- **Scale out:** boot a node with a new `node.id` + same Redis + return route;
  add its `:8443` to the HAProxy backend; `systemctl reload haproxy`.
- **Drain (zero-drop):** `curl -X POST http://<node>:9443/admin/drain` →
  readiness 503 → HAProxy ejects after `fall` checks → stop the process.
- **Rolling upgrade:** drain → replace binary → start → wait `/healthz/ready`
  200 → next node. Config plane keeps policy consistent across mixed versions.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| WAF sees all traffic from the HAProxy IP (mass false blocks) | `source … usesrc clientip` missing, or caps not granted | add the `source` line; `setcap cap_net_admin,cap_net_raw+ep haproxy` or run as root |
| Connections hang / client gets RST after handshake | **return routing** not set — WAF replies bypass HAProxy | set WAF default gw to HAProxy, or policy-route (§2.4 a/b), or use the docker-gateway pattern (c) |
| HAProxy can't bind spoofed IP | `ip_nonlocal_bind` off | `sysctl -w net.ipv4.ip_nonlocal_bind=1` |
| TLS errors at the client | certs on the wrong host | certs live on the **WAF nodes** now (HAProxy passes TLS through) |
| HTTP/3 not balanced | h3 is UDP; `mode tcp` is TCP-only | test h3 against a node directly, or add a UDP LB |
| Nodes show different `/api/config` versions | a node can't reach Redis | check `state.redis.urls` + firewall; node falls back to local-only |
| Bind `Address already in use` | a WAF already on the ports | stop it first (`systemctl restart`, or `make restart-copilot` locally) |

---

## 8. AI-assistant execution checklist

1. Infra host: Redis (private), multi-protocol mock (§5), SigNoz
   (`make signoz-up` + onboard), HAProxy `mode tcp` + TPROXY (§2.4) with
   `ip_nonlocal_bind=1` + caps.
2. **Return routing**: pick (a) gateway / (b) policy route / (c) docker
   gateway so WAF replies traverse HAProxy. **Verify before traffic.**
3. Each WAF node: deploy binary + `prod-balanced.yaml` + TLS certs; set
   `WAF_NODE__ID` (unique) + `WAF_STATE__REDIS__URLS` + OTLP endpoint; start;
   confirm `/healthz/ready` 200.
4. Wire upstream pools (one per protocol) **once** via the dashboard /
   `PUT /api/config`; confirm `/api/config` version matches on all nodes.
5. Add every node's `:8443` (+`:8080`) to the HAProxy backends; reload.
6. Run §4 verification — **especially the client-IP check** (WAF peer = real
   client, not the HAProxy IP) and a per-protocol smoke.
7. Confirm spans from all `node.id`s in SigNoz + fleet-wide Prometheus.

**Stop-and-ask gates:** TPROXY return-routing method, enabling the copilot
(external LLM egress), and exposing any port other than HAProxy `:443`.

---

## Appendix — load balancer options

For a WAF (itself an L7 security proxy), an **L4 / TCP-passthrough LB that
preserves the client source IP** lets the WAF be the edge → real client IPs +
JA3/JA4 + every protocol, no per-protocol config. The WAF has **no
PROXY-protocol** and trusts XFF only from RFC1918, so an L4 LB must preserve
the source IP at L3 (DSR / TPROXY / `externalTrafficPolicy: Local` / cloud
client-IP preservation) — an L4 LB that **SNATs** hides the client.

| Option | Layer | Client IP | JA3/JA4 | Multi-proto | Notes |
|---|---|---|---|---|---|
| **HAProxy `mode tcp` + TPROXY** ← *this guide* | L4 | ✅ real | ✅ | ✅ (TCP) | needs return routing; h3/UDP separate |
| Cloud L4 NLB (AWS NLB / GCP TCP LB / Azure LB) w/ client-IP preservation | L4 | ✅ | ✅ | ✅ | simplest on cloud |
| IPVS/LVS (DR) or Cilium (DSR) | L4 | ✅ | ✅ | ✅ | best bare-metal perf |
| DNS round-robin (no LB in path) | — | ✅ | ✅ | ✅ | simplest sim; coarse balance; DNS-TTL failover |
| HAProxy `mode http` (shipped cfg) | L7 | ⚠ XFF (private hop) | ❌ | h1/ws/gRPC | active health checks; re-terminates |
| Envoy / Traefik | L7 | ⚠ XFF | ❌ | best L7 | heavier / k8s-native |
| nginx | L7 | ⚠ XFF | ❌ | per-family blocks | `proxy_pass` downgrades h2→h1; gRPC needs `grpc_pass`; `stream{}` SNAT loses client IP |
| **Cloudflare / managed edge** | L7 | ⚠ public edge IP (XFF untrusted by WAF; uses `CF-Connecting-IP`) | ❌ | ✅ | it's a *second* WAF + breaks Aegis per-IP today (trusted-proxy + `CF-Connecting-IP` are roadmap gaps). Not for this fleet |
