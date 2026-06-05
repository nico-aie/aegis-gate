# Aegis-Gate — Concrete Deployment (3 VMs · Cloudflare DNS-only · DNS round-robin cluster)

> **Your setup:** a domain on Cloudflare (switch the WAF host to **DNS-only**),
> **3 VMs**. **Goal:** a 2-node WAF **cluster** serving **HTTPS / WS / gRPC /
> raw TCP** with the **full WAF feature set** (JA3/JA4, per-IP risk/rate-limit/
> DDoS, detectors, copilot, config plane).
>
> **Design (chosen):** Cloudflare grey-cloud (DNS-only) → **two A records**
> round-robin straight to the two WAF VMs, which are the **TLS edge**. One
> infra VM holds Redis + the multi-protocol mock + SigNoz. No L7 proxy, no
> HAProxy, no TPROXY — the WAF terminates TLS itself, so every core feature
> works. For the LB-in-front alternative (HAProxy `mode tcp` + TPROXY) and the
> full options matrix, see [`HACKATHON-FLEET.md`](./HACKATHON-FLEET.md). For
> image/systemd/Helm mechanics see [`GUIDE.md`](./GUIDE.md).
>
> **Why not Cloudflare proxy (orange cloud):** it terminates TLS at Cloudflare
> → no JA3/JA4, the real client lands in `CF-Connecting-IP` (which the WAF
> doesn't read), and raw TCP needs paid Spectrum. DNS-only keeps all of it.

---

## 0. Topology

```
                 Cloudflare DNS (grey / DNS-only)
                 waf.example.com  A → <VM2 public IP>
                 waf.example.com  A → <VM3 public IP>     ← round-robin
                          │                       │
              (client connects DIRECTLY; real client IP + TLS reach the WAF)
                          ▼                       ▼
                 VM2  waf-a  (TLS edge)    VM3  waf-b  (TLS edge)
                 :443 TLS / :80 / tcp      :443 TLS / :80 / tcp
                 admin :9443 (private)     admin :9443 (private)
                          └─────────┬─────────┘
                                    ▼  (private network)
                 VM1  infra:  Redis :6379 · mock (http/ws/grpc/tcp) · SigNoz :4317
                 both WAF nodes → VM1 Redis  ⇒ ONE cluster
                 (shared rate-limit · cumulative risk · config plane · leader lease ·
                  block-list union · fleet-wide metrics)
```

| VM | Role | Public | Private |
|---|---|---|---|
| **VM1** `infra` | Redis + multi-protocol mock + SigNoz | — (private only) | `10.0.0.10` |
| **VM2** `waf-a` | WAF cluster node (TLS edge) | `<VM2 public IP>` :443/:80/tcp | `10.0.0.11` |
| **VM3** `waf-b` | WAF cluster node (TLS edge) | `<VM3 public IP>` :443/:80/tcp | `10.0.0.12` |

Because clients hit the WAF **directly**, the connection peer **is the real
client** — JA3/JA4 + per-IP security work with no XFF/trusted-proxy concern.

---

## 1. Cloudflare DNS

In the Cloudflare dashboard for `example.com`:
1. Add **two A records** for the WAF host, **Proxy status = DNS only (grey
   cloud)**:
   - `waf` → `<VM2 public IP>`  · DNS only
   - `waf` → `<VM3 public IP>`  · DNS only
   (Two A records on the same name = client-side round-robin.)
2. Low **TTL** (e.g. 60s) so a removed node drains quickly (DNS-RR has no
   health checks — see §7).
3. Keep any *other* hostnames proxied (orange) if you want Cloudflare's CDN
   there; only the WAF host must be grey.
4. Create a **Cloudflare API token** scoped to `Zone:DNS:Edit` for `example.com`
   — used for **DNS-01** cert issuance (§3).

> **Trade-off you accepted:** grey-cloud exposes your origin IPs and forgoes
> Cloudflare's L3/4 DDoS scrubbing for this host. The WAF's own DDoS gate
> handles per-IP volumetric abuse, but can't absorb a large L3/4 flood like
> Cloudflare. For real prod, consider Cloudflare **Magic Transit/Spectrum**
> (keeps the WAF at the edge while restoring L3/4 protection).

---

## 2. Phase 1 — infra VM (VM1)

All on the **private** interface; firewall these off the public NIC.

```sh
# Redis — shared cluster state
docker run -d --name aegis-redis --restart unless-stopped \
  -p 10.0.0.10:6379:6379 redis:7-alpine \
  redis-server --save 60 1 --appendonly yes

# Multi-protocol mock upstream (§5) — or: make mock-build
(cd deploy/mock && go build -o /usr/local/bin/aegis-mock .)
aegis-mock --http :9991 --ws :9992 --grpc :9993 --tcp :9994 &

# SigNoz (onboard the admin org in its UI before expecting spans)
make signoz-up      # collector on 10.0.0.10:4317
```

---

## 3. Phase 2 — TLS certs (DNS-01 wildcard, issued centrally)

Each WAF node terminates TLS, so each needs the cert. With DNS round-robin,
inbound HTTP-01 is racy — use **DNS-01** (no inbound challenge, works
regardless of which node DNS picks). Issue once on VM1 and distribute:

```sh
# on VM1 — certbot with the Cloudflare DNS plugin
printf 'dns_cloudflare_api_token = <CF_API_TOKEN>\n' > /etc/letsencrypt/cf.ini
chmod 600 /etc/letsencrypt/cf.ini
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cf.ini \
  -d waf.example.com -d '*.example.com' --agree-tos -m ops@example.com

# distribute the SAME PEMs to both WAF nodes
for n in 10.0.0.11 10.0.0.12; do
  scp /etc/letsencrypt/live/waf.example.com/{fullchain,privkey}.pem aegis@$n:/etc/aegis/
done
```

On the WAF nodes, serve the provisioned cert and **disable in-WAF ACME**
(it can't reliably renew across a fleet — see [`HACKATHON-FLEET.md`](./HACKATHON-FLEET.md) §3.1):

```yaml
# config/profiles/prod-balanced.yaml (or an overlay) on each WAF node
tls:
  certificates:
    - cert: "${secret:file:/etc/aegis/fullchain.pem}"
      key:  "${secret:file:/etc/aegis/privkey.pem}"
  acme:
    auto_renew: false      # certbot on VM1 owns issuance/renewal
```

**Renewal:** `certbot renew` on VM1 (cron/timer) with a deploy-hook that
re-pushes the PEMs to both nodes; the WAF hot-reloads its cert store (or
restart the node). A wildcard cert means you only re-issue when it expires
(~60–90d), not per-node.

---

## 4. Phase 3 — WAF cluster nodes (VM2, VM3)

Same binary + profile; per-node values via the `WAF_…__…` env overlay:

```sh
# VM2 (waf-a) — repeat on VM3 with NODE id waf-b
WAF_NODE__ID=waf-a \
WAF_STATE__BACKEND=redis \
WAF_STATE__REDIS__URLS='["redis://10.0.0.10:6379"]' \
WAF_OBSERVABILITY__OTEL__ENDPOINT=http://10.0.0.10:4317 \
LLM_API_KEY="$(cat /etc/aegis/llm.key)"   # only if copilot enabled \
  ./waf run --config config/profiles/prod-balanced.yaml
```

Per-node requirements:
- **Unique `node.id`** (`waf-a`, `waf-b`) — leader lease + per-node ACK +
  metrics aggregation.
- **Same `state.redis.urls`** (VM1) on both → that's what makes them **one
  cluster** (shared rate-limit, risk, config plane, leases, block-list union).
- **Data listeners bind public** (`0.0.0.0:443` TLS, `0.0.0.0:80` redirect,
  + any raw-TCP port); **admin `:9443` binds private** (`10.0.0.1x`).
- **Upstream pools** point at the infra mock (`10.0.0.10:9991` etc.) — set once
  via the dashboard / `PUT /api/config`; the config plane propagates to both.

Run under systemd / the distroless image for production ([`GUIDE.md`](./GUIDE.md) §1–2).

### Firewall (the WAF VMs are now directly internet-facing)
| Port | Scope |
|---|---|
| `443` (TLS), `80` (redirect), any raw-TCP port | **public** (clients) |
| `9443` (admin), `6379` (Redis), `4317` (OTLP), mock ports | **private only** — never public |
Default-deny everything else (cloud security group / nftables / ufw).

### Config once, converge everywhere
Edit detectors / rules / tiers / upstream pools / AI-toggle on **either** node
(dashboard or `PUT /api/config`) → converges on both within ~3 s, surviving
restart + leader failover. Don't hand-edit each node's YAML.
See [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md).

---

## 5. Multi-protocol mock upstream

The WAF proxies HTTP/1.1, HTTP/2, WebSocket, gRPC, raw TCP (and HTTP/3).
**Built:** [`deploy/mock/`](./mock/) — one Go binary serving every family
(`make mock-build`, or `cd deploy/mock && go build -o aegis-mock .`):

| Flag | Protocol | Behaviour |
|---|---|---|
| `--http :9991` | HTTP/1.1 + h2c | `GET /` 200 echo; `/api/health`; mirror the `tests/hackathon/upstream/fast-upstream.go` API surface (`/login`, `/products`) so detectors still fire |
| `--ws :9992` | WebSocket | upgrade + echo each frame; close on `bye` |
| `--grpc :9993` | gRPC (HTTP/2) | `Echo` service: `Say(EchoReq) → EchoResp` |
| `--tcp :9994` | raw TCP | line echo (for `scheme:tcp` upstreams) |

Wire one WAF route/pool per protocol: `/` → http, `/ws` → ws (`scheme: auto`),
`/grpc` → grpc (`scheme: grpc`), a `scheme: tcp` route for raw TCP. Per-path
verification commands + the gRPC `echo.proto` are in
[`deploy/mock/README.md`](./mock/README.md).

---

## 6. Phase 4 — verification (per protocol, through the real domain)

```sh
# HTTP/1.1 + HTTP/2 (WAF terminates TLS → JA3/JA4 captured)
curl  https://waf.example.com/                 # 200 from the mock
curl --http2 https://waf.example.com/api/health

# JA3/JA4 + real-client-IP proof (the whole point):
#   send an attack, confirm Top Attackers shows YOUR real IP (not a CF/LB IP),
#   and that the AI/bot fingerprint columns are populated.
curl "https://waf.example.com/?q=1'%20OR%20'1'='1"   # SQLi → 403

# WebSocket   wscat -c wss://waf.example.com/ws
# gRPC        grpcurl waf.example.com:443 mock.Echo/Say
# raw TCP     nc waf.example.com <tcp-port>          # if a tcp route is wired
# HTTP/3      curl --http3 https://waf.example.com/  # needs --features http3

# Cluster health — both nodes serving, one config version, real client IPs:
for n in 10.0.0.11 10.0.0.12; do
  curl -s http://$n:9443/healthz/ready -o /dev/null -w "$n ready %{http_code}\n"
  curl -s http://$n:9443/api/config | jq .version          # equal on both
done
curl -s http://10.0.0.11:9443/api/top-attackers | jq '.[].ip'   # real client IPs
```
Reuse [`../tests/protocols/`](../tests/protocols/) against `waf.example.com`.

---

## 7. Operate

- **Failover (DNS-RR has no health checks):** if a node dies, ~half of new
  resolutions still hit it until you **remove its A record** in Cloudflare
  (fast with the 60s TTL). For automatic health-checked steering, add
  **Cloudflare Load Balancing** (DNS-based health checks over your two grey
  origins) — the hands-off upgrade to plain round-robin.
- **Scale out:** add VM4 with a new `node.id` + same Redis + cert; add a third
  A record. Done.
- **Drain (zero-drop):** remove the node's A record → wait one TTL →
  `curl -X POST http://<node>:9443/admin/drain` → stop the process.
- **Rolling upgrade:** drain one node, upgrade, wait `/healthz/ready` 200,
  re-add its A record, next node. Config plane keeps policy consistent.

---

## 8. AI-assistant execution checklist

1. **Cloudflare:** WAF host = two **DNS-only** A records (VM2, VM3), TTL 60s;
   create a `Zone:DNS:Edit` API token.
2. **VM1 infra:** Redis (private), multi-protocol mock (§5), SigNoz
   (`make signoz-up` + onboard).
3. **Certs:** DNS-01 wildcard via certbot-dns-cloudflare on VM1; push PEMs to
   both WAF nodes; profile sets `tls.certificates` + `acme.auto_renew: false`.
4. **VM2/VM3:** deploy binary + profile; `WAF_NODE__ID` (unique) +
   `WAF_STATE__REDIS__URLS` (VM1) + OTLP endpoint; data listeners public, admin
   private; start; confirm `/healthz/ready` 200 + matching `/api/config`
   version on both.
5. **Firewall:** public = 443/80/tcp-port only; private = 9443/6379/4317/mock.
6. **Wire upstream pools** (one per protocol) once via the dashboard /
   `PUT /api/config`.
7. **Verify** (§6) — per protocol + **real client IP + JA3/JA4 populated** +
   both nodes in SigNoz with fleet-wide metrics.

**Stop-and-ask gates:** exposing any private port publicly, enabling the
copilot (external LLM egress), and the DDoS posture (grey-cloud forgoes
Cloudflare's L3/4 scrubbing).
