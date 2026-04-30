# HA test methodology — what we measure today, what we don't

> **Status:** known gap. The current cluster perf harness
> drives traffic at each node *separately* on a different
> port; that's not how production HA works. This doc names
> the gap explicitly and proposes three concrete next steps,
> ordered cheapest → highest fidelity.

## What the run-04 (and earlier) cluster smoke actually tests

```text
                     k6 (single client, runs sequentially)
                            │
            ┌───────────────┴───────────────┐
            │                               │
            ▼                               ▼
   WAF node A :8080                 WAF node B :8090
            │                               │
            └────────────┬──────────────────┘
                         ▼
              shared Redis :6379
              shared aegis-httpbin :8081
```

Concretely:

1. `tests/cluster/run-all.sh` brings up node A on `:8080` /
   `:9443` and node B on `:8090` / `:9543`.
2. The k6 baseline test runs 15 s against `:8080`, then
   another 15 s against `:8090`.
3. Each node hits its **own** `IpRateLimiter` budget
   (10 000 req / 60 s, by design — see
   [`docs/security/rate-limiting.md`](../../docs/security/rate-limiting.md)).
4. Both nodes share one Redis primary, so `LeaderView` +
   named-bucket sliding limiters + block lists are observed
   across the cluster.

This proves a useful slice — the gateway is wire-compatible
with itself in cluster mode, two nodes can coexist against
the same Redis, and per-node performance is identical
(±1 % on RPS, ±10 % on p95 latency in run-04). But it does
**not** measure what an operator running a real fleet
cares about.

## What this does NOT measure

| Real-world property | Why the current harness misses it |
|---|---|
| **Single-endpoint throughput** | Clients in prod hit one VIP / DNS name; a load balancer distributes. We measure each node's ceiling in isolation. |
| **LB-to-WAF connection reuse** | An L4 LB opens a small pool of long-lived connections to each backend; the WAF sees N persistent peers, not N × 200 short-lived k6 VUs. The hot-path code paths exercised differ (keep-alive, idle close, half-close). |
| **Cross-node session continuity** | If node A dies mid-flight, an L4/L7 LB transparently shifts new conns to node B. Our test stops talking to A, then talks to B *separately* — there is no "mid-burst failover" signal. |
| **Sticky-session behaviour** | Many enterprise LBs hash on `X-Forwarded-For` or a cookie so a client keeps hitting the same backend. We can't measure stick rate or cache-hit ratio under that pattern. |
| **Connection pool exhaustion under cluster** | Real fleets hit upstream pools, not a single httpbin. With both nodes pulling from the same upstream pool, p99 tail latency depends on shared upstream queue depth — invisible here. |
| **Cluster-aware rate-limit semantics** | The test's per-IP load (200 VUs from `127.0.0.1`) saturates each node's local budget; with one LB in front, the load fans out and a single source IP would be rate-limited *cluster-wide* via the named-bucket limiter we documented for that purpose. |
| **Real partition tolerance under live load** | Test 04 stops the Redis container while the cluster is idle. A real partition happens at p99 traffic and the failover budget includes draining in-flight requests. |

## How to make it better — three options, ranked

### Option 1 — DNS round-robin (cheapest, lowest fidelity)

Add an `aegis-cluster-dns` entry (or `/etc/hosts` line) that
resolves `aegis-cluster.local` to both `127.0.0.1:8080`
and `127.0.0.1:8090`. k6 hits the hostname; the per-iteration
DNS resolution alternates ports.

```text
    k6 ─▶ aegis-cluster.local ─▶ {127.0.0.1:8080, :8090}
```

| Pros | Cons |
|---|---|
| Zero new infrastructure. | Doesn't reuse L4 connections — every iteration re-resolves DNS. |
| Drives both nodes from a single client config. | No mid-burst failover (DNS TTL caching defeats fast cutover). |
| 15 minutes to wire. | Doesn't model sticky sessions or LB hashing. |

Use when: you only need to demonstrate that traffic can
*reach* the cluster through one logical endpoint, not how
the LB distributes under load.

### Option 2 — HAProxy / Nginx / Envoy in front (recommended)

Drop a dedicated LB container into
`deploy/docker-compose.dev.yml`:

```yaml
services:
  aegis-lb:
    image: haproxy:2.9-alpine
    container_name: aegis-lb
    ports:
      - "9080:80"     # plaintext data plane
      - "9443:443"    # TLS data plane (with cert mounted)
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - aegis-redis
```

`haproxy.cfg`:

```text
defaults
  mode http
  timeout connect 5s
  timeout client  60s
  timeout server  60s

frontend in
  bind *:80
  bind *:443 ssl crt /certs/cluster.pem alpn h2,http/1.1
  default_backend cluster

backend cluster
  balance roundrobin
  option httpchk GET /healthz/live
  http-check expect status 200
  server nodeA  host.docker.internal:8080 check
  server nodeB  host.docker.internal:8090 check
```

Then point k6 at `http://aegis-lb:80` instead of node-specific
ports. The new behaviour we'd be able to measure:

- Both nodes serve every test, traffic genuinely fans out.
- HAProxy's health-check pulls a node out within `httpchk
  inter` ms when it dies; k6 sees a brief surge of
  retries, not a hard cutover. **This is the failover
  budget that matters in prod.**
- Connection pool: HAProxy keeps a small N of long-lived
  upstream connections; k6's 200 VUs go through the LB's
  multiplex.
- Sticky-session probes: flip `balance` to `source` (hash
  by client IP) and re-run; both nodes still receive
  traffic because docker NAT obscures the client IP, but
  enterprise tests with real clients would see stick.

| Pros | Cons |
|---|---|
| Production-realistic LB behaviour. | One more container in `deploy/`. |
| First-class failover semantics (drain, retry, pool). | Need to maintain `haproxy.cfg`. |
| Sticky-session + health-check coverage. | TLS termination becomes a HAProxy concern (or operate end-to-end TLS to backends). |

Use when: you want to publish HA SLOs (failover < N ms,
single-flow throughput, sticky-session correctness).
**This is the recommended next step.**

### Option 3 — `SO_REUSEPORT` on a single bind address (highest fidelity, most invasive)

Make both `waf` processes bind the **same** `127.0.0.1:8080`
with `SO_REUSEPORT`. The Linux kernel hashes incoming
connections across the two sockets. k6 hits a single
endpoint and sees per-flow stick (kernel-level), no LB
process at all.

This requires:

1. A small change in `aegis-proxy::run` to set
   `SO_REUSEPORT` on the listener (on Linux/macOS — both
   support it).
2. Operator opt-in via `listeners.data[*].reuse_port: true`
   in YAML so the default single-process semantics are
   preserved.
3. A coordination point so both nodes pick *different*
   admin ports automatically (or operator config picks them
   per node, as today).

| Pros | Cons |
|---|---|
| Zero LB hops — kernel-level distribution. | Requires real Linux semantics; macOS dev experience differs. |
| Lowest possible cluster latency (1 hop). | Doesn't model an external LB at all — bypasses the layer most operators run. |
| Trivial reverse proxy compatibility (looks like one server). | Adds a runtime knob and a small piece of platform-specific code. |

Use when: you want to measure best-case cluster RPS with
zero LB overhead. Realistic for some embedded / edge
deployments; not a substitute for option 2 in standard
fleets.

## Recommendation

**Land option 2 next.** It's the only option that produces
SLOs an operator can publish to their downstream
consumers ("failover < 500 ms, single-VIP throughput
> 50 k RPS"). Option 1 is a stop-gap when CI can't run
docker-compose. Option 3 is a follow-up for sites that
care about kernel-level distribution.

Concrete plan:

1. Add `aegis-lb` service to
   `deploy/docker-compose.dev.yml` with the HAProxy config
   above.
2. New `tests/cluster/05-single-vip-baseline.sh` — fires
   k6 at `aegis-lb` and asserts both backends served at
   least 30 % of traffic.
3. New `tests/cluster/06-mid-burst-failover.sh` — kills
   node B mid-`baseline.js`; asserts LB pulled it within
   `httpchk inter` and overall `allow_success` stays
   above the SLO.
4. Update
   [`run-04-2026-04-29-cluster-https/README.md`](../results/run-04-2026-04-29-cluster-https/README.md)
   with a follow-up run-05 once the LB-fronted topology
   is wired.

## Pointers

- [`plans/cluster-ingress-lb.md`](../../plans/cluster-ingress-lb.md)
  — the implementation plan that lands HA-T1..HA-T5 (HAProxy
  reference deploy + single-VIP load test + stable
  `node.id` + `peers[]` membership + LB-friendly readiness
  semantics). This is what closes the gap.
- [`docs/operations/ha-clustering.md`](../../docs/operations/ha-clustering.md)
  — the operator-facing spec for what HA mode is supposed to
  guarantee. §"Cluster topology" and §"Load balancer
  patterns" cover the three deployment shapes; §"Roadmap"
  ticks off as plan items land.
- [`tests/cluster/README.md`](./README.md) — the per-script
  contracts the current harness exercises.
- [`tests/results/run-04-2026-04-29-cluster-https/README.md`](../results/run-04-2026-04-29-cluster-https/README.md)
  — the run that exposed this gap (passes the smoke contract
  but doesn't model production traffic).
