# Data plane (M1)

Everything in the request path: listening, routing, upstream
selection, TLS, traffic management. Owner: **M1** —
[`plans/archive/proxy.md`](../../plans/archive/proxy.md).

## Request flow (suggested reading order)

1. [reverse-proxy.md](./reverse-proxy.md) — listener + the full
   per-request stage pipeline
2. [routing-ingress.md](./routing-ingress.md) — host + path table,
   longest-prefix-wins
3. [upstream-pools.md](./upstream-pools.md) — load balancing, health
   checks, circuit breaker
4. [traffic-management.md](./traffic-management.md) — canary, steering,
   shadow mirror, retries
5. [tls-termination.md](./tls-termination.md) — SNI, ACME, OCSP,
   FIPS, mTLS to upstream

## Reference

| Doc | Summary |
|---|---|
| [session-affinity.md](./session-affinity.md) | Sticky cookies + consistent-hash |
| [per-route-quotas.md](./per-route-quotas.md) | Body size, header, timeout limits |
| [transformations-cors.md](./transformations-cors.md) | Header / URL rewrites, CORS |
| [service-discovery.md](./service-discovery.md) | File / DNS / Consul / etcd / k8s |
| [smart-caching.md](./smart-caching.md) | Cache with security awareness |
| [sse-streaming.md](./sse-streaming.md) | SSE stream-through, idle timeout, concurrency cap |
| [adaptive-load-shedding.md](./adaptive-load-shedding.md) | Gradient2 + tier priority |
| [graceful-degradation.md](./graceful-degradation.md) | Circuit breakers, timeouts, fallback |
