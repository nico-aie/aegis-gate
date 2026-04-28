# Service Discovery (v2, new, optional)

> **New in v2 (optional).** Populate upstream pool membership
> dynamically from File, DNS SRV, Consul, etcd, or Kubernetes endpoints,
> so backend scale-out / scale-in doesn't require a config edit.

## Purpose

Keep the upstream pool definition in [`upstream-pools.md`](./upstream-pools.md)
in sync with a dynamic source of truth. Additions get health-probed
before taking traffic; removals drain gracefully.

## Providers

### File

`watch:` a JSON / YAML file listing members. Cheapest option. Good for
Ansible / Chef / Nix deployments.

```yaml
upstreams:
  api_pool:
    discovery:
      provider: file
      path: /etc/waf/pools/api_pool.json
      format: json
```

### DNS SRV

Poll a SRV record; members are the `(host, port, weight)` tuples.

```yaml
discovery:
  provider: dns_srv
  name: "_api._tcp.example.com"
  interval_s: 10
  resolver: system     # system | override
```

Uses `hickory-resolver` (formerly `trust-dns`) for cache-aware lookups.

### Consul

```yaml
discovery:
  provider: consul
  endpoint: "https://consul.internal:8501"
  service: "api"
  tag: "prod"
  token: "${secret:env:CONSUL_TOKEN}"
  ca_bundle: "/etc/waf/certs/consul-ca.pem"
```

Long-polls `/v1/health/service/<name>?passing` so changes propagate in
seconds.

### etcd v3

```yaml
discovery:
  provider: etcd
  endpoints: ["https://etcd-0:2379", "https://etcd-1:2379"]
  prefix: "/waf/pools/api/"
  auth: { username: waf, password: "${secret:env:ETCD_PW}" }
```

Watches the prefix and reflects add/remove events.

### Kubernetes endpoints

```yaml
discovery:
  provider: k8s
  namespace: apps
  service: api
  port_name: https
  in_cluster: true
```

Uses the Kubernetes informer pattern via `kube-rs` (feature-gated).

## Reconciliation

On each discovery update:

1. Compute delta against the current member set
2. **Added**: member enters `probing` state; active health check runs
   until `healthy_threshold`, then joins the LB ring
3. **Removed**: member enters `draining`; in-flight finishes; removed
   after `drain_timeout`
4. **Changed weight / metadata**: updated in place

No hot-reload config bump is needed; discovery updates are orthogonal
to the `ArcSwap<WafConfig>` path (they live on the pool manager state
instead).

## Safety limits

- Minimum size floor: refuse to apply a discovery update that would
  drop the pool below `min_members` (default 1) — prevents a bad
  discovery source from emptying the pool
- Maximum churn rate: burst limit on add/remove per interval
- Signed sources (Consul/etcd/k8s use mTLS) preferred over file

## Configuration

```yaml
upstreams:
  api_pool:
    lb: least_conn
    health: { path: /healthz, interval_s: 2 }
    discovery:
      provider: consul
      endpoint: "https://consul.internal:8501"
      service: api
      tag: prod
      token: "${secret:env:CONSUL_TOKEN}"
      min_members: 2
      max_churn_per_interval: 10
```

## Implementation

- `src/discovery/file.rs` — notify-watcher
- `src/discovery/dns_srv.rs` — hickory-resolver
- `src/discovery/consul.rs` — long-poll client
- `src/discovery/etcd.rs` — watch client
- `src/discovery/k8s.rs` — informer (feature-gated)
- `src/discovery/reconcile.rs` — delta + safety-limit enforcement

## Performance notes

- All providers run in background tasks; hot path is untouched
- Reconcile delta is `O(members)` per update; typical pools are small
- DNS SRV cache TTL honored to avoid hammering the resolver
