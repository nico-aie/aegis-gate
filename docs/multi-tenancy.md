# Multi-Tenancy (v2, enterprise)

> **Enterprise addendum.** A single WAF cluster serves multiple tenants
> with isolated config, state, metrics, audit, and dashboards — no
> cross-tenant data leakage, and tenants cannot weaken cluster-wide
> security floors.

## Purpose

Let a platform operator host many customer workloads behind one WAF
without needing a separate cluster per customer, while guaranteeing
data and privilege isolation.

## Tenant model

```rust
pub struct Tenant {
    pub id: String,                // stable
    pub name: String,
    pub quotas: TenantQuotas,
    pub allowed_hosts: Vec<String>,
    pub tier_overrides: Vec<TenantTierOverride>,
    pub rule_namespace: String,    // rule ids prefixed with this
    pub audit_sinks: Vec<SinkRef>, // tenant-owned sinks only
    pub data_residency: Option<String>, // region pin
}
```

## Isolation boundaries

### Routing

Host → tenant mapping is a hashmap. Routes can only reference
upstreams, tiers, and transforms declared within their tenant or the
cluster-wide pool.

### State keyspace

Every state-backend key is prefixed with `{tenant_id}:`. A tenant
cannot read or write another tenant's counters, block lists, or
session state.

### Audit + metrics

- Audit events carry `tenant_id`
- Metrics series are labeled `tenant`
- Dashboard queries project through the token's `tenant_id` claim
- Tenant sinks only receive their own events

### Rules

Rule ids are namespaced. Tenant A cannot modify tenant B's rules via
the admin API. Cluster-wide rules are read-only to tenants.

### Secrets

Secret references resolved within a tenant scope can only access
that tenant's provider mount. Cluster secrets are invisible.

## Quotas

```yaml
tenants:
  acme:
    quotas:
      rps_cluster: 5000
      rps_per_route: 500
      max_rules: 2000
      max_routes: 500
      max_upstreams: 50
      audit_retention_days: 90
      max_body_bytes: 10Mi
```

Enforced at config load and at request time.

## Security floors

Cluster-wide admins set floors a tenant cannot weaken:

- Minimum CRITICAL tier controls
- Minimum TLS version
- Minimum audit retention
- Required detectors

Tenant config that drops below a floor is rejected at load time.

## Dashboard scoping

Tenant users see only their own:

- Routes, upstreams, rules
- Live feed
- Audit log
- Metrics (via labeled Prometheus queries)

Cluster-wide operators see everything. See
[`dashboard.md`](./dashboard.md) and [`rbac-sso.md`](./rbac-sso.md).

## Data residency

Tenants can pin their data to a region. Audit sinks, state backend
writes, and metric exports honor the pin. See
[`data-residency-retention.md`](./data-residency-retention.md).

## Noisy-neighbor protection

Per-tenant concurrency limits in the adaptive load shedder prevent
one tenant's traffic spike from starving others:

```yaml
tenants:
  acme:
    concurrency_soft: 500
    concurrency_hard: 800
```

When the global pool is saturated, low-tier traffic from over-quota
tenants is shed first.

## Configuration

```yaml
tenants:
  acme:
    id: acme
    allowed_hosts: ["*.acme.example.com"]
    rule_namespace: acme
    quotas: { rps_cluster: 5000, max_rules: 2000 }
    data_residency: { region: us-east-1 }
  globex:
    id: globex
    allowed_hosts: ["*.globex.example.com"]
    rule_namespace: globex
    quotas: { rps_cluster: 2000 }
```

## Implementation

- `src/tenancy/model.rs` — `Tenant` + loader
- `src/tenancy/scope.rs` — request → tenant resolver (host match)
- `src/tenancy/keyspace.rs` — state-key prefixing
- `src/tenancy/quotas.rs` — per-tenant quota enforcement
- `src/tenancy/floor.rs` — security floor validator

## Performance notes

- Tenant resolution is one hashmap lookup on the SNI host
- Key prefixing is a compile-time format string, no allocation
  beyond the key itself
- Metric labels are interned; label sets reused per tenant
