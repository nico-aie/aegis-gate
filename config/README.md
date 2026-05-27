# `config/` — WAF configuration files

Several YAML configs cover every supported deployment shape. Pick
one, run `waf validate`, then run `waf run`. Three opinionated
production profiles live under `profiles/`; pick by reading
[`docs/operator/profiles.md`](../docs/operator/profiles.md) first.

```
config/
├── README.md                       # This guide
├── prod.yaml                       # Generic production template
├── dev.yaml                        # Single-node dev / CI
├── cluster-a.yaml                  # HA fixture node A — Redis-backed
├── cluster-b.yaml                  # HA fixture node B — pairs with cluster-a
├── profiles/                       # Opinionated production profiles
│   ├── prod-balanced.yaml          #   Default — sane production defaults
│   ├── prod-high-throughput.yaml   #   Throughput-first; recon + brute_force OFF
│   └── prod-strict.yaml            #   Compliance-first; mTLS required, 90d audit
└── rules/
    └── example.yaml                # Custom rule examples
```

---

## Pick one — which config?

| Use case | File | Run command |
|---|---|---|
| **Default production** | `profiles/prod-balanced.yaml` | `waf run --config config/profiles/prod-balanced.yaml` |
| Throughput-first prod (CDN-fronted, ≥ 5 k RPS sustained) | `profiles/prod-high-throughput.yaml` | `waf run --config config/profiles/prod-high-throughput.yaml` |
| Compliance-driven prod (PCI / HIPAA / SOC2 / GDPR / FedRAMP) | `profiles/prod-strict.yaml` | `waf run --config config/profiles/prod-strict.yaml` |
| Custom production (none of the above fit) | fork `prod.yaml` | edit, then `waf validate` to catch drift |
| Local development | `dev.yaml` | `waf run --config config/dev.yaml` |
| k6 / integration tests | `dev.yaml` | (same as dev — load_mode thresholds match the k6 scripts) |
| Two-node HA cluster | `cluster-a.yaml` + `cluster-b.yaml` | one `waf run` per node + Redis + HAProxy |

Profile picking guide with empirical numbers:
[`docs/operator/profiles.md`](../docs/operator/profiles.md).

The default config path when no `--config` is passed is `config/prod.yaml`.

---

## Quick validate + run

```sh
# Validate before booting — exit 0 means the config is loadable
# AND the compliance profile (FIPS / PCI / SOC2 / GDPR / HIPAA)
# accepts it.
waf validate --config config/prod.yaml

# Boot the WAF
waf run --config config/prod.yaml
```

---

## Production setup — fork `prod.yaml`

The shipped `prod.yaml` is a template. Three things every operator
must edit before production use:

### 1. Replace inline secrets with resolver references

Production secrets must come from a real secret manager, never
plain YAML. Supported resolvers (the trailing `#field` selects a
sub-field of a JSON secret):

```yaml
admin:
  dashboard_auth:
    password_hash_ref: "${secret:vault:secret/aegis/admin#hash}"
    csrf_secret_ref:   "${secret:aws:arn:aws:secretsmanager:…:aegis/csrf#value}"

state:
  redis:
    url: "${secret:gcp:projects/p/secrets/aegis-redis-url#latest}"
```

| Resolver | URI shape |
|---|---|
| Vault | `${secret:vault:<path>#<field>}` (AppRole or k8s auth) |
| AWS Secrets Manager | `${secret:aws:<arn>#<field>}` |
| GCP Secret Manager | `${secret:gcp:<resource>#<field>}` |
| Azure Key Vault | `${secret:azure:<vault>:<secret>#<field>}` |
| etcd | `${secret:etcd:<key>#<field>}` |
| Environment | `${secret:env:VAR_NAME}` |
| File | `${secret:file:/path}` |

Build the binary with the matching Cargo feature (`vault`, `aws`,
`gcp`, `azure`, `consul`, `etcd`, `k8s`) — see [`docs/control-plane/secrets-management.md`](../docs/control-plane/secrets-management.md).

### 2. Bind admin to operator network only

```yaml
admin:
  bind: "10.0.0.5:9443"          # internal address, NOT 0.0.0.0
  dashboard_auth:
    ip_allowlist:
      - "10.0.0.0/8"             # operator subnet
      - "172.16.0.0/12"          # bastion subnet
```

### 3. Pick a state backend

| Backend | When | Config |
|---|---|---|
| `in_memory` | single node, ephemeral counters OK | default — nothing to set |
| `redis` | HA cluster, shared rate limits, leader lease | `state.backend: redis` + `state.redis.url` |

```yaml
state:
  backend: redis
  redis:
    url: "redis://aegis-redis:6379"
    pool_size: 16
```

---

## HA cluster setup

`cluster-a.yaml` + `cluster-b.yaml` boot two WAF nodes against a
shared Redis. They differ only in:

| Field | `cluster-a.yaml` | `cluster-b.yaml` |
|---|---|---|
| `node.id` | `waf-a` | `waf-b` |
| Data listener | `:8080` | `:8090` |
| Admin listener | `:9443` | `:9543` |

Both share `state.backend: redis` + `state.redis.url`, so rate
limits, block lists, and leader leases are cluster-shared.

```sh
# 1. Bring up Redis.
docker run -d --name aegis-redis -p 6379:6379 redis:7-alpine \
  redis-server --save "" --appendonly no

# 2. Boot two WAF nodes.
target/release/waf run --config config/cluster-a.yaml &
target/release/waf run --config config/cluster-b.yaml &

# 3. Front them with HAProxy (reference deploy at deploy/haproxy/).
haproxy -f deploy/haproxy/haproxy.cfg
```

Cluster smoke tests live at `tests/cluster/`. Run with
`bash tests/cluster/run-all.sh`.

---

## Hot-reload — change config without restart

The WAF watches the config file and reloads on change. Or trigger
explicitly:

```sh
curl -XPOST -H "x-csrf-token: $CSRF" -b cookies.txt \
     http://localhost:9443/admin/reload
```

The dashboard's status bar shows "Last config sync 14s" so you
know reload took effect. SLA: ≤ 10 s (Hackathon WAF-FE §2 #5).

---

## Section reference (what's in each YAML)

> **Looking for a per-block walkthrough?** Open
> [`REFERENCE.md`](./REFERENCE.md) — it has one section per
> top-level YAML block with the operator-relevant knobs, defaults,
> and a link back to the topic deep-dive. The table below is the
> 30-second index; `REFERENCE.md` is the 5-minute scan.

| Section | Purpose | Per-knob ref | Deep-dive |
|---|---|---|---|
| `listeners` | Bind ports for data + admin planes | [REFERENCE.md#listeners](./REFERENCE.md#listeners) | [`docs/architecture/protocols.md`](../docs/architecture/protocols.md) |
| `routes` | Host + path → upstream mapping | [REFERENCE.md#routes](./REFERENCE.md#routes) | [`docs/data-plane/routing-ingress.md`](../docs/data-plane/routing-ingress.md) |
| `upstreams` | Backend pools + LB strategy + circuit breakers | [REFERENCE.md#upstreams](./REFERENCE.md#upstreams) | [`docs/data-plane/upstream-pools.md`](../docs/data-plane/upstream-pools.md) |
| `tls` | Cert sources, ACME, OCSP stapling | [REFERENCE.md#tls](./REFERENCE.md#tls) | [`docs/data-plane/tls-termination.md`](../docs/data-plane/tls-termination.md) |
| `detectors` | OWASP + Phase F detector chain + per-tier mask | [REFERENCE.md#detectors](./REFERENCE.md#detectors) | [`docs/security/detectors/README.md`](../docs/security/detectors/README.md) |
| `ai` | ONNX classifier detector | [REFERENCE.md#ai](./REFERENCE.md#ai) | per-deployment calibration in [`docs/security/detectors/README.md`](../docs/security/detectors/README.md) |
| `risk` | Scoring weights, strike thresholds, decay | [REFERENCE.md#risk](./REFERENCE.md#risk) | [`docs/operator/risk-tuning.md`](../docs/operator/risk-tuning.md) |
| `load_mode` | Auto-degradation thresholds (elevated / critical RPS) | [REFERENCE.md#load_mode](./REFERENCE.md#load_mode) | [`docs/data-plane/graceful-degradation.md`](../docs/data-plane/graceful-degradation.md) |
| `load_shedder` | Adaptive concurrency limiter (Gradient2) | [REFERENCE.md#load_shedder](./REFERENCE.md#load_shedder) | source comments in `crates/aegis-proxy/src/shed.rs` |
| `ddos` | Per-IP burst gate + EWMA spike | [REFERENCE.md#ddos](./REFERENCE.md#ddos) | [`docs/security/ddos-protection.md`](../docs/security/ddos-protection.md) |
| `rate_limit` | Per-IP token-bucket limiter | [REFERENCE.md#rate_limit](./REFERENCE.md#rate_limit) | [`docs/security/rate-limiting.md`](../docs/security/rate-limiting.md) |
| `state` | In-memory or Redis-backed counters / leases | [REFERENCE.md#state](./REFERENCE.md#state) | [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) |
| `admin` | Auth (argon2 / TOTP / mTLS / IP allowlist), CSRF, sessions | [REFERENCE.md#admin](./REFERENCE.md#admin) | [`docs/control-plane/dashboard-auth.md`](../docs/control-plane/dashboard-auth.md) |
| `audit` | Hash chain + SIEM sinks | [REFERENCE.md#audit](./REFERENCE.md#audit) | [`docs/observability/audit-logging.md`](../docs/observability/audit-logging.md) |
| `slo` | SLO definitions + multi-burn alert receivers | [REFERENCE.md#slo](./REFERENCE.md#slo) | [`docs/observability/slo-sli-alerting.md`](../docs/observability/slo-sli-alerting.md) |
| `compliance` | Profile clamp (FIPS / PCI / SOC2 / GDPR / HIPAA) | [REFERENCE.md#compliance](./REFERENCE.md#compliance) | [`docs/operations/compliance.md`](../docs/operations/compliance.md) |
| `gitops` | Config-as-code git poll-and-pull | [REFERENCE.md#gitops](./REFERENCE.md#gitops) | [`docs/control-plane/gitops-change-management.md`](../docs/control-plane/gitops-change-management.md) |
| `runtime` | Worker count + CPU pinning | [REFERENCE.md#runtime](./REFERENCE.md#runtime) | [`docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) |
| `node` | Stable cluster node identity | [REFERENCE.md#node](./REFERENCE.md#node) | [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) |
| `interop` | External interop contract surface | [REFERENCE.md#interop](./REFERENCE.md#interop) | [`plans/archive/interop-contract.md`](../plans/archive/interop-contract.md) + [`docs/control-plane/api.openapi.yaml`](../docs/control-plane/api.openapi.yaml) |
| `proxy` | Global body cap | [REFERENCE.md#proxy](./REFERENCE.md#proxy) | (knob-only — see source `crates/aegis-core/src/config.rs::ProxyConfig`) |
| `logging` | Tracing verbosity | [REFERENCE.md#logging](./REFERENCE.md#logging) | hot-flippable via `set_profile` |

For per-field detail beyond [`REFERENCE.md`](./REFERENCE.md), read
the `///` doc comments on `WafConfig` and its sub-structs in
[`crates/aegis-core/src/config.rs`](../crates/aegis-core/src/config.rs)
— authoritative and always in sync with the binary.

---

## Validation invariants

The validator runs a compliance check on every load. These trip
common mistakes:

| Error | Likely cause | Fix |
|---|---|---|
| `missing field admin.bind` | YAML key drift | Compare against `config/prod.yaml` template |
| `tls enabled but no cert source` | Listener has `tls: true` without `tls.acme` or `tls.cert_files` | Add cert source or set `tls: false` |
| `state.backend = redis but no state.redis.url` | Cluster config without resolver | Set `state.redis.url` (literal or `${secret:…}`) |
| `compliance.fips conflicts with tls.min_version: 1.1` | FIPS forbids TLS < 1.2 | Bump min_version or drop FIPS clamp |

---

## Custom rules

Two ways to supply operator rules:

1. **Inline (recommended) — `rules.inline[]`.** Persistent + cluster-
   propagated: the live `RuleStore` is seeded from this list at boot, and
   dashboard rule CRUD (`POST/PUT/DELETE /api/rules`, `…/toggle`) edits it
   through the config plane so changes survive restart and reach every node.

   ```yaml
   rules:
     inline:
       - id: block-internal-ua
         body: "- id: block-internal-ua\n  priority: 100\n  when: true\n  then: log_only\n"
         enabled: true
     max_rule_count: 10000
     strict_compile: false
   ```

2. **Files — `rules.paths[]`.** Kept for the backup/snapshot tooling. **Note:**
   `rules.paths` is **not** loaded into the live engine (only `rules.inline` +
   dashboard CRUD are). Rule DSL grammar:
   [`docs/security/rule-engine.md`](../docs/security/rule-engine.md).

> **`detectors.per_tier` is now live.** Per-tier detector overrides
> (`detectors.per_tier.<tier>.<class>: true|false`, `true` force-on, `false`
> force-off, omitted = inherit base) are consumed by the engine and treated as
> the source of truth (a live override absent from the config is cleared on
> reload). See [`../docs/operations/cluster-config-distribution.md`](../docs/operations/cluster-config-distribution.md).
