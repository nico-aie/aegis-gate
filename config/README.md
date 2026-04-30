# `config/` — WAF configuration files

Four YAML configs cover every supported deployment shape. Pick one,
run `waf validate`, then run `waf run`.

```
config/
├── README.md           # This guide
├── prod.yaml           # Production template — secrets via ${secret:…} resolvers
├── dev.yaml            # Single-node dev / CI — passwords inline, no Redis
├── cluster-a.yaml      # HA fixture node A — Redis-backed shared state
├── cluster-b.yaml      # HA fixture node B — pairs with cluster-a.yaml
└── rules/
    └── example.yaml    # Custom rule examples
```

---

## Pick one — which config?

| Use case | File | Run command |
|---|---|---|
| Production single node | `prod.yaml` | `waf run --config config/prod.yaml` |
| Local development | `dev.yaml` | `waf run --config config/dev.yaml` |
| k6 / integration tests | `dev.yaml` | (same as dev — load_mode thresholds match the k6 scripts) |
| Two-node HA cluster | `cluster-a.yaml` + `cluster-b.yaml` | one `waf run` per node + Redis + HAProxy |
| Anything else | fork `prod.yaml` | edit, then `waf validate` to catch drift |

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

| Section | Purpose | Spec |
|---|---|---|
| `listeners` | Bind ports for data + admin planes | [`docs/architecture/protocols.md`](../docs/architecture/protocols.md) |
| `routes` | Host + path → upstream mapping | [`docs/data-plane/routing.md`](../docs/data-plane/routing.md) |
| `upstreams` | Backend pools + LB strategy + circuit breakers | [`docs/data-plane/upstreams.md`](../docs/data-plane/upstreams.md) |
| `tls` | Cert sources, ACME, OCSP stapling | [`docs/data-plane/tls.md`](../docs/data-plane/tls.md) |
| `security` | Rule files, detector toggles | [`docs/security/rule-engine.md`](../docs/security/rule-engine.md) |
| `risk` | Scoring weights, strike thresholds, decay | [`docs/security/risk-engine.md`](../docs/security/risk-engine.md) |
| `load_mode` | Auto-degradation thresholds (elevated / critical RPS) | [`docs/operations/load-modes.md`](../docs/operations/load-modes.md) |
| `state` | In-memory or Redis-backed counters / leases | [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) |
| `admin` | Auth (argon2 / TOTP / mTLS / IP allowlist), CSRF, sessions | [`docs/control-plane/dashboard-auth.md`](../docs/control-plane/dashboard-auth.md) |
| `audit` | Hash chain + SIEM sinks (8 formats) | [`docs/observability/siem-export.md`](../docs/observability/siem-export.md) |
| `slo` | SLO definitions + multi-burn alert receivers | [`docs/observability/slo-sli-alerting.md`](../docs/observability/slo-sli-alerting.md) |
| `compliance` | Profile clamp (FIPS / PCI / SOC2 / GDPR / HIPAA) | [`docs/operations/compliance.md`](../docs/operations/compliance.md) |
| `gitops` | Config-as-code git poll-and-pull | [`docs/control-plane/gitops-change-management.md`](../docs/control-plane/gitops-change-management.md) |
| `runtime` | Worker count + CPU pinning | [`docs/operations/runtime-tuning.md`](../docs/operations/runtime-tuning.md) |
| `node` | Stable cluster node identity | [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) |
| `interop` | External interop contract surface (always on) | [`plans/interop-contract.md`](../plans/interop-contract.md) |

For full schema details with every field, fork `prod.yaml` and
read its inline comments — every block carries an explanation.

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

Drop additional `.yaml` files into `rules/` and point
`security.rules.path` at the directory. The example rule lives at
[`rules/example.yaml`](./rules/example.yaml). Rule DSL grammar:
[`docs/security/rule-engine.md`](../docs/security/rule-engine.md).
