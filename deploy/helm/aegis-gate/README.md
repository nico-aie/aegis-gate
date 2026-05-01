# `aegis-gate` Helm chart

Deploys the Aegis WAF on Kubernetes 1.27+. Two Services
(data plane LoadBalancer + admin ClusterIP), opinionated
PodDisruptionBudget + NetworkPolicy + drain hook, and optional
HPA / ServiceMonitor / Ingress.

## TL;DR

```sh
# 1. Generate the admin password hash + a CSRF secret
PASSWORD_HASH=$(./waf admin set-password)
CSRF_SECRET=$(openssl rand -hex 32)

# 2. Provide a TLS cert in a Secret
kubectl create secret tls aegis-gate-tls \
    --cert=fullchain.pem --key=privkey.pem

# 3. Install
helm install aegis deploy/helm/aegis-gate \
    --namespace aegis --create-namespace \
    --set admin.password.hash="$PASSWORD_HASH" \
    --set admin.csrf.secret="$CSRF_SECRET" \
    --set tls.existingSecret=aegis-gate-tls \
    --set image.tag=1.4.2

# 4. Reach the admin dashboard
kubectl port-forward -n aegis svc/aegis-aegis-gate-admin 9443
open https://localhost:9443/dashboard/
```

## Required values

| Key | Default | Why |
|---|---|---|
| `image.tag` | `1.4.2` | Pin to an immutable digest in production |
| `admin.password.hash` | _(empty — must override)_ | argon2id PHC string from `waf admin set-password` |
| `admin.csrf.secret` | _(empty — must override)_ | 32+ random bytes (`openssl rand -hex 32`) |
| `tls.existingSecret` | `aegis-gate-tls` | Pre-existing `kubernetes.io/tls` Secret with `tls.crt` + `tls.key` |
| `config.state.redis.url` | `redis://aegis-redis-master.redis:6379` | Required when `config.state.backend: redis` (the default) |

For password + CSRF, prefer the `existingSecret` path so values
never live in helm-rendered manifests:

```yaml
admin:
  password:
    existingSecret:
      name: my-existing-secret
      key:  argon_hash
  csrf:
    existingSecret:
      name: my-existing-secret
      key:  csrf
```

## Topology

| Workload | Replicas | Type |
|---|---|---|
| `Deployment` (the WAF) | `replicaCount: 2` | RollingUpdate, maxSurge 1, maxUnavailable 0 |
| `Service` (data plane) | _(N/A)_ | `LoadBalancer` by default — ports 8080 + 8443 |
| `Service` (admin) | _(N/A)_ | Always `ClusterIP` — port 9443 |
| `PodDisruptionBudget` | _(N/A)_ | `minAvailable: 1` |
| `NetworkPolicy` (admin) | _(N/A)_ | restricts admin port to operator-side namespaces |

Pod anti-affinity is preferred (not required) on
`kubernetes.io/hostname` — replicas spread across nodes when
capacity allows but won't refuse to schedule on a single-node
cluster.

## Required permissions

The chart provisions a ServiceAccount with no API permissions
(`automountServiceAccountToken: false`). The WAF doesn't read the
Kubernetes API; it ships static config + reads its own admin
endpoints.

## HA + drain semantics

The `drain.graceMs` value (default `10000`) becomes
`AEGIS_DRAIN_GRACE_MS` and matches the preStop hook duration.
When a pod terminates:

1. preStop `waf admin drain` posts to the admin port → readiness
   flips to 503.
2. The kubelet's readiness probe picks up the 503 within ≤ 5 s,
   the cluster Service stops sending new connections.
3. The preStop hook sleeps for `graceMs` so in-flight requests
   complete.
4. The kubelet sends SIGTERM → the WAF's normal drain path runs.
5. After `terminationGracePeriodSeconds` the kubelet sends SIGKILL.

Run-05 measured 100 % graceful failover (zero 5xx) on this path
with HAProxy as the LB; a k8s Service behaves the same.

## VipTalk SLO alerts (CI-T7)

```yaml
viptalk:
  enabled: true
  existingSecret:
    name: aegis-viptalk
    botTokenKey: bot_token
    roomIdsKey: room_ids
  apiBase: https://api.viptalk.org
```

Expects a Secret with two keys:

```sh
kubectl create secret generic aegis-viptalk \
    --from-literal=bot_token="<your-bot-token>" \
    --from-literal=room_ids="!ROOM:matrix.viptalk.org"
```

The image must be built with `--features alerts` (the default
`production` umbrella includes it).

## Customising the WAF config

The chart synthesises a minimum-viable `waf.yaml` from the
`config.*` knobs in values.yaml. To ship a fully-custom config:

```yaml
config:
  raw: |
    listeners:
      data:
        - bind: "0.0.0.0:8080"
          tls: false
    state:
      backend: in_memory
    # ... rest of your WafConfig
```

The chart still mounts it at `/etc/aegis/waf.yaml` and reloads
the pods on change (via `checksum/config` annotation).

## Verifying

```sh
# Lint
helm lint deploy/helm/aegis-gate

# Render to stdout (dry-run, no install)
helm template aegis deploy/helm/aegis-gate \
    --set admin.password.hash=test \
    --set admin.csrf.secret=test

# Install with a values override file
helm install aegis deploy/helm/aegis-gate -f my-values.yaml \
    --namespace aegis --create-namespace
```

## Uninstall

```sh
helm uninstall aegis -n aegis
# State backend (Redis) is external — chart leaves it alone.
# TLS Secret is operator-managed — chart leaves it alone.
```
