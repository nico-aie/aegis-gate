# `deploy/etcd/` — Control Plane Key Layout

etcd is the **source of truth** for Aegis-Gate configuration,
secrets (when stored in etcd), and leader-election leases. This
directory holds the dev bootstrap script and the minimum seed
config.

## Key Layout

```
/aegis/
├── config/
│   └── waf                          # authoritative WafConfig (YAML blob)
├── rules/                           # optional: per-rule split for large deployments
│   └── <rule-id>
├── secrets/                         # when using the `etcd` secret provider
│   └── <name>                       # value is the raw secret, ACL-gated
├── leases/
│   ├── acme                         # leader-only: ACME cert issuance
│   ├── threat-intel                 # leader-only: feed fetch
│   └── witness-export               # leader-only: audit witness
└── nodes/
    └── <node-id>                    # cluster membership hints (ttl-keyed)
```

The data plane never reads etcd directly. The control plane
(`aegis-control`) watches `/aegis/config/` with the etcd v3 Watch
API, validates + compiles each new revision, and swaps
`ArcSwap<CompiledConfig>` in-process. Data plane threads see the
new config on their next read — no external I/O on the hot path.

## Semantics

- **Revision-aware CAS** on writes: `waf config put` sends
  `txn { compare mod_rev == last_seen ; put new }`. Rejected on
  conflict; the dashboard surfaces the collision.
- **Atomic swaps**: writes to `/aegis/config/waf` are a single
  `put`. Split-rule mode uses etcd `txn` to group writes.
- **Watcher recovery**: on watch channel loss, the control plane
  re-issues `range(prefix=/aegis/config/)` with the last seen
  revision, then resumes watching. No config is lost, duplicates
  are deduped by `mod_revision`.
- **Boot ordering**: data plane listeners are held until the
  first compile succeeds. Until then, `/healthz/ready` returns
  503 and readiness gates the bind.

## Bootstrap

```sh
# One-liner: start etcd, seed the dev config, run the WAF
docker compose -f deploy/docker-compose.dev.yml up -d
./deploy/etcd/bootstrap.sh
cargo run -p aegis-bin -- run --config config/waf.dev.yaml
```

`bootstrap.sh` is idempotent — it only writes `/aegis/config/waf`
if the key is absent. Pass `--force` to overwrite, `--show` to
print the current value.

## Disaster Recovery

- **etcd snapshot**: `etcdctl snapshot save /backup/aegis-<date>.db`
  (daily cron in production).
- **Restore**: `etcdctl snapshot restore` into a new data dir,
  rejoin the cluster, verify `/aegis/config/waf` still decodes.
- **Local fallback**: the control plane persists each successfully
  compiled config to `~/.cache/aegis/last-good-config.yaml`. If
  etcd is unreachable at boot, the WAF starts from this cache with
  a banner on the dashboard and `config_source="cache"` metric label.
  It does NOT accept new configs while in cache mode.

## Security

- **Dev**: `ALLOW_NONE_AUTHENTICATION=yes`. No TLS. Localhost only.
  Do not expose port 2379 to the internet.
- **Production** (W5+): etcd client-cert auth with per-role users
  (`aegis-reader`, `aegis-writer`, `aegis-admin`) backed by etcd's
  built-in role system, TLS for all peer + client traffic. Client
  certs distributed via the existing secrets workflow. (Note: this
  is etcd-native access control on the control-plane store — it is
  *not* the deferred application-level RBAC for dashboard users,
  which stays out of scope for v1.)

## Migrating Config Between Environments

```sh
# Export from one env
./waf config export --from etcd://prod:2379 > prod.yaml

# Diff against staging
./waf config diff --left prod.yaml --right staging.yaml

# Apply (with CAS, will refuse if someone else wrote since export)
./waf config apply --from prod.yaml --to etcd://staging:2379
```
