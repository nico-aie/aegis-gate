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
cargo run -p aegis-bin -- run --config config/dev.yaml
```

`bootstrap.sh` is idempotent — it only writes `/aegis/config/waf`
if the key is absent. Pass `--force` to overwrite, `--show` to
print the current value.

## Loading config from etcd (ETCD-T1)

The data plane can boot directly from `/aegis/config/waf`
instead of a local YAML file. This is gated behind the `etcd`
Cargo feature.

```sh
# Build with etcd config support
cargo build -p aegis-bin --features etcd --release

# Switch the boot path to etcd
export AEGIS_CONFIG_SOURCE=etcd
export AEGIS_ETCD_ENDPOINTS="http://localhost:2379"
# Optional — defaults to /aegis/config/waf
export AEGIS_CONFIG_ETCD_KEY="/aegis/config/waf"

./target/release/waf run
```

| Variable | Purpose | Default |
|---|---|---|
| `AEGIS_CONFIG_SOURCE` | `file` (default) or `etcd` | `file` |
| `AEGIS_CONFIG_ETCD_ENDPOINTS` | Comma-sep etcd v3 endpoints; falls back to `AEGIS_ETCD_ENDPOINTS` | `http://127.0.0.1:2379` |
| `AEGIS_CONFIG_ETCD_KEY` | Key holding the YAML blob | `/aegis/config/waf` |
| `AEGIS_CONFIG_ETCD_USER` / `_PASSWORD` | etcd v3 auth; falls back to shared `AEGIS_ETCD_*` | unset |
| `AEGIS_CONFIG_ETCD_CA_CERT_PATH` / `_CLIENT_CERT_PATH` / `_CLIENT_KEY_PATH` | mTLS material; falls back to shared | unset |
| `AEGIS_CONFIG_ETCD_POLL_INTERVAL_MS` | Watcher poll cadence | `5000` |

The etcd value is verbatim YAML — same shape the file loader
accepts. Validation runs through the same
`WafConfig::validate` as the file path. When the key is absent
or the value fails to decode, boot fails with a clear error
("etcd key X is empty or absent" / "config decode: …"). The
dashboard's `validate` command still works against a file copy
of the same blob:

```sh
./deploy/etcd/bootstrap.sh --show > /tmp/cfg.yaml
./target/release/waf validate --config /tmp/cfg.yaml
```

**Hot-reload on etcd change** ships in the watcher hook
(`spawn_watcher`); wiring it through to `aegis-proxy::run` is
a follow-up that lands alongside file-watcher reload (the
existing `spawn_config_watcher` is dormant pending the same
`Arc<ArcSwap<WafConfig>>` plumbing).

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
