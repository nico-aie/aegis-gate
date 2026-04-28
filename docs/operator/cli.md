# `waf` — CLI reference (authoritative)

This is the single source of truth for the `aegis-bin` binary. All
documents that mention `./waf <cmd>` MUST match this list. Adding or
renaming a subcommand requires updating this file in the same PR.

The binary is produced by `crates/aegis-bin` and installed as `waf`
(or run from the repo as `cargo run -p aegis-bin --`).

```
waf [GLOBAL OPTIONS] <SUBCOMMAND> [ARGS]
```

## Global options

| Flag                 | Default            | Purpose |
|----------------------|--------------------|---------|
| `--config <PATH>`    | `./config/waf.yaml`| Path to the root config file. |
| `--log-format <FMT>` | `text`             | `text` or `json`. |
| `--log-level <LVL>`  | `info`             | `error|warn|info|debug|trace`. |
| `--no-color`         | off                | Disable ANSI colors. |

## Subcommands

### `waf run`
Boot the data plane + control plane. This is the long-running
service mode.

```
waf run [--config PATH] [--workers N] [--ready-fd FD]
```
- `--workers N` — overrides `workers.count` from config.
- `--ready-fd FD` — write `READY=1` to FD when `/healthz/ready` flips green (systemd / supervisor integration).

Exit codes: `0` clean drain, `1` config error, `2` bind error,
`3` panic, `64+` reserved.

### `waf validate`
Parse, resolve secrets, compile, and lint the config. No listeners
are bound. Returns non-zero on any error.

```
waf validate [--config PATH] [--strict]
```
- `--strict` — treat warnings as errors.

### `waf config <SUB>`
Config introspection and migration. None of these subcommands
mutate live state.

```
waf config export   [--config PATH] [--format yaml|json] [--redact-secrets]
waf config import   --from PATH --to PATH [--format yaml|json]
waf config diff     --left PATH --right PATH
waf config apply    --from PATH                   # GitOps-staged apply
waf config schema   [--out PATH]                  # emit JSON Schema
```
- `export` writes the fully-resolved compiled config (post-includes, secrets redacted by default).
- `import` is the inverse — reads an exported snapshot and writes a normalized YAML tree.
- `diff` shows a structural diff with semantic awareness (rule reorder, route add/remove, etc.).
- `apply` stages a config from disk through the GitOps pipeline (signature verify → validate → swap).
- `schema` emits the JSON Schema for `WafConfig` (consumed by IDEs and CI lint).

### `waf snapshot <SUB>`
State backend snapshot/restore for DR.

```
waf snapshot create  --out PATH [--include rules,routes,risk,...]
waf snapshot restore --from PATH [--dry-run]
waf snapshot list    [--backend redis|raft|in_memory]
```

### `waf audit <SUB>`
Audit chain operations.

```
waf audit verify    --from PATH [--witness PATH]
waf audit export    --since RFC3339 --until RFC3339 --out PATH
waf audit witness   --out PATH                    # write current merkle root
```
- `verify` walks the hash chain and validates against an optional witness file.
- `export` writes a sealed JSONL bundle for SIEM ingest or compliance audit.

### `waf rules <SUB>`
Offline rule tooling. Reads files only — does not touch a running instance.

```
waf rules lint     --path DIR
waf rules test     --path DIR --corpus DIR        # replay benign + malicious corpora
waf rules compile  --path DIR --out PATH          # binary rule cache
```

### `waf cert <SUB>`
TLS material inspection (does not bind listeners).

```
waf cert list      [--config PATH]
waf cert show      --name NAME
waf cert renew     --name NAME                    # ACME force-renew via control plane
```

### `waf cluster <SUB>`
Cluster membership view (read-only, talks to the local admin API).

```
waf cluster peers
waf cluster leases
waf cluster drain   [--node ID]
```

### `waf version`
Print build info: semver, git sha, rustc version, enabled feature flags.

```
waf version [--json]
```

## Conventions

- All subcommands accept `--config` and the global logging flags.
- All `<SUB>` groups print their own `--help` listing the leaf commands.
- Long-running commands respect `SIGTERM` for graceful shutdown.
- Subcommands that mutate the running instance go through the admin
  API over a Unix socket (`/var/run/waf/admin.sock` by default,
  override with `--admin-socket`); they never touch the state backend
  directly.
