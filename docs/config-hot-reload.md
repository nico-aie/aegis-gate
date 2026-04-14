# Config Hot Reload (v2)

> **v1 → v2:** hot reload now runs a **dry-run validator** before any swap,
> resolves **secret references** through pluggable providers, and optionally
> pulls from Git (GitOps). Malformed updates are rejected and the running
> config is preserved.

## Purpose

Operators must be able to update WAF policy (routes, rules, upstream pools,
TLS, tenants) without restarting or dropping connections. A bad config
must never break a running node.

## Lifecycle

```
 source change ─► loader ─► secret resolve ─► compile/validate ─► dry-run ─► ArcSwap swap ─► notify subscribers
                                                          │
                                                          └─ error: rollback, alert, preserve old
```

## Sources

- **File** (default) — YAML files in `config/` watched via `notify`
- **Git** — periodic `git pull` with signed-commit verification
  (see [`gitops-change-management.md`](./gitops-change-management.md))
- **Admin API** — `PUT /api/config` from the control plane
- **Secret provider notifications** — rotating a secret in Vault / AWS SM
  triggers re-resolution without needing a config diff

Each source feeds the same pipeline; the loader does not care which one
pushed the change.

## Compile / validate

The loader performs a **full compilation** of the candidate config before
it is considered valid:

1. Parse YAML → `WafConfig` via `serde`
2. Resolve `${secret:...}` references
3. Compile all regex patterns (rules, transforms, DLP)
4. Build the route table (host + path trie)
5. Instantiate upstream pools with parsed health-check configs
6. Resolve TLS cert + key pairs and verify the chain
7. Cross-check references: every `upstream_ref` in a route points to a
   defined pool; every `tenant_id` exists
8. Run the **rule linter**: depth limits, no conflicting rule ids,
   priority uniqueness warnings
9. Run the **compliance linter** when FIPS / PCI mode is enabled
   (refuses non-FIPS ciphers, rejects TLS < 1.2)

Failure at any step → the candidate is discarded, the running config is
untouched, an error event goes to the dashboard + audit log.

## Dry-run CLI

Operators can validate locally before pushing:

```
waf config check ./config/waf.yaml
waf config diff  ./config/waf.yaml       # shows changes vs live
waf config apply ./config/waf.yaml       # sends to admin API
```

## Atomic swap

The new, fully-constructed `WafConfig` is stored in an `ArcSwap<WafConfig>`.
Readers on the hot path take a `.load()` handle (a cheap `Arc` clone) at
the start of each request and see a consistent view for its duration.

Subscribers (e.g. the upstream pool manager, TLS resolver, threat-intel
feed refresher) register via a `tokio::sync::broadcast` channel and react
to the swap: pools reconcile members, TLS reloads certs, etc.

## Secret references

`${secret:<provider>:<path>[#field]}` syntax, resolved at compile time:

```yaml
tls:
  certificates:
    - host: "api.example.com"
      cert_file: "/etc/waf/certs/api.pem"
      key_file:  "${secret:vault:kv/data/waf/tls#key}"

challenge:
  secret: "${secret:env:CHALLENGE_SECRET}"
```

See [`secrets-management.md`](./secrets-management.md) for providers and
rotation semantics.

## Rule file hot reload

Files under `rules_dir` are watched independently so tightening a single
rule doesn't re-parse the full `waf.yaml`. Each file is parsed, compiled,
and merged into the rule snapshot via `ArcSwap<Vec<Rule>>`.

## Configuration

```yaml
config:
  source: file               # file | git | api
  rules_dir: "/etc/waf/rules"
  git:
    enabled: false
    repo_url: "git@github.com:acme/waf-config.git"
    branch: main
    signed_commits_only: true
    allowed_signers: "/etc/waf/allowed_signers"
    poll_interval_s: 60
  validator:
    strict: true             # fail on warnings
    dry_run_before_swap: true
```

## Notifications

Every reload attempt emits an `operational` audit event with:

- Source (file path, git commit hash, or admin actor)
- Outcome (`applied`, `rejected`, `no_change`)
- Compile errors or linter warnings
- Diff summary (counts of added/removed/changed items)

The dashboard surfaces these in a timeline so operators can see exactly
what happened during an incident.

## Implementation

- `src/config/loader.rs` — YAML parse + figment
- `src/config/secrets.rs` — reference parser + provider dispatch
- `src/config/watcher.rs` — `notify` watcher + debounce
- `src/config/validator.rs` — dry-run compile + linter
- `src/config/git_sync.rs` — Git source (feature-gated)
- `src/config/swap.rs` — `ArcSwap` + subscriber broadcast

## Performance notes

- Debounce window (200 ms) coalesces burst file events
- Compile cost is paid off-hot-path on the config task, not on the
  request handler
- `ArcSwap` load on the hot path is wait-free
