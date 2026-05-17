---
id: 2026-05-17-gitops-sync-dead-code
date: 2026-05-17T00:00Z
severity: CRITICAL
area: GitOps · config sync
component: crates/aegis-control/src/gitops/mod.rs (GitOpsLoader::sync, dry_run_validate, break_glass_edit)
interop_contract: §5.9 bonus (Zero-downtime Config Sync) · Round-1 audit-mutated CRUD
status: open
test_mode: source-review (spot-verified via grep)
---

# F-CRITICAL-005 · `GitOpsLoader::sync` is dead code; `dry_run_validate` is a no-op — §5.9 zero-downtime sync bonus completely uncollected

## Summary

The GitOps module looks production-ready: 806 LoC, fixture-shaped
types, signed-commit verification, polling cadence config, break-glass
edit flow. **But it has zero production callers** and the validation
that gates auto-apply is a no-op:

**Spot-verified** via `grep -rn "loader.sync\|GitOpsLoader::sync" crates/`:
all hits are inside `gitops/mod.rs:570-650` — `#[cfg(test)]` blocks
only. Same for `break_glass_edit`. No `aegis_proxy::run` or
`aegis_bin::main` call site.

**Spot-verified** at [gitops/mod.rs:185-192](aegis-gate/crates/aegis-control/src/gitops/mod.rs#L185-L192):

```rust
fn dry_run_validate(content: &str) -> Result<()> {
    let _: serde_json::Value = serde_yaml::from_str(content)?;
    Ok(())
}
```

This is a YAML well-formed check, nothing else. Inputs that pass:

- `"hello"` — a literal YAML string
- `42` — a literal number
- `null`
- `{}` — empty map
- `[]` — empty list
- A YAML document with zero `listeners`/`routes`/`upstreams` — valid YAML, totally broken WAF config

If `sync` were ever wired, an attacker who got commit access to the
GitOps repo could push `waf.yaml: 42` and the WAF would auto-apply,
brick itself, and audit-chain the change.

Compounding (Agent C HIGH findings):
- `sync` never emits any `AuditEvent` even when it "works"
- `sync` never publishes via any `ConfigBroadcast`/swap
- `git clone` runs synchronously on the tokio runtime with no timeout
- `break_glass_edit` accepts `X-Actor` verbatim into branch name + Markdown PR body

## Observed code path

[gitops/mod.rs:237-305](aegis-gate/crates/aegis-control/src/gitops/mod.rs#L237-L305) — `sync` body:

```rust
pub async fn sync(&self, client: &impl GitClient) -> Result<SyncRecord> {
    let head = client.head_sha(...).await?;
    if head == self.last_applied_sha { return Ok(SyncRecord::NoOp); }

    let content = client.read_file(&head, "waf.yaml").await?;
    Self::dry_run_validate(&content)?;            // ← stub

    // ... stamps last_applied_sha ...
    // ... NO services.mutate.apply(...) call ...
    // ... NO config broadcast ...
}
```

[aegis-control/src/lib.rs] + `aegis-proxy/src/run.rs` — no
`GitOpsLoader::new(...)` construction site outside tests.

## Impact

- **§5.9 bonus "Zero-downtime Config Sync" (Cao difficulty)** —
  fully uncollected. The work LOOKS done (large module, signed
  commits, hash check); the work IS NOT done.
- **README claim** of "multi-region deployment + zero-downtime config sync" — false.
- **If anyone wires it later**:
  - `dry_run_validate` accepts garbage → WAF bricks on push of malformed waf.yaml.
  - No audit emit → Round-1 audit-mutated CRUD violation on git-driven changes.
  - `git clone` synchronous on tokio reactor → DoS via hanging remote.

## Suggested fix

Two paths. Pick one and commit.

### Path A — Wire it

1. Construct `GitOpsLoader` in `aegis-proxy/src/run.rs` from
   `cfg.gitops` (if enabled).
2. Spawn `poll_driver` loop that calls `loader.sync(&git_client)` on
   `cfg.gitops.poll_interval` cadence.
3. Replace `dry_run_validate` with real schema check:

```rust
fn dry_run_validate(content: &str) -> Result<()> {
    let cfg: WafConfig = serde_yaml::from_str(content)?;
    cfg.validate()?;          // existing boot-path validator
    Ok(())
}
```

4. On successful validate, call `services.mutate.apply(MutationRequest { actor: "gitops", reason: format!("git sync {head_sha}"), ... })` to chain audit.
5. Wrap `git clone` in `tokio::time::timeout(cfg.gitops.clone_timeout, ...)`.

### Path B — Delete

If the §5.9 bonus isn't feasible by the deadline, delete the module
and remove the README sections that claim it. The half-shipped state
is the worst — operators reading the README THINK GitOps works.

## Verification

After Path A:

```sh
# Push a valid waf.yaml to the GitOps repo.
git -C $GIT_REPO commit -am "..." && git -C $GIT_REPO push
# Within poll_interval seconds, WAF should:
# - call services.mutate.apply
# - emit audit-chain entry with actor=gitops, sha=<commit>
# - data plane reflects new config

curl -sk "$HOST/api/audit/since?ip=&rule_id=&since=..." | jq '.events[] | select(.fields.actor == "gitops")'
```

Add a failing-validation test: push `waf.yaml: 42` → assert `sync`
returns Err, no audit emit, `last_applied_sha` unchanged.

## Severity rationale

CRITICAL on §5.9 bonus loss (entire bonus category uncollected) plus
README-veracity risk. If reviewed by judges who try to verify the
GitOps claim, they find a shell. Same pattern as F-CRITICAL-006 in
the proxy audit.
