# GitOps & Change Management (v2, enterprise)

> **Enterprise addendum.** WAF config, rules, and routing live in Git.
> Changes go through PR review + signed commits + CI lint + dry-run +
> admin approval. The WAF pulls signed commits from `main` and reloads
> atomically. Direct API edits are preserved as a fallback for emergency
> changes, and **always** round-trip to Git.

## Purpose

Make every production change reviewable, reversible, and auditable. A
compliant deployment (SOC 2, PCI, ISO 27001) wants to see that no
change reached production without:

- peer review
- automated validation
- cryptographic attribution
- rollback capability

Git is the source of truth for all of these.

## Repo layout

```
waf-config/
├── waf.yaml            # top-level
├── routes/
│   ├── api.yaml
│   └── static.yaml
├── upstreams/
├── tenants/
├── rules/
│   ├── core/           # cluster-wide, admin-owned
│   └── acme/           # tenant-owned (namespaced)
├── secrets.refs.yaml   # references only, never values
└── .waf/
    ├── allowed_signers
    └── ci.yaml
```

## Signed-commits enforcement

The pull path (and the admin API write path) verify:

- Commit is signed (GPG or SSH-sig) by a key in `.waf/allowed_signers`
- Commit author matches the configured `trusted_authors` list
- Merge commits carry `Signed-off-by:` trailers from ≥ 2 reviewers
  when the changed files touch `rules/` or `tenants/`

Unsigned or unauthorized commits are rejected by the loader and emit
an `operational` audit event.

## CI lint pipeline

Runs on every PR before merge:

1. YAML syntax check
2. Schema validate against `WafConfig` JSON schema
3. Full dry-run compile (same path as the runtime validator)
4. Rule linter: depth limits, id uniqueness, priority conflicts
5. Compliance linter (if `compliance.modes` includes `pci` / `hipaa` / `fips`)
6. Diff summary posted back to the PR

CI runs the exact same validator binary the runtime uses, so a passing
CI guarantees the runtime will accept the config.

## Admin approval

For merges into `main`:

- Policies under `rules/core/` and `tenants/` require **2 approvers**,
  at least one with the `admin` role
- Policies under `routes/` and `upstreams/` require 1 `operator` or
  `admin` approver
- `break_glass` bypass is allowed only with an audit note + post-hoc
  review

## Runtime pull

The cluster leader polls the repo (or receives a webhook):

```yaml
config:
  source: git
  git:
    repo_url: "git@github.com:acme/waf-config.git"
    branch: main
    ssh_key: "${secret:file:/etc/waf/keys/git.key}"
    signed_commits_only: true
    allowed_signers: "/etc/waf/.waf/allowed_signers"
    trusted_authors: ["ops@example.com"]
    poll_interval_s: 60
```

On a new commit:

1. Verify signature + author
2. Run dry-run validator
3. On success, `ArcSwap` swap + notify subscribers
4. Emit `operational` audit event with commit hash + diff summary
5. On failure, keep running config, open an alert

## Direct API edits (break-glass)

When someone edits via the dashboard or `PUT /api/config`:

1. Change is validated + applied (same dry-run path)
2. A Git commit is auto-generated against the configured repo under
   branch `auto/<timestamp>-<actor>`
3. Branch is pushed; a PR is opened
4. A banner in the dashboard warns that there's a pending round-trip PR
5. An operator must accept (merge) or revert — otherwise the next Git
   pull will revert the change on the next poll

This guarantees Git remains authoritative while still allowing
emergency edits during incidents.

## Configuration

```yaml
gitops:
  enabled: true
  repo_url: "git@github.com:acme/waf-config.git"
  branch: main
  poll_interval_s: 60
  signed_commits_only: true
  allowed_signers: "/etc/waf/.waf/allowed_signers"
  trusted_authors: ["ops@example.com", "security@example.com"]
  approval:
    rules_core_min_approvers: 2
    routes_min_approvers: 1
  auto_pr_on_direct_edit: true
```

## Implementation

- `src/gitops/pull.rs` — git pull + signature verify
- `src/gitops/ci_bridge.rs` — shared validator entrypoint (used by CI)
- `src/gitops/auto_pr.rs` — direct-edit round-trip PR builder
- `src/gitops/signers.rs` — allowed-signers verifier (GPG + SSH-sig)

## Performance notes

- Poll runs on the leader only, off the hot path
- Validation runs on a background task; the data plane keeps serving
  with the previous config during validation
- Auto-PR branch push is async with retry on failure
