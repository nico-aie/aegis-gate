# plans/issues — known issues & multi-node gaps (for dev triage)

Field-found issues from the `pre-prod` 3-node deployment. Each entry has type,
severity, root cause, impact, workaround, and a suggested fix.

## Open

| File | Type | Severity | One-liner |
|---|---|---|---|
| [`multi-node-consistency.md`](./multi-node-consistency.md) | analysis | Mixed | What's cluster-consistent vs per-node: control plane (`set_profile`/`reset_state`) per-node (C-1), `/healthz/ready` upstream-blind (C-2), admin console per-node metrics (C-3), logs per-node (C-4), `X-Forwarded-For` ignored/unplumbed (C-5). **Implementation plan:** [`../multi-node-consistency-implementation.md`](../multi-node-consistency-implementation.md) (P1=C-5, P2=C-1, P3=C-3/C-4, P4=C-2). |
| [`UX-zero-trust-page-upstream-mtls-flow.md`](./UX-zero-trust-page-upstream-mtls-flow.md) | UX | Medium | Zero Trust page: per-upstream mTLS setup is supported but undiscoverable — upload UI vanishes silently when `allow_ca_upload` is off, no step-by-step flow, per-pool Save unguarded against missing identity/bundle prerequisites. |

## Resolved (archived)

| File | Type | Severity | Resolution |
|---|---|---|---|
| [`archived/BUG-config-plane-audit-sinks-yaml-enum.md`](./archived/BUG-config-plane-audit-sinks-yaml-enum.md) | **BUG** | High | ✅ Fixed in PR #14 (`aa25b21`, merged `develop` 2026-06-10). `load_config_str` validates via figment (same as boot); both `audit.sinks` map and `!`-tag forms round-trip. Regression tests added. |
