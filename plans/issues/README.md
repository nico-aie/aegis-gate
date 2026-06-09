# plans/issues — known issues & multi-node gaps (for dev triage)

Field-found issues from the `pre-prod` 3-node deployment. Each entry has type,
severity, root cause, impact, workaround, and a suggested fix.

| File | Type | Severity | One-liner |
|---|---|---|---|
| [`BUG-config-plane-audit-sinks-yaml-enum.md`](./BUG-config-plane-audit-sinks-yaml-enum.md) | **BUG** | High | Config plane (detector toggle / `PUT /api/config`) rejects the `audit.sinks` map form the shipped profiles use — `!`-tag enum mismatch between figment (boot) and serde_yaml 0.9 (config plane). Freezes runtime policy. |
| [`multi-node-consistency.md`](./multi-node-consistency.md) | analysis | Mixed | What's cluster-consistent vs per-node: control plane (`set_profile`/`reset_state`) per-node (C-1), `/healthz/ready` upstream-blind (C-2), admin console per-node metrics (C-3), logs per-node (C-4), `X-Forwarded-For` ignored/unplumbed (C-5). |
