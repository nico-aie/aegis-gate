# plans/issues — known issues, multi-node gaps & feature tracks (for dev triage)

Field-found issues from the `pre-prod` 3-node deployment plus forward feature
tracks, in one table ordered open → resolved. Issue entries have type, severity,
root cause, impact, workaround, and a suggested fix; feature tracks carry a phase
checklist and acceptance gates, with the full design living in
[`../future/`](../future/).

| File | Type | Status | Notes |
|---|---|---|---|
| [`QC-CLUSTER-RESULTS-2026-06-11.md`](./QC-CLUSTER-RESULTS-2026-06-11.md) | QC report | 🔴 Open — 3 HIGH · 6 MED · 2 LOW | Cluster-mode QC run. Consensus healthy; defects in dashboard client, audit read-path, health-probe auth, session UX. |
| [`FIX-cluster-qc-2026-06-11.md`](./FIX-cluster-qc-2026-06-11.md) | fix plan | 🟠 In progress | Phased fix plan (P1–P6) for the QC findings. Re-scopes F14/F13/F2 after code review. **All phases implemented on `fix/cluster-qc-2026-06-11`** (commits 2c6d621 → P6); pending live re-check + merge. |
| [`FEAT-proxy-protocol-l4-client-ip.md`](./FEAT-proxy-protocol-l4-client-ip.md) | FEAT | 🟡 Designed — not started | PROXY-protocol real client IP behind an L4 load balancer (opt-in per listener, default off). Design: [`../future/proxy-protocol.md`](../future/proxy-protocol.md). |
| [`FEAT-websocket-message-inspection.md`](./FEAT-websocket-message-inspection.md) | FEAT | 🟡 Designed — not started | WebSocket text-frame (opcode `0x1`) message inspection through the body detectors (opt-in per route, default off). Design: [`../future/websocket-message-inspection.md`](../future/websocket-message-inspection.md). |
| [`archived/multi-node-consistency.md`](./archived/multi-node-consistency.md) | analysis | ✅ Resolved 2026-06-10 | Cluster/per-node audit (C-1…C-5). Every concern shipped or dropped: C-5 (`trusted_proxies`), C-1 (`set_profile`/`reset_state` fleet sync), C-3/C-4 (per-node console banner + `collect-audit.sh`) shipped; C-2 (upstream-aware readiness) dropped by operator decision. Plan: [`../archive/multi-node-consistency-implementation.md`](../archive/multi-node-consistency-implementation.md); forward fleet-console work: [`../archive/cluster-mode-multinode-sync.md`](../archive/cluster-mode-multinode-sync.md). |
| [`archived/UX-zero-trust-page-upstream-mtls-flow.md`](./archived/UX-zero-trust-page-upstream-mtls-flow.md) | UX | ✅ Shipped 2026-06-10 | Branch `feat/zt-upstream-mtls-ux`, merged `develop`. Zero Trust page UX pass: live setup stepper, `allow_ca_upload=false` now explains the YAML path instead of hiding upload, identity model stated up front, per-pool Save guarded against missing-identity apply-time failures, unified "applies-when" copy, actionable empty states. |
| [`archived/BUG-config-plane-audit-sinks-yaml-enum.md`](./archived/BUG-config-plane-audit-sinks-yaml-enum.md) | **BUG** | ✅ Fixed 2026-06-10 | PR #14 (`aa25b21`, merged `develop`). `load_config_str` validates via figment (same as boot); both `audit.sinks` map and `!`-tag forms round-trip. Regression tests added. |

_No open field-found issues — all `pre-prod` deployment issues are resolved (rows above)._
