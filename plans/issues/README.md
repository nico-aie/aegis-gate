# plans/issues — known issues, multi-node gaps & feature tracks (for dev triage)

Field-found issues from the `pre-prod` 3-node deployment plus forward feature
tracks, in one table ordered open → resolved. Issue entries have type, severity,
root cause, impact, workaround, and a suggested fix; feature tracks carry a phase
checklist and acceptance gates, with the full design living in
[`../future/`](../future/).

## Open

| File | Type | Severity | Summary |
|---|---|---|---|
| [`UX-zero-trust-page-simplify-per-pool-cert-upload.md`](./UX-zero-trust-page-simplify-per-pool-cert-upload.md) | UX / refactor | Medium | 🟡 Zero Trust page upstream section: clean up layout + promote the WAF-cert download, **remove** the standalone Step 2 Backend-CA Trust Bundles card, and rework Step 3 into a per-pool table with inline cert upload (persisted to the Redis config plane) + an enable/disable mTLS toggle per pool. Frontend-first; reuses existing `aegis:zt:upstream:*` storage. Reported by liud 2026-06-11. |

> **Carry-over (not a file):** **F14** — `/api/audit/since` ~182 ms latency — was
> deferred from the cluster-QC-v2 fix (it needs *live* `render_ms>25` telemetry from
> the fleet to attribute the cause before coding). The self-timing + the
> `scope=fleet` fallback warn are already shipped; the breadcrumb lives in the
> archived [`FIX-cluster-qc-2026-06-11-V2.md`](./archived/FIX-cluster-qc-2026-06-11-V2.md)
> (§PD). Re-open here only if a live run shows the cost is handler-side.

## Resolved (archived)

| File | Type | Severity | Resolution |
|---|---|---|---|
| [`archived/FIX-cluster-qc-2026-06-11-V2.md`](./archived/FIX-cluster-qc-2026-06-11-V2.md) | fix plan | 🟠→✅ | **Shipped 2026-06-11 (PR #29, `develop`).** N2 (config-plane pub/sub nudge → ~ms convergence + Save "Applied on N/N nodes" pill), N1 (alert receivers folded into the shared config doc → propagate fleet-wide), F6 (roster-driven fleet merge instead of whole-keyspace `SCAN`), F2 (`/api/config/version` self-describing). **F14 deferred** (live telemetry — see Open carry-over). |
| [`archived/QC-CLUSTER-RESULTS-2026-06-11-V2.md`](./archived/QC-CLUSTER-RESULTS-2026-06-11-V2.md) | QC report | ✅ | Post-redeploy re-check. N1 (alert-channel node-local) + N2 (config apply polling-bound) new findings; F6/F2 still-open; F11/F7/F10 confirmed fixed. All but F14 resolved by the V2 fix plan. |
| [`archived/FIX-cluster-qc-2026-06-11.md`](./archived/FIX-cluster-qc-2026-06-11.md) | fix plan | ✅ | v1 phased fix (P1–P6) for the first QC run. All phases shipped; superseded by the v2 post-redeploy re-check above. |
| [`archived/QC-CLUSTER-RESULTS-2026-06-11.md`](./archived/QC-CLUSTER-RESULTS-2026-06-11.md) | QC report | ✅ | First cluster-mode QC run. Consensus healthy; defects in dashboard client, audit read-path, health-probe auth, session UX — all addressed across the v1/v2 fix plans. |
| [`archived/FEAT-proxy-protocol-l4-client-ip.md`](./archived/FEAT-proxy-protocol-l4-client-ip.md) | FEAT | ✅ Shipped (PR #26) | PROXY-protocol real client IP behind an L4 load balancer (opt-in per listener, default off). Design: [`../archive/proxy-protocol.md`](../archive/proxy-protocol.md). |
| [`archived/FEAT-websocket-message-inspection.md`](./archived/FEAT-websocket-message-inspection.md) | FEAT | ✅ Shipped (PR #27) | WebSocket text-frame (opcode `0x1`) message inspection through the body detectors (opt-in per route, default off). Design: [`../archive/websocket-message-inspection.md`](../archive/websocket-message-inspection.md). |
| [`archived/multi-node-consistency.md`](./archived/multi-node-consistency.md) | analysis | ✅ Resolved 2026-06-10 | Cluster/per-node audit (C-1…C-5). Every concern shipped or dropped: C-5 (`trusted_proxies`), C-1 (`set_profile`/`reset_state` fleet sync), C-3/C-4 (per-node console banner + `collect-audit.sh`) shipped; C-2 (upstream-aware readiness) dropped by operator decision. Plan: [`../archive/multi-node-consistency-implementation.md`](../archive/multi-node-consistency-implementation.md); forward fleet-console work: [`../archive/cluster-mode-multinode-sync.md`](../archive/cluster-mode-multinode-sync.md). |
| [`archived/UX-zero-trust-page-upstream-mtls-flow.md`](./archived/UX-zero-trust-page-upstream-mtls-flow.md) | UX | ✅ Shipped 2026-06-10 | Branch `feat/zt-upstream-mtls-ux`, merged `develop`. Zero Trust page UX pass: live setup stepper, `allow_ca_upload=false` now explains the YAML path instead of hiding upload, identity model stated up front, per-pool Save guarded against missing-identity apply-time failures, unified "applies-when" copy, actionable empty states. |
| [`archived/BUG-config-plane-audit-sinks-yaml-enum.md`](./archived/BUG-config-plane-audit-sinks-yaml-enum.md) | **BUG** | ✅ Fixed 2026-06-10 | PR #14 (`aa25b21`, merged `develop`). `load_config_str` validates via figment (same as boot); both `audit.sinks` map and `!`-tag forms round-trip. Regression tests added. |

_One open item (the Zero Trust page simplify) plus the F14 carry-over; all `pre-prod`
deployment + cluster-QC issues are resolved (rows above)._
