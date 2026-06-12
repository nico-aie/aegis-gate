# plans/issues — known issues, multi-node gaps & feature tracks (for dev triage)

Field-found issues from the `pre-prod` 3-node deployment plus forward feature
tracks, in one table ordered open → resolved. Issue entries have type, severity,
root cause, impact, workaround, and a suggested fix; feature tracks carry a phase
checklist and acceptance gates, with the full design living in
[`../future/`](../future/).

## Open

| File | Type | Severity | Summary |
|---|---|---|---|
| [`WEBSOCKET_ATTACK_REPORT.md`](./WEBSOCKET_ATTACK_REPORT.md) | gap analysis | Medium | 🟡 WebSocket attack-surface gap report (4/29 blocked at time of writing). **Partially resolved:** RC-1 (`ws_inspect` ON by default, PR #40), RC-3 (cookie-injection detector, PR #42), and oversized-frame fail-closed + XFF/IP-spoof hardening (PR #41) all shipped. **Still open:** RC-2 (WS `Origin` allowlist / `ws_require_origin` — not in code), RC-5 (`Sec-WebSocket-Protocol` / WS-specific header scanning), and the RC-4 SSE cross-site (CORS/Origin) check. Re-scope the residual before picking it up. |

> **Carry-over (not a file):** **F14** — `/api/audit/since` ~182 ms latency — was
> deferred from the cluster-QC-v2 fix (it needs *live* `render_ms>25` telemetry from
> the fleet to attribute the cause before coding). The self-timing + the
> `scope=fleet` fallback warn are already shipped; the breadcrumb lives in the
> archived [`FIX-cluster-qc-2026-06-11-V2.md`](./archived/FIX-cluster-qc-2026-06-11-V2.md)
> (§PD). Re-open here only if a live run shows the cost is handler-side.

## Resolved (archived)

| File | Type | Severity | Resolution |
|---|---|---|---|
| [`archived/FIX-detector-toggle-and-config-lag.md`](./archived/FIX-detector-toggle-and-config-lag.md) | fix plan | 🟠→✅ | **Shipped 2026-06-12 (PRs #34, #36).** All three linked issues: velocity mask-bypass id fix + drift-guard test (#34), config-plane latency cuts + detector-toggle 412 churn (version-from-PUT-response + serialize) (#34), and the full-mask PUT clobber from stale base (#36). |
| [`archived/VELOCITY_SEQUENCE_BUG_REPORT.md`](./archived/VELOCITY_SEQUENCE_BUG_REPORT.md) | **BUG** | ✅ Fixed 2026-06-12 (PR #34) | `VelocitySequenceDetector::id()` now returns `"velocity"` (matched `DetectorClass::Velocity`), so the mask gates it; the `all_registered_detectors_map_to_a_class` drift-guard test prevents recurrence. Source report for the fix plan above. |
| [`archived/JWT_ATTACK_REPORT.md`](./archived/JWT_ATTACK_REPORT.md) | gap analysis | ✅ Resolved 2026-06-12 | Source report (600 samples, ~0% effective). Closed by the `jwt_inspection` detector (`DetectorClass::JwtInspection`, bit 1<<16; dashboard toggle + `/api/detectors` catalog): alg:none, jku/x5u SSRF, x5c/jwk inline, kid traversal/SQLi, time-claim forge all **blocked**; role-escalation **log_only** (opt-in). weak-secret + RS256→HS256 are gateway/app-side, out of WAF scope. Plan: [`../archive/jwt-and-smuggling-detection.md`](../archive/jwt-and-smuggling-detection.md). |
| [`archived/HTTP_SMUGGLING_REPORT.md`](./archived/HTTP_SMUGGLING_REPORT.md) | gap analysis | ✅ Resolved 2026-06-12 | Source report (185 sent, "49.7% missed"). Reframed: hyper already rejects ambiguous framing (400) and re-serializes outbound, so those were **rejections, not bypasses**. `header_injection` now adds `smuggling_cl_te` / `_multi_cl` / `_multi_te` / `_h2_forbidden` (score 70) for **attribution + defense-in-depth**; only `smuggling_h2_forbidden` fires in normal operation. B2 body-embedded-line deferred by decision. Plan: [`../archive/jwt-and-smuggling-detection.md`](../archive/jwt-and-smuggling-detection.md). |
| [`archived/UX-zero-trust-page-simplify-per-pool-cert-upload.md`](./archived/UX-zero-trust-page-simplify-per-pool-cert-upload.md) | UX / refactor | ✅ Shipped 2026-06-12 | Zero Trust upstream section simplified: standalone Step 2 Backend-CA Trust Bundles card **removed** (`ZtTrustBundlesCard` gone), Step 3 reworked into the per-pool `ZtUpstreamPoolsCard` with inline cert upload (auto-named `pool-<P>` bundle, persisted to the Redis config plane), per-pool enable/disable mTLS toggle, `identityReady` gate, and `allow_ca_upload`-aware shown-but-disabled control. Reported by liud 2026-06-11. |
| [`archived/FIX-cluster-qc-2026-06-11-V2.md`](./archived/FIX-cluster-qc-2026-06-11-V2.md) | fix plan | 🟠→✅ | **Shipped 2026-06-11 (PR #29, `develop`).** N2 (config-plane pub/sub nudge → ~ms convergence + Save "Applied on N/N nodes" pill), N1 (alert receivers folded into the shared config doc → propagate fleet-wide), F6 (roster-driven fleet merge instead of whole-keyspace `SCAN`), F2 (`/api/config/version` self-describing). **F14 deferred** (live telemetry — see Open carry-over). |
| [`archived/QC-CLUSTER-RESULTS-2026-06-11-V2.md`](./archived/QC-CLUSTER-RESULTS-2026-06-11-V2.md) | QC report | ✅ | Post-redeploy re-check. N1 (alert-channel node-local) + N2 (config apply polling-bound) new findings; F6/F2 still-open; F11/F7/F10 confirmed fixed. All but F14 resolved by the V2 fix plan. |
| [`archived/FIX-cluster-qc-2026-06-11.md`](./archived/FIX-cluster-qc-2026-06-11.md) | fix plan | ✅ | v1 phased fix (P1–P6) for the first QC run. All phases shipped; superseded by the v2 post-redeploy re-check above. |
| [`archived/QC-CLUSTER-RESULTS-2026-06-11.md`](./archived/QC-CLUSTER-RESULTS-2026-06-11.md) | QC report | ✅ | First cluster-mode QC run. Consensus healthy; defects in dashboard client, audit read-path, health-probe auth, session UX — all addressed across the v1/v2 fix plans. |
| [`archived/FEAT-proxy-protocol-l4-client-ip.md`](./archived/FEAT-proxy-protocol-l4-client-ip.md) | FEAT | ✅ Shipped (PR #26) | PROXY-protocol real client IP behind an L4 load balancer (opt-in per listener, default off). Design: [`../archive/proxy-protocol.md`](../archive/proxy-protocol.md). |
| [`archived/FEAT-websocket-message-inspection.md`](./archived/FEAT-websocket-message-inspection.md) | FEAT | ✅ Shipped (PR #27) | WebSocket text-frame (opcode `0x1`) message inspection through the body detectors (opt-in per route, default off). Design: [`../archive/websocket-message-inspection.md`](../archive/websocket-message-inspection.md). |
| [`archived/multi-node-consistency.md`](./archived/multi-node-consistency.md) | analysis | ✅ Resolved 2026-06-10 | Cluster/per-node audit (C-1…C-5). Every concern shipped or dropped: C-5 (`trusted_proxies`), C-1 (`set_profile`/`reset_state` fleet sync), C-3/C-4 (per-node console banner + `collect-audit.sh`) shipped; C-2 (upstream-aware readiness) dropped by operator decision. Plan: [`../archive/multi-node-consistency-implementation.md`](../archive/multi-node-consistency-implementation.md); forward fleet-console work: [`../archive/cluster-mode-multinode-sync.md`](../archive/cluster-mode-multinode-sync.md). |
| [`archived/UX-zero-trust-page-upstream-mtls-flow.md`](./archived/UX-zero-trust-page-upstream-mtls-flow.md) | UX | ✅ Shipped 2026-06-10 | Branch `feat/zt-upstream-mtls-ux`, merged `develop`. Zero Trust page UX pass: live setup stepper, `allow_ca_upload=false` now explains the YAML path instead of hiding upload, identity model stated up front, per-pool Save guarded against missing-identity apply-time failures, unified "applies-when" copy, actionable empty states. |
| [`archived/BUG-config-plane-audit-sinks-yaml-enum.md`](./archived/BUG-config-plane-audit-sinks-yaml-enum.md) | **BUG** | ✅ Fixed 2026-06-10 | PR #14 (`aa25b21`, merged `develop`). `load_config_str` validates via figment (same as boot); both `audit.sinks` map and `!`-tag forms round-trip. Regression tests added. |

_One open item (the WebSocket report's RC-2/RC-4/RC-5 residual) plus the F14
carry-over; the 2026-06-12 security-team sweep (velocity, detector-toggle/config
lag, JWT, smuggling) and the Zero Trust page simplify all shipped, and every
`pre-prod` deployment + cluster-QC issue is resolved (rows above)._
