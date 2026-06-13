# Pre-prod feature run — 2026-06-13 — n-tester (Chrome MCP)

**Build / cluster:** Aegis WAF v0.1.0 · 3 nodes (`waf-infra-1`, `waf-2`, `waf-3`) ·
**Env:** pre-prod cluster · admin `:56243/:56244/:56245` · data VIP `https://185.23.199.194:56208` (TLS-only) ·
**Upstreams:** 10.20.0.72 — `/ws`→ws-pool:9992, `/grpc`→grpc-pool:9993, catch-all `/`→http-pool:9991 (http+ws) ·
**Driver:** Claude Desktop + Chrome MCP · **Mode:** UI/UX + feature + contract conformance

## Environment notes that shaped the run

1. **Data plane is HTTPS-only on :56208** (L4 VIP → WAF `:8443` TLS listener; plaintext `:8080` not published). Self-signed cert had to be accepted in Chrome once before any data-plane test worked.
2. **Untrusted `X-Forwarded-For` is correctly ignored** (contract §10). The L4 VIP passes raw TLS, so the WAF keys risk/identity on the real peer (`10.200.0.1`), not on spoofed XFF. → per-IP test methodology via XFF spoofing does not work; all client traffic is attributed to one identity.
3. **LB connection persistence (keep-alive)** pins a browser client to a single node (`waf-infra-1`), so genuine cross-node traffic can't be generated from one client.
4. The contract **control endpoints are not reachable on the VIP** (see CRIT-1), so `reset_state` couldn't be used; risk was cleared via the admin-side `DELETE /api/risk` instead.

## Results matrix

| Case | Result | Sev | Notes |
|---|---|---|---|
| **CL-01** roster/leaderless | ✅ PASS | High | 3-peer roster; distinct `our_node` per node; role=peer (no leader); all HEALTHY; Scaling shows config **v88 in sync** on all 3. |
| **CL-02** config convergence | ✅ PASS | Critical | recon off on N1 → all 3 → v89/recon=false in <~3s; re-enabled from N2 → v90. Hash-chained audit `detector_mask_set` (actor=admin, src=dashboard) + **3 per-node `config_reload`** rows. |
| **CL-03** versions/CAS/409 | ✅ PASS | High | Concurrent PUTs `/api/response-filter` → **6×409 `version_conflict`** (with `current`) + 2×200. Version history monotonic. (Detector PUT is last-write-wins by design — not CAS — correct.) |
| **CL-04** blacklist fleet-wide | ❌ FAIL | **HIGH** | Entry added on N1 (201) **did not propagate** to N2/N3 (count 0 after wait) and **did not bump shared config_version**. Node-local only — see HIGH-2. |
| **CL-05** shared rate-limit | ⚠️ INCONCLUSIVE | — | 150 concurrent reqs from one IP all `allow`; rate limit not tripped at safe test volume. Shared-counter claim not validated. |
| **CL-06** cross-node live events | ⚠️ PARTIAL | — | Audit carries `node_id` (fleet_events plumbing present), but all traffic pinned to `waf-infra-1` (keep-alive) → cross-node aggregation not exercisable from one client. |
| **CL-07** control-API parity | ❌ FAIL | **CRITICAL** | Control endpoints proxied to upstream on VIP — see CRIT-1. |
| **WS-01** plaintext-upgrade fix | ✅ PASS | Critical | WSS upgrade on **both `/ws` and catch-all `/`** opens, echoes the sent frame, closes **1000** (no 1006 drop). Headline bug fix verified. |
| **WS-02** handshake security | ✅ PASS | High | SQLi handshake probe → **403 block rule=sqli**; attack upgrade never opens. Handshake runs full pipeline. |
| **WS-03** ws_inspect log_only | ⚠️ N/A | — | `ws_inspect` disabled on all routes (not configured in pre-prod); not togglable via API. Benign frame forwarded (byte-tunnel baseline confirmed). |
| **WS-04** ws_inspect enforce (BUG-WS-2/3) | ⚠️ N/A | — | Not reachable without `ws_inspect` enabled. |
| **WS-05** Live Feed WS Proto render | ✅ PASS | Medium | Live Feed SSE CONNECTED (80/80); **PROTO renders as plain inline text** (the `d359e5b` fix), filters work, clean 404 page for bad route. |
| **WS-06** handshake headers + audit | ⚠️ PARTIAL | High | Handshake carries WAF decision headers (`x-waf-action` etc., seen in WS-02); explicit request-id↔audit match not run. |
| **MT-01** Zero Trust page mounts | ✅ PASS | High | Mounts clean; upstream cards (WAF Client Identity CONFIGURED, Upstream mTLS by Pool [grpc/http/tcp/ws], Handshake Failures 0). Finding MED-4. |
| **MT-02** downstream toggle/validation | ✅ PASS | High | Per-pool mTLS toggle is **instant** + **correct validation rejection** ("requires upstream_identity … none is set"); unenforceable config not persisted. Finding LOW-5. |
| **MT-03** downstream enforcement | ⛔ BLOCKED | — | No downstream UI; no test client certs; needs data-plane mTLS. |
| **MT-04** upstream mTLS | ⚠️ PARTIAL | High | Identity/pools/failures plumbing present; live handshake blocked (in-console upload off, no mTLS backend). |
| **MT-05** failures telemetry | ✅ PASS | Medium | Honest empty state (0 total). Real endpoint `/api/zero-trust/upstream/failures`. |
| **MT-06** certs page | ⚠️ PARTIAL | Medium | "Download cert" (WAF identity) present; in-console upload disabled (`allow_ca_upload` off). |
| **MT-07** config converge / nav badge | ✅ PASS | High | **No "NEW" nav badge** (Beta only). zero_trust convergence covered by config-plane (CL-02). |
| **CP-01** panel/feature state | ✅ PASS | High | Copilot configured + live (`openai:Qwen3.6-35B-A3B`); endpoints 200 with token accounting. |
| **CP-02** situational summary | ✅ PASS | High | Structured advisory brief; grounded — references real attack classes + blocks after traffic. |
| **CP-03** ask | ❌ FAIL | **MEDIUM** | `/api/copilot/ask` → **404** (not wired on this build) — see MED-3. |
| **CP-04** triage never auto-applied | ✅ PASS | Critical | 5 suggestions (`id, cluster, explanation, suggested_rule, confidence`); **active rules stayed 0** — nothing auto-applied. |
| **CP-05** CostGuard budget | ⚠️ PARTIAL | — | Per-response token accounting present; full budget-exceeded path not force-tested (LLM cost). |
| **CP-06** egress redaction | ⚠️ NOT RUN | — | Needs provider-egress/log capture; not verifiable from UI alone. |
| **CP-07** cluster-aware summary | ⚠️ PARTIAL | — | Summary reflects telemetry; cross-node consistency not validated (traffic pinned to one node). |
| **CP-08** advisory-only | ✅ PASS | Critical | Copilot activity left rules/blacklist/config-version unchanged. |

## Findings

### CRIT-1 — Contract control interface is proxied to the upstream on the data VIP
`GET /__waf_control/capabilities` (and `reset_state`, `set_profile`, `flush_cache`) on `https://185.23.199.194:56208` return the **mock upstream echo** `{"echo":"/__waf_control/capabilities","host":"[INTERNAL]:9991",...}` — i.e. they're caught by the catch-all `/` route and forwarded to http-pool:9991. Consequences:
- Violates contract §2.1: "control endpoints … MUST NOT be proxied to upstream."
- Violates §2.2: missing `X-Benchmark-Secret` returns **200** (upstream echo), not **403**.
- `reset_state`/`set_profile`/`flush_cache` are **non-functional** via the VIP (they hit the upstream, not the control handler).
- Side effect: while a client's risk is high, even these paths return `403 blocked-by-risk` (they ride the normal request pipeline), so the organizer's "send attacks → reset_state from same source" flow would fail.
**Fix:** intercept `/__waf_control/*` before routing (local/admin-only handler, secret-gated), ahead of the catch-all and the risk gate. **Severity: CRITICAL** (a core hackathon contract surface is absent on the exposed edge).

### HIGH-2 — Operator blacklist entries do not propagate across the cluster
A blacklist entry created on N1 (`POST /api/blacklist` → 201) never appeared on N2/N3 (`/api/blacklist` count stayed 0 after >5s) and **did not advance the shared `config_version`** (stayed v97 on N1 and N2). The detector mask *does* converge via the config plane, so blacklist is on a different, **node-local** path. Behind the LB this means an IP blocked on one node is still served by the other two (~1/3 enforcement). Contradicts the HA doc's "shared block lists" guarantee. **Fix:** route operator access-list mutations through the same converged config plane (or the shared Redis set the data plane actually reads). **Severity: HIGH.**

### MED-3 — `/api/copilot/ask` returns 404
Only `/api/copilot/summary` and `/api/copilot/suggestions` are wired on this build; `ask` 404s though it exists in source. Either wire it or drop it from the spec/UI. **Severity: MEDIUM.**

### MED-4 — Zero Trust page surfaces the upstream direction only
The "Zero Trust" page shows WAF→backend (upstream) mTLS only: WAF Client Identity, Upstream mTLS by Pool, Handshake Failures. The **downstream** direction (client certs presented *to* the WAF) is not in the UI (config-only via `zero_trust.downstream`). The feature doc claims one page owns "both directions." **Severity: MEDIUM** (UI/feature-coverage gap).

### LOW-5 — "WAF Client Identity: CONFIGURED" contradicts toggle validation
The identity card shows `CN=aegis-waf-client … CONFIGURED · LIVE · ROTATED ×1`, but enabling a pool's mTLS fails validation with "requires a configured `zero_trust.upstream_identity` … none is set." The displayed live/rotated identity is evidently not the YAML `upstream_identity` the pool toggle requires — confusing. **Severity: LOW** (messaging/consistency).

### INFO observations
- **`/api/mtls/*` endpoints do not exist (404)** — the real namespace is `/api/zero-trust/{upstream,downstream}/*` (e.g. `/upstream/failures`, `/downstream/ca-bundle/capability`). The draft test plan referenced `/api/mtls/*` — **plan needs correction.**
- **XFF correctly ignored** (§10) — good security; documented here because it changes per-IP test methodology.
- **Pre-prod health:** copilot brief + the "3 FIRING" badge report active **DataPlaneAvailability** SLO alerts / 400-error volume — a real environment signal worth investigating.
- **CSRF double-submit enforced** — a DELETE with a stale csrf token returned 403; with a fresh token, 200.

## What passed cleanly (positives)

- **Cluster config plane** is solid: leaderless 3-node roster, near-instant bidirectional convergence, monotonic versioning, true CAS `version_conflict` (409 + `current`), hash-chained audit with actor + per-node reload rows.
- **WebSocket upgrade bug fix verified** end-to-end over WSS on both `/ws` and the catch-all; handshake security blocks attacks before a socket forms.
- **AI Copilot** is live, grounded, advisory-only, with working smart-catch triage suggestions (clustered, explained, never auto-applied) and CostGuard token accounting.
- Detection + risk lifecycle correct (sqli/xss/path_traversal blocked with right `X-WAF-Rule-Id`; risk accumulates to a block; clean baseline headers all conform to §5.1).

## End-of-run summary

```
Pre-prod feature run · 2026-06-13 · Chrome MCP
Cases: 13 PASS · 2 FAIL · 9 PARTIAL/INCONCLUSIVE · 1 BLOCKED · 2 N/A (ws_inspect off)
Findings: 1 CRITICAL · 1 HIGH · 2 MEDIUM · 1 LOW · 4 INFO
Top blocker: CRIT-1 — control endpoints proxied to upstream on the data VIP (contract §2.1/§2.2).
Runner-up: HIGH-2 — operator blacklist entries don't propagate across the cluster.
Release verdict: HOLD pending CRIT-1 + HIGH-2 (both are contract/cluster-correctness, not cosmetic).
```

State left clean: recon re-enabled (18/18), response-filter restored, blacklist `cl04-test` deleted, risk cleared.
