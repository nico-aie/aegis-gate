# Aegis-Gate — Cluster-Mode QC Results & Developer Report

**Run:** 2026-06-11 · cluster sync (§3) + control APIs (§4) + full-QC widen (pages, API sweep, perf, concurrency) · driver: Claude in Chrome (remote QC laptop)
**Fleet:** waf-infra-1 / waf-2 / waf-3 · consoles `:56243` / `:56244` / `:56245` · data VIP `:56208`

## Headline

The **leaderless backend converges correctly** — roster, merged stats, and config versioning stay
consistent across nodes, config changes propagate fleet-wide in ~2 s, all 17 dashboard pages mount
cleanly with no console errors, and the UI itself is smooth (no main-thread long-tasks on idle).
The defects are in the **dashboard client, the audit read-path, the health-probe auth gating, and
session handling** — not in cluster consensus.

**Findings: 0 CRITICAL · 3 HIGH · 6 MEDIUM · 2 LOW · 3 INFO**

Most important:
- **F11 (HIGH)** — `/healthz/live` & `/healthz/startup` require auth (401). Orchestrator probes can't
  authenticate → liveness failures cause **restart loops**, startup failures keep pods un-ready.
- **F7 (HIGH)** — detector toggles silently desync: writes get dropped while the UI shows them
  applied, so a detector can read "enabled" in the console while the engine has it **disabled**.
- **F6 (HIGH)** — Live Feed / Audit Trail lose cross-node records on refresh (SSE is fleet-wide, the
  reload backfill is node-local).
- **F14 (MEDIUM, perf)** — `/api/audit/since` has a fixed ~260 ms latency floor (≈100× other
  endpoints); it's the source of the Live Feed / Audit "lag."

---

## Cluster SLO results (§3 / §4)

| Check | Result | Evidence |
|---|---|---|
| §3.1 Fleet roster (`/api/cluster`) | **PASS** | Same 3 peers on all consoles; `our_node` correct per node; **no `is_leader`**; heartbeats fresh. |
| §3.2 Merged stats (`fleet_nodes`) | **PASS** | `fleet_nodes:3`, identical `blocks_total`/upstream across consoles. |
| §3.3 Live events (SSE) | **PASS (fanout) / BUG (backfill → F6)** | SSE is fleet-wide (waf-2 toggle fanned waf-2 **and** waf-3 events into waf-infra-1's stream); reload backfill is node-local. |
| §3.4 Config convergence | **PASS** | Toggle propagated to all 3 nodes' `applied` vector in ~2 s, both directions; cross-console well-spaced writes both survived (version 41/43 on all nodes). |
| §4 `/__waf_control` APIs | **NOT RUN** | No reachable path from this laptop — see F4. |
| §4.5 Gating (negative) | **PARTIAL** | `/__waf_control/*` via admin `:5624x` → 404; data-VIP path unreachable from QC. |
| Page mount sweep (17 pages) | **PASS** | Every sidebar page renders its heading, no error-boundary card, 0 console errors. |
| API sweep (38 endpoints) | **PASS w/ 3×404** | 35/38 → 200; `/api/mtls/{connections,failures,ca-summary}` → 404 (F13). |

---

## Performance observation (you asked about lag)

The UI is **not** the bottleneck — the chart-heavy Overview produced **zero** long-tasks over a 3 s
idle window, and pages mount fast. The lag is **one slow server endpoint**:

| Endpoint | Median latency | Notes |
|---|---|---|
| `/api/cluster`, `/api/stats`, `/api/detectors`, `/api/slo`, `/api/attacks/top`, `/api/stats/timeseries` | **2–3 ms** | Fast, even the 37 KB timeseries payload. |
| **`/api/audit/since`** | **~260 ms** | `limit=5` → 255 ms, `limit=80` → 337 ms, `limit=200` → 266 ms. |

The audit latency is a **fixed ~260 ms floor independent of result size** (limit 5 is as slow as
limit 200), so it isn't payload volume — it's a per-request cost (most likely re-reading/parsing the
audit log or ndjson hash-chain from disk, or a blocking flush, on every call). Network RTT is ~2 ms
(see the other endpoints), so essentially all 260 ms is server-side. Because **both Live Feed and
Audit Trail poll this endpoint**, every refresh stalls ~¼ second — that's the perceived lag.

Data-plane (WAF) latency from `/api/analytics/latency` during this idle run: detect p50 ≈ 1.9 ms,
total p50 ≈ 3.8 ms (only 9 samples, so p95/p99 here are noise — not comparable to the 5k-RPS
prod-balanced baseline; would need a real load run via `:56208`).

**Suggested fix (F14, MEDIUM):** back `/api/audit/since` with an in-memory ring buffer / index, or
cache the tail, so the dashboard's poll doesn't pay a disk/parse cost each time. Target parity with
the other endpoints (single-digit ms).

---

## Findings (for the dev team)

### F11 · HIGH · `/healthz/live` and `/healthz/startup` require auth (should be open)
**Area:** admin-api / routing · **Component:** health-probe auth middleware

**Summary.** `/healthz/ready` is correctly unauthenticated, but `/healthz/live` and
`/healthz/startup` are behind the admin-auth middleware. Verified both ways: logged out →
`ready=200, live=401, startup=401`; logged in → all `200`. Consistent across nodes (checked
waf-infra-1 and waf-3). Liveness/startup probes from k8s, load balancers, or the VIP health checker
cannot present a session cookie, so they will receive 401.

**Impact.** In an orchestrated deployment a failing **liveness** probe restarts the container
(crash-loop risk) and a failing **startup** probe prevents the pod from ever becoming ready. This
can take down healthy nodes.

**Repro.** Logged out: `curl -i http://<admin>/healthz/live` → 401; `/healthz/ready` → 200.

**Suggested fix.** Move `live` and `startup` to the same open route group as `ready` (exempt all
`/healthz/*` from the admin-auth middleware).

**Severity rationale.** Operational outage risk in production orchestration; trivial to hit. HIGH.

---

### F7 · HIGH · Detector toggles silently desync (UI says ON, engine is OFF)
**Area:** dashboard + admin-api · **Component:** detectors-page / detector-mask save

**Summary.** Each flip POSTs the **full** detector mask (read-modify-write). Writes get dropped when
they race — and the UI optimistically shows them applied — so the console can show a detector
enabled while `/api/detectors` (the enforcement mask) has it disabled.

**Evidence.**
- A single deliberate toggle works and converges. But **three rapid flips** bumped config version
  36→39 (three full-mask writes) and ended with the UI showing `recon=ON, nosql=ON` ("15/16
  enabled") while the backend mask had both **OFF** (13/16). Verified against raw `/api/detectors`
  (single `mask` object, `overrides:{}`).
- **Reinforced during cleanup:** a *single* deliberate revert of `template_injection` (switch
  showed ON) was **silently dropped** — backend stayed OFF — because the write interleaved with
  ongoing cluster propagation. So lost-writes aren't limited to rapid same-page toggling; any write
  that coincides with propagation can vanish.
- A hard browser reload re-syncs the UI to the (true) backend; a soft in-app nav does not (see F8).

**Impact.** Silent security misconfiguration — an operator believes a detector class (recon,
NoSQLi, …) is protecting traffic when it is not.

**Suggested fix.** Server: per-detector PATCH (`{class, enabled}`) instead of full-mask overwrite, or
optimistic-concurrency (reject writes built on a stale config version / CAS). Client: reconcile the
switch from the save **response** (not the request), serialize/debounce flips, and re-render from the
authoritative mask on every `config_reload` SSE.

---

### F6 · HIGH · Live Feed / Audit Trail drop cross-node records on refresh
**Area:** dashboard + admin-api · **Component:** audit read-path

**Summary.** The live SSE feed is fleet-wide, but the page's reload backfill `GET /api/audit/since`
returns **only the local node's** log, so cross-node rows shown live disappear on refresh.

**Evidence.** The three consoles return **disjoint** audit sets (14 / 12 / 8, no overlap). No fleet
option exists (`?scope=fleet|fleet=true|all=true` all return the local set; `/api/audit/fleet` →
404). SSE is provably fleet-wide (waf-2 toggle delivered waf-2 + waf-3 `config_reload` into
waf-infra-1's stream — events absent from waf-infra-1's backfill).

**Suggested fix.** Give the audit read-path a fleet-merged mode (mirror the `fleet:snap:*` stats
merge): a `scope=fleet` param or `/api/audit/fleet` that fans out to peers / reads a shared stream;
use it for the initial load + pagination. Also stamp `node_id` on data-plane rows (F10) for
attribution.

---

### F12 · MEDIUM · Session dropped mid-run and the SPA never surfaced it
**Area:** dashboard · **Component:** auth/session UX

**Summary.** During the run the admin session became invalid (all `/api/*` → 401, reason
`admin_unauthenticated`). The SPA kept rendering the **stale dashboard chrome** — it did **not**
redirect to login or show a "session expired" banner; data silently stopped updating. A SOC analyst
would stare at frozen data unaware they're logged out.

**Repro.** Let the session lapse (or trigger invalidation); keep the dashboard open → pages keep
showing old data while every API call 401s.

**Suggested fix.** Global 401 interceptor → redirect to `/admin/login` (preserve `next=`) or show a
clear "session expired, re-authenticate" interstitial. Don't leave stale authenticated UI on screen.
*(Also worth confirming the intended session TTL / what invalidated it — if idle-timeout, document
it.)*

---

### F13 · MEDIUM · mTLS endpoints return 404
**Area:** admin-api · **Component:** Settings / mTLS

`/api/mtls/connections`, `/api/mtls/failures`, `/api/mtls/ca-summary` all return **404** while
authenticated. The Settings page's mTLS section pulls these; the page mounts gracefully (no crash)
but the data is missing. *Fix:* implement/route these, or if mTLS is unconfigured return an empty
`200` payload so the UI can render an honest empty state rather than swallowing a 404. *(If this is
a documented "mTLS not configured" limitation, downgrade to LOW and surface it in the UI.)*

---

### F9 · MEDIUM · "↻ Reload model" froze the renderer
Clicking "↻ Reload model" (Detectors page) made the tab unresponsive (>45 s; JS eval + screenshots
timed out), needing a hard reload to recover. *Fix:* make the action async with a loading state +
timeout; never block the main thread, even when no `.onnx` model is configured.

---

### F8 · MEDIUM · No working in-page refresh on Detectors to reconcile UI↔backend
When the UI desyncs (F7), no in-page control re-pulls authoritative state — a soft route change
doesn't refetch; only a hard browser reload re-syncs (verified). Matches "refresh button doesn't
work." *Fix:* add a real Refresh that re-fetches `/api/detectors`, and refetch on route re-entry.

---

### F14 · MEDIUM · `/api/audit/since` ~260 ms latency floor (lag source)
See the Performance section. Fixed ~260 ms per request regardless of `limit`; polled by Live Feed +
Audit Trail. *Fix:* in-memory tail/index/cache for the audit read-path.

---

### F4 · MEDIUM · §4 control-plane not testable from a remote QC laptop as configured
No `/__waf_control` path worked from this laptop: `:56208` is behind an un-scriptable self-signed
cert (sandbox `curl` → `000`); `:5624x` → 404; SSH tunnel not used. So §4 + the traffic-driven halves
of §3.2/§3.3 are unverified. *To finish:* bring up `ssh -N -L 9443:127.0.0.1:9443 …` **or** accept
the `:56208` cert once in the driven Chrome.

---

### F2 · LOW · `/api/config/version` disagrees with `/api/config`
`/api/config` reports the real version (33→43) with a per-node `applied` vector; `/api/config/version`
reports `version:0`. Two "version" numbers, confusing. *Fix:* reconcile or rename one field.

### F3 · LOW · `/__waf_control` via admin port returns 404, not the documented 401
Guide expects 401 via `:5624x`; actual 404. *Fix:* update the guide, or return 401 to match the contract.

### F10 · LOW · Data-plane audit rows emitted without `node_id`
`block`/`allow` rows have empty `fields.node_id` (only admin events are tagged), blocking per-node
attribution and complicating the F6 merge. *Fix:* stamp `node_id` at emit time.

### F1 · INFO · Leaderless backend convergence is solid
Roster, merged stats, config-plane all consistent; toggles converge on all 3 nodes in ~2 s, both
directions; well-spaced cross-console writes both survived. Consensus layer is healthy.

### F5 · INFO · Console sessions shared across the three ports
Login to `:56243` authenticates `:56244`/`:56245` (cookies aren't port-scoped on a shared host).
Expected; noted so it isn't mistaken for an auth bypass.

### F15 · INFO · UI is robust and smooth
All 17 pages mount with correct headings, no error-boundary cards, 0 console errors; no main-thread
long-tasks during idle on the chart-heavy Overview. The client rendering is solid — the issues are
data/latency/auth, not React stability.

---

## Not evaluable this run
- **Top Attackers / by-detector regressions** (loopback ranking, combo-string bucketing) and **audit
  double-write** — no attack data present and the data plane (`:56208`) is unreachable from QC, so
  these couldn't be exercised. `/api/attacks/top` and `/api/attacks/by-detector` returned empty.
- **Tight cross-console write collision** (true split-brain) — couldn't reliably synchronize two
  consoles to sub-propagation-window timing through the browser harness. Well-spaced concurrent
  writes converge correctly; the F7 full-mask-clobber is the mechanism that would bite under true
  simultaneity.

## Priority for developers
1. **F11** health-probe auth — production crash-loop risk; one-line routing fix.
2. **F7** detector toggle desync (+ lost single writes during propagation) — security-impacting silent misconfig.
3. **F6** Live Feed audit merge (+ F10 node_id tagging).
4. **F14** audit endpoint ~260 ms — the user-visible lag.
5. **F12** session-expiry UX; **F9** reload-model freeze; **F8** real Refresh; **F13** mTLS 404s.
6. **F2 / F3 / F10** consistency cleanups.

## Test state left behind
Detector mask restored to baseline (recon / nosql_injection / open_redirect OFF → 13/16 enabled;
template_injection and velocity restored to ON), converged on all 3 nodes. Config version churned to
43 by the repro/cleanup writes but the effective config equals the original. No access-list,
session, break-glass, or destructive changes made.

## Still blocked (needs operator action)
§4 control APIs · traffic-driven §3.2/§3.3 · attacker-analytics regressions · data-plane behavioral
effect of config changes — all need `:56208` reachable (accept the cert) or the SSH tunnel.
