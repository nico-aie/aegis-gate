# Aegis-Gate — Cluster-Mode QC Results & Developer Report (v2, post-redeploy re-check)

**Fleet:** waf-infra-1 / waf-2 / waf-3 · consoles `:56243` / `:56244` / `:56245` · data VIP `:56208`
**Driver:** Claude in Chrome (remote QC laptop). **Note:** the prior copy of this file was an
untracked file and got removed by the redeploy's git operation — this is a clean rebuild.

---

## ⟳ Re-check after redeploy — fix status

| ID | Finding | Status | Evidence |
|---|---|---|---|
| **F11** | `/healthz/live` & `/healthz/startup` required auth | ✅ **FIXED** | Unauthenticated (`credentials:omit`): live=200, ready=200, startup=200. |
| **F7** | Detector toggles silently desync (UI ON / engine OFF) | ✅ **FIXED** | Rapid 3-detector flip then settle → UI matches backend, no persistent desync. |
| **F10** | Data-plane audit rows missing `node_id` | ✅ **FIXED** | `block`/`allow` rows now carry `fields.node_id`. |
| **F14** | `/api/audit/since` ~260 ms latency | 🟡 **IMPROVED, not resolved** | Median now ~182 ms (was ~260 ms) vs ~3 ms for other endpoints. Still the slowest by ~60×. |
| **F6** | Live Feed / Audit Trail lose cross-node rows on refresh (node-local backfill) | ❌ **STILL OPEN** | Consoles still return disjoint sets: waf-infra-1=42, waf-2=21, waf-3=23 events; no overlap. |
| **F13** | `/api/mtls/{connections,failures,ca-summary}` → 404 | ⚪ **NOT A BUG — descoped** | Per operator: the mTLS endpoints were intentionally removed; coming back as a separate feature. The 404s are expected; the Settings page handles them gracefully. No action. |
| **F2** | `/api/config/version` disagrees with `/api/config` | ❌ **STILL OPEN** | `/api/config` → version 48; `/api/config/version` now returns `version: undefined` (was `0`). |

Not re-evaluated (need data-plane `:56208`): F4 control APIs, F3 gating, F9 reload-model freeze,
F8 detectors refresh, F12 session-expiry UX, F5/F1/F15 INFO items.

---

## 🆕 New findings this round (both match what you observed)

### N1 · HIGH · Alert-channel / receiver config is node-local — it does NOT propagate fleet-wide
**Area:** admin-api / config-plane · **Component:** alert-receivers

**Summary.** Alert receivers are stored per-node and are not propagated through the cluster config
path, so a receiver configured on one node is invisible to the others. This is exactly the
"alert channel config still in single node" symptom.

**Evidence.**
- `/api/alert-receivers` on **waf-infra-1** → 1 receiver ("Viptalk", `vip_talk`, last delivery ok).
- `/api/alert-receivers` on **waf-2** → **0 receivers**.
- `/api/alert-receivers` on **waf-3** → **0 receivers**.
- The receiver was created on waf-infra-1 (its audit shows `alert_receivers_set` +
  `alert_receiver_test`); it never appeared on the peers.

**Impact.** In a leaderless fleet any node can raise an alert. If an alert fires on waf-2 or waf-3,
they have **no receiver** and the notification is silently dropped — alerting works for only 1 of 3
nodes. For a security product this means missed pages.

**Suggested fix.** Route alert-receiver config through the same shared config doc / propagation path
that detector mask + compliance use (it already converges in ~seconds), instead of node-local
storage. Then `alert_receivers_set` should fan out and all nodes deliver. Add a convergence check to
the receiver test flow.

**Severity rationale.** Silent loss of security alerting on 2/3 of the fleet. HIGH.

---

### N2 · MEDIUM · Config changes are slow to apply — polling-bound, not CPU
**Area:** config-plane · **Component:** config apply / nudge

**Summary.** A config change takes ~2 s to apply **even on the node that made it**, and ~4 s to
converge across the fleet. The host is idle on 128 cores, so this is not CPU — it's the apply path
waiting on a periodic poll tick rather than an immediate push.

**Evidence (two runs, consistent).**
- Local node reflects the change: **~2.0 s / ~2.3 s** after the click.
- All 3 nodes converged: **~4.0 s / ~4.3 s**.
- `/api/runtime`: `workers:128`, `host_logical_cpus:128`, `cpu_affinity_active:true`.
  `/api/loadmode`: `mode:normal`, `rps_last_sample:0` (idle, no traffic).

**Diagnosis (answering "CPU or logic?").** **Logic, not CPU.** The box is idle with 128 cores. The
fixed ~2 s steps — one tick for the local node, another tick for the peers — are the signature of a
periodic **poll** interval. The pubsub "nudge" that's supposed to make this near-instant (the
contract claims ≈ms with nudge, ≤2-3 s on polling fallback) appears not to be firing, so every node
(including the writer) waits for its next poll cycle. This also looks like a **regression**: in the
pre-redeploy run the writing node reflected changes near-instantly and the fleet converged in ~2 s;
now the local apply itself lags ~2 s and convergence is ~4 s.

**Suggested fix.** Make the config-write path emit the pubsub nudge so the local node applies
synchronously on write and peers apply on the nudge, not the next poll. Verify the nudge channel is
actually subscribed post-redeploy (the symptom is consistent with the subscriber being dropped).

---

## Original findings — current state (full detail retained)

### F6 · HIGH · STILL OPEN · Live Feed / Audit Trail drop cross-node records on refresh
The live SSE feed is fleet-wide but `GET /api/audit/since` returns only the local node's log, so
cross-node rows shown live vanish on refresh. Re-check: the three consoles still return disjoint
audit sets (42 / 21 / 23, no overlap) and no fleet/merge option exists. *Fix:* fleet-merged audit
backfill (mirror the stats `fleet:snap:*` merge) used by the initial load + pagination. (Node_id
tagging F10 is now fixed, which is a prerequisite — good.)

### F13 · NOT A BUG (descoped) · mTLS endpoints 404
`/api/mtls/connections|failures|ca-summary` → 404. Per operator, the mTLS endpoints were
intentionally removed and will return as a separate feature. The 404s are expected and the Settings
page degrades gracefully. **No action — closed as won't-fix / deferred to the mTLS feature.**

### F14 · MEDIUM · IMPROVED · `/api/audit/since` latency
Now ~182 ms median (was ~260 ms), still ~60× the other endpoints (~3 ms) and polled by Live Feed +
Audit Trail. *Fix:* in-memory tail/index/cache to reach single-digit ms.

### F2 · LOW · STILL OPEN · `/api/config/version` inconsistent
`/api/config` reports the real version; `/api/config/version` returns `undefined` (previously `0`).
*Fix:* reconcile or rename.

### F11 · HIGH · FIXED · health-probe auth
`/healthz/{live,ready,startup}` all open now. Good — removes the orchestrator crash-loop risk.

### F7 · HIGH · FIXED · detector toggle desync
Rapid toggles now reconcile to the backend after settle; no persistent UI/engine divergence.
*(Note N2: the slower poll-based apply may be part of why the race no longer manifests; the desync
symptom is gone either way.)*

### F10 · LOW · FIXED · audit rows now carry `node_id`.

### Still-open / not-re-evaluated from round 1 (unchanged)
- **F4** §4 control APIs not testable from remote laptop (need cert accept or SSH tunnel).
- **F9** "↻ Reload model" froze the renderer — not retested this round.
- **F8** no working in-page Refresh on Detectors — not retested.
- **F12** session-expiry leaves stale authenticated UI (no redirect/banner) — not retested.
- **F3** `/__waf_control` via admin returns 404 not 401 — unchanged expectation.
- **INFO:** F1 leaderless convergence solid · F5 cookies shared across ports · F15 UI stable (17
  pages mount clean, no console errors, no idle long-tasks).

---

## Priority for developers (current)
1. **N1** alert-channel config not propagating — missed alerting on 2/3 nodes. **HIGH, new.**
2. **F6** Live Feed audit fleet-merge — still losing cross-node rows on refresh. **HIGH.**
3. **N2** config apply polling-bound (~2 s local / ~4 s fleet) — make the pubsub nudge fire; likely a redeploy regression. **MEDIUM.**
4. **F14** audit endpoint latency (improved to ~182 ms, target single-digit ms). **MEDIUM.**
5. **F2** config/version inconsistency. *(F13 mTLS 404s — closed, descoped per operator.)*
6. Re-verify the not-retested items (F8, F9, F12) once the data plane is reachable.

## Fixed since last round ✅
F11 (health-probe auth), F7 (detector desync), F10 (audit node_id tagging). F14 improved.

## Test state left behind
Detectors restored to the post-redeploy default (all 16 enabled); net-zero toggles. Config version
churned to ~49 by the latency-measurement writes but effective config equals the default. No
alert-receiver, access-list, session, or destructive changes made.

## Still blocked (needs operator action)
§4 control APIs · traffic-driven §3.2/§3.3 · attacker-analytics regressions · data-plane behavioral
verification — all need `:56208` reachable (accept the self-signed cert in the driven Chrome) or the
§2.3 SSH tunnel.
