# Fix Plan — Cluster-Mode QC V2 (2026-06-11, post-redeploy re-check)

**Source report:** [`QC-CLUSTER-RESULTS-2026-06-11-V2.md`](./QC-CLUSTER-RESULTS-2026-06-11-V2.md)
**Prior plan:** [`FIX-cluster-qc-2026-06-11.md`](./FIX-cluster-qc-2026-06-11.md) (v1 — P1–P6 shipped)
**Scope:** 2 HIGH (N1, F6) · 2 MEDIUM (N2, F14) · 1 LOW (F2). F13 descoped, F4 operator-blocked.
**Headline:** the leaderless backend is healthy. The open defects are (a) two surfaces that
were never folded into the shared config doc (alert receivers — N1), (b) a propagation path
that is poll-only with no nudge (config apply — N2, the **2–4 s save UX**), and (c) one
fleet-merge feature that shipped but isn't taking effect at runtime (F6).

**Progress (branch `fix/cluster-qc-2026-06-11-v2`):**
- ✅ **PC-1 (N2 backend)** — config-plane pub/sub nudge. `ConfigStore::activate` fires
  `config:waf:bump` on success; every node's `watch_loop` subscribes and re-polls on the bump
  (poll = backstop). Writer subscribes to its own channel → local + fleet apply drop from
  ~2 s/~4 s to ~ms. 7 unit tests green; builds with/without `redis`.
- ✅ **PC-2 (N2 UX)** — non-blocking fleet-convergence pill. `fetchConfigState()` reads
  `/api/config` (cluster version + applied roster); `notifyConfigConvergence()` surfaces
  "Applied on N/N nodes" (silent on single-node), fired from `waitForVersion` so every save
  flow gets it with zero call-site churn. Dashboard bundle rebuilt.
- ✅ **PA (N1 receivers)** — alert receivers folded into the shared config doc. New aegis-core
  mirror types (`AlertingConfig`/`ReceiverConfig`/…) on `cfg.alerting` (Option: None = legacy
  env/boot-seeded, untouched; Some = config-managed, propagates). `apply_cfg_change_to_receivers`
  re-derives the live `slo::AlertReceiver` store on each swap; PUT/DELETE handlers fold into the
  blob + `activate()` (gets propagation + the N2 nudge). Secrets ride in the blob (operator
  decision). 4 fold/round-trip tests; full proxy lib suite green (871).
- ✅ **PB (F6 roster-MGET)** — the fleet audit/metrics merge now fans out by the in-memory
  cluster roster (`RosterView`, lease-backed) — one `GET fleet:*:<node>` per known id — instead
  of a whole-keyspace `SCAN MATCH` that times out on a busy/remote/sharded Redis. Falls back to
  the legacy scan when the roster only knows self (cold start / single-node / not wired). Added
  a `warn` when `scope=fleet` finds no merged cache (the silent local-fallback is now visible).
  `merge_from_roster` / `merge_audit_from_roster` unit-tested; proxy lib suite green (871).
- ✅ **PE (F2)** — `/api/config/version` is now self-describing (a `note` + a pointer to
  `/api/config`), so an external sweep no longer reads a removed `version` field as `undefined`.
  The substantive half (the post-save convergence signal keying off the wrong counter) was
  already fixed in PC-2, which reads the cluster version + applied roster from `/api/config`.
- ⬜ PD (F14) — deferred: plan says *measure first*; needs the live `render_ms>25` telemetry
  from the 3-node fleet (can't be generated locally). The v1 self-timing + the new
  `scope=fleet` fallback warn are in place to attribute it on the next live run.

> **Flagship of this round = N2 (config-apply latency / Save UX).** The operator called the
> 2–4 s save "quite bad UX". It is not CPU — it is a 3 s poll loop with no pub/sub nudge on
> the config plane. The fix is both a backend latency cut (nudge → ~ms) **and** a Save-flow
> UX redesign (decouple "saved" from "converged", show honest per-node convergence).

---

## Triage → workstreams

| # | Finding | Sev | Root cause (verified in code) | Workstream |
|---|---------|-----|-------------------------------|------------|
| N1 | Alert-receiver config is node-local; never propagates fleet-wide | HIGH | receivers live in a per-node `Arc<ArcSwap<Vec<AlertReceiver>>>` seeded from `slo::default_receivers()` at boot; `apply_replace`/`apply_delete` (`api/alert_receivers.rs:421,438`) swap the **local** ArcSwap only — receivers are **not** a `WafConfig` section and are never folded into `config:waf:doc` | **PA — receiver config fold** |
| F6 | Live Feed / Audit drop cross-node rows on refresh | HIGH | `scope=fleet` **is** implemented (`admin_get.rs:427`, `metrics/fleet_audit.rs`) and the dashboard requests it (`data.jsx:423,972`), yet QC still sees disjoint 42/21/23 sets → the merged path silently falls back to local because `services.fleet_audit_cache` is `None` (or unpopulated) at runtime | **PB — fleet audit: diagnose + enable** |
| N2 | Config apply is polling-bound (~2 s local / ~4 s fleet) | MED ⭐ | `config_source/redis_source.rs:36,111` — `watch_loop` is a pure `sleep(DEFAULT_POLL = 3 s)` poll; **no** subscription. `admin_mutate.rs:2212` (+10 other `.activate()` callers) write the Redis doc and return — no local apply, no nudge. The pub/sub nudge (`CONTROL_BUMP_CHANNEL`, `interop/control.rs:450`) exists for the **control plane only**, never the config plane | **PC — config nudge + Save UX** |
| F14 | `/api/audit/since` ~182 ms (was ~260 ms) vs ~3 ms others | MED | improved in v1 but still ~60×; live views poll the `tail` path. v1 added a `render_ms>25` warn — this round we read that telemetry and fix the confirmed cause | **PD — audit latency (data-driven)** |
| F2 | `/api/config/version` returns `version: undefined` | LOW | v1 renamed the field `version` → `audit_chain_len` (`admin_get.rs`); the dashboard reads the new name (`data.jsx:1462,1475`). QC's `version: undefined` is the **stale external sweep** reading the old key. **But** a real latent bug: the post-save wait hook (`data.jsx:1450`) keys convergence off `audit_chain_len` (local audit-chain length), **not** the cluster config version | **PE — version semantics + doc** |

---

## PA — Alert-receiver config fold (N1) · HIGH · ~1–1.5 days

**Root cause.** Detectors, rules, tiers, and upstreams all converge because they are folded into
the shared `WafConfig` doc and re-derived on every node in `apply_and_swap`
(`redis_source.rs:181`). Alert receivers were built as a **standalone** in-process store
(`api/alert_receivers.rs` module doc, lines 11–18: "held in the dispatch task's closure …
loaded once at boot via `slo::default_receivers()`"). The write handlers swap a node-local
`ArcSwap`; the change never reaches `config:waf:doc`, so peers never see it (QC: 1 receiver on
waf-infra-1, 0 on waf-2/waf-3).

**Fix — make receivers a folded config section (mirror the upstreams fold, which is the closest
precedent — async-resolved, re-derived per node).**
1. **Schema.** Add an `alerting.receivers: Vec<AlertReceiver>` section to `WafConfig`
   (`aegis-core/src/config.rs`). `AlertReceiver`/`ReceiverKind` already derive serde
   (`slo.rs`). Secrets stay in the blob server-side (the blob never leaves the control plane;
   the **wire view** stays redacted via `RedactedKind`).
2. **Write path.** `handle_alert_receivers_put` / `_delete` stop swapping the local ArcSwap
   directly. Instead they: load current config → apply `apply_replace`/`apply_delete` to the
   `alerting.receivers` list → re-serialize → `store.activate(expected, blob, …)` (the same
   audited CAS path config uses). Keep the `validate_receivers` gate **before** activation.
3. **Apply path.** Add `reload::apply_cfg_change_to_receivers(cfg, targets.receiver_writer)`
   and a `receiver_writer: Option<Arc<ArcSwap<Vec<AlertReceiver>>>>` field on `ApplyTargets`
   (`redis_source.rs:41`). Wire it into `apply_and_swap` so every node re-derives its receiver
   store from `cfg` on each swap — identical to `apply_cfg_change_to_tiers`/`_to_upstreams`.
4. **Convergence check in the test flow.** `POST /api/alert-receivers/{name}/test` reports the
   per-node applied roster (reuse `ConfigStore::applied_map`) so the operator sees the receiver
   has fanned out before relying on it.

**Files:** `aegis-core/src/config.rs` (schema), `aegis-control/src/api/alert_receivers.rs`
(write helpers already exist — adjust to return the new list for folding),
`aegis-proxy/src/admin_mutate.rs` (receiver PUT/DELETE → activate path),
`aegis-proxy/src/config_source/reload.rs` (`apply_cfg_change_to_receivers`),
`aegis-proxy/src/config_source/redis_source.rs` (`ApplyTargets` + `apply_and_swap`),
`aegis-proxy/src/accept.rs` (boot wiring — share the receiver `ArcSwap` into `ApplyTargets`).

**Tests:**
- Unit: `apply_cfg_change_to_receivers` re-derives the store from a `WafConfig` with receivers.
- Unit: a folded receiver list round-trips through the YAML blob with secrets intact server-side.
- Integration (multi-backend / in-memory): PUT on node A → after one apply, node B's
  `GET /api/alert-receivers` shows the receiver (redacted).
- Regression: the redacted wire view is unchanged; secrets never appear in the GET body.

**Risk:** MEDIUM. Touches `WafConfig` (schema migration — must default-empty so existing
configs/boot YAML without an `alerting:` block still load). Secrets now live in the config blob
(already the case for upstream credentials) — confirm the blob is never exposed by any GET
(`/api/config` returns version only; the YAML-backup card must keep redacting).

---

## PB — Fleet audit/metrics merge breaks on Redis Cluster (F6) · HIGH · ~0.5–1 day

**Re-scoped from v1 → confirmed root cause (2026-06-11).** The v1 merge **shipped and is
correct** in code: `spawn_fleet_snapshot_task` (`accept.rs:119`) publishes this node's tail to
`fleet:audit:<node>` **and** merges peers via `fa::scan_and_merge_audit` (`accept.rs:189`);
`scope=fleet` is wired (`admin_get.rs:427`); the dashboard requests it on every audit query
(`data.jsx:423,943,972`). The operator's deployed `cluster:` flags are correct
(`fleet_view.enabled: true`, `fleet_events.enabled: true`, `pubsub_nudge: true`).

**The break is `scan_prefix` under a too-tight timeout.** `metrics/fleet_audit.rs:107` and the
metrics merge both rely on `StateBackend::scan_prefix`, whose Redis impl (`state/redis.rs:631`)
issues a `SCAN ... MATCH 'fleet:audit:*'` that walks the **entire shared keyspace** in batches,
then `GET`s each node key. Each op is wrapped in `with_timeout(state.redis.timeout)`. The
operator's deployment (confirmed 2026-06-11) runs a **single-node remote Redis**
(`urls: ["redis://10.20.0.72:6379"]`, no `cluster: true`) with **`timeout: "100ms"`** — vs the
reference `cluster-*.yaml` which uses a localhost Redis at **`timeout: "1s"`**. Off-box Redis
adds network RTT *and* the timeout was tightened 10×; the shared keyspace also holds risk keys /
rate-limit windows / nonces / auto-block entries, so the `SCAN MATCH` walk routinely exceeds
100 ms. On timeout `scan_and_merge_audit` returns empty → the task falls back to storing only
this node's tail (`accept.rs:191-195`) → every console serves local-only rows = the disjoint
**42/21/23** QC observed. The asymmetry is the tell: single-fixed-key paths (modes
`control:waf:modes`, the config doc `config:waf:doc`) fit in 100 ms and converge fine, while
every keyspace-walking `SCAN` merge times out and silently degrades to local. (A genuine Redis
Cluster endpoint would break the same merge a second way — single-connection `SCAN` misses
other shards — so the roster-MGET fix below is the durable answer for both.)

**Step 0 — immediate config mitigation (no code):** set `state.redis.timeout: "1s"` to match
the reference and re-check F6. If the disjoint sets converge, the tight timeout was the cause.

**Step 1 — confirm on the deployment box.**
```bash
redis-cli -h 10.20.0.72 --scan --pattern 'fleet:audit:*'        # expect all 3 node ids
redis-cli -h 10.20.0.72 --scan --pattern 'config:waf:applied:*' # expect all 3 node ids
# all 3 present but consoles still show local-only → SCAN merge is timing out at 100ms
# only 1 present → nodes aren't sharing one Redis (urls mismatch) — config fix, not code
```

**Step 2 — fix: roster-driven key fan-out, not `SCAN`.** Replace the enumeration with a
**known-roster `MGET`**: we already track live nodes via `config:waf:applied:*`
(`ConfigStore::applied_map`) and the lease roster. Build `fleet:audit:<node>` (and
`fleet:snap:<node>`) keys from that roster and `MGET` them. This works identically on
single-node and cluster (no key enumeration, no cross-slot SCAN). Apply the same change to the
fleet **metrics** merge (`metrics/fleet_snapshot.rs` — same `scan_prefix` dependency, same
latent cluster break).
- Plus **observability:** when `scope=fleet` is requested but the merge yields only the local
  node, set `x-audit-scope: local-fallback` + a `warn`, so a silent fallback can never again be
  mistaken for a working merge in a QC sweep.

**Files:** `metrics/fleet_audit.rs:102` + `metrics/fleet_snapshot.rs` (roster `MGET` instead of
`scan_prefix`), `aegis-proxy/src/accept.rs:119` (pass the roster source into the task),
`aegis-proxy/src/admin_get.rs:427` (observable fallback marker). `state/redis.rs` left as-is
(a cluster-aware `scan_prefix` is a bigger lift and unnecessary once the merge is roster-driven).

**Tests:** unit — roster `MGET` merge returns the union from 3 node keys; integration (in-memory
multi-ring) — `scope=fleet` returns the union, default stays local; fallback marker set when the
roster yields only self.

**Risk:** LOW–MEDIUM. The merge logic has v1 unit coverage; the change is the key-discovery
mechanism. Confirm the roster source (`applied_map`) lists all live nodes promptly (TTL 30 s —
fast enough). If a node is mid-boot and not yet in the roster, it's simply excluded from the
merge that tick — self-heals next tick.

---

## PC — Config-plane nudge + instant local apply + Save UX (N2) · MED ⭐ · ~1.5–2 days

**The operator's headline. Two halves: kill the latency (backend nudge) and fix the perceived
wait (Save-flow UX).**

### PC-1 — Backend: config-plane pub/sub nudge (the ~ms fix)

**Root cause.** `watch_loop` (`redis_source.rs:111`) only ever `sleep(poll_interval)`s
(`DEFAULT_POLL = 3 s`, `:36`). The writer's own node applies on its next tick (≤3 s); peers on
theirs (≤2 ticks → ~4 s). No nudge exists on the config plane — the `CONTROL_BUMP_CHANNEL`
nudge (`interop/control.rs:450`) is control-plane only (modes/reset).

**Fix — mirror the control-plane nudge exactly, one channel for the whole fleet incl. the
writer.**
1. Add `CONFIG_BUMP_CHANNEL = "config:waf:bump"` (next to `CONTROL_BUMP_CHANNEL`).
2. After a successful `Activate::Applied`, fire a 1-byte publish on the `FleetBus`. Do it in
   **one shared helper** so all 11 `.activate()` callers (`admin_mutate.rs` config / detectors
   / rules / tiers / upstreams) get it for free — e.g. fire inside the mutation-apply success
   path rather than at each call site.
3. `watch_loop` takes an optional `FleetBus`, subscribes to `CONFIG_BUMP_CHANNEL`, and
   `tokio::select!`s between the poll timer and a bump. On bump → re-poll + apply immediately.
   The poll stays as the backstop (a dropped bump just falls back to ≤3 s — never a stall).
4. **The writer subscribes to the same channel** → its own publish wakes its own loop → instant
   local apply. One mechanism fixes both local (~2 s → ~ms) and fleet (~4 s → ~ms) convergence.

**Why not "apply synchronously in the handler":** that forks a second apply path and risks
divergence from the watcher's `apply_and_swap` (route rebuild, NACK/fail-static, ACK stamping).
The nudge reuses the single proven apply path. Rejected.

### PC-2 — Frontend: decouple "saved" from "converged"

The `activate` handler already returns `{ok, version}` at HTTP 200 the instant the Redis CAS
commits (`admin_mutate.rs:2222`) — the write is **durable** before any apply. Today the Save
flow blocks the user on a post-save poll (`data.jsx:1450`: "polls `/api/config/version` every
250 ms until version moves") that (a) waits on apply latency the user shouldn't have to watch,
and (b) keys off the wrong counter (`audit_chain_len`, not the cluster config version — see PE).

**Fix:**
1. On 200, immediately render **"Saved — v{N}"** (optimistic; durable in Redis). No spinner
   blocking the form.
2. Replace the wait hook with an honest **convergence indicator** driven by the per-node
   applied roster (`ConfigStore::applied_map` → surface on `/api/config`): "converging…
   1/3 nodes" → "applied on 3/3". Reads the **cluster config version**, not `audit_chain_len`.
3. With PC-1 the indicator flips to done in ~ms; without it (backstop) it still resolves in
   ≤3 s but is now truthful about per-node state instead of a fake global spinner.

**Files:** `aegis-proxy/src/config_source/cluster_sync.rs` or a new const (channel),
`redis_source.rs` (`spawn_watcher`/`watch_loop` subscribe + select),
`admin_mutate.rs` (fire nudge in the shared apply-success path),
`accept.rs` (pass the `FleetBus` into `spawn_watcher`),
`admin_get.rs` / `config_versions.rs` (expose `applied_map` for the indicator),
`assets/dashboard/src/data.jsx` + `pages.jsx` (Save UX + convergence indicator).

**Tests:**
- Unit: `watch_loop` applies on a bump without waiting for the poll timer (fake bus + a
  `Notify`/`watch` signal; assert apply happens < poll_interval).
- Integration: a successful `activate` fires exactly one bump; a subscribed node applies within
  a tight bound; a dropped bump still converges within `poll_interval` (backstop intact).
- Client: Save shows "Saved — v{N}" immediately on 200; the convergence pill reflects
  `applied_map` (1/3 → 3/3); no blocking spinner.

**Risk:** MEDIUM. Touches the config apply hot path on every node. Guardrails: keep the 3 s
poll as backstop; preserve version monotonicity, NACK, and fail-static; the nudge is
best-effort and non-load-bearing (correctness lives in the polled key, exactly like the
control-plane nudge).

---

## PD — Audit endpoint latency (F14) · MED · data-driven, ~0.5 day

**Re-scoped from v1.** v1 proved the ring render is sub-ms and added a `render_ms > 25` `warn`
to attribute the live 182 ms. This round: **read that telemetry from the fleet log first**,
then fix the confirmed cause (candidates from v1: lock contention with the witness/mutation
writer on the `AuditRing`/cache mutex; per-call re-serialization of the `tail`; or
TLS/handshake cost on `:5624x` dominating — i.e. not the handler at all). If the warn never
fires in the live run, the 182 ms is environmental (TLS/connection churn through driven
Chrome) and F14 closes as "not the handler" with evidence.

**Likely fix if handler-side:** cache the `tail` slice on `(limit, filter-hash)` with the same
TTL as `render_since_filtered` (`api/audit.rs:432`), or shorten the lock hold (clone-out under
lock, serialize outside). Target single-digit-ms parity.

**Files:** `aegis-control/src/api/audit.rs`, possibly `admin_get.rs`.
**Tests:** warm-`tail`-poll timing assertion under a set bound; existing audit tests stay green.
**Risk:** LOW once the cause is known; the risk is guessing — measurement gates the change.

---

## PE — `/api/config/version` semantics + Save-convergence signal (F2) · LOW · ~0.25 day

- **F2 proper (QC-stale):** v1 renamed `version` → `audit_chain_len`; the dashboard reads the
  new name. QC's `version: undefined` is the external sweep reading the old key. Update the QC
  guide. **Optionally** add back a `cluster_config_version` field to `/api/config/version` so
  the endpoint is self-describing (chain length **and** the cluster doc version side by side) —
  this directly serves PC-2's convergence indicator.
- **Latent bug (real):** the post-save wait hook (`data.jsx:1450`) keys convergence off
  `audit_chain_len` (local audit-chain length), which is the wrong signal — it moves on any
  local audit event, not when config version N is applied fleet-wide. Folded into PC-2: the
  indicator must read the **cluster config version + applied roster**, not `audit_chain_len`.

**Files:** `admin_get.rs` (`/api/config/version` body), `data.jsx` (convergence hook — shared
with PC-2), the QC test guide.
**Risk:** LOW.

---

## Suggested sequencing

1. **PC (N2)** — flagship; self-contained backend nudge + Save UX. Highest operator-visible win.
   PC-1 (nudge) and PC-2 (UX) can land as two PRs; PC-2 also subsumes PE's client work.
2. **PA (N1)** — receiver config fold; the highest-severity correctness fix (silent alert loss).
   Independent of PC; can run in parallel.
3. **PB (F6)** — diagnose-then-enable the fleet-audit merge; mostly wiring/observability.
4. **PD (F14)** — read the live `render_ms` telemetry, then fix the confirmed cause.
5. **PE (F2)** — version semantics + QC-guide doc; trivial, fold the client bit into PC-2.

Each phase is independently shippable with its own tests. Nothing forces a big-bang PR.

## Out of scope (operator action, not code)
- **F4** / traffic-driven §3.2/§3.3 / attacker-analytics — need `:56208` reachable from QC
  (SSH tunnel or accept the self-signed cert). Re-run after access is restored.
- **F13** (mTLS 404s) — descoped per operator; the bare 404 stands. QC-guide doc fix only.
- **Not re-evaluated** (F8/F9/F12) — re-verify once the data plane is reachable; v1 shipped
  fixes for all three.

## Resolved decisions (operator, 2026-06-11)
1. **PC-2 Save UX** — ✅ **Optimistic + convergence pill.** Render "Saved — v{N}" the instant the
   200 lands (durable in Redis pre-apply); a separate non-blocking indicator shows
   "applied on X/3 nodes" driven by the per-node applied roster. No blocking spinner.
2. **PA receiver secrets** — ✅ **In the `config:waf:doc` blob** (same path as upstream
   credentials today). Single propagation path; the blob is never returned by a GET. Confirm the
   YAML-backup card + any `/api/config*` GET keep redacting before merge.
3. **F6 scope** — ✅ **Config + code.** Ship `state.redis.timeout: "1s"` as the immediate
   mitigation **and** replace the `SCAN`-based fleet merge (`fleet_audit.rs` + `fleet_snapshot.rs`)
   with roster-driven `MGET` so the merge is timeout-safe and immune to keyspace growth / a
   future Redis Cluster.
