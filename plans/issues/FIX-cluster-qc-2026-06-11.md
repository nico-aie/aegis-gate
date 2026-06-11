# Fix Plan — Cluster-Mode QC (2026-06-11)

**Source report:** [`QC-CLUSTER-RESULTS-2026-06-11.md`](./QC-CLUSTER-RESULTS-2026-06-11.md)
**Scope:** 3 HIGH · 6 MEDIUM · 2 LOW (the 3 INFO findings are positive — no action).
**Headline:** cluster consensus is healthy. Every defect is in the dashboard client,
the audit read-path, health-probe auth gating, or session UX — not the leaderless backend.

**Progress (branch `fix/cluster-qc-2026-06-11`):**
- ✅ **P1 (F11)** — `/healthz/*` namespace exempted from admin auth. `admin_auth_middleware.rs`.
- ✅ **F10** — `node_id` stamped centrally at ring ingest (`dashboard_services.rs::dispatch_event`).
- ✅ **P2 (F7)** — detector CAS via `If-Match`. Found the server already had config-doc CAS but
  used a *fresh* `expected`; now uses the client's `If-Match` (the applied version from
  `GET /api/detectors`, read from the per-node ACK key). Stale → **412**. Client echoes the
  version, replays the single flip on 412, and re-syncs on the `config_reload` SSE.
- ✅ **P3 (F6)** — fleet audit tail. New `metrics::fleet_audit` mirrors the `fleet_snapshot`
  publish/scan/merge: each node ships a bounded N=200 tail to `fleet:audit:<node>`; the publish
  task merges peers newest-first into a sync `FleetAuditCache`. `GET /api/audit/since?scope=fleet`
  serves it; the dashboard backfills (Live Feed, Audit Trail, risk heatmap) request `scope=fleet`.
  `node_id` (F10) carries attribution; each event lives on one node so the merge needs no dedup.
- ✅ **P4 (F14)** — profiled. A test proves a full 10k-entry ring tail render is **sub-millisecond**,
  so the ~260 ms floor is **environmental** (TLS/connection churn or lock contention on the remote
  node), *not* this handler — confirming the report's "add a ring buffer" suggestion was a misdiagnosis
  (the ring + cache already existed). Shipped: (a) self-reporting timing — the handler logs a `warn`
  when a render exceeds 25 ms, so the next live run attributes the cost; (b) the previously-uncached
  `tail` path (polled every 3 s) is now cached on its own `(limit)` slot. The real 260 ms source needs
  the live-fleet log to confirm.
- ⏳ P5 (F12/F8/F9), P6 (F13/F2/F3) — pending.

> ⚠️ **Three of the report's suggested fixes are re-scoped below after reading the code:**
> - **F14** — the audit ring + JSON cache the report asks for **already exist**
>   (`api/audit.rs:432`). The 260 ms floor is *not* a disk/parse cost; it must be profiled
>   before coding. → Phase 3 starts with measurement, not a rewrite.
> - **F13** — `/api/mtls/*` was **hard-renamed** to `/api/zero-trust/downstream/*` in the
>   Zero Trust rebuild (no alias, by design). The dashboard already calls the new paths.
>   The 404s come from a **stale QC test guide**, not a missing endpoint. → Doc fix, not code.
> - **F2** — `/api/config/version` and `/api/config` report **two different counters**
>   (local audit-chain length vs. cluster config-doc version). Reconcile/rename, don't "fix a bug".

---

## Triage → workstreams

| # | Finding | Sev | Root cause (verified) | Workstream |
|---|---|---|---|---|
| F11 | `/healthz/live` + `/healthz/startup` need auth | HIGH | `is_open_endpoint` GET arm omits the two sub-paths (`admin_auth_middleware.rs:308`) | **P1 — health gate** |
| F7 | Detector toggles silently desync | HIGH | full-mask read-modify-write, no CAS (`api/detectors.rs:183`); client renders optimistic request, not response; no re-sync on `config_reload` SSE | **P2 — detector concurrency** |
| F6 | Live Feed / Audit drop cross-node rows on refresh | HIGH | audit read-path is node-local; `fleet_view` merge (`admin_get.rs:57`) is not wired to audit | **P3 — audit fleet merge** |
| F10 | Data-plane audit rows lack `node_id` | LOW | `node_id` stamped only on admin events | **P3 (prereq)** |
| F14 | `/api/audit/since` ~260 ms floor | MED | **needs profiling** — ring+cache already present; live views poll the *uncached* `tail`/filtered path | **P4 — audit latency** |
| F12 | Session drop not surfaced in SPA | MED | no global 401 interceptor; stale chrome stays rendered | **P5 — client UX** |
| F8 | No in-page Detectors refresh to reconcile UI↔backend | MED | no refetch on route re-entry; no Refresh control | **P5 — client UX** |
| F9 | "↻ Reload model" freezes renderer | MED | synchronous/blocking reload on main thread (`pages.jsx:4189`, `api/ai_reload.rs`) | **P5 — client UX** |
| F13 | `/api/mtls/*` → 404 | MED→LOW | endpoints renamed to `/api/zero-trust/downstream/*`; client already migrated; QC guide stale | **P6 — docs/consistency** |
| F2 | `/api/config/version` disagrees with `/api/config` | LOW | two distinct counters, both correct, confusingly named | **P6 — docs/consistency** |
| F3 | `/__waf_control` via admin port → 404 not documented 401 | LOW | unknown-path on the session gate; contract drift | **P6 — docs/consistency** |
| F4 | §4 control plane untestable from remote QC laptop | — | tooling/access, not a code defect | **Out of scope** — operator action (SSH tunnel / accept `:56208` cert) |

---

## P1 — Health-probe auth gate (F11) · HIGH · ~30 min

**Root cause.** `is_open_endpoint` (`crates/aegis-proxy/src/admin_auth_middleware.rs:308`)
matches only `"/healthz" | "/healthz/ready" | "/readyz" | "/metrics"` as open GETs.
`/healthz/live` and `/healthz/startup` fall through to the session gate → `401` for any
probe that can't present a cookie.

**Fix.** Exempt the whole `/healthz/*` namespace from admin auth (it is non-sensitive — see
`health.rs`). Replace the `/healthz`-prefixed literals in the match with
`path == "/healthz" || path.starts_with("/healthz/")`, keeping `/readyz` and `/metrics`
as-is.

**Files:** `crates/aegis-proxy/src/admin_auth_middleware.rs` (the `is_open_endpoint` GET arm).

**Tests (RED→GREEN):**
- Extend `health_probes_are_open` to assert `/healthz/live` and `/healthz/startup` open
  (currently absent — would fail today).
- Add an integration-level assertion (logged-out) that `live`/`startup` return `200`,
  mirroring the existing `/healthz/ready` coverage.

**Risk:** none material — these probes expose no sensitive data; widening to the
namespace also future-proofs new `/healthz/*` probes. Confirm no *other* route lives under
`/healthz/` that must stay gated (grep shows none).

---

## P2 — Detector toggle concurrency (F7) · HIGH · ~1–1.5 days

The security-impacting one: an operator can read "enabled" while the engine has a class
**disabled**. Two independent defects — server lost-writes and client optimistic render —
both must be fixed.

### Server — optimistic-concurrency on the mask write
**Root cause.** `apply_put_body` (`crates/aegis-control/src/api/detectors.rs:183`) does
`next.base = base_body.into()` — a full-mask overwrite. Concurrent writes (rapid flips, or a
write that interleaves with cluster `config_reload` propagation) clobber each other;
last-write-wins silently drops intermediate state.

**Fix (choose 2a; 2b optional follow-up):**
- **2a — CAS guard (primary).** Carry the caller's observed config version (the value from
  `/api/config`) in an **`If-Match` header** on `PUT /api/detectors` (operator decision
  2026-06-11). Reject the write with `412 Precondition Failed` + the current authoritative mask
  when the version is stale, so the client re-reads and re-applies instead of clobbering. Thread
  the header through the proxy admin dispatch into `services.mutate.apply()` (the audit-mutation
  path that already version-stamps). A missing `If-Match` is rejected for `PUT /api/detectors`
  (force callers to opt into CAS) — confirm no scripted caller relies on the unconditional PUT
  before enforcing; if one does, treat absent `If-Match` as "no precondition" and log a deprecation warn.
- **2b — per-detector PATCH (optional).** Add `PATCH /api/detectors {class, enabled}` for
  single-class flips so the common UI action no longer round-trips the whole mask. Reduces the
  race window structurally; can land after 2a.

### Client — reconcile from response, serialize flips, re-sync on SSE
**Root cause.** The toggle handler renders the *requested* state optimistically and the soft
nav doesn't refetch (`pages.jsx` detector save ~`3394`, `4891`).

**Fix:**
- Reconcile each switch from the **save response body** (the PUT already returns the new mask —
  `pages.jsx:3394` notes this), not the optimistic request.
- **Serialize/debounce** flips so three rapid toggles don't issue three racing full-mask writes.
- On every `config_reload` SSE event, re-render the mask grid from the authoritative
  `/api/detectors` payload (this also resolves F8 for the live case).
- On `412 Precondition Failed` from 2a, transparently re-fetch the authoritative mask + replay
  the user's intended single change with the fresh `If-Match` version.

**Files:** `crates/aegis-control/src/api/detectors.rs`, the mutation/apply path
(`crates/aegis-control/src/api/mutation.rs`), proxy dispatch
(`crates/aegis-proxy/src/admin_mutate.rs` / `admin_dispatch.rs`),
`crates/aegis-control/assets/dashboard/src/pages.jsx` (+ `data.jsx`).

**Tests:**
- Unit: `apply_put_body` rejects a write built on a stale version (new CAS arg).
- Unit (if 2b): per-class PATCH flips exactly one bit, leaves others intact.
- Integration: two interleaved PUTs — the second with a stale `If-Match` → `412`, mask unchanged.
- Client: switch reflects the *response* mask, not the request, when they differ.

**Risk:** MEDIUM. Touches the audit-mutation path that feeds cluster propagation — must not
break version monotonicity or the `config_reload` fanout. Land server CAS behind tests before
the client change.

---

## P3 — Audit fleet merge (F6 + F10 prereq) · HIGH · ~1–2 days

**Root cause.** SSE fanout is fleet-wide, but `GET /api/audit/since` returns only the local
node's ring, so cross-node rows seen live vanish on refresh. The stats path already solves the
analogous problem via `fleet_view` (`admin_get.rs:57`) → scan-and-merge of `fleet:snap:<node>`
state keys (`metrics/fleet_snapshot.rs`). Audit data is not in that snapshot, and there is no
peer HTTP fan-out path (`cluster_sync.rs` is publish/scan, not request/response).

### F10 first (prerequisite) — stamp `node_id` on data-plane rows
Data-plane `block`/`allow` rows emit empty `fields.node_id` (only admin events are tagged).
Stamp `node_id` at emit time so the merged view can attribute + dedup rows. Without this, a
fleet merge produces ambiguous, un-orderable rows.

**Files:** data-plane audit emit (`crates/aegis-proxy/src/data_plane.rs` audit-row build),
`crates/aegis-control/src/api/audit.rs` (row shape / `AuditRing`).

### F6 — give the read-path a fleet-merged mode
**Recommended approach (matches existing architecture):** ride a **bounded recent-audit tail**
in the per-node `FleetSnapshot` (`fleet:snap:<node>`), then expose `GET /api/audit/since?scope=fleet`
that merges the local ring with peers' tails (sort by `(ts, node_id, seq)`, dedup on
`request_id+node_id`). Use it for the initial backfill + pagination on Live Feed / Audit Trail.

- Tail bound **N=200 events** (operator-confirmed 2026-06-11), with a size cap, so the snapshot
  key stays small —
  this is a backfill aid, not a durable cross-node log. Deep history stays per-node (collect via
  the existing `collect-audit.sh`).
- Alternative (heavier, rejected for now): synchronous peer HTTP fan-out via the interop control
  channel — adds a request/response path the cluster doesn't currently have and couples backfill
  latency to peer reachability.

**Files:** `crates/aegis-control/src/metrics/fleet_snapshot.rs` (add bounded tail to snapshot +
merge), `crates/aegis-control/src/api/audit.rs` (fleet render), `crates/aegis-proxy/src/admin_get.rs`
(`scope=fleet` branch on `/api/audit/since`), `pages.jsx`/`data.jsx` (request `scope=fleet`).

**Tests:**
- Unit: merge of three disjoint node tails → ordered, deduped, attributed by `node_id`.
- Unit: `node_id` present on a synthesized data-plane block row.
- Integration (single-process multi-ring fixture): `scope=fleet` returns the union; default
  stays node-local (back-compat).

**Risk:** MEDIUM. Snapshot size growth (mitigated by the bound); ordering/dedup correctness is
the main test surface.

---

## P4 — Audit endpoint latency (F14) · MED · profile first, then ~0.5–1 day

**Re-scoped.** The report's suggested fix ("back it with an in-memory ring / cache the tail")
is *already* implemented for the unfiltered `since` path (`api/audit.rs:432`, `render_since_filtered`
caches on `(cursor, limit)` for `cache_ttl`). So the 260 ms floor is **not** the disk/parse cost
the report assumes. Two live-view realities bypass that cache:
- the dashboard polls `?tail=1` (`render_latest_filtered`, **explicitly not cached** — `audit.rs:499`), and
- any populated filter field bypasses the cache by design (`audit.rs:461`).

**Step 1 — measure (mandatory before any change).** Reproduce locally and attribute the 260 ms:
add a `tracing` span / timing around `render_latest_filtered` + the `AuditRing` lock acquire.
Candidate causes to confirm or rule out: (a) lock contention with the witness/mutation writer
holding `AuditRing`/cache mutex, (b) per-call full re-serialization of the tail, (c) something in
the proxy admin dispatch wrapper, (d) the value is dominated by TLS/handshake on `:5624x` rather
than the handler (the report measured through driven Chrome).

**Step 2 — fix the confirmed cause.** Likely one of: cache the `tail` slice on `(limit, filter-hash)`
with the same TTL; shorten the lock hold (clone-out under lock, serialize outside); or reuse a
serialized buffer. Target single-digit ms parity with the other endpoints.

**Files:** `crates/aegis-control/src/api/audit.rs`, possibly `crates/aegis-proxy/src/admin_get.rs:375`.

**Tests:** micro-benchmark / timing assertion that a warm `tail` poll is < a set bound; correctness
unchanged (existing audit tests stay green).

**Risk:** LOW once the cause is known; the risk is *guessing wrong* — hence Step 1 gates Step 2.

---

## P5 — Client UX hardening (F12, F8, F9) · MED · ~1 day total

All three are dashboard-only (`pages.jsx` / `data.jsx`), no backend contract change.

- **F12 — global 401 interceptor.** Wrap the shared fetch/`useApi` helper (`data.jsx`): on any
  `/api/*` → `401 admin_unauthenticated`, stop polling and either redirect to
  `/admin/login?next=<path>` or show a "session expired — re-authenticate" interstitial. Never
  leave stale authenticated chrome rendering dead data. (Server already supports the redirect for
  HTML navigations — `admin_auth_middleware.rs:206`; this is the SPA-fetch counterpart.)
  *Also:* confirm + document the intended session TTL / what invalidated it.
- **F8 — real Detectors refresh.** Add a Refresh control that re-fetches `/api/detectors`, and
  refetch on route re-entry. Largely subsumed by the P2 client `config_reload` re-render, but the
  explicit control + on-mount refetch close the manual-reconcile gap.
- **F9 — non-blocking model reload.** Make "↻ Reload model" async with a loading state +
  timeout; never block the main thread, even when no `.onnx` is configured. Verify the
  `POST /api/ai/reload` handler (`api/ai_reload.rs`) isn't doing synchronous blocking work on the
  request thread; if it is, offload it.

**Tests:** client interaction tests for the 401 path (poll halts, redirect/banner shows) and the
reload button (stays responsive, shows loading). Visual-regression on the Detectors page states.

**Risk:** LOW.

---

## P6 — Consistency & docs (F13, F2, F3) · LOW · ~0.5 day

- **F13 (re-scoped to docs — doc-only, operator decision 2026-06-11).** Verify no client surface
  still calls `/api/mtls/*` (grep currently shows none — only `/api/zero-trust/downstream/*`),
  then **update the QC test guide / API sweep list** to the renamed paths. No `410 Gone` shim —
  the bare `404` stands. If any real consumer is later found on the old paths, escalate back to MED.
- **F2 (rename, operator decision 2026-06-11).** `/api/config/version` returns
  `services.mutate.chain_len()` (local audit-chain length — `admin_get.rs:305`), while
  `/api/config` reports the cluster config-doc version. **Rename the field** to disambiguate
  (e.g. `audit_chain_len`, keeping `applied_at_ms` / `applied_on_node`) rather than repointing it
  at the cluster version — the chain length is genuinely useful, it was just mislabeled "version".
  Update any dashboard/doc reference to the old `version` key.
- **F3.** `/__waf_control` via the admin port returns `404` where the guide expects `401`.
  Update the guide to the actual contract, **or** return `401` for `/__waf_control/*` from
  non-loopback peers to match the documented behavior. Low-stakes; align doc ↔ code either way.

---

## Suggested sequencing

1. **P1 (F11)** — ship first, standalone. One-line routing fix; production crash-loop risk.
2. **P3-prereq (F10)** — small, unblocks P3 and improves attribution immediately.
3. **P2 (F7)** — server CAS → client reconcile. The security-impacting fix.
4. **P3 (F6)** — fleet audit merge (depends on F10).
5. **P4 (F14)** — profile, then fix the real cause.
6. **P5 (F12/F8/F9)** — client UX batch.
7. **P6 (F13/F2/F3)** — consistency + doc cleanup; can run in parallel any time.

Each phase is independently shippable with its own tests; nothing forces a big-bang PR.

## Out of scope (operator action, not code)
- **F4** — make `:56208` reachable from QC (SSH tunnel `ssh -N -L 9443:127.0.0.1:9443 …` or
  accept the self-signed cert once in driven Chrome) to unblock §4 control-plane + traffic-driven
  §3.2/§3.3 + attacker-analytics regressions. Re-run those checks after access is restored.

## Resolved decisions (operator, 2026-06-11)
1. **F7 CAS transport** — ✅ `If-Match` header (stale version → `412 Precondition Failed`).
2. **F6 tail bound** — ✅ N=200 audit tail in the fleet snapshot.
3. **F2** — ✅ rename the field (`version` → `audit_chain_len`); do not repoint at cluster version.
4. **F13** — ✅ doc-only; no `410 Gone` shim, the `404` stands.
