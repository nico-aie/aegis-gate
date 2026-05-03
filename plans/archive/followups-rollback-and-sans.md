# Follow-ups: HACK-T4 rollback + MTLS-T7 SAN allowlist

> **Status:** ✅ DONE — both parts shipped, live-verified, full
> workspace test sweep green. Two cohesive follow-ups bundled in
> one plan since they're both Console mutation surfaces on
> already-shipped tracks.
>
> **Verification (2026-05-02):**
> - **Part A — rollback:** drove `PUT /api/mode log_only`,
>   `POST /api/config/versions/1/rollback` returned
>   `{"ok":true,"action":"mode_set","before":{"mode":"enforce"},
>   "after":{"mode":"log_only"},"rolled_back_to_seq":1}`; mode
>   reverted; audit chain captured `mode_set_rollback` at seq
>   #2 with `rollback_to_seq: 1`.
> - **Part B — SAN allowlist:** `GET` empty → `PUT` 3 entries →
>   `GET` confirms → `POST .../{san}/test` exact match, wildcard
>   single-label match, wildcard multi-label rejected, unknown
>   rejected → `DELETE` one entry succeeds, `DELETE` missing
>   returns 400 → audit chain captured `mtls_sans_set` (seq #1)
>   and `mtls_sans_removed` (seq #2) with full before/after diff.

---

## 0 · Scope

### Part A — HACK-T4 rollback action

Round out the Tier-B Config history card with a "Rollback to
#N" action that re-applies the captured `before` state of an
audit-mutated change. Tier-B value is the operator workflow
("mistake → one click undo"), not breadth — start with the
mutations whose audit event carries a complete `before` field
and grow the supported set in follow-ups.

**In scope (v1):**
- `mode_set` rollback — single flat field, fully captured in
  `before.mode` / `after.mode`. Re-applies via the existing
  `PUT /api/mode` audit-mutated handler.

**Deferred to v2 (separate slices):**
- Detector-mask rollback (multi-class state).
- Rule upsert/delete rollback (the audit event captures the id
  but not always the full body).
- Blacklist/whitelist rollback (entry-by-entry).
- Risk thresholds, alert receivers, upstream pools.

The v1 path is a clean dispatcher with the seam to grow. Each
new rollback target adds one more case to the dispatcher and
one more test.

### Part B — MTLS-T7 Console SAN allowlist

`cfg.tls.client_auth.allowed_sans: Vec<String>` already lives
in the schema. Today it's snapshot at boot; this slice makes
it a live ArcSwap'd allowlist that the data plane consults at
identity-extraction time, plus three audit-mutated endpoints
and a Console card to manage it.

---

## 1 · Architecture

### Part A — rollback dispatcher

```
POST /api/config/versions/{seq}/rollback   (CSRF-gated, audit-mutated)
   │
   ▼
admin_dispatch::handle_rollback
   │
   ├─ load AuditEvent for {seq} from AuditRing
   ├─ check class == Admin
   ├─ check action ∈ ROLLBACKABLE_ACTIONS
   ├─ extract `before` from event.fields
   │
   ▼
RollbackDispatcher::apply(action, before, services)
   │
   ├─ "mode_set"          → ModeStore::set + audit-emit "mode_rollback"
   └─ (future)            → other handlers
```

Audit emit for the rollback itself is a NEW Admin event with
`action: "{original_action}_rollback"`, `fields: { rollback_to_seq: N, before, after }` so the chain captures the fact that
a rollback happened (and is itself rollback-able by re-rolling
forward).

### Part B — SAN allowlist runtime

```
boot:  cfg.tls.client_auth.allowed_sans → AllowedSansStore
                                           (Arc<ArcSwap<Vec<String>>>)
                                                │
                ┌───────────────────────────────┼──────────────────┐
                ▼                               ▼                  ▼
   identity.rs::extract...           admin_get.rs                handlers
   (match SAN against list)          GET /api/mtls/sans          PUT/DELETE/POST-test
```

Identity extraction stays in `aegis-proxy::listener::identity`
and gains a `&AllowedSansStore` parameter. When the allowlist
is non-empty AND the cert's SAN doesn't match, the result is
`Anonymous` (verifier already accepted the chain — we just
narrow the principal set).

The allowlist is its own ArcSwap not part of `WafConfig`-wide
hot-reload because admin-mutated edits would otherwise be
overwritten on the next file-source reload. Same pattern as
`alert_receivers_store`.

---

## 2 · Phases (smallest first, both tracks)

### Phase A.1 — Rollback dispatcher core (~1 h)

- New `aegis-control/src/api/rollback.rs`.
- `pub enum RollbackError { NotFound, NotRollbackable, MissingBefore, ApplyFailed }`.
- `pub struct RollbackOutcome { rolled_back_to_seq, action, before }`.
- `pub fn rollback_for_seq(ring, seq, mode_store) -> Result<RollbackOutcome, RollbackError>`.
- v1 supports only `mode_set`.
- Unit tests: not-found, not-rollbackable action, missing
  before field, mode_set happy path, mode_set missing
  before.mode subfield.

### Phase A.2 — Dispatch + audit emit (~30 min)

- `admin_dispatch::handle_rollback` async handler:
  - Parse seq from path.
  - Call `rollback_for_seq`.
  - On success: emit Admin event `action: "{orig}_rollback"`,
    `fields: { rollback_to_seq, before, after, actor: "admin" }`.
  - Map errors to 404 / 422 / 500 with operator-readable
    bodies.
- Wire dispatch arm in `admin_dispatch::handle_admin_request`.

### Phase A.3 — UI Rollback button (~45 min)

- `data.jsx`: new `configRollback(seq)` helper (CSRF + POST).
- `pages.jsx::ConfigVersionsCard`: Rollback button on
  rollback-able rows; two-step confirm modal showing the
  `before` state preview.
- Disabled-with-tooltip on non-rollback-able rows so operators
  see what's coming.

### Phase A.4 — Live verification + run-18 (~30 min)

- Drive: PUT /api/mode log_only → enforce → rollback to first
  log_only event → assert mode is back to log_only AND a
  `mode_rollback` audit event landed.

---

### Phase B.1 — `AllowedSansStore` runtime + boot wire (~30 min)

- New `aegis-control/src/api/mtls.rs` (extends the existing
  read-only module from MTLS-T6) — `pub struct AllowedSansStore { inner: Arc<ArcSwap<Vec<String>>> }` with `current() / store(new) / contains(san) / matches(san)` (handles `*.example.com` wildcard).
- `aegis-proxy::run` initialises from
  `cfg.tls.client_auth.allowed_sans` and stashes on
  `services.allowed_sans_store: Option<AllowedSansStore>`.

### Phase B.2 — Identity-extraction gate (~30 min)

- `identity::extract_identity_from_peer_certs` gains an
  `Option<&AllowedSansStore>` parameter.
- When the store is `Some` AND non-empty AND the cert SAN
  doesn't match → return `ClientIdentity::Anonymous` (chain
  ok, but unauthorised SAN).
- Tests: empty store admits everything (back-compat); matching
  SAN admits; non-matching SAN → Anonymous; wildcard matches.

### Phase B.3 — Read endpoint (~15 min)

- `GET /api/mtls/sans` returns `{ allowed: [...] }`.
- Dispatch in `admin_get.rs`.

### Phase B.4 — Mutation endpoints (~45 min)

- `PUT /api/mtls/sans` — whole-list replace, audit-mutated.
- `DELETE /api/mtls/sans/{san}` — single-entry remove.
- `POST /api/mtls/sans/{san}/test` — synthetic check
  ("would `san` admit through the allowlist?") returning
  `{ admitted: bool, matched: Option<pattern> }`.
- All three CSRF-gated via the `AuditedMutate` pipeline,
  same pattern as alert receivers.

### Phase B.5 — UI card on `#/mtls` (~30 min)

- New "Allowed SANs" card on PageMtls with:
  - List of allowed SANs (each with a "Test" + "Remove" button)
  - "Add SAN" inline input + button
  - Live update via the standard `useApi` polling

### Phase B.6 — Live verification + run-19 (~30 min)

- Drive: PUT new SAN list → GET shows live state →
  POST-test admits matching cert → DELETE removes → PUT
  full reset.

---

## 3 · Sequencing

```
A.1 Rollback core      ── A.2 Dispatch ── A.3 UI ── A.4 verify
                                                       │
                                                       ▼
B.1 Store + boot ── B.2 Gate ── B.3 GET ── B.4 PUT/DEL/test ── B.5 UI ── B.6 verify
```

Total estimated: **A 2.75 h + B 3.5 h = ~6 h**.

---

## 4 · Risks + mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Rollback misses subfields | MED | v1 hardcodes the supported action list; operators see "Rollback to #N" only on those rows |
| Rollback creates orphaned state | LOW | Re-using the existing audit-mutated handler for the inverse means audit chain stays consistent |
| SAN mutation overwritten by file-source reload | MED | Use ArcSwap directly, NOT round-trip through `WafConfig` (matches `alert_receivers_store`) |
| Identity extraction perf regression | LOW | Allowlist check is `Vec::iter().any(...)` — O(n) on small lists; same as today's runtime cert checks |
| ArcSwap allowlist + cfg-watcher race | LOW | We don't touch `cfg.tls.client_auth.allowed_sans` from the watcher when the operator has mutated via UI — same skip-on-edit pattern as upstream pools |

---

## 5 · Definition of Done

### Part A
- [x] `POST /api/config/versions/{seq}/rollback` returns 200 +
      JSON outcome on `mode_set`; 404 on missing seq; 422 on
      non-rollback-able action.
- [x] Audit chain shows the rollback as a new Admin event
      with `rollback_to_seq` + `before` + `after`.
- [x] UI Rollback button renders only on supported rows and
      runs the full two-step confirm.
- [x] Live verified end-to-end (run-18).

### Part B
- [x] `cfg.tls.client_auth.allowed_sans` round-trips through
      the live `AllowedSansStore` (boot, GET, PUT, DELETE).
- [x] Identity extraction returns `Anonymous` for certs with
      SANs not on the allowlist.
- [x] Wildcard matching works (`*.api.example.com` matches
      `svc.api.example.com` only — RFC 6125 §6.4.3 single label).
- [x] UI card renders allowed list, add/remove/test buttons
      work end-to-end (Settings page > "mTLS — Allowed SANs").
- [x] Live verified end-to-end (run-mtls-sans, 2026-05-02).

### Both
- [x] All workspace tests green; production build clean.
      (`cargo test --workspace`: ~2500 tests passed; release
      build: 11.84 s clean.)
- [x] `Implement-Progress.md` Last Completed entry follows
      § 0.3 protocol.
