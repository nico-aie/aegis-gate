# Console Config Pages — `CC-T*`

> **Status:** Plan only — awaiting confirmation. Track ID prefix
> `CC-T<n>`. Two follow-ups to the closed CI-T*
> console-API-integration track:
>
> 1. **Upstreams config page** — full CRUD on `upstreams.*`.
> 2. **Alert channels block** in the existing Tracking page —
>    list / add / edit / remove `slo.alert_receivers`.
>
> Both reuse the audit-mutated PUT pipeline established in CI-T6
> (`/api/mode`) and CI-T12 (`/api/risk/thresholds`). No new
> infrastructure.

## 0 · Why now

The Console can already read both surfaces (`/api/upstreams`,
firing alerts via `/api/alerts`) but every change still requires
editing waf.yaml + restarting. Two changes close that gap and
make the Console fully self-serve for the most common
operator-facing config edits.

## 1 · Currently-shipped surface (what we keep)

| Surface | Endpoint(s) | Today | Gap |
|---|---|---|---|
| Upstream pools | `GET /api/upstreams`, `GET /api/upstreams/summary` | Read-only summary; Tracking page shows `state / healthy_members / pools[]` | No mutation endpoint, no edit UI, no per-member detail |
| Alert receivers | none — `default_receivers()` reads env vars at boot | `slo::AlertReceiver` + 6 `ReceiverKind` variants exist; `dispatch::send_alert` delivers to VipTalk live; non-VipTalk kinds are descriptive metadata read by an off-box dispatcher | No GET, no PUT — operators can't see or edit channels in the Console |
| Tracking page | `/dashboard/#/tracking` | SLO budget, firing alerts, cluster, certs, gitops, upstream-summary tile | Lacks an "Alert channels" management surface |

## 2 · Requirements restatement

### CC-T1 — Upstreams config page

A dashboard page at `/dashboard/#/upstreams` that lets an operator:

- See every pool (`auth-pool`, `backend-pool`, `static-pool`, …)
  with full member detail, lb strategy, health-check config,
  circuit-breaker config, connection-pool config.
- Add a new pool, rename, delete (with confirm).
- Within a pool: add / remove / edit members (`addr`, `weight`,
  optional `zone`).
- Edit lb strategy (5-way enum), health interval/timeout/path,
  circuit-breaker thresholds, connection-pool tuning.
- See **which routes reference each pool** — deletion is blocked
  if any route still points at the pool (with a list of
  references shown).
- See **live health** — the existing `/api/upstreams/summary`
  is folded in so each pool's row shows `healthy/total` next to
  its config.
- Apply changes via the audit-mutated PUT pipeline (CSRF gate,
  version bump, SSE broadcast, toast feedback) — same UX as
  CI-T6 mode toggle.

### CC-T2 — Alert channels in Tracking page

Add a new card to the Tracking page (between "Active alerts"
and the cluster table) titled **Alert channels**. Operators can:

- See every configured `AlertReceiver` (name + kind + sanitised
  detail).
- **Add** a new receiver — pick a kind from the dropdown
  (VipTalk / Slack / PagerDuty / ServiceNow / Jira /
  AlertmanagerWebhook), fill the kind-specific fields,
  optionally hit "Send test" before saving.
- **Edit** an existing receiver in place.
- **Remove** with confirm. Last-receiver guard prevents an
  empty list (operators can disable but not zero-out without
  an explicit "no alerts" toggle).
- See **last delivery state** per receiver — `last_delivered_at`,
  `last_status` (`ok` / HTTP code / "skipped no-feature"),
  `consecutive_failures`. Powered by a new in-memory dispatch
  log on `dispatch::send_alert`.

## 3 · Design — non-negotiable invariants

These come straight from existing project rules (CLAUDE / plan.md
§ 0.4) and from the CI-T* pattern:

- **Audit-mutated.** Every PUT goes through
  `services.mutate.apply::<_, _, MutationError>(…)`. No
  side-channel writes.
- **CSRF gate.** `aegis_csrf` cookie + `x-csrf-token` header.
  Match the existing `mutationPreamble` extraction.
- **Validate before commit.** Reject:
  - Pool with zero members.
  - Member `weight: 0` (LB algorithms divide).
  - Health `timeout >= interval` (would never finish).
  - Circuit breaker `error_rate_threshold` outside `[0.0, 1.0]`.
  - Receiver name collision.
  - Empty `bot_token` / `room_ids` for VipTalk.
  - Empty `webhook_url` / `routing_key` for the rest.
- **Hot-applied via ArcSwap.** Both `upstreams` and the SLO
  engine receivers swap atomically — no restart. The version
  counter advances; SSE clients refresh.
- **Secrets redaction at the API boundary.** GET responses
  return `bot_token` / `webhook_url` / `routing_key` as
  `"<redacted>"` after first read; only the *last 4 chars*
  surface so operators can identify which token is which.
- **Test channel = throwaway.** "Send test" calls
  `dispatch::send_alert` with a synthetic `SloAlert` (severity
  `Info`, fixed text "Aegis-Gate test alert"). It does NOT
  modify config — it's a one-shot probe.

## 4 · Phases

### CC-T1.1 — Mutation endpoint for upstreams

**Target:** `aegis-control` (handler) + `aegis-proxy` (dispatch).

```text
GET  /api/upstreams/config     → full PoolConfig map (redacted)
PUT  /api/upstreams/config     → audit-mutated whole-map replace
PUT  /api/upstreams/pool/{id}  → audit-mutated single-pool upsert
DELETE /api/upstreams/pool/{id}→ audit-mutated delete (route-ref guarded)
```

Two write shapes (whole-map + per-pool) match the dashboard
edit flow: per-pool for in-place edits, whole-map for the
"reorder pools" / "import YAML" case.

- New module `aegis-control/src/api/upstreams_config.rs`
  (separate from the existing `upstreams.rs` summary handler).
- Add `validate_pool(&PoolConfig)` returning a typed
  `MutationError`.
- Add `routes_referencing(&WafConfig, pool_id)` so DELETE can
  refuse with the list.
- Apply via `services.mutate.apply` — the existing config-swap
  hook handles version-bump + SSE.

### CC-T1.2 — Upstreams page (dashboard)

**Target:** `crates/aegis-control/assets/dashboard/src/`.

- New route `/upstreams` (icon `Servers`, label `Upstreams`)
  in nav, after `Routes`.
- Two-column layout:
  - **Left:** pool list (id, lb badge, healthy/total pill,
    member count). "+ New pool" CTA.
  - **Right:** detail editor for the selected pool — members
    table (`addr` / `weight` / `zone` / row delete), lb
    strategy `<select>`, health-check fieldset,
    circuit-breaker fieldset, connection-pool fieldset.
- Save row at the bottom — validates client-side, fires PUT,
  shows toast with audit-chain `request_id`. Disable Save until
  the form is dirty + valid.
- Delete pool button — if `routes_referencing()` returns a
  non-empty list, show modal listing routes; deletion blocked.
- Reuses the existing `<DiffPreview>` widget pattern from CI-T6
  to show the delta.

### CC-T2.1 — Alert receivers endpoints

**Target:** `aegis-control` + `aegis-proxy`.

```text
GET    /api/alert-receivers           → list (redacted)
PUT    /api/alert-receivers           → audit-mutated whole-list replace
POST   /api/alert-receivers/{name}/test → fire a synthetic alert
DELETE /api/alert-receivers/{name}    → audit-mutated remove
```

- New module `aegis-control/src/api/alert_receivers.rs`.
- Receiver list lives in `slo::SloEngine::receivers` (already
  there). Add `set_receivers(Vec<AlertReceiver>)` that swaps
  the receiver list atomically (`ArcSwap` already on
  `SloEngine` — verify; if not, add).
- Add `dispatch::send_test(...)` — calls `send_alert` with a
  fixed `SloAlert` template; returns `(ok|err, latency_ms,
  http_status?)`.
- Add a tiny in-memory ring of "last 8 dispatch outcomes per
  receiver name" so the GET response can include
  `last_delivered_at`, `last_status`, `consecutive_failures`.

### CC-T2.2 — Alert channels card in Tracking page

**Target:** `pages.jsx::PageTracking`.

- New card inserted after "Active alerts" / before the cluster
  table: title "Alert channels", count pill on the right.
- List rows: kind badge, name, redacted target (e.g.
  `vt:****abcd`), last-delivery pill (`ok` / `failed N×` /
  `idle`), `[Test]` `[Edit]` `[Remove]` buttons.
- "+ Add channel" CTA opens a modal with kind-aware form fields.
- "Edit" opens the same modal pre-filled (token field is
  blank with `<placeholder>****abcd</placeholder>` so leaving
  it empty preserves the existing secret).
- "Test" calls POST `/api/alert-receivers/{name}/test`, shows
  toast with the result.

### CC-T3 — Cross-cutting polish

- **i18n.** Add `en` + `zh` strings for both surfaces (project
  already has both tracks; CI-T6 set the precedent).
- **OpenAPI.** Add the four upstream config paths + four alert
  receiver paths to `docs/control-plane/api.openapi.yaml` with
  full request/response schemas. Extend the
  `tests/api/openapi-shape.sh` 25-check to 33.
- **Docs.** Update `docs/control-plane/api.md` (endpoint
  table) and `docs/data-plane/upstream-pools.md` + the SLO doc
  to reference the new self-serve UI; flip any
  `> **Status:** Partial` banners that the new endpoints close.
- **Help/onboarding.** Append two slides to `help.jsx` covering
  pool editing + alert-channel onboarding.
- **Acceptance script.** Extend
  `tests/dashboard/round1-acceptance.sh` with a CC-T smoke:
  PUT a test pool → confirm /api/upstreams shows it → DELETE →
  confirm gone. Same for an alert receiver round-trip.

## 5 · Sequencing

```
CC-T1.1 (upstreams PUT/DELETE endpoints)
   └─> CC-T1.2 (Upstreams page)
CC-T2.1 (alert-receivers endpoints)
   └─> CC-T2.2 (Tracking-page card)
CC-T3 (i18n / OpenAPI / docs / acceptance)  — last, after both surfaces ship
```

CC-T1 and CC-T2 are independent — they could run in parallel
if multiple operators are working, but the typical single-thread
order above is fine.

## 6 · Doc impact

| Doc | Change | Why |
|---|---|---|
| `docs/control-plane/api.openapi.yaml` | **+8 paths** + 4 schemas (PoolConfig, MemberConfig, HealthCheckConfig, CircuitBreakerConfig, ConnectionPoolConfig, AlertReceiver, ReceiverKind, DispatchOutcome) | Contract for the new endpoints |
| `docs/control-plane/api.md` | New endpoint rows in §"Mutation endpoints" | Discoverability |
| `docs/data-plane/upstream-pools.md` | New §"Editing via Console" with screenshot | Self-serve workflow doc |
| `docs/operations/runbook-soc.md` (if exists) / `docs/operator/soc-runbook.md` | Add "How to add a new alert channel" entry | Operator-facing |
| `docs/control-plane/enterprise/api.md` | Refresh the Tracking-page description | Spec sync |
| `docs/control-plane/enterprise/pages/tracking.md` | Note new "Alert channels" block | Spec sync |
| `tests/api/openapi-shape.sh` | +8 checks | Contract test sync |
| `tests/dashboard/round1-acceptance.sh` | +2 round-trips | Acceptance |
| `Implement-Progress.md` | Track `CC-T*` open + Next Task = CC-T1.1 | Status |
| `plans/README.md` | Status-board row | Status |
| `plans/implementation-matrix.md` | Mark `upstream-pools.md` config-CRUD: Implemented after CC-T1; mark SLO doc: alert-channel-config Implemented after CC-T2 | Per-doc status sync |

**No removal.** All changes are additive. No existing endpoint
contracts change; no existing UI surface is removed.

## 7 · Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Whole-map PUT loses concurrent edits | MEDIUM | If-Match-style optimistic concurrency: PUT body carries last-known `version`; reject with 409 if mismatched (the version counter is already in `services.mutate`) |
| Secret leakage via GET | HIGH | Redact at the boundary (last-4-chars only); don't log raw secrets in audit body either — log `redacted` |
| Sending live test alerts to prod chat | MEDIUM | Test endpoint requires explicit POST + CSRF + the receiver's own `name` in the path; admin-port-only; logged in audit chain like any other mutation |
| Pool deletion orphans routes | HIGH | DELETE returns 409 + list of referencing routes; UI surfaces the list before user confirms |
| ReceiverKind enum drift | LOW | Variants are tagged unions; serde tag-based deserialisation already in place |
| Boot env-var override (`AEGIS_VIPTALK_*`) bypasses the new UI | MEDIUM | Document precedence: env > YAML > Console-applied; show a banner on the Tracking card when env override is in effect |

## 8 · Estimated complexity: **MEDIUM-HIGH**

| Phase | Work |
|---|---|
| CC-T1.1 | 4-5 h (handler + validate + route-ref guard + tests + dispatch wiring) |
| CC-T1.2 | 5-6 h (Upstreams page + nav + form fieldsets + DiffPreview + toast) |
| CC-T2.1 | 3-4 h (handler + receiver swap + dispatch log ring + test endpoint + tests) |
| CC-T2.2 | 3-4 h (Tracking card + add/edit modal + per-kind fieldset) |
| CC-T3 | 2-3 h (i18n + OpenAPI + docs + acceptance script) |
| **Total** | **17-22 h** |

## 9 · Definition of Done

- [ ] Upstreams page lets an operator add → edit → delete a
      pool, with audit-chain entry per change.
- [ ] DELETE pool blocked when routes still reference it,
      with the list of references in the response.
- [ ] Tracking page renders the Alert channels card with
      all six `ReceiverKind` variants creatable.
- [ ] "Send test" delivers a real test alert to VipTalk when
      built with `--features alerts`; logs + counts as
      `external` otherwise.
- [ ] Secrets redacted to last-4 chars in every GET response
      and every audit-chain `body` field.
- [ ] Concurrent-edit conflict returns 409 with the current
      version; UI prompts the user to reload.
- [ ] OpenAPI shape smoke (`tests/api/openapi-shape.sh`) green
      with the 8 new checks.
- [ ] `cargo test --workspace` green, no regressions.
- [ ] Bundle ≤ 256 KB after CC-T1.2 + CC-T2.2.
- [ ] `Implement-Progress.md` Last Completed entry per § 0.3.

## 10 · Files (likely touched)

**Backend (Rust):**
- `crates/aegis-control/src/api/upstreams_config.rs` — new
- `crates/aegis-control/src/api/alert_receivers.rs` — new
- `crates/aegis-control/src/api/mod.rs` — pub mod adds
- `crates/aegis-control/src/slo.rs` — `SloEngine::set_receivers`,
  receiver-dispatch ring buffer
- `crates/aegis-control/src/slo/dispatch.rs` — `send_test`,
  `DispatchOutcome` capture hook
- `crates/aegis-proxy/src/lib.rs` — dispatch arms for the 8
  new endpoints; wire `set_receivers` into the config-swap hook;
  pool whole-map / per-pool replace into the same hook
- `crates/aegis-control/src/dashboard/dispatch.rs` —
  routing entries
- `crates/aegis-control/tests/router_smoke.rs` — new shape
  asserts
- `crates/aegis-core/src/config.rs` — only if validation needs
  a helper (e.g. `PoolConfig::validate(&self)`)

**Frontend (React in JSX):**
- `crates/aegis-control/assets/dashboard/src/data.jsx` —
  `useUpstreamsConfigApi`, `useAlertReceiversApi`, plus
  audit-mutated PUT helpers (`upstreamsPut`, `poolPut`,
  `poolDelete`, `alertReceiversPut`, `alertReceiverTest`,
  `alertReceiverDelete`)
- `crates/aegis-control/assets/dashboard/src/pages.jsx` —
  new `PageUpstreams`; extend `PageTracking` with the
  `<AlertChannelsCard>` block
- `crates/aegis-control/assets/dashboard/src/widgets.jsx` —
  reusable `<MemberRow>`, `<KindFieldset>`, `<RedactedInput>`
- `crates/aegis-control/assets/dashboard/src/app.jsx` — nav +
  route entry for `/upstreams`
- `crates/aegis-control/assets/dashboard/i18n.json` — strings

**Docs / contract:**
- `docs/control-plane/api.openapi.yaml`
- `docs/control-plane/api.md`
- `docs/data-plane/upstream-pools.md`
- `docs/control-plane/enterprise/api.md`
- `docs/control-plane/enterprise/pages/tracking.md`
- `tests/api/openapi-shape.sh`
- `tests/dashboard/round1-acceptance.sh`
- `Implement-Progress.md`
- `plans/README.md`
- `plans/implementation-matrix.md`

---

**Awaiting confirmation.** Reply:
- `proceed` → start with CC-T1.1 (upstreams mutation endpoints).
- `start with alerts` → swap order to CC-T2.1 first.
- `modify: …` → adjust scope (e.g. "skip Send Test", "drop the
  per-pool endpoint, whole-map only", "use POST not PUT for
  add").
