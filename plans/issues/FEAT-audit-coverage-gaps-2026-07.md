# FEAT — Audit-logging coverage gaps + risk-decay caveats

> **Type:** FEAT (committee round-2 🟡3) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `AU-<1–4>` · Verified 2026-07-04 across both audit paths (hash-chain +
> interop contract log) and the risk tracker.

**Objective (intent, not letter):** every security-relevant action leaves a trail an investigator
can trust; the risk-decay story is provable to the committee with evidence, and its sharp edges
are either fixed or documented as designed.

---

## 1. Verified current state

### What's already strong (respond to committee with evidence, don't rebuild)
- Tamper-evident SHA-256 hash chain over admin mutations: `AuditedMutate::apply` wraps **~40
  mutation call sites** — config activate/rollback, rules CRUD/toggle, mode/loadmode, risk
  resets/thresholds, white/blacklist edits, gates, zero-trust, AI routes (`mutation.rs:187-278`,
  call sites throughout `admin_mutate.rs`). Daily-rotated on-disk chain re-seeds `prev_hash`
  (`sinks/jsonl.rs:380-471`); offline verification exists (`audit/verify.rs`); 9 SIEM sink formats.
- **Risk decay is fully implemented**: linear trust recovery, default **30 pts/hr**
  (`config.rs:4744-4759`), hot-tunable; decay-on-read via `decayed_slot` on every gate decision,
  API view, and write rebase (`tracker.rs:591-599, 694-752, 1054-1076`); strikes deliberately
  never decay; optional Redis durability persists struck slots with wall-clock age. The committee
  question "is decay implemented?" → **yes**, package the evidence (AU-4).

### Real gaps (fix)

| # | Gap | Anchor |
|---|---|---|
| 1 | **Login success / failure / logout emit NO audit event** — `authenticate()`/`logout()` have zero `AuditBus` references | `login.rs` (whole file), `admin_login.rs:99-199` |
| 2 | **Control-plane `reset_state` wipes all risk/state with no audit event** — destructive, trail-free | `admin_dispatch.rs:1230-1260` |
| 3 | **No purpose-built credential-change events** — password/TOTP rotation only visible as a whole-config `config_activate` diff | `login.rs:34-126` |
| 4 | **Delivery is best-effort**: `emit()` drops silently when buffer full/no subscriber (`audit.rs:337-339`); broadcast lag = logged drop (`jsonl.rs:551-556`); fsync only on daily rotation + graceful shutdown → crash loses un-synced tail | `audit.rs`, `jsonl.rs:388-390,438-448,574-585` |
| 5 | Witness/external anchoring absent (schema-only) | `witness.rs:1-8` — handled by placeholder-cleanup plan; real anchoring stays future |

### Risk-decay caveats (decide: fix vs document-as-designed)

| # | Caveat | Anchor |
|---|---|---|
| A | **Idle eviction wipes strikes**: slot removed after `IDLE_TTL = 3600s` idle → "lifetime" strikes reset for an attacker who goes quiet 1 h (unless Redis durability on + under cap) | `tracker.rs:55-105, 473-492` |
| B | **Cardinality cap silently stops accumulation** at `MAX_TRACKED_KEYS = 1_000_000` — new keys score per-request but never accumulate; behaves as Allow | `tracker.rs:68, 614-618, 662-665` |
| C | `trust_per_hour: 0` disables decay entirely (sticky scores) — reachable via API | `tracker.rs:1070` |

## 2. Staging

### AU-1 — auth + destructive-action audit events · **S** · ✅ shipped 2026-07-04 (`feat/au1-audit-coverage`)
- ✅ `Access` events from the login path via `api::login_audit::LoginAuditor`: `login_success`,
  `login_failure`, `logout` (real revocations only). Per-IP flood aggregation (immediate first
  event + `fields.count` roll-up, 30 s window; flush on next event / on success).
  **Bucket deviation (deliberate):** reasons mirror `LoginOutcome` —
  `invalid_credentials` / `locked_out` / `rate_limited` / `store_unavailable`. Bad-password vs
  bad-totp are NOT distinguished: `authenticate()` deliberately collapses them (anti-enumeration,
  F-CRITICAL-003) and splitting them would require touching M2's TF-1 territory in `login.rs`.
- ✅ `reset_state`: `Admin`-class event emitted in `ControlContext::reset_state_async` **before**
  the wipe (covers both dispatch paths: admin listener + data-plane loopback short-circuit);
  order proven by test.
- TOTP enroll/disable + password change events — land with `FEAT-2fa-enforcement` TF-2 and
  AA-P1a/b (those PRs add the endpoints; this plan owns the event taxonomy — reuse
  `login_audit::event` buckets).

### AU-2 — delivery honesty + durability knob · **S–M** · ✅ shipped 2026-07-04 (narrowed — see below)
- ✅ `waf_audit_events_dropped_total{consumer}` (dashboard / jsonl / syslog / metrics) wired into
  every Lagged branch. **Emit-side counting dropped (verified unnecessary):** `broadcast::send`
  only errs with zero subscribers — a boot/shutdown-window artifact, not a loss path; buffer
  pressure always manifests as receiver lag, which IS counted. Documented in the metric's docs.
- ✅ Per-sink delivery counters shipped with PE-2 (`/api/cold-tier` + `DeliveryRegistry`).
- ✅ **`audit.fsync_interval` knob dropped (plan premise was stale):** the JSONL sink has done
  per-batch `flush` + `sync_data` since F-CRITICAL-013 (2026-05-17) — loss window is already
  bounded by `max_batch`/`flush_interval`, strictly stronger than the proposed knob. Durability
  model documented honestly in `docs/operator/usage.md` §6.
- Posture kept: best-effort delivery, never block the data plane on audit I/O.

### AU-3 — risk-decay caveats · **S–M**
- **A (strike eviction):** owner decision — if "lifetime strikes" is the contract, exempt
  struck slots from idle eviction (bounded: struck-slot count is small) or require Redis
  durability for the strike gate; else fix the docs to say "strikes survive 1 h idle".
- **B (cap):** emit `waf_risk_tracker_saturated_total` + dashboard warning when the cap gates
  accumulation — silent fail-open is the committee-relevant part.
- **C:** validation floor or explicit warning when `trust_per_hour: 0` set via API/config.

### AU-4 — committee evidence pack · **S**
- Short doc (or section in the round-2 response) with the decay formula, defaults, file:line
  anchors, and a reproducible test transcript (score a key, advance clock, show decayed read +
  strike persistence). Same for audit coverage: the mutation-site enumeration.

## 3. Tests (RED-first)

- Login success/failure/logout each produce exactly one chained event; failure-flood produces
  aggregated events, not one-per-attempt; no secret material in any event.
- `reset_state` event present in chain *after* a state wipe (order proven).
- Drop counters increment under forced broadcast lag; fsync knob bounds loss in a kill-test.
- Strike-eviction behavior per owner decision (exempt or documented); saturation metric fires at cap.
- Chain verification suite stays green (`audit/verify.rs`).

## 4. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Audit-event flood from failed logins (DoS the bus) | aggregation window per IP; bounded reason cardinality |
| LOW | fsync knob hurts hot-path latency | audit path is already off the request path (broadcast + writer task); knob affects writer task only |
| LOW | Strike-eviction fix inflates memory | struck slots only; cap the exempt set |

## 5. Acceptance

- [ ] Login/logout/failed-login/reset_state/credential-change all leave chained audit events.
- [ ] Drop/delivery metrics exposed; durability model documented truthfully.
- [ ] Decay caveats A–C dispositioned (fixed or documented as designed).
- [ ] Evidence pack delivered for the committee (decay = already implemented).
