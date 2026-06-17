---
id: 2026-06-17-section-02-control-plane
contract_section: "§2 — WAF Control Interface"
checklist_ids: C-2.1-* C-2.2-* C-2.3-* C-2.4-* C-2.5-* C-2.6-* C-2.6b-* C-2.7-*
verdict: PASS (1 MEDIUM, see F-V26-002)
test_mode: source-review
---

# §2 — WAF Control Interface

Primary code: `crates/aegis-control/src/interop/{control,mode}.rs`,
dispatch `crates/aegis-proxy/src/admin_dispatch.rs:954`, routing
`crates/aegis-proxy/src/accept.rs:1752`.

## §2.1 Required endpoints — ✅ PASS

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-2.1-02..05 | 4 endpoints present | ✅ | `admin_dispatch.rs:976-1089` matches capabilities / reset_state / set_profile / flush_cache |
| C-2.1-06 | local/admin-only | ✅ | `classify_control_request` (`accept.rs:2277`) requires loopback peer; non-loopback gets a hidden 404 |
| C-2.1-07 | MUST NOT proxy to upstream | ✅ | `accept.rs:1752` intercepts the namespace *ahead* of routing/risk-gate; comment "CRIT-1 (§2.1) — never falls through to catch-all" |
| C-2.1-08/09 | accept body, don't reject on body present | ✅ | reset_state/flush_cache ignore the body (don't read or reject it); set_profile reads it. No 415/400-on-body-present path |
| C-2.1-10/11 | ≤5s SLA, no blocking | ✅ (by design) | handlers are non-blocking; reset uses async cleaners awaited before 200 |

## §2.2 Authentication — ✅ PASS

- `admin_dispatch.rs:964-974`: secret pulled from `CONTROL_SECRET_HEADER`
  and checked via `rt.control.check_auth()` **before the method/path match**,
  so every method (GET/POST/PUT/DELETE) on every endpoint is gated.
- `control.rs:293 check_auth` → `constant_time_eq` (`control.rs:30`), defeats
  timing side-channel. Missing/invalid → `ControlError::Forbidden` → **403**
  (`control.rs:197`). Matches C-2.2-01/02.
- Header name `x-benchmark-secret`; default value `DEFAULT_CONTROL_SECRET`
  (confirm it equals `waf-hackathon-2026-ctrl` in config — see note below).

> **Confirm:** the contract pins the secret VALUE to
> `waf-hackathon-2026-ctrl` (C-2.2-01). Verify `interop.control_secret`
> default / deploy config resolves to exactly that string.

## §2.3 Capabilities — ✅ PASS

- `control.rs:305 capabilities()` returns `{ok, features{supported,toggleable,policies[]}, active{default_mode,overrides}}`
  — matches the contract example shape (C-2.3-03).
- `active` rendered live from the ModeStore (`render_active`, `control.rs:613`).
- Feature/policy names are static (built once in `run.rs build_interop_runtime`)
  → stable for the run (C-2.3-06). Tests `capabilities_lists_*` guard drift.

## §2.4 reset_state — ✅ PASS

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-2.4-01/02/03 | clear runtime state, fresh runtime | ✅ | sync callback chain + async cleaners (`reset_state_async`, `control.rs:348`); StateBackend ephemeral wipe (nonces, rate windows, auto-block, risk keys) |
| C-2.4-05 | MUST NOT revert feature/policy modes | ✅ | reset only runs registered runtime cleaners; ModeStore is NOT in the chain. Test `reset_state_preserves_unrelated_state_surface` |
| C-2.4-06 | MUST NOT truncate audit log | ✅ | JSONL sink opened `append(true)`; test `sink_is_append_only_across_reopens` |
| C-2.4-08/10 | synchronous + atomic | ✅ | `reset_state_async` awaits all async cleaners before building the 200; `reset_in_progress` RAII guard (`admin_dispatch.rs:1010`) short-circuits in-flight non-control reqs with 503+Retry-After:0 (the contract's "MAY temporarily reject") |
| C-2.4-12 | response shape `{ok,action,audit_log_preserved,ts_ms}` | ✅ | `ResetResponse` `control.rs:77` |

> Carry-over note from the v2.3 audit (C-03): `audit_log_preserved: true`
> is a hardcoded literal, not derived from a runtime check. Harmless (the
> sink really is append-only) but it does not *prove* preservation.

## §2.5 set_profile — ⚠️ MOSTLY (see F-V26-002)

| ID | Requirement | Result | Evidence |
|----|-------------|--------|----------|
| C-2.5-11/12 | body schema, `scope:all` MUST | ✅ | `SetProfileRequest` `control.rs:92`; `set_all` clears overrides |
| C-2.5-13/14 | `features` / `policies` scopes | ✅ | `validate_and_apply` `control.rs:542` |
| C-2.5-15/19/20 | unsupported → not silently ignored, listed | ⚠️ partial | unknown feature in `features` scope and unknown policy under a known feature → **200 + unsupported list** (correct). BUT unknown FEATURE in `policies` scope → **422** (`control.rs:596`). See **F-V26-002** |
| C-2.5-17/18 | response shape + override key conventions | ✅ | `SetProfileResponse` + `render_active` dot-notation |
| C-2.5-16 | `scope:all`+enforce clears overrides | ✅ | `set_all` → `ModeSnapshot::empty` (test `set_profile_scope_all_clears_overrides`) |

## §2.6 flush_cache — ✅ PASS

- `control.rs:517`: when no cache callback wired → **200 OK + `supported:false`**
  (not 404). Matches C-2.6-02/03. When wired, runs the eviction callback
  before returning (C-2.6-04). Cache flush callback registered late at boot
  (`register_flush_callback`).

## §2.6b Implementation notes — ✅ PASS

- Data-plane core is a single Rust binary (`./waf run`) per workspace layout.
- Control plane handled in-process (intercepted on the data-plane listener),
  a valid topology per C-2.6b-03.
- Hot-reload: detector mask + modes via ArcSwap; rule CRUD via dashboard.
  (Round-1 "live rule rebuild" was a separate v2.3 finding — out of scope
  for the automated contract, which does not call a reload endpoint.)

## §2.7 Control-mode correlation header — ✅ PASS

- `X-WAF-Mode` resolved per **firing rule** via `rule_map::mode_for_rule`
  (`admin_dispatch.rs:1311`), not a global constant — satisfies C-2.7-02.
- log_only intent: the challenge arm (`data_plane.rs:1444`) and block arm
  report the intended action via `X-WAF-Action` while forwarding upstream
  and stamping `X-WAF-Mode: log_only` — satisfies C-2.7-03 / C-2.5-06.

## Net
Control plane is robust and faithful to v2.6. Only deviation: the
`policies`-scope unknown-feature 422 (F-V26-002).
