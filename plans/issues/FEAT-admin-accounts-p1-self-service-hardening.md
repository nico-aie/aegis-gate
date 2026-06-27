# FEAT — Admin accounts P1: self-service hardening (single-admin model)

> **Type:** FEAT (enterprise-identity / foundation track) · **Status:** ☐ Not started — planned 2026-06-27 · **Branch:** `feat/admin-accounts-p1-*` (per stage)
> **Track ID prefix:** `AA-P1<a–d>`
> **Design doc:** [`../future/admin-accounts-rbac-sso.md`](../future/admin-accounts-rbac-sso.md) §4.1 (decisions + the full P1–P5 arc live there)
> **Tracker slot:** [`../implementation-sequence.md`](../implementation-sequence.md) Wave 3 — `admin-accounts-rbac-sso P1`
> **Honors (contracts, NOT bugs):** [[project_admin_public_http_contract]] (public-HTTP admin, no loopback/TLS migration), [[project_control_secret_contract_mandated]] (default control secret out of scope — distinct from the admin *password* hash).

**Goal (one line):** harden the **control-plane** admin identity on the existing **single-admin** model — wire the dormant self-service endpoints, move login lockout fleet-wide, and kill committed default creds — **no data-model change** (multi-user is P2). Pure wiring + secret hygiene over a crypto/session foundation that already ships and is unit-tested.

---

## Why now

Most P1 *primitives* already exist + are tested but are **wired to nothing**: `handle_password_change` (`api/admin.rs:42`), `SessionStore::revoke` (`session.rs:192`), `provisioning_uri` / `verify_recovery_code` (`totp.rs:184,207`), `BreakGlass::enable/disable`. Today only **GET** `/api/admin/sessions` + **GET** `/api/admin/break-glass` exist (`admin_get.rs:923,927`). Login rate-limit is per-node `Mutex<HashMap>` (`rate_limit.rs:86-87`), bypassable across the cluster. Committed `aegis-test-1234` hash + weak `csrf_secret` ship in `waf.yaml` / `config/dev.yaml` / `config/cluster-b.yaml`. P1 closes these gaps; it ships standalone and is worth doing regardless of P2–P5.

## Contract guardrails (do NOT touch)

- Public-HTTP admin on `0.0.0.0:9443` + `AEGIS_INSECURE_COOKIES` — committee contract. No loopback/TLS migration.
- Default **control secret** `waf-hackathon-2026-ctrl` — v2.6-mandated, loopback-gated. Out of scope. (The admin **password** hash + `csrf_secret` in the YAMLs ARE real default creds to harden — distinct from the control secret.)

## Staging (4 small PRs, ordered by risk; ship each green)

### AA-P1a — wire the 3 simple self-service endpoints · **S** · START HERE
Pure wiring of built+tested logic behind the existing gate (session + CSRF + `write` scope, `admin_auth_middleware.rs:148-200`). No new persistence, no boot change, no dev-config change.
- `POST /api/admin/password` → `handle_password_change`; on success invalidate **other** sessions (existing `invalidate_sessions` closure), keep the caller's own.
- `DELETE /api/admin/sessions/{id}` → dashboard `SessionStore::revoke`.
- `POST /api/admin/break-glass` → `BreakGlass::enable/disable`.

### AA-P1b — TOTP in-dashboard enrollment + recovery-code login · **M**
New persistence (config doc + `control:waf:*`).
- `POST /api/admin/totp/enroll` + `/confirm` → `provisioning_uri` + first-code verify; persist the secret to the **config doc** (NOT the YAML file — [[project_config_plane_doc_vs_file]]; rides the `config_backend` seam fixed in #96).
- Recovery-code login: wire `verify_recovery_code` as a TOTP fallback in `authenticate` (`login.rs:145`), **consume-once** (consumed state under `control:waf:*`).

### AA-P1c — fleet-wide login rate-limit · **M**
Move `LoginRateLimiter` counters from per-node `Mutex<HashMap>` onto the Redis `StateBackend` already used by sessions (mirrors `g:rl:*`), so cluster lockout can't be sidestepped by hitting another node + survives restart. Keep the in-memory path as the single-node fallback.

### AA-P1d — kill committed defaults + first-boot setup token · **M** (the careful one — do LAST)
- Remove the baked `aegis-test-1234` hash + weak `csrf_secret` from `waf.yaml` / `config/dev.yaml` / `config/cluster-b.yaml`. Empty `password_hash_ref` already disables login (`accept.rs:435-441`).
- Add a one-time, short-TTL, single-use **setup token** (printed once to stdout/logs) that forces an initial password + TOTP enrollment before the dashboard unlocks; invalidated the instant the first admin is set.
- Dev/CI/bench fallout: move those flows to an explicit, clearly-named *test* hash via env (NOT the production default) — update Makefile `run-dev`, QUICKSTART, bench harness, e2e recipe ([[feedback_e2e_docker_cleanup]]).

## Tests (RED-first, per stage)

- **AA-P1a:** password-change route invalidates *other* sessions but not self; session-revoke evicts a listed session; break-glass enable/disable round-trips; each route rejects without session / without CSRF / with read-only scope.
- **AA-P1b:** TOTP enroll→confirm round-trip persists to the doc; recovery code consumes once then fails; user-enumeration timing stays flat (`dummy_verify`).
- **AA-P1c:** lockout observed from a *second* simulated node (fleet-wide) + survives restart; in-mem fallback when no backend wired.
- **AA-P1d:** empty default config → login disabled + setup-token gate; setup token single-use + TTL'd; dev/CI configs use the explicit test hash; bench/e2e still boot.
- Keep the RFC 6238 / argon2 / CSRF / session unit suites green throughout.

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | **P1d dev/CI/bench fallout** — removing defaults breaks flows assuming `admin`/`aegis-test-1234` | explicit `*-test` env hash + update Makefile/QUICKSTART/bench/e2e in the same PR |
| MEDIUM | **Fleet-wide lockout DoS** (P1c) — per-user lockout can lock a real operator | per-IP + per-user limits stay independent; never lock the last admin; break-glass bypass under MFA |
| LOW | **Setup token on public-HTTP** (P1d) | one-time, short-TTL, single-use, invalidated on first-admin create; document loopback/SSH-tunnel enrollment ([[project_control_plane_loopback_only]]) |
| LOW | **P1a** | near-zero — wiring tested logic behind the existing gate |

## Acceptance

- [ ] AA-P1a: 3 mutating endpoints live + gated + tested; develop green.
- [ ] AA-P1b: TOTP enroll/confirm + recovery-code login; consume-once; doc-persisted.
- [ ] AA-P1c: lockout fleet-wide + restart-durable; single-node fallback intact.
- [ ] AA-P1d: no committed default creds; setup-token first-boot flow; dev/CI/bench updated.
- [ ] Contract guardrails untouched (public-HTTP transport, control secret).
- [ ] `docs/control-plane/dashboard-auth.md` updated; archive this FEAT file on completion.

## Out of scope (P1)

Multi-user store (P2), RBAC (P3), per-user audit (P4), OIDC SSO (P5); transport/cookie posture (contract); the default control secret.
