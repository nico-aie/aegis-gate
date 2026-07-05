# FEAT — Admin account management UI (runtime multi-admin CRUD)

> **Type:** FEAT (enterprise-identity / foundation track) · **Status:** ☐ Not started — planned 2026-07-05 · **Branch:** `feat/admin-account-mgmt-ui` (off `feat/2fa`, per stage)
> **Track ID prefix:** `AM-P2<a–d>` (realises §4.2 **P2 — multi-user account store** of the design doc)
> **Design docs:** [`../future/round-2-improvement/basic-admin-user-model-mvp.md`](../future/round-2-improvement/basic-admin-user-model-mvp.md) (the branch's conceptual spec — equal-`Admin`, no RBAC, per-account TOTP + recovery codes) · [`../future/admin-accounts-rbac-sso.md`](../future/admin-accounts-rbac-sso.md) §4.2 (P2 — multi-user store) + §4-cross-cutting ("Users & Access" page). This FEAT is the concrete runtime-CRUD + UI implementation of that MVP model.
> **Builds on:** `feat/2fa` (PR #167) — multi-admin data model, per-account TOTP, `SessionRecord.user`, `TotpEnrollmentStore`.
> **Honors (contracts, NOT bugs):** [[project_admin_public_http_contract]] (public-HTTP admin — no loopback/TLS migration), [[project_control_secret_contract_mandated]], [[project_config_plane_doc_vs_file]], [[project_apply_and_swap_helper_guard]].

**Goal (one line):** give an authenticated admin a dashboard page to **create / delete / reset-password / reset-TOTP / revoke-sessions** for admin accounts at runtime — no YAML edit, no restart — on a fleet-wide durable store, plus fold in the `feat/2fa` review hardening.

---

## 1. Why now / what's already shipped

`feat/2fa` shipped the **multi-admin data model** but accounts are **boot-frozen**: they're read once at boot into an immutable `Arc<AdminDirectory>` (`accept.rs:553` → `AdminDirectory::from_config`), stored on `DashboardServices.admin_directory` (`dashboard_services.rs:104`). Onboarding/offboarding a teammate today means editing YAML (`admin.dashboard_auth.accounts`) or running `deploy/create-admin.sh` **and restarting the WAF**. There are `apply_cfg_change_to_{tiers,upstreams,rules,mask}` reload helpers but **none for admin accounts** — so even a config-doc mutation would not take effect without a restart.

`feat/2fa` *also* already established the exact runtime-overlay pattern we need: **`TotpEnrollmentStore`** (`admin_auth/totp_store.rs`) keeps active TOTP factors in a Redis hash `control:waf:admin:totp` (fleet-wide + restart-durable via `StateBackend`), and `AdminDirectory::effective_totp` overlays the store over the YAML bootstrap (`login.rs:198` — "store wins when present"). This plan mirrors that pattern one level up: a runtime **account** store overlaying the YAML-seeded account set.

This realises **P2** of [`admin-accounts-rbac-sso.md`](../future/admin-accounts-rbac-sso.md) §4.2, whose stated storage is exactly "Redis hash in the existing `StateBackend`" seeded from the bootstrap admin.

## 2. Contract guardrails (do NOT touch)

- Public-HTTP admin on `0.0.0.0:9443` + `AEGIS_INSECURE_COOKIES` — committee contract. No transport migration.
- Default **control secret** — out of scope (distinct from the admin *password* hashes this plan manages).
- Identity is durable config-class state → lives under `control:waf:*`, which `reset_state`'s `EPHEMERAL_PATTERNS` already excludes (a state wipe must NOT delete admin accounts → permanent lockout). Depends on the mounted Redis `/data` volume (`redis-interim-durability.md` §5 — already shipped).

## 3. Architecture decision — runtime `AdminAccountStore` overlay (recommended)

**Chosen: a runtime account store overlaying the YAML-seeded set — NOT config-doc mutation.**

| | Runtime store overlay (**chosen**) | Config-doc mutation (rejected) |
|---|---|---|
| Precedent | `TotpEnrollmentStore` (shipped in `feat/2fa`); design-doc §4.2 | `service_accounts` in the doc |
| Hot login path | untouched — `resolve()` gains an async overlay like `effective_totp` | must make `admin_directory` an `ArcSwap` (today a frozen `Arc`) |
| Reload plumbing | none — store is read live per login | must add `apply_cfg_change_to_admin_accounts` to **both** watchers + the [[project_apply_and_swap_helper_guard]] structural test (missing one = silent node-local-until-restart — "how zero-trust + copilot broke") |
| Delete a YAML-seeded account | tombstone in the store | clean removal from the doc |
| Risk | **LOW** — additive, mirrors a shipped pattern | MED — touches the hot path + the apply-side guard |

**Model:** `control:waf:admin:accounts` — Redis hash, field = username, value = `{username, password_hash, disabled, created_at, updated_at, source}` (JSON). This is the MVP doc's `AdminUser` record minus the factor fields (`totp_secret`/`totp_enabled` stay in `TotpEnrollmentStore`; `recovery_code_hashes` is reserved for TF-2 recovery-login and left out of v1 — see AM-0e). Precedence per username = **store wins, else YAML-seeded** (identical to `effective_totp`). New accounts live only in the store. Deleting a YAML-seeded account writes a **tombstone** (`{deleted:true}`) so the overlay hides it without a YAML edit; deleting a store-only account drops the field. TOTP factors keep living in the existing `TotpEnrollmentStore` (reset-TOTP = delete that account's active entry → re-enroll at next login). Sessions keep living in `SessionStore` (revoke-by-user = a new `SessionStore::revoke_user`).

**Never stored in the doc / never returned to the client:** password hashes and TOTP secrets stay server-side; the list API returns only non-secret metadata.

## 4. Companion hardening — fold in the `feat/2fa` review (Wave 0, ships first)

Small, mostly independent; several are prerequisites for a safe management surface.

- **AM-0a [HIGH] — re-enroll step-up.** A fully-verified session can silently overwrite its own active TOTP factor with no proof of the current factor (`totp_enrollment.rs:enroll`/`confirm` never check for an existing `enabled` factor). Require the current TOTP code (or password re-entry) to *replace* an already-`enabled` factor; first-time enrollment stays as-is. (An admin resetting *another* account's TOTP via §5 is a distinct, authorised recovery action.)
- **AM-0b [MED] — open-redirect.** `login.js:safeNextUrl` blocks `//` but not `/\evil.com` (browsers normalise `\`→`/`). Also reject `\`, or validate `new URL(next, origin).origin === location.origin`.
- **AM-0c [MED] — CLI password echo.** `waf admin create-account` / `set-password` read the password with plain `read_line` (echoes to TTY / scrollback). Suppress echo (`rpassword` or a raw-mode read), matching `create-admin.sh`'s `read -rs`.
- **AM-0d [LOW] — username charset validation.** `validate_admin_accounts` (`config.rs:2181`) checks empty/duplicate only. A non-header-safe username makes `HeaderValue::from_str(actor)` no-op → `actor_from` falls back to `"admin"`, silently misrouting enroll/confirm. Restrict to `^[A-Za-z0-9_.-]{1,64}$`, fail closed at boot. **Reused verbatim by the create-account API in AM-1.**
- **AM-0e [LOW] — recovery-code framing.** CLI prints "recovery codes, each usable once" but no recovery-login path exists (deferred to TF-2). Drop the misleading copy; the admin-driven **reset-TOTP** action in §5 becomes the real lost-phone recovery for v1.

## 5. Staging (RED-first per stage; ship each green)

### AM-P2a — `AdminAccountStore` + overlay in `resolve` · **M** · backend only, no UI
- New `admin_auth/account_store.rs` mirroring `totp_store.rs`: `with_backend` / `in_memory`, `list()`, `get()`, `upsert()`, `tombstone()`, backed by `control:waf:admin:accounts`. Manual `Debug` that never prints hashes.
- `AdminDirectory` gains `with_account_store(...)` + makes `resolve` async, overlaying the store over the YAML-seeded accounts (store wins; tombstone hides). `authenticate` already `.await`s `effective_totp`, so the async resolve is a small ripple.
- Boot wiring in `accept.rs` alongside the existing `totp_store` (`accept.rs:548-555`); inject into `DashboardServices` like `totp_store`.
- `SessionStore::revoke_user(user)` — evict all of a user's sessions (backend: scan `adminsess:*`, drop matching `record.user`; local map: retain-filter).
- Tests: overlay wins over YAML; tombstone hides a seeded account; create→login round-trip; revoke_user evicts only that user; unknown user still hits `dummy_verify` (timing flat).

### AM-P2b — account management API · **M** · behind the existing gate
All under the session + CSRF + write-scope gate (`admin_auth_middleware.rs:148-200`); acting admin from `x-aegis-actor`. Added to the `admin_dispatch.rs` path chain next to the TOTP routes (`admin_dispatch.rs:120-125`).
- `GET  /api/admin/accounts` → `[{username, totp_enrolled, disabled, source, active_sessions}]` — **no secrets**.
- `POST /api/admin/accounts {username, password}` → validate charset (AM-0d) + password policy + dedup; argon2id-hash server-side; `upsert`. New account is un-enrolled → `require_totp` sends it to first-login enrollment.
- `POST /api/admin/accounts/{username}/password {new_password}` → re-hash + `revoke_user` (force re-login).
- `POST /api/admin/accounts/{username}/totp/reset` → delete the account's active factor from `TotpEnrollmentStore` → re-enrolls next login (lost-phone recovery).
- `DELETE /api/admin/accounts/{username}` → `tombstone`/drop + purge TOTP entry + `revoke_user`.
- (Optional) `POST /api/admin/accounts/{username}/disable|enable`.
- **Safety rails:** last-enabled-admin guard (can't delete/disable the final account → lockout); self-TOTP-reset requires step-up (ties to AM-0a); every action emits an `AuditClass::Admin` event (actor = server-owned `x-aegis-actor`, never the target).
- Tests: create/delete/reset round-trips; last-admin guard blocks; delete purges TOTP + sessions; read-only scope & missing-CSRF rejected; list never leaks a hash/secret.

### AM-P2c — "Access" dashboard page · **M** · the UI the ask is about
- New `NAV` entry (`app.jsx:18`, near Settings) → `access` page in `pages.jsx` (hook-aliased per [[project_dashboard_js_hook_safety]]; rebuild `app.js` via `build.sh`, which runs the acorn rules-of-hooks guard).
- Accounts table: username · 2FA status badge · active sessions · source (bootstrap/runtime) · row actions.
- "Add admin" modal (username + password with live charset/strength validation) → `POST /api/admin/accounts` via `csrfMutate` (`data.jsx:859`).
- Row actions (each a confirm dialog): **Reset password**, **Reset 2FA**, **Revoke sessions**, **Delete** — the last two gated in-UI by the last-admin guard the API also enforces.
- Empty/error/loading states; optimistic refresh via the existing `useApi` refresh.
- Guards: rules-of-hooks acorn check green; page renders under both themes.

### AM-P2d — self-service "Account" page + docs · **S/M**
- Self "Account" panel: change my password (→ revoke my *other* sessions, keep current), re-enroll my TOTP (with AM-0a step-up), view/revoke my own sessions.
- Docs: extend `deploy/ADMIN-ACCOUNTS.md` + `docs/control-plane/dashboard-auth.md` with the runtime-management flow; note that YAML/`create-admin.sh` remain the bootstrap path and the UI is the day-2 path.

## 6. Risks / open decisions

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | **Any admin can delete/reset any admin** (no RBAC in v1 — all accounts equal-privilege) | Explicit non-goal (RBAC = design-doc P3). Last-admin guard prevents lockout; every action is audited with the real actor. Surface the "equal privilege" reality in the UI + docs. **Decision to confirm with owner.** |
| MED | **Lockout** — deleting/disabling the last admin, or resetting your own TOTP as sole admin | Last-enabled-admin guard (API + UI); self-TOTP-reset step-up; break-glass path stays via YAML seed + restart |
| MED | **Store durability** — accounts only in an unmounted Redis = wipe → lockout | `control:waf:*` excluded from `reset_state`; requires the mounted `/data` volume (shipped); YAML seed is a re-assertable floor |
| LOW | **Overlay/tombstone confusion** — a YAML account "reappears" after tombstone removal | Tombstone is explicit + audited; list API shows `source`; documented |
| LOW | **Secret leakage via the list API** | Response DTO carries metadata only; a test asserts no `$argon2`/secret substring in any accounts response |

## 7. Acceptance

- [ ] AM-0a–e review hardening merged (step-up, open-redirect, CLI echo, charset, recovery framing).
- [ ] AM-P2a: `AdminAccountStore` + async overlay `resolve` + `revoke_user`; overlay/tombstone/round-trip tests green.
- [ ] AM-P2b: 5 account endpoints live + gated + audited; last-admin guard; list leaks no secrets.
- [ ] AM-P2c: Access page — list/create/delete/reset-password/reset-2FA/revoke-sessions; hooks-guard green; both themes.
- [ ] AM-P2d: self-service Account panel + docs.
- [ ] Contract guardrails untouched; `cargo test --workspace` green; `build.sh` hooks-guard green.
- [ ] Archive this FEAT file + tick §4.2 P2 in the design doc on completion.

## 8. Out of scope

RBAC / roles (design-doc **P3** — the next track; all admins stay equal-privilege here), per-user audit querying (**P4**), OIDC SSO (**P5**), recovery-code *login* (TF-2 — replaced for v1 by admin-driven reset-TOTP), config-doc account storage / `ArcSwap` hot-swap (explicitly rejected in §3), transport/cookie posture (contract).
