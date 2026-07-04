# FEAT — Enforce 2FA for all admin access

> **Type:** FEAT (committee round-2 🔴2) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `TF-<1–3>` · **Extends:** `plans/issues/FEAT-admin-accounts-p1-self-service-hardening.md`
> (AA-P1b web enrollment + recovery login, AA-P1d setup token) — this plan adds the *enforcement*
> layer those stages deliberately left out. Do **not** duplicate their scope here.

**Objective (intent, not letter):** a password alone must never grant admin access. Every
interactive admin login requires a second factor; the escape hatches (recovery codes, break-glass)
are themselves authenticated and audited.

---

## 1. Verified current state (2026-07-04)

| Fact | Anchor |
| --- | --- |
| TOTP impl is solid: RFC 6238 SHA1, constant-time compare, replay guard | `admin_auth/totp.rs:18-175` |
| `totp_enabled` defaults **false**; `#[serde(default)]` → omitted config = off | `config.rs:6050-6051, 6131` |
| No `require_totp` / global MFA flag exists anywhere | (grep: none) |
| Password-only login fully supported when flag off | `login.rs:215`, test `login.rs:766-777` |
| Enrollment is CLI→YAML paste only (`waf admin enroll-totp`); no web enrollment | `main.rs:650-695`, `config.rs:6058` |
| Recovery codes generated + printed but **not consumable at login** — no storage field, `verify_recovery_code` has zero callers | `totp.rs:191-209`, `main.rs:683` |
| Docs overstate: claim argon2-stored recovery codes + a `waf admin disable-totp` command; neither exists | `dashboard-auth.md:55,230,260` (`[[project_docs_overstate_impl]]` again) |
| Service-account bearer tokens are a separate non-interactive path (no TOTP) | `config.rs:6144`, `main.rs:726` |
| Secondary identity-construction path skips TOTP fields (`..AdminIdentity::default()`) | `aegis-proxy/src/lib.rs:400-403` |

## 2. Staging

### TF-1 — `require_totp` enforcement flag · **S** · START HERE
- Add `admin.dashboard_auth.require_totp: bool` — **default `true`**.
- Semantics at login (`authenticate`, `login.rs:144`):
  - `require_totp && !totp_enabled` → login returns a distinct `enrollment_required` state that
    admits the session into a **TOTP-enrollment-only** surface (nothing else unlocked) — pairs
    with AA-P1b's `POST /api/admin/totp/enroll|confirm`. Until AA-P1b lands, fallback: reject
    login with an actionable "run `waf admin enroll-totp`" error (still enforced, worse UX).
  - `require_totp && totp_enabled` → unchanged strict path.
  - `require_totp: false` → today's behavior (explicit, visible opt-out for dev).
- Boot-time validation warning (not error) when `require_totp: false` in a non-dev profile.
- Audit the secondary identity path (`lib.rs:400-403`) so enforcement can't be sidestepped by
  whichever boot path constructed the identity.
- Dev/CI/bench: set `require_totp: false` explicitly in `config/dev.yaml` etc. — enforcement is
  the *default*, dev opts out loudly.

### TF-2 — close the escape-hatch gaps · **M**
- **Recovery-code login**: AA-P1b owns the wiring (consume-once, doc-persisted). This plan adds:
  recovery login *counts as 2FA* (allowed under `require_totp`), emits a distinct audit event,
  and burns toward forced re-enrollment when codes run low.
- **`waf admin disable-totp`** CLI: exists in docs, not in code — implement it (requires current
  password + a recovery/TOTP code; emits audit event) or strip it from the docs. Recommend
  implement; YAML-editing-to-disable stays possible but is then an audited config change.
- **Service accounts**: unchanged (non-interactive), but document that `require_totp` does not
  apply to bearer tokens, and their scopes are the mitigation.

### TF-3 — truth-up docs + committee evidence · **S**
- Fix `docs/control-plane/dashboard-auth.md` to match reality after TF-1/2 (recovery storage,
  disable command, enforcement defaults).
- Verification artifact for the committee: test transcript showing password-only login rejected
  on a default config.

## 3. Tests (RED-first)

- Default config (`require_totp` unset) + `totp_enabled: false` → password-only login **fails** /
  routes to enrollment-only state; nothing else accessible in that state.
- `require_totp: false` explicit → legacy behavior preserved (regression guard).
- Recovery-code login satisfies enforcement, consumes once, and audit event fires.
- `disable-totp` requires second factor; a disable is followed by enforced re-enrollment at next
  login (because `require_totp` still true).
- Both identity-construction paths (accept.rs + lib.rs) enforce identically.
- Keep RFC 6238 / argon2 / rate-limit suites green.

## 4. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Lockout: enforcement lands before enrollment UX (AA-P1b) | sequence after AA-P1b, or accept the CLI-error fallback window; loopback + YAML edit remains the break-glass |
| MEDIUM | Dev/CI/bench flows break on default-true | explicit opt-out in dev configs in the same PR |
| LOW | Enrollment-only session surface leaks other APIs | scope it via the existing middleware gate (`admin_auth_middleware.rs:81-200`), test-enumerate the route table against it |

## 5. Acceptance

- [ ] Fresh default install: no admin session without a second factor — committee's literal ask.
- [ ] Enrollment-required flow usable end-to-end (with AA-P1b) or CLI fallback documented.
- [ ] Recovery + disable paths implemented, audited, and matching the docs.
- [ ] Dev/CI/bench green with explicit opt-outs.
