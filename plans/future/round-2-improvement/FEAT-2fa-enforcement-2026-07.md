# FEAT — Enforce 2FA for all admin access

> **Type:** FEAT (committee round-2 🔴2) · **Status:** ☐ Not started — planned 2026-07-04, **round-3 scope + owner: L-Tester member (2026-07-05)**
> **Track ID prefix:** `TF-<1–4>` · **Extends:** `plans/issues/FEAT-admin-accounts-p1-self-service-hardening.md`
> (AA-P1b web enrollment + recovery login, AA-P1d setup token) — this plan adds the *enforcement*
> layer those stages deliberately left out. Do **not** duplicate their scope here.
>
> **Round-3 additions (owner, 2026-07-05):** enforce with the **Google Authenticator app**
> (`otpauth://` QR enrollment — TF-1a) and support **multiple admin accounts** (TF-4). The base
> `TF-1…TF-3` enforcement work is unchanged.

**Objective (intent, not letter):** a password alone must never grant admin access. Every
interactive admin login requires a second factor **from a standard authenticator app (Google
Authenticator, Authy, 1Password, …)**; every admin **account** has its own factor; the escape
hatches (recovery codes, break-glass) are themselves authenticated and audited.

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
| **Exactly one interactive admin identity today** — `dashboard_auth` carries a single `password_hash_ref` + single `totp_secret_b32`; no notion of multiple named admins | `config.rs:6061-6096` (`DashboardAuthConfig`) |
| **`provisioning_uri` already emits a Google-Authenticator-compatible `otpauth://totp/…` URI** (SHA1 / 6 digits / 30s period) — GA support is *surfacing the QR*, not new crypto | `admin_auth/totp.rs:184-186`, test `totp.rs:334` |

## 2. Staging

### TF-1 — `require_totp` enforcement flag · **S** · START HERE
- Add `admin.dashboard_auth.require_totp: bool` — **default `true`**.
> **TF-4 interaction:** with multiple accounts, `require_totp` is a **global** policy — it applies
> to *every* admin account, not per-account. An account without an enrolled factor lands in the
> enrollment-required state exactly like the single-admin path. Land TF-1 first on the single-admin
> model, then TF-4 generalizes the identity lookup underneath it — the enforcement semantics don't
> change, only *which* identity's factor is checked.
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

### TF-1a — Google Authenticator QR enrollment · **S–M** · (pairs with AA-P1b)
The crypto is done (`provisioning_uri` → GA-compatible `otpauth://`); this stage makes enrollment
*usable from the app* instead of pasting a base32 secret.
- **Enrollment endpoint (AA-P1b owns the route; this plan owns the payload):** on
  `POST /api/admin/totp/enroll`, generate a fresh secret, store it *pending-confirm* (not yet
  active), and return **both** the `otpauth://` URI and a **QR code** (render server-side as an SVG
  or a `data:` PNG — no external QR service; a small self-contained QR crate or inline SVG path).
  Issuer = `Aegis` (or the configured `admin.environment` label so `prod`/`staging` are
  distinguishable in the app), account = the admin username (TF-4).
- **Confirm step:** `POST /api/admin/totp/confirm` with a code the app now generates; only on a
  correct code does the secret become active (`totp_enabled = true` for that account). Prevents
  enrolling a secret the operator never actually scanned.
- **Manual-entry fallback:** show the base32 secret alongside the QR for app setups that type it in.
- **CLI parity:** `waf admin enroll-totp` prints the same `otpauth://` URI + an ASCII-QR so
  headless setup matches the web flow.
- Emits an audit event on enroll + confirm (folds into AU-1 taxonomy — do not invent a second one).
- **No algorithm change:** stay on SHA1/6/30 — that's the GA-interoperable baseline (the `totp.rs`
  doc history already records that an SHA256 URI mismatch was a bug). If a future app needs SHA256,
  it's a separate, tested change.

### TF-4 — multiple admin accounts · **M–L**
Today `DashboardAuthConfig` is a single identity. Generalize to N named admins, each with its own
password hash + TOTP secret + recovery codes.
- **Config shape:** add `admin.dashboard_auth.accounts: [{ username, password_hash_ref,
  totp_secret_b32?, totp_enabled?, recovery_codes_ref? }]`. Keep the existing top-level
  `password_hash_ref`/`totp_secret_b32` as a **back-compat single-admin shorthand** (migrate it to a
  synthesized `accounts` entry named e.g. `admin` at load; reject configs that set *both* the legacy
  fields and `accounts` to avoid ambiguity).
- **Login lookup:** `authenticate()` currently compares against one identity; make it resolve the
  submitted `user` against the account set (constant-time username compare + the existing
  `dummy_verify` on miss so account existence doesn't leak via timing — preserve that property per
  account).
- **Per-account state:** rate-limit / lockout counters are already keyed by `(ip, user)` — verify
  they partition correctly across accounts (a lockout on one admin must not lock another).
- **Both identity-construction paths** (`accept.rs:527`, `lib.rs:400`) build from the account set
  identically — the TF-1 guard against a TOTP-skipping path applies per account.
- **Audit:** every event carries the acting `username` (AU-1 already has the `user` field).
- **Out of scope (say so):** full RBAC / per-account scopes / SSO — that's the
  `admin-accounts-rbac-sso.md` track. TF-4 is *authentication* for multiple admins, not
  *authorization* tiers; all admins are equal-privilege here.

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
- **TF-1a (Google Authenticator):** enroll returns a parseable `otpauth://totp/…` URI (SHA1/6/30)
  **and** a self-contained QR (SVG/`data:` PNG, no external host); a code generated from the
  returned secret confirms and activates; an unconfirmed secret never grants login. Cross-check the
  URI against a known-answer GA vector.
- **TF-4 (multi-account):** each account authenticates with its own password+TOTP; a wrong factor
  on account A never admits; lockout on A does not lock B; unknown username runs `dummy_verify` (no
  existence leak); legacy single-`password_hash_ref` config still boots (migrated to one `accounts`
  entry); config setting *both* legacy fields and `accounts` is rejected at validation.

## 4. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Lockout: enforcement lands before enrollment UX (AA-P1b) | sequence after AA-P1b, or accept the CLI-error fallback window; loopback + YAML edit remains the break-glass |
| MEDIUM | Dev/CI/bench flows break on default-true | explicit opt-out in dev configs in the same PR |
| MEDIUM | TF-4 config migration ambiguity (legacy fields + `accounts` both set) | reject at validation with a clear error; migrate legacy→one `accounts` entry deterministically; round-trip test |
| MEDIUM | QR rendering pulls a heavy/networked dependency | server-side SVG or a small pure-Rust QR crate only; no external QR service (offline admin box must work); vet the crate for `unsafe`/deps |
| LOW | Enrollment-only session surface leaks other APIs | scope it via the existing middleware gate (`admin_auth_middleware.rs:81-200`), test-enumerate the route table against it |
| LOW | Per-account lockout counters bleed across accounts | keyed by `(ip, user)` already — add an explicit A-locked-B-open test |

## 5. Acceptance

- [ ] Fresh default install: no admin session without a second factor — committee's literal ask.
- [ ] Enrollment-required flow usable end-to-end (with AA-P1b) or CLI fallback documented.
- [ ] **Google Authenticator**: an operator scans the QR in the GA app and logs in with the
      app-generated code — demoed end-to-end (TF-1a).
- [ ] **Multiple admin accounts**: ≥2 admins, each with independent password + TOTP, both log in;
      legacy single-admin config still boots (TF-4).
- [ ] Recovery + disable paths implemented, audited, and matching the docs.
- [ ] Dev/CI/bench green with explicit opt-outs.
