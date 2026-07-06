# FEAT — TOTP with Google Authenticator: first-login enrollment + enforced login code

> **Type:** FEAT (round-3, owner ask 2026-07-05) · **Status:** ☐ In progress · **Branch:** `feat/2fa`
> **Track ID prefix:** `TOTP-<1–4>` · **Derives from:**
> [`../future/round-2-improvement/FEAT-2fa-enforcement-2026-07.md`](../future/round-2-improvement/FEAT-2fa-enforcement-2026-07.md)
> (TF-1 / TF-1a / TF-4) and
> [`../future/round-2-improvement/basic-admin-user-model-mvp.md`](../future/round-2-improvement/basic-admin-user-model-mvp.md)
> (multi-admin, no RBAC). Complements `FEAT-admin-accounts-p1-self-service-hardening.md`
> (AA-P1b owns recovery-code login wiring; AA-P1c owns fleet-wide rate limit — NOT duplicated here).

**Goal (one line):** every admin account enrolls its own Google-Authenticator TOTP on first
login (QR scan → confirm code) and every subsequent login requires the app-generated code;
multiple equal-privilege admin accounts; enforcement ON by default.

---

## Storage decision (cluster vs standalone)

Runtime TOTP state (enrolled secret, enabled flag, pending enrollment) rides the
**`StateBackend` seam already used by admin sessions** (`session.rs` `with_backend`):

| Deploy shape | Backend | Behaviour |
| --- | --- | --- |
| Cluster (redis) | Redis | Fleet-wide + restart-durable: enroll on node A, login on node B works. Durable entries in hash `control:waf:admin:totp` (`hset_multi`/`hscan` — same pattern as `control:waf:incidents`); pending enrollments as TTL keys `control:waf:admin:totp:pending:<user>` (15 min). |
| Standalone + redis | Redis | Same as cluster — durable across restart. |
| Standalone `in_memory` | in-process | Works within the process lifetime; lost on restart → YAML (`accounts[].totp_secret_b32`) + CLI remain the durable bootstrap, boot warning tells the operator. |

Why not the etcd config doc / `ConfigBackend`: TOTP login state has the exact same
consistency need as **sessions** (checked on every login on any node) — following the session
seam keeps one storage story for all auth-runtime state. Deployments with
`config_plane.store: etcd` still run their sessions (and now TOTP state) on the configured
StateBackend. Config-YAML remains the *bootstrap* source; the runtime store is an overlay
that wins when present (enrollment without YAML edits).

## Reuse map (do NOT rebuild)

| Existing | Where | Reused for |
| --- | --- | --- |
| RFC 6238 TOTP + replay guard + ct-compare | `admin_auth/totp.rs` | verify at login + confirm step (unchanged crypto: SHA1/6/30 = GA baseline) |
| `provisioning_uri()` (GA-compatible `otpauth://`) | `totp.rs:184` | enroll response + CLI |
| Secret generation (2×UUIDv4 → 32B → RFC 4648 b32) | `main.rs cmd_admin_enroll_totp` | extracted + shared by endpoint & CLI |
| argon2id `hash_password` / `verify_password` / `dummy_verify` | `admin_auth/password.rs` | account passwords (CLI `create-account` reuses `set-password` logic) |
| Session store w/ `totp_verified` flag + `mark_totp_verified` | `admin_auth/session.rs` | enrollment-only session state (flag existed, zero callers → now wired) |
| Login rate limit keyed `(ip, user)` | `admin_auth/rate_limit.rs` | per-account lockout partitioning for free |
| Auth middleware gate | `admin_auth_middleware.rs` | enrollment-only surface restriction |
| Audit bus + AU-1 taxonomy | `login_audit.rs` / `AuditBus` | enroll/confirm audit events |

## Issues

### TOTP-1 — multi-account config + directory lookup · **M** · (TF-4 core)
- `admin.dashboard_auth.accounts: [{username, password_hash_ref, totp_secret_b32?, totp_enabled?}]`.
- Legacy top-level `password_hash_ref`/`totp_secret_b32` = back-compat shorthand → synthesized
  `accounts` entry named `admin` at load; config setting **both** legacy fields and `accounts`
  rejected at validation.
- `AdminDirectory` (N × `AdminIdentity`, each with own replay guard); `authenticate()` resolves
  the submitted user; unknown user still runs `dummy_verify` (no existence leak).
- `SessionRecord.user` (serde-default `admin` for old records); middleware `Identity.actor` =
  session user → audit events carry the acting username.
- Both boot paths (`accept.rs`, `lib.rs`) build from the account set.
- RED: two accounts each log in with own password; wrong cross-account factor rejected; unknown
  user no-leak; legacy config still boots; both-set config rejected.

### TOTP-2 — `require_totp` enforcement flag · **S** · (TF-1)
- `admin.dashboard_auth.require_totp: bool`, **default `true`** (global policy, applies to every account).
- Login semantics: password OK + `require_totp` + account not enrolled →
  `LoginOutcome::EnrollmentRequired`: session issued with `totp_verified=false`, body says
  `enrollment_required`; middleware admits that session ONLY to
  `POST /api/admin/totp/enroll|confirm` + logout (403 `totp_enrollment_required` elsewhere).
- Fully-enrolled login sets `totp_verified=true`; `require_totp: false` → today's behavior.
- Explicit `require_totp: false` added to `config/dev.yaml` + cluster/bench configs in the same
  PR; boot warning when false.
- RED: default config password-only login → enrollment-only surface, `/api/*` 403; opt-out
  regression guard; enrolled path unchanged strict.

### TOTP-3 — Google Authenticator enrollment: endpoints + QR + runtime store · **M** · (TF-1a)
- `TotpEnrollmentStore` (aegis-control): StateBackend-backed per the storage decision above;
  in-memory fallback mirrors `SessionStore`.
- `POST /api/admin/totp/enroll` → fresh CSPRNG secret stored *pending-confirm* (TTL 15 min),
  returns `{otpauth_uri, secret_b32 (manual-entry fallback), qr_svg}`. QR rendered server-side
  with the pure-Rust `qrcode` crate (SVG string — no external host, offline admin box works).
  Issuer = `admin.environment` label or `Aegis`, account = session username.
- `POST /api/admin/totp/confirm {code}` → verify against pending secret; only a correct code
  activates (`enabled=true` persisted); marks the session `totp_verified`; an unconfirmed
  secret never grants login.
- `authenticate()` reads effective TOTP state = runtime store overlay > YAML account entry.
- Audit events `totp_enroll_started` / `totp_enroll_confirmed` on the existing bus (AU-1 shape).
- RED: enroll returns parseable GA URI (SHA1/6/30) + self-contained SVG; code from returned
  secret confirms + next login requires it; unconfirmed secret rejected at login; pending
  expires; works via in-memory fallback (standalone).

### TOTP-4 — CLI parity (reuse existing `waf admin`) · **S**
- `waf admin create-account --username <u>`: prompts password (reuses `hash_password`), prints
  ready-to-paste YAML `accounts:` fragment (+ optional `--with-totp` inline enrollment reusing
  the same secret-gen helper → prints `otpauth://` URI + ASCII QR).
- `waf admin enroll-totp` gains `--qr` ASCII QR output so headless setup matches the web flow.

### TOTP-5 — login-page FE: TOTP field + in-browser QR enrollment · **S** · (added 2026-07-05)
Backend flow was complete but `login.js` still spoke the old password-only protocol —
a 200 blind-redirected to the dashboard (which 403s for enrollment-only sessions) and the
form had no way to submit an app code.
- Login form gains an optional `totp_code` input (enrolled accounts).
- `enrollment_required: true` on 200 switches the card to the enrollment surface:
  `POST /api/admin/totp/enroll` (CSRF header from the `aegis_csrf` cookie) → render the
  inline-SVG QR + manual-entry secret → operator scans with Google Authenticator →
  `POST /api/admin/totp/confirm {code}` → redirect to `?next=`.
- Contract-guard tests pin the shipped assets to the backend protocol (field names +
  endpoint paths) so the FE/backend drift class can't silently recur.

## Out of scope (tracked elsewhere — say so, don't duplicate)
- Recovery-code **login** consumption + `waf admin disable-totp` → TF-2 (`FEAT-2fa-enforcement` §TF-2, AA-P1b owns wiring).
- Fleet-wide login rate limit → AA-P1c.
- Setup token / first-boot flow → AA-P1d. RBAC/SSO → separate track.

## Acceptance
- [ ] Fresh default config: no admin session without a second factor; password-only lands in
      enrollment-only state.
- [ ] Operator scans QR in Google Authenticator, confirms, re-logs-in with app code — end to end.
- [ ] ≥2 admins with independent password+TOTP both log in; lockout on A doesn't lock B.
- [ ] Legacy single-admin YAML still boots (migrated); both-set config rejected with clear error.
- [ ] Cluster mode: enroll on one node, login via another (Redis-backed store).
- [ ] Dev/CI/bench green with explicit `require_totp: false`.
