# Admin Accounts, RBAC & SSO — control-plane identity (future plan)

**Status:** Drafted 2026-06-24. Not started. Foundation / enterprise-readiness track.

> **Scope guard.** This plan covers the **control-plane** admin/dashboard identity (`crates/aegis-control/src/admin_auth/*` + `crates/aegis-proxy/src/admin_*`). It does **NOT** touch the **data-plane** external-auth that protects *upstream* routes (`crates/aegis-proxy/src/auth/*` — JWT/JWKS, OIDC-RP, ForwardAuth, Basic; see `docs/security/external-auth.md`). Two different planes, two different threat models — keep them separate.
>
> **Consolidates** the repeatedly-referenced-but-missing `docs/future/rbac-sso.md` (dangling refs in `plans/archive/{control,security,console-api-integration}.md`). The single-admin v1 model and deferred RBAC/SSO/multi-tenancy carve-out are long-standing — this is the plan to finally land them.
>
> **Honors** [[project_admin_public_http_contract]]: admin runs on public `0.0.0.0:9443` over plain HTTP with `AEGIS_INSECURE_COOKIES=1` by committee contract. That is NOT a bug and this plan does **not** propose loopback/TLS migration — it hardens *identity* on top of that transport posture. Related: [[project_control_secret_contract_mandated]], [[feedback_dev_xff_single_ip_gates]].

---

## 1. Goal / Why

Today the dashboard authenticates **one hard-coded principal** — user literal `"admin"` at `accept.rs:466`, every session resolves to `actor: "admin", scopes: Scopes::FULL` (`admin_auth_middleware.rs:382-399`). For a security product that an enterprise SOC team logs into, that is the weakest link:

- **No accountability** — every action in the audit trail is `"admin"`; you cannot tell *which* operator flipped enforce→log-only or reset a risk gate.
- **Shared credential** — one password, pasted into YAML, rotated by hand + restart (`waf admin set-password` → paste hash → restart). Onboarding/offboarding a teammate means rotating the shared secret for everyone.
- **No least privilege** — a junior analyst who should only *read* dashboards has the same `Scopes::FULL` as the operator who can disable defenses.
- **Committed default credentials** ship in `waf.yaml`, `config/dev.yaml`, `config/cluster-b.yaml` (`admin` / `aegis-test-1234` + a weak committed `csrf_secret`), with no forced first-boot rotation.

**How the industry solves it.** Cloudflare's dashboard moved from single-login → multi-user → account-scoped RBAC with a Super Administrator, multiple roles per user, fail-closed permissions, and dashboard SSO via the customer IdP. The enterprise-readiness consensus build order is **RBAC → audit logs → SSO → SCIM** (RBAC first because everything keys off roles; SCIM last, only on request).

**The trap.** Most of the *primitives* already exist and are unit-tested — but several are **wired to nothing** (password-change, in-dashboard TOTP enrollment, session-revoke, break-glass, recovery-code login). The temptation is to jump straight to SSO. Don't. The highest value-per-effort is **(a)** wiring the dormant self-service endpoints and killing committed defaults, then **(b)** replacing the hard-coded admin with a real user store, *then* RBAC, *then* federation. Each phase ships safely on the single-admin model it replaces.

## 2. What already ships (verified 2026-06-24)

The crypto and session foundation is solid. This is a **wiring + data-model** plan far more than a crypto plan.

| Surface | Anchor | Verdict |
| --- | --- | --- |
| Password hash (argon2id, PHC, CSPRNG salt) | `admin_auth/password.rs:9-33` | ✅ Reuse as-is |
| TOTP RFC 6238 + replay guard + constant-time | `admin_auth/totp.rs:18-175` | ✅ Reuse as-is |
| Recovery codes (gen + hash) | `admin_auth/totp.rs:191-209` | ◐ Generated, **never consumable at login** |
| HMAC-bound server-side sessions, Redis fleet-wide | `admin_auth/session.rs:30-224`, `accept.rs:457` | ✅ Reuse; needs `user_id` field |
| Dual idle/absolute TTL + sliding window | `session.rs:55-57,181-187` | ✅ Reuse |
| CSRF double-submit | `admin_auth/csrf.rs:14-38` | ✅ Reuse |
| The 7-step gate (IP allowlist→bearer→session→CSRF) | `admin_auth_middleware.rs:81-200` | ✅ Reuse; RBAC slots at step 6b |
| Session→identity resolution | `admin_auth_middleware.rs:382-399` | ⛔ Returns fixed `admin`/`FULL` — **replace** |
| `authenticate` / `logout` orchestration | `api/login.rs:145-318,324` | ◐ Extend for multi-user lookup |
| Password-change logic + session-invalidation | `api/admin.rs:42-87` | ◐ Implemented + tested, **no HTTP route** |
| Service-account bearer tokens + read/write scopes | `admin_auth_middleware.rs:357-380`, `config.rs:5203-5209` | ✅ Only existing multi-principal mechanism |
| Login rate-limit + lockout + backoff | `admin_auth/rate_limit.rs:31-174` | ⚠️ **Per-node in-memory** — not Redis, bypassable across cluster |
| Hard-coded admin identity | `accept.rs:466-468`, `api/login.rs:106-128` | ⛔ Replace with user store |
| Committed default creds | `waf.yaml:422`, `dev.yaml:485`, `cluster-b.yaml:23` | ⛔ Remove + forced first-boot rotation |
| Auth docs | `docs/control-plane/dashboard-auth.md` | ◐ "v1 = ONE admin"; update per phase |

**Dormant-but-built (zero new logic to wire):** `handle_password_change` (`api/admin.rs:42`), `BreakGlass::enable/disable`, dashboard `SessionStore::revoke`, `verify_recovery_code`, `provisioning_uri` for in-dashboard TOTP enrollment. All have routes that are GET-only or absent (`admin_get.rs:923-928`).

## 3. Scope

**In scope:** control-plane admin identity — self-service hardening, multi-user account store, human RBAC, per-user audit, dashboard SSO (OIDC).
**Out of scope (this plan):** data-plane `auth/*`; SAML and SCIM (deferred, §10); multi-tenancy / multiple isolated accounts (single-tenant fleet stays the model); changing the public-HTTP transport contract.

## 4. Design

Phases are independently shippable; each replaces the model below it without a flag-day.

### 4.0 — Storage, durability & dependencies (no new DB; not blocked by etcd)

**No new datastore.** Identity rides the seams that already exist; there are two,
and the split matters:

Each datum is stored by **data class against a trait**, never against Redis
directly — this is what makes the storage backend swappable and the etcd-order
question a non-issue (see below):

| Data | Class | Seam / trait | Precedent | Post-etcd home |
| --- | --- | --- | --- | --- |
| **Users, roles, SSO config** | declarative config | the **config doc** (`config:waf:doc`) via `ConfigStore` | `service_accounts` already live in `DashboardAuthConfig` (`config.rs:5203`) — users extend the exact same pattern: CAS, fleet-wide convergence, hot-reload | **etcd** (rides the config plane) |
| **Recovery-code-consumed / per-user runtime flags** | durable, low-write | **`control:waf:*`** runtime namespace | `redis-interim-durability` puts incidents/risk here | **etcd** (low-write, fine) |
| **Sessions** (TTL'd bearer records) | ephemeral w/ TTL | **`StateBackend`** | sessions already use it (`accept.rs:457`) | **stays Redis** |
| **Login lockout / rate-limit counters** (P1) | ephemeral counters | **`StateBackend`** | mirrors `g:rl:*` | **stays Redis** |

So adding users = extending an existing config struct + a few `control:waf:*`
keys + reusing the session/counter `StateBackend`. No SQL, no second infra
dependency — consistent with [[project_cache_l2_single_node]] and the
"don't add infra until a tier outgrows it" stance across the `future/` plans.

**Not blocked by [[config-etcd-source-of-truth]], and order-independent either
way.** That plan splits one trait into two — a narrow `ConfigBackend` (→ etcd:
the config doc + `control:waf:*`) and the hot `StateBackend` (stays Redis) — and
swaps *implementors*, not call-sites. Because identity is stored **through those
seams by class** (config-class → config doc; ephemeral → `StateBackend`):

- **etcd first:** the `ConfigBackend`/`StateBackend` split already exists at the
  type level, so identity slots into pre-separated seams — the compiler enforces
  config-class data onto `ConfigBackend`, ephemeral onto `StateBackend`. **No
  rework; the easier direction.**
- **this plan first:** identity lives *inside* `config:waf:doc`, so etcd's own
  P1 trait-extraction and P3 doc-copy migration sweep users/roles along
  automatically — nothing identity-specific to migrate. Sessions/counters were
  already on `StateBackend`, which etcd doesn't touch.

The one rule to hold in either order: **don't park high-frequency state on the
config plane** — the data-class table above is the contract. Honor the
file-vs-doc authority rule [[project_config_plane_doc_vs_file]] and the
apply-side reload guard [[project_apply_and_swap_helper_guard]] regardless.

**The real prerequisite is durability, and it's already met.** `PREREQ-A` (the
Redis `/data` volume, shipped 2026-06-23 per `redis-interim-durability.md` §5) is
load-bearing here: if user records live only in an unmounted Redis, a
`docker compose down` or wipe erases **every admin account → permanent lockout**.
With the volume mounted this is closed; the plan must still wire the
`reset_state` contract so a state wipe does **not** delete identity (identity is
durable config, not ephemeral `g:*` — it stays under `control:waf:*`/config doc,
which `EPHEMERAL_PATTERNS` already excludes, `redis.rs:699-705`).

**Secret management — only P5 needs it.** P1–P4 persist **argon2id hashes and
HMAC-derived material** (safe at rest); no plaintext secret handling required.
The one real gap is **P5's OIDC `client_secret`** (a live plaintext credential),
which wants the `${secret:...}` indirection that the `_ref` config fields
document (`config/REFERENCE.md`) but that is **not actually applied** to
`password_hash_ref`/`csrf_secret_ref` at the auth boot path today (consumed as
literals — `accept.rs:469`). P5 therefore carries a small dependency: wire a
real secret resolver for at least the OIDC client secret (env-var indirection is
an acceptable v1; a full secret-manager backend is deferred). This is a gap, not
a separate blocking plan.

### 4.1 — P1: Self-service hardening (single-admin model, no data-model change)

Pure wiring + secret hygiene. Ships on the existing one-admin model.

- **Wire the dormant mutating endpoints** behind the gate (session + CSRF + `write` scope already enforced at `admin_auth_middleware.rs:148-200`):
  - `POST /api/admin/password` → existing `handle_password_change` (`api/admin.rs:42`); on success invalidate *other* sessions via the existing `invalidate_sessions` closure.
  - `POST /api/admin/totp/enroll` + `/confirm` → `provisioning_uri` + first-code verify; persist secret to the config doc (not YAML file — see [[project_config_plane_doc_vs_file]]).
  - `DELETE /api/admin/sessions/{id}` → dashboard `SessionStore::revoke`.
  - `POST /api/admin/break-glass` → `BreakGlass::enable/disable`.
- **Recovery-code login path** — wire `verify_recovery_code` as a TOTP fallback in `authenticate` (`login.rs:216-268`); consume-once.
- **Fleet-wide rate limiting** — move `LoginRateLimiter` counters from per-node `Mutex<HashMap>` (`rate_limit.rs:86-87`) to the Redis `StateBackend` already used by sessions, so lockout can't be sidestepped by hitting another cluster node and survives restart. Keep the in-memory path as the single-node fallback.
- **Kill committed defaults** — remove the baked `aegis-test-1234` hash and weak `csrf_secret` from `waf.yaml`/`dev.yaml`/`cluster-b.yaml`. Empty `password_hash_ref` already disables login (`accept.rs:435-441`); add a **first-boot setup token** (printed once to stdout/logs) that forces an initial password + TOTP enrollment before the dashboard unlocks.

### 4.2 — P2: Multi-user account store

Replace the hard-coded admin with a real, fleet-shared user collection.

- **Storage** — Redis hash `admin:users:{username}` in the existing `StateBackend` (same backend as sessions; no new infra — consistent with [[project_cache_l2_single_node]]). Record: `{username, password_hash (argon2id), totp_secret_b32?, totp_enabled, recovery_hashes[], roles[], disabled, created_at, password_changed_at}`. Seeded on first boot from the setup token (P1) → becomes the first SuperAdmin.
- **`authenticate` lookup** — replace the `req.user == admin.user` equality (`login.rs:193`) with a store lookup; **keep `dummy_verify`** (`password.rs:61`) for the unknown-user branch so timing stays flat and user-enumeration defense (already tested, `login.rs` matrix) holds.
- **`SessionRecord` gains `user_id`** (`session.rs:30-38`) — HMAC already covers stored fields, so add `user_id` to the signed tuple. This is the change the existing comment at `middleware:389-393` ("no `user_id` until RBAC lands") anticipates.
- **CRUD endpoints** (SuperAdmin-only, lands with P3 roles): `GET/POST /api/admin/users`, `PATCH/DELETE /api/admin/users/{username}`, disable/enable, force-rotate.

### 4.3 — P3: Human RBAC

- **Roles** (account-scoped, fail-closed — undefined ⇒ no access, per Cloudflare's model): `Reader` (GET dashboards/config, no mutations), `Operator` (mode/risk/rule mutations, no user mgmt), `Admin` (+ config publish, service accounts), `SuperAdmin` (+ user mgmt, break-glass). Multiple roles per user allowed; effective permission = union.
- **Enforcement** — extend the existing `Scopes` bitset (`middleware:52-66`, today only `read`/`write` for service accounts) into a permission set, and replace the fixed `Scopes::FULL` in `try_session_auth` (`middleware:394-398`) with the logged-in user's resolved permissions. Per-route permission requirement declared where routes are registered. Service-account scopes map onto the same permission lattice.
- **Config** — role definitions are code constants (not config) in v1 to avoid a privilege-escalation config surface; custom roles are §10 deferred.

### 4.4 — P4: Per-user audit

- The audit actor is already spoof-protected (`X-Actor` stripped, `middleware:294`) and `is_service_account` is flagged (`middleware:43-49`). Now that the actor is a real `user_id`, emit structured auth events — `login.success/failure`, `logout`, `totp.fail`, `lockout`, `password.change`, `user.create/disable`, `role.grant`, `break_glass` — into the existing event pipeline, queryable in the dashboard. Aligns with the durable event store in [[security-analytics-and-reporting]] — reuse that sink rather than a parallel one.

### 4.5 — P5: Dashboard SSO (OIDC)

- **OIDC Relying-Party for the *dashboard*** — note the data plane already has an OIDC-RP implementation (`auth/oidc_rp.rs`) to study/port, but this is a *separate* control-plane login flow. Authorization-code + PKCE against the customer IdP; on callback, map IdP claims → local user (JIT provision if enabled) → mint the *same* HMAC session cookie (P2 sessions are unchanged, so MFA/lockout/audit all keep working).
- **Role mapping** — IdP group/claim → local roles (P3), configurable. Local password login stays available as break-glass (gated by `BreakGlass`).
- **Config** — new `dashboard_auth.oidc` block (issuer, client_id, client_secret ref, claim mappings, `jit_provisioning`, allowed domains). Goes in the config doc; honor the file-vs-doc authority rule [[project_config_plane_doc_vs_file]] and the apply-side reload wiring guard [[project_apply_and_swap_helper_guard]] so it converges fleet-wide and doesn't silently go node-local-until-restart.

### Cross-cutting: hot-reload, dashboard, docs, tests

- Every new config surface (`dashboard_auth.users` seed policy, `oidc`) must be wired into **both** the cluster config watcher and the file watcher apply paths — the structural guard test from [[project_apply_and_swap_helper_guard]] is the safety net; add the new sections to it.
- Dashboard: a Settings → **Users & Access** page (users, roles, sessions, SSO config) + self-service **Account** page (change password, enroll TOTP, view/revoke own sessions). Matches the deferred items in `plans/archive/dashboard-redesign-early-brief/pages/M10-settings.md`.
- Update `docs/control-plane/dashboard-auth.md` and `dashboard.md` per phase; create the long-referenced `docs/future/rbac-sso.md` → fold into `docs/control-plane/` once shipped.

## 5. Risks / open decisions

1. **Lockout DoS via Redis-wide rate limit (P1)** — fleet-wide per-user lockout means an attacker who knows a username can lock a real operator out across the whole fleet. *Mitigation:* keep per-IP and per-user limits independent (already separate, `rate_limit.rs:31-34`); never lock the last-enabled SuperAdmin; break-glass local login bypasses lockout under MFA.
2. **First-boot setup token handling (P1)** — printing a token to logs on a public-HTTP box. *Mitigation:* one-time, short-TTL, single-use, invalidated the instant the first SuperAdmin is created; document the loopback/SSH-tunnel enrollment path ([[project_control_plane_loopback_only]]).
3. **Session-HMAC migration (P2)** — adding `user_id` to the signed tuple invalidates in-flight sessions on deploy. *Mitigation:* acceptable (forces re-login once); version the HMAC input so old cookies fail closed, not open.
4. **Removing committed defaults breaks dev/CI/bench (P1)** — many flows assume `admin`/`aegis-test-1234`. *Mitigation:* dev/test configs use an explicit, clearly-named *test* hash via env, not the production default; update Makefile `run-dev`, QUICKSTART, bench harness, and the e2e recipe ([[feedback_e2e_docker_cleanup]]).
5. **The big one — RBAC enforcement gaps.** A missed route = privilege escalation. *Mitigation:* default-deny — routes without a declared permission requirement are rejected, not allowed; a coverage test enumerates every `/api/*` route and asserts each declares a permission (mirror the structural guard pattern).
6. **OIDC on plain HTTP (P5)** — auth-code flow over public HTTP behind the committee contract. *Mitigation:* PKCE mandatory; `state`+nonce; document that TLS termination is expected upstream of the public listener; SSO is opt-in.

## 6. Effort

- P1 self-service hardening — **S/M** (mostly wiring built+tested logic; the real work is fleet-wide rate-limit migration + dev/CI default-credential fallout).
- P2 user store — **M**.
- P3 RBAC — **M** (the lattice + default-deny route coverage is the careful part).
- P4 per-user audit — **S** (reuses [[security-analytics-and-reporting]] sink).
- P5 OIDC SSO — **M/L** (new login flow, IdP integration testing).

## 7. Phasing

`P1 self-service hardening` → `P2 multi-user store` → `P3 human RBAC` → `P4 per-user audit` → `P5 dashboard OIDC SSO`. P1 ships standalone and is worth doing **regardless** of the rest (it closes the committed-default-creds and dormant-endpoint gaps). P2 is the pivot; P3–P5 build on it. SAML/SCIM/custom-roles are §10.

## 8. Tests

- **P1:** password-change route invalidates other sessions but not self; TOTP enroll→confirm round-trip; recovery-code consumes once then fails; rate-limiter lockout observed from a *second* simulated node (fleet-wide); empty default config → login disabled + setup-token gate; user-enumeration timing still flat after store lookup.
- **P2:** create/disable/delete user; disabled user cannot login; unknown user hits `dummy_verify` (timing); session `user_id` survives HMAC validate; old-version cookie fails closed.
- **P3:** Reader blocked from every mutation route; Operator blocked from user-mgmt; route-coverage test asserts every `/api/*` route declares a permission (default-deny); multi-role union.
- **P4:** each auth event emits with correct `user_id` + spoof-proof actor; service-account events flagged.
- **P5:** OIDC code+PKCE happy path mints a valid session; claim→role mapping; JIT provision on/off; local break-glass still works when SSO configured; `state`/nonce mismatch rejected.
- Keep the RFC 6238 / argon2 / CSRF / session unit suites green throughout.

## 9. Out of scope

Data-plane `auth/*`; transport/cookie posture changes (committee contract); multi-tenancy (multiple isolated accounts); changing service-account bearer mechanics beyond mapping them onto the new permission lattice.

## 10. Deferred (promote on demand)

- **SAML** — only if an enterprise IdP can't do OIDC; OIDC covers the modern majority.
- **SCIM** — automated leaver/mover provisioning; enterprise build-order says last, only when a customer explicitly asks.
- **Custom / config-defined roles** — v1 ships fixed role constants to avoid a privilege-escalation config surface.
- **Per-user/passkey WebAuthn** — stronger than TOTP; revisit after P3.

## 11. Follow-up

Per `plans/README.md` lifecycle convention, slot this onto a tier in `world-class-waf-roadmap.md` (enterprise-readiness/foundation, alongside the operational `future/` track) when promoted from drafted → active — confirm placement with Nico first.
