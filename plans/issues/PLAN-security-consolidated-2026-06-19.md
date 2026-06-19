# PLAN — Consolidated security remediation (Redis hijack + admin lockout + host audit) 2026-06-19

- **Type:** PLAN (consolidation of 3 findings → one register → fix-all, split OPERATOR vs REPO)
- **Status:** 🟡 IN PROGRESS (2026-06-19). Incident contained. **R-1 + R-2 + R-6 shipped** to `develop`
  (PR #62, `fix/session-store-loud-failure-and-redis-hardening`): loud session-store failure (login 503),
  hardened `deploy/redis/redis.conf` (protected-mode + `rename-command REPLICAOF/SLAVEOF/CONFIG/MODULE/DEBUG`
  + `save`), dev compose loopback bind + optional auth, runbook hardening. Remaining REPO: R-1b, R-3, R-4, R-5,
  R-8, O-7. OPERATOR track (O-1, O-2, O-4…O-9 + secret rotation) outstanding on the box.
- **Supersedes / folds in:**
  - `plans/issues/PLAN-prod-redis-hijack-and-admin-lockout-2026-06-19.md` (Redis hijack + login loop; **now
    superseded by this doc** — its Parts B/C/D become R-* items here).
  - `plans/issues/security_audit_2026-06-19.md` (host/OS audit; C-1…C-3, H-1…H-5, M-1…M-4, L-*).
  - `skills/aegis-waf-tester/reports/findings/2026-06-19/crit-admin-login-redirect-loop.md` (the lockout symptom).
- **Already done this session (audit §399):** Redis re-bound `127.0.0.1:6379`; `REPLICAOF NO ONE`; 6 unused
  containers removed; ~1.5 GB reclaimed; WAF restarted, `/healthz/ready` 200. Forensics: **no follow-on
  compromise** (no SSH-key/cron/module tamper) — attacker only ran `REPLICAOF`.

---

## 0. One-paragraph synthesis

An internet-exposed, unauthenticated Redis (`0.0.0.0:6379`, no `requirepass`, `protected-mode` off behind a
non-loopback bind, permissive AWS SG) was hijacked via `REPLICAOF 175.24.232.83:24551` at **2026-06-18
23:25 UTC**, flipping it read-only and wiping the dataset (95 config versions gone). Read-only Redis →
**every WAF state write fails** → the admin `SessionStore::put_record` **silently swallows the error**
(`session.rs:101`) → login returns 200 + an unstored cookie → every `/api/*` 401s → **admin lockout**. The
host audit then surfaced the broader posture gaps the same exposure model implies. So the remediation is:
**(1) the repo makes silent-failure loud + ships hardened Redis/CI defaults so this can't recur, (2) operator
hardens the host (firewall, sshd, fail2ban, …) and adds compensating controls on the admin plane.**

> **Scope correction (2026-06-19, operator):** the admin dashboard being **public on `0.0.0.0:9443` over plain
> HTTP** is a **committee contract requirement for the hackathon, NOT a bug or config drift.** The committee
> must reach the admin UI publicly over HTTP. Therefore audit **C-3** is *re-scoped*: do **not** move admin to
> loopback or force TLS, and `AEGIS_INSECURE_COOKIES=1` (no `Secure` flag) is **required** over HTTP — both are
> accepted constraints. The Redis exposure is the actual bug; the admin-plane work becomes *compensating
> controls that function over plain HTTP* (TOTP, credential rotation, login rate-limit/fail2ban, optional
> committee-CIDR allowlist, short session TTL). The repo's loopback default still stands for non-committee
> deployments; the box's public bind is the contracted override.

---

## 1. Consolidated issue register

Severity → ID → owner. **OPERATOR** = action on the prod host (agent can't reach it; provides runbook).
**REPO** = code/config/CI change the agent implements here.

| ID | Sev | Issue | Source | Owner |
|----|-----|-------|--------|-------|
| **R-1** | CRIT | Read-only/down backend silently swallowed → admin lockout (`put_record` `let _ =`, login still 200) | login-loop + incident | ✅ **DONE** (PR #62) |
| **R-2** | CRIT | Redis ships with no auth / no `rename-command REPLICAOF/CONFIG` / publishes 6379 | incident + audit C-1/M-2 | ✅ **DONE** repo (PR #62); OPERATOR applies on box |
| **O-1** | CRIT | No host firewall; `0.0.0.0` services rely solely on AWS SG (audit **C-1**) | audit | **OPERATOR** |
| **O-2** | CRIT | `sshd PermitRootLogin yes` (audit **C-2**) | audit | **OPERATOR** |
| **O-3** | ~~CRIT~~ **ACCEPTED** | Admin plane public `0.0.0.0:9443` + `0.0.0.0/0` + HTTP + insecure cookies (audit **C-3**) — **committee contract requirement, NOT a bug.** Re-scoped to *compensating controls over HTTP* (O-9) | audit + operator | **ACCEPTED CONSTRAINT** |
| **O-9** | HIGH | Compensating controls for the contracted public-HTTP admin plane: **enable TOTP 2FA**, rotate the shared password, login rate-limit + fail2ban jail, optional committee-CIDR allowlist, short session TTL | derived from O-3 | **OPERATOR** (+ REPO: TOTP already supported) |
| **R-3** | HIGH | Cross-node session non-portability: `csrf_secret` drift → 401 loop even with healthy Redis; only a `warn!` at boot | login-loop §RootCause | **REPO** |
| **R-4** | HIGH | No `cargo audit` in CI (audit **H-5**) | audit | **REPO** |
| **O-4** | HIGH | No bruteforce protection / fail2ban (audit **H-1**) | audit | **OPERATOR** |
| **O-5** | HIGH | WAF `NoNewPrivs: 0`; no systemd sandboxing (audit **H-2**) | audit | **OPERATOR** |
| **O-6** | HIGH | journald volatile (no `/var/log/journal`) (audit **H-3**) | audit | **OPERATOR** |
| **O-7** | HIGH | `logs/audit/` 4.9 GB; retention not enforcing → disk-fill crash (audit **H-4**) | audit | **OPERATOR** + **REPO** (verify sweeper) |
| **R-5** | MED | Secrets inline in deployed `waf.yaml` (csrf_secret, argon2 hash) (audit **M-3**) — repo profiles use `${secret:...}` refs; box inlined | audit | **OPERATOR** (rotate→env ref) + **REPO** (verify profile refs) |
| **R-6** | MED | No Redis persistence/backup (`--save ""`) (audit **M-2**) | audit | ✅ **DONE** (PR #62; `save` in redis.conf) |
| **O-8** | MED | Stale `/etc/aegis-gate.env` secret sprawl (audit **M-1**) | audit | **OPERATOR** |
| **R-7** | ~~MED~~ **ACCEPTED** | `aegis_session` no `Secure` (AEGIS_INSECURE_COOKIES=1) (audit **M-4**) — **required** over the contracted HTTP admin plane; browsers drop `Secure` cookies on HTTP. Accepted; mitigated by O-9 (TOTP + short TTL) | audit | **ACCEPTED CONSTRAINT** |
| **R-8** | LOW | HAProxy `cluster_http` no session affinity (backstop for R-3) | login-loop §fix-3 | **REPO** (config) |

> Audit **L-1…L-12** are confirmed-good (key-only SSH, non-root WAF, `CAP_NET_BIND_SERVICE`-only, loopback
> control plane, hash-chained audit, etc.) — no action.

---

## 2. REPO track — what the agent implements (with tests)

### R-1 — Make a failed session write fail LOUD (the single highest-value fix)
*Files:* `crates/aegis-control/src/admin_auth/session.rs`, `crates/aegis-control/src/api/login.rs`.
- `put_record` (and `del_record`) return `Result<(), StoreError>` instead of swallowing `b.set`/`b.del`.
  `create()` propagates. The in-memory backend path stays infallible.
- `authenticate()` gains `LoginOutcome::StoreUnavailable` → **HTTP 503** (`"session store unavailable"`), so a
  read-only/down backend surfaces *at login*, not as a silent redirect loop.
- **TDD:** a failing/read-only backend mock → `create` returns `Err`, `authenticate` → `StoreUnavailable`;
  in-memory → unchanged `Ok`; all existing session/login tests stay green.

### R-1b — Surface backend write-health on readiness
*File:* `crates/aegis-control/src/health.rs`. `state_backend_up` is a read/ping check (stayed `true` against a
read-only replica). Add a `state_backend_writable` signal (cheap periodic write-probe or reflect observed write
failures) so `/healthz/ready` reports `degraded`. Report-only — consistent with the reported-not-gating posture.

### R-2 / R-6 — Hardened Redis config (ship secure defaults)
*Files:* new `deploy/redis/redis.conf` + `deploy/docker-compose*.yml`.
- `requirepass ${REDIS_PASSWORD}`; WAF `state.redis.urls` carry the password.
- `protected-mode yes`; bind private; keep compose publish at `127.0.0.1:6379` (already changed on box).
- `rename-command REPLICAOF ""` / `SLAVEOF ""` / `CONFIG ""` / `MODULE ""` / `DEBUG ""` (WAF needs none).
- `--save 900 1` (R-6 persistence) + document a `BGSAVE` offsite cron in the runbook.
- Update `HACKATHON-DEPLOY.md`/`HACKATHON-FLEET.md`: auth + private-bind + SG lockdown as an explicit checklist.

### R-3 — Cross-node session portability hardening
*Files:* `crates/aegis-proxy/src/accept.rs`, `crates/aegis-control/src/health.rs`.
- Boot **hard-fail** (not `warn!`) when `state.backend != in_memory` and `csrf_secret` empty/short (`accept.rs:406-418`).
- Emit a non-secret **`session_key_fp` = `blake3(session_key)[..8]`** at boot and on `/healthz/ready` →
  operators diff two nodes in one glance to catch `csrf_secret` drift.
- **TDD:** boot guard rejects empty-secret + redis backend; fingerprint stable per secret, differs across secrets.

### R-4 — `cargo audit` in CI
*File:* `.github/workflows/ci.yml`. Add a job: `cargo install cargo-audit && cargo audit` (fail on `RUSTSEC-*`,
explicit-waiver file for accepted advisories). Optionally `cargo deny check`.

### R-5 (repo half) — confirm prod profiles use secret refs
Verify `config/profiles/prod-*.yaml` keep `password_hash_ref`/`csrf_secret_ref` as `${secret:env:...}` (not
inline) and document that the **box must not inline them into `waf.yaml`**.

### R-8 — HAProxy session affinity backstop
*File:* `deploy/haproxy/haproxy.cfg`. Add `cookie aegis_session prefix` (or a stick-table on the session cookie)
to `backend cluster_http` so a session sticks to its minting node even if key sync regresses.

### O-7 (repo half) — confirm the audit-retention sweeper actually deletes
Trace the `audit.retention` sweeper; if it isn't pruning, fix it (the 4.9 GB is partly an operator logrotate
gap, partly a possible sweeper bug). Add a test for the prune path.

---

## 3. OPERATOR track — runbook (agent writes the checklist; operator executes on the box)

Ordered, each reversible, WAF stays up. (Verbatim commands in audit C-1/C-2/H-1/H-2/H-3/H-4 + incident A1–A5.)
1. **O-9 (compensating controls for the contracted public-HTTP admin plane — do NOT close it):**
   - `admin.dashboard_auth.totp_enabled: true` + enroll TOTP per operator (works over HTTP; biggest single win
     against the shared password + cookie-theft risk).
   - Rotate the shared `aegis-hackathon-2026` password (committee-known) to a per-operator credential.
   - fail2ban jail on `/admin/login` 401s (see O-4) — the WAF's 100/min/IP rate-limit amortises across IPs.
   - Optionally tighten `ip_allowlist` to the committee's CIDRs if they provide them (narrows exposure without
     breaking the public-HTTP contract).
   - Keep session TTLs short (already 30 m idle / 8 h absolute) to bound stolen-cookie validity.
   - **Accept & document**: cookie-on-the-wire exposure is inherent to the committee's HTTP contract (R-7).
2. **O-1** host firewall (firewalld/iptables default-DROP, allow `22000/80/443`/**`9443`** — `9443` stays OPEN
   per the committee contract) + **SG coordination** with SA team (scope `:9443` to committee CIDRs if provided).
3. **O-2** `PermitRootLogin no` (test in a second SSH session first).
4. **O-4** fail2ban (sshd jail on `:22000`; optional `/admin/login` jail off `waf_audit.log`).
5. **O-5** `NoNewPrivileges=yes` + systemd sandbox (or `setpriv --no-new-privs` in `run-staging.cmd`).
6. **O-6** persistent journald; **O-7** logrotate + trim `logs/audit/` now; **O-8** delete/rotate
   `/etc/aegis-gate.env`.
7. **Secret rotation** (incident A4): rotate `csrf_secret`, admin hash, zero-trust key, upstream creds, LLM key —
   distributed identically across nodes (rotating `csrf_secret` also invalidates stolen cookies).

---

## 4. Execution order (fix-all)

| Phase | Items | Owner | Why first |
|-------|-------|-------|-----------|
| **P0 (now)** | O-9 (TOTP + rotate password on the contracted public admin) + O-1 (firewall, `:9443` stays open) + SG | OPERATOR | compensate for the public-HTTP admin per contract |
| **P1** | **R-1** loud session-store failure + R-1b readiness | REPO (agent) | turn silent lockouts into clear errors |
| **P1** | **R-2/R-6** hardened Redis config | REPO + OPERATOR | prevent re-hijack + add backups |
| **P2** | R-3 boot-guard + key fingerprint; R-8 HAProxy affinity | REPO | cluster session safety |
| **P2** | O-2 sshd, O-4 fail2ban, O-5 NoNewPrivs | OPERATOR | host hardening |
| **P3** | R-4 cargo audit CI; R-5 profile refs; O-7 retention | REPO | supply-chain + durability |
| **P3** | O-6 journald, O-8 env cleanup, secret rotation | OPERATOR | forensics + sprawl |

## 5. Exit criteria
- Login → `/api/about` 10/10 on the cluster; a read-only/down backend makes **login 503** + `/healthz/ready`
  `degraded` (never a silent 200→401 loop).
- Redis: auth-required, private-bound, `REPLICAOF/CONFIG` renamed, persistence + offsite backup; AWS SG closed.
- Admin plane: stays public on HTTP per committee contract, **with compensating controls** — TOTP enabled,
  shared password rotated, fail2ban on `/admin/login`, short TTL (cookie-on-HTTP exposure accepted/documented).
- Host: firewall default-DROP, `PermitRootLogin no`, fail2ban, NoNewPrivs, persistent journal, audit retention.
- `cargo audit` green in CI; secrets via env refs, rotated; `aegis-security`/`aegis-control` suites green with
  new R-1/R-3 fixtures.

## 6. Risks / boundaries
- **OPERATOR items are not the agent's to run** — they're live prod ops on a contained-but-sensitive host; the
  operator has the shell. Agent owns REPO (code/config/CI) + the runbook text.
- R-1's 503-on-store-failure is a deliberate availability trade (clear retry beats silent lockout).
- Rotating `csrf_secret` logs everyone out (expected).
- The repo's admin default is loopback (`project_control_plane_loopback_only`), but for THIS deployment the
  **committee contract requires the admin plane public over HTTP** — that is an accepted constraint, not a bug;
  O-9 compensates within it. The loopback `/__waf_control/*` data-edge surface is unaffected and stays gated.
