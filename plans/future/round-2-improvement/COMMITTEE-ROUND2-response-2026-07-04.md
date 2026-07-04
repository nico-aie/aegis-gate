# Committee Round 2 — verified response & plan index

> **Status:** Drafted 2026-07-04 from the round-2 internal review. Every committee claim below was
> re-verified against the codebase before planning (file:line evidence in the linked plans).
> Nothing in this set is implemented yet — each linked plan waits for owner go-ahead.
> **Team assignment & schedule:** [TEAM-PLAN-round2-3-members-2026-07.vi.md](../round-2-improvement-vi/TEAM-PLAN-round2-3-members-2026-07.vi.md) (tiếng Việt).
> **Bản dịch tiếng Việt:** [COMMITTEE-ROUND2-response-2026-07-04.vi.md](../round-2-improvement-vi/COMMITTEE-ROUND2-response-2026-07-04.vi.md) — mọi bản dịch nằm trong `round-2-improvement-vi/`.

---

## 1. Verification verdicts (claim by claim)

| # | Committee claim | Verdict | Evidence (summary) | Plan |
|---|---|---|---|---|
| 🔴1 | mTLS implemented but disabled by default for admin | **CONFIRMED — worse than stated** | `zero_trust.downstream.apply_to` *defaults* to `[Admin]` (`config.rs:4299-4300`) but the Admin scope is **never consumed** — only `Data` is wired (`run.rs:1195-1210`). The admin TLS acceptor is built `with_no_client_auth()` (`run.rs:2177-2185`). So even an operator who configures admin mTLS today gets no client-cert check. | [FEAT-admin-mtls-default-2026-07.md](FEAT-admin-mtls-default-2026-07.md) |
| 🔴2 | 2FA not enabled / not enforced | **CONFIRMED** | `totp_enabled` defaults `false` (`config.rs:6131`); no `require_totp` flag exists; password-only login fully supported (`login.rs:215`, test `login_with_totp_disabled_ignores_totp_code`). Recovery codes are printed at enrollment but **not verifiable at login** (no storage field, zero callers of `verify_recovery_code`). Docs claim a `waf admin disable-totp` command that does not exist. | [FEAT-2fa-enforcement-2026-07.md](FEAT-2fa-enforcement-2026-07.md) |
| 🔴3 | Placeholder endpoints (auth-gated, no business logic) | **CONFIRMED — 7 concrete endpoints** | `/api/threat-intel/feeds` (hardcoded, no backing config), `/api/gitops/status` (module deleted), `/api/analytics/query` (503/empty shells), `/api/audit/witness` (schema-only, signing deleted), `/api/cold-tier` (`delivery:"unknown"` hardcoded), `render_cert_renew` (implemented but unrouted = dead), `/api/geoip/status` (`indicator_count:0` hardcoded). | [FEAT-placeholder-endpoints-cleanup-2026-07.md](../../issues/FEAT-placeholder-endpoints-cleanup-2026-07.md) |
| 🟡1 | Improve detection accuracy / reduce FPs | **VALID — matches known loose thread** | `enumeration` + `behavior_analyzer` shipped default-OFF pending FP tuning (untracked until now). Recon/secret-exposure coverage analyzed from the l-tester report: the "263 paths bypass" headline is real, but the cause is low-confidence scoring (recon=25 < block=70), not the regex bypasses the report claims (V1/V3/V4 FALSE) — fix via canary seeding + tiered scoring + the 7 genuinely-missing signatures. | [IMPROVE-detection-fp-tuning-2026-07.md](IMPROVE-detection-fp-tuning-2026-07.md) · [IMPROVE-recon-detection-and-canary-2026-07.md](IMPROVE-recon-detection-and-canary-2026-07.md) |
| 🟡2 | Dashboard usability | **GENERIC — needs specifics** | Large UX passes already shipped (scope badges, node selector, timeseries widget, risk-key pivot, SLO health page). See §3 below. | §3 of this doc |
| 🟡3 | Verify audit logging + risk decay | **SPLIT VERDICT** | Risk decay: **fully implemented** (linear trust recovery, default 30 pts/hr, decay-on-read, `tracker.rs:1054-1076`) — respond to committee with evidence. Audit logging: **real gaps** — login/logout/failed-login and control-plane `reset_state` emit **no** audit event; delivery is best-effort (fsync only on rotation/shutdown). | [FEAT-audit-coverage-gaps-2026-07.md](../../issues/FEAT-audit-coverage-gaps-2026-07.md) |
| 🟡4 | Egress + internal observability | **VALID — mostly greenfield** | Response-direction inspection partially exists (response-outcome channel, AI response filter); true egress/internal-flow monitoring does not. | [FEAT-egress-internal-observability-2026-07.md](../../issues/FEAT-egress-internal-observability-2026-07.md) |
| 🟡5 | Validate under real operating conditions | **VALID** | SLO/alerting manual smoke was never run; failure/recovery drills are ad-hoc. | [PLAN-ops-validation-realistic-2026-07.md](../../issues/PLAN-ops-validation-realistic-2026-07.md) |
| 🟡6 | Focus on intent of requirements | **PROCESS NOTE** | See §4. | — |

## 2. Decision points for the owner (blocking, decide before implementation)

1. **Round-1 vs round-2 transport contradiction.** Round 1 mandated public plain-HTTP admin
   (recorded as a hard contract in `plans/future/admin-accounts-rbac-sso.md` and
   `plans/issues/FEAT-admin-accounts-p1-self-service-hardening.md` guardrails). Round 2 now asks for
   **mTLS by default on admin** — which requires TLS on the admin listener. These cannot both hold.
   **Recommendation:** treat round 2 as superseding round 1; update the guardrail notes in both
   existing plans and the `project_admin_public_http_contract` memory when the mTLS plan starts.
2. **"Default on" semantics for admin mTLS.** True default-on with zero certs bricks first boot.
   The mTLS plan recommends a phased posture (wire → bootstrap tooling → flip default with a
   provisioning path). Pick the end-state: fail-closed default vs. required-when-CA-configured.
3. **Placeholder endpoints: complete vs remove.** Per-endpoint recommendations are in the cleanup
   plan; two (`analytics/query`, `cold-tier delivery`) have a cheap "complete" path, the rest
   should be removed.

## 3. 🟡2 Dashboard usability (kept here — needs committee specifics)

The comment is generic and much has already shipped (fleet-scope badges, degraded banners, node
selector, truthful window chips, TimeseriesChart, investigation pivot, explainable Health page).
Rather than guessing, run a structured pass and derive a concrete backlog:

- **Click-path audit** of the top 6 operator tasks (triage an attack, flip mode, edit a rule,
  investigate an IP, check fleet health, export a report) — count steps/dead-ends.
- **Consistency sweep**: naming (allow/bypass/whitelist), empty-state copy, error toasts,
  confirmation patterns for destructive actions.
- Fix the placeholder-backed UI tiles (threat-intel, gitops, witness) as part of 🔴3 — stale
  "coming soon" panels are themselves a usability finding.
- Timebox: 1 day audit → small-PR backlog. No dedicated plan file until the audit produces one.

## 4. 🟡6 Intent of requirements (process note)

Adopt for every remaining committee/contract item: state the **security objective** (not the
literal wording) at the top of each plan, and add an acceptance line "objective met, not just
letter" — e.g. mTLS's objective is *unauthenticated parties cannot reach the admin channel at
all*, so the plan must also cover the plain-HTTP fallback and `AEGIS_INSECURE_COOKIES`, not just
bolt a verifier onto TLS.

## 5. Suggested sequencing

1. **FEAT-2fa-enforcement** (small; extends already-planned AA-P1 in `plans/issues/`) — fastest 🔴 win.
2. **FEAT-admin-mtls-default** P1 (wire the Admin scope — rejects certless connections when configured).
3. **FEAT-placeholder-endpoints-cleanup** (small PRs, low risk, visible to committee).
4. **FEAT-audit-coverage-gaps** (login/reset_state events are cheap; do with #1).
5. mTLS P2/P3 (bootstrap tooling, default flip) + **IMPROVE-detection-fp-tuning**.
6. **PLAN-ops-validation** before round 3.
7. **FEAT-egress-internal-observability** — design-first, largest, last.
