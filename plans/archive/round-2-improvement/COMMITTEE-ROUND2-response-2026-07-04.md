# Committee Round 2 — verified response & plan index

> **Status:** Drafted 2026-07-04; **updated 2026-07-05** — first delivery wave shipped, round-3 scope
> set. Every committee claim was re-verified against the codebase before planning (file:line evidence
> in the linked plans).
> **Team assignment & schedule:** [TEAM-PLAN-round2-3-members-2026-07.vi.md](../round-2-improvement-vi/TEAM-PLAN-round2-3-members-2026-07.vi.md) (tiếng Việt).
> **Bản dịch tiếng Việt:** [COMMITTEE-ROUND2-response-2026-07-04.vi.md](../round-2-improvement-vi/COMMITTEE-ROUND2-response-2026-07-04.vi.md) — mọi bản dịch nằm trong `round-2-improvement-vi/`.

## 0. Delivered so far (2026-07-05) · what's next

**Shipped & merged to `develop`** (the "everything else" lane — one owner, RED-first, reviewed):
- 🔴3 **Placeholder endpoints** — all 7 dispositioned (removed or completed) + CI route guard. Plan **COMPLETE**, archived.
- 🟡3 **Audit gaps + risk-decay caveats** — login/logout/`reset_state` audit events, drop metric, strike-block-survives-idle, saturation observability, decay evidence pack. Plan **COMPLETE**, archived.
- 🟡4 **Egress** — EG-1 design doc delivered (awaiting owner review; gates EG-2/EG-3 code).
- 🟡5 **Ops validation** — runbook delivered; drills need a live fleet (scheduled).

**Round-3 scope (owner decisions, 2026-07-05):**
1. **🔴1 admin-mTLS default — DROPPED.** We will **not** build mTLS-by-default on the admin listener.
   Instead the next round **validates the already-shipped `zero_trust` / mTLS feature** end-to-end
   (upstream + downstream mTLS, cert-swap, SAN allow-list) via the ops-validation drills. The
   admin-mTLS-default plan is **deferred, not deleted** — see §2.1.
2. **🔴2 2FA — YES, expanded.** Enforce a second factor **with the Google Authenticator app**
   (`otpauth://` QR enrollment) **and support multiple admin accounts** (today there is exactly one
   admin identity). Scope added to the 2FA plan.
3. **🟡1 detection accuracy — measure then improve.** Establish the **current FP metric** (new
   baseline plan) and then reduce it; land the recon/canary hardening in parallel.

**Round-3 assignment** (supersedes the round-2 3-member split for these tracks):

| Owner | Track | Plan |
|---|---|---|
| **L-Tester member** | 🔴2 2FA — Google Authenticator + multiple admin accounts | [FEAT-2fa-enforcement-2026-07.md](FEAT-2fa-enforcement-2026-07.md) |
| **S-Tester member** | FP — measure current FP baseline, then reduce it | [PLAN-fp-baseline-measurement-2026-07.md](PLAN-fp-baseline-measurement-2026-07.md) → [IMPROVE-detection-fp-tuning-2026-07.md](IMPROVE-detection-fp-tuning-2026-07.md) |
| **Nico** | Recon detection hardening + canary seeding; review/merge; zero-trust/mTLS validation coordination | [IMPROVE-recon-detection-and-canary-2026-07.md](IMPROVE-recon-detection-and-canary-2026-07.md) |

---

## 1. Verification verdicts (claim by claim)

| # | Committee claim | Verdict | Evidence (summary) | Plan |
|---|---|---|---|---|
| 🔴1 | mTLS implemented but disabled by default for admin | **CONFIRMED — worse than stated** · **DROPPED for round 3** (validate zero-trust/mTLS instead — §2.1) | `zero_trust.downstream.apply_to` *defaults* to `[Admin]` (`config.rs:4299-4300`) but the Admin scope is **never consumed** — only `Data` is wired (`run.rs:1195-1210`). The admin TLS acceptor is built `with_no_client_auth()` (`run.rs:2177-2185`). | [FEAT-admin-mtls-default-2026-07.md](FEAT-admin-mtls-default-2026-07.md) (deferred) |
| 🔴2 | 2FA not enabled / not enforced | **CONFIRMED** · **round-3 scope: L-Tester** | `totp_enabled` defaults `false` (`config.rs:6131`); no `require_totp` flag exists; password-only login fully supported. Recovery codes printed at enrollment but **not verifiable at login**. Single admin identity today — round 3 adds **multiple admin accounts** + **Google Authenticator** QR enrollment. | [FEAT-2fa-enforcement-2026-07.md](FEAT-2fa-enforcement-2026-07.md) |
| 🔴3 | Placeholder endpoints (auth-gated, no business logic) | ✅ **COMPLETE 2026-07-05** — all 7 dispositioned + CI guard | `/api/threat-intel/feeds`, `/api/gitops/status`, `/api/audit/witness`, `render_cert_renew` **removed**; `/api/analytics/query` (real Prometheus proxy), `/api/cold-tier` (per-sink delivery), `/api/geoip/status` (real `indicator_count`) **completed**. | [FEAT-placeholder-endpoints-cleanup-2026-07.md](../../issues/archived/FEAT-placeholder-endpoints-cleanup-2026-07.md) (archived) |
| 🟡1 | Improve detection accuracy / reduce FPs | **VALID — round-3 scope: S-Tester (FP) + Nico (recon)** | `enumeration` + `behavior_analyzer` default-OFF pending FP tuning. Recon report's "263 paths bypass" headline real, but the cause is low-confidence scoring (recon=25 < block=70), not the regex bypasses it claims — fix via canary seeding + tiered scoring + the 7 genuinely-missing signatures. Round 3: **measure the current FP baseline first**, then reduce; recon/canary in parallel. | [PLAN-fp-baseline-measurement-2026-07.md](PLAN-fp-baseline-measurement-2026-07.md) · [IMPROVE-detection-fp-tuning-2026-07.md](IMPROVE-detection-fp-tuning-2026-07.md) · [IMPROVE-recon-detection-and-canary-2026-07.md](IMPROVE-recon-detection-and-canary-2026-07.md) |
| 🟡2 | Dashboard usability | **GENERIC — needs specifics** | Large UX passes already shipped (scope badges, node selector, timeseries widget, risk-key pivot, SLO health page). See §3 below. | §3 of this doc |
| 🟡3 | Verify audit logging + risk decay | ✅ **COMPLETE 2026-07-05** | Risk decay was already **fully implemented** (evidence pack shipped). Audit gaps **fixed**: login/logout/`reset_state` events, drop metric, decay caveats A/B/C. | [FEAT-audit-coverage-gaps-2026-07.md](../../issues/archived/FEAT-audit-coverage-gaps-2026-07.md) (archived) · [EVIDENCE-decay-and-audit-2026-07.md](EVIDENCE-decay-and-audit-2026-07.md) |
| 🟡4 | Egress + internal observability | ⏳ **EG-1 design doc delivered** (awaiting owner review; gates EG-2/EG-3) | Response-direction inspection partially exists (response-outcome channel, AI response filter); true egress/internal-flow monitoring does not. | [FEAT-egress-internal-observability-2026-07.md](../../issues/FEAT-egress-internal-observability-2026-07.md) · [DESIGN-EG1-egress-response-inspection-2026-07.md](DESIGN-EG1-egress-response-inspection-2026-07.md) |
| 🟡5 | Validate under real operating conditions | ⏳ **Runbook delivered; drills need a live fleet** | SLO/alerting manual smoke was never run; failure/recovery drills ad-hoc. Runbook now also carries the **zero-trust/mTLS cert-swap drill** (replaces the dropped 🔴1). | [PLAN-ops-validation-realistic-2026-07.md](../../issues/PLAN-ops-validation-realistic-2026-07.md) · [`docs/ops/validation-runbook.md`](../../../docs/ops/validation-runbook.md) |
| 🟡6 | Focus on intent of requirements | **PROCESS NOTE** | See §4. | — |

## 2. Decisions (resolved 2026-07-05)

### 2.1 admin-mTLS default — **DROPPED for round 3; validate zero-trust/mTLS instead**
The round-1 vs round-2 transport contradiction (round 1 mandated public plain-HTTP admin; round 2
asked for mTLS-by-default) is **resolved by not building admin-mTLS-default this round.** Rationale:
the admin channel is already mitigated (TOTP — see 🔴2 — + password rotation + fail2ban + IP
allow-list), and the higher-value move is to **prove the mTLS machinery we already shipped actually
works** rather than bolt it onto a second listener.
- `FEAT-admin-mtls-default-2026-07.md` is **deferred, not deleted** — the "Admin scope is a silent
  no-op" finding stands and is worth fixing later.
- The `project_admin_public_http_contract` memory **stays valid** (round 1 not superseded).
- Instead: the ops-validation runbook (🟡5) gains a **zero-trust / mTLS end-to-end drill** — upstream
  + downstream mTLS handshake, unknown-CA rejection, SAN allow-list, hot cert-swap, expiry alert.
  Nico coordinates; folds into OV-2/OV-3.

### 2.2 2FA — **YES, expanded** (owner, 2026-07-05)
Enforce a second factor **with the Google Authenticator app** (standard `otpauth://` TOTP —
`provisioning_uri` already emits a GA-compatible URI) and **support multiple admin accounts** (the
config carries a single admin identity today). Details in `FEAT-2fa-enforcement-2026-07.md` (TF-4
added). Owner: L-Tester member.

### 2.3 Detection accuracy — **measure the current FP metric first, then improve**
Split into a measurement deliverable (establish the baseline FP/TP numbers with a reproducible
harness) and the tuning work that consumes it. Owner: S-Tester member. Recon/canary hardening
(Nico) runs in parallel on the same corpus.

### 2.4 Placeholder endpoints — **RESOLVED (shipped).** analytics/query + cold-tier + geoip completed; the rest removed.

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

## 5. Sequencing

**Done (2026-07-05):** placeholder cleanup (🔴3) · audit gaps + decay (🟡3) · EG-1 design doc (🟡4) ·
OV runbook (🟡5).

**Round 3 (three parallel lanes, one owner each):**
1. **L-Tester — 2FA** (`TF-1…TF-4`): enforcement flag → escape hatches → **multiple admin accounts**
   → **Google Authenticator QR enrollment** → docs/evidence.
2. **S-Tester — FP**: `PLAN-fp-baseline-measurement` (establish the current metric) → then
   `IMPROVE-detection-fp-tuning` FP-2/FP-3 (reduce it, graduate the dormant detectors).
3. **Nico — recon/canary** (`RC-1…RC-5`): canary tripwires → tiered scoring → missing signatures;
   shares the S-Tester corpus. Plus: coordinate the **zero-trust/mTLS validation drill** and
   review/merge the other two lanes.

**Then (before round 3 review):** run the OV drills on a live fleet (all three) → evidence pack.

**Deferred (not this round):** admin-mTLS-default (§2.1), EG-2/EG-3 egress code (gated on EG-1 review).
