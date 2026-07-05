# FEAT — Recon detection hardening + canary-path seeding (implementation)

> **Type:** FEAT (from round-2 IMPROVE) · **Status:** 🔄 In progress — RC-1 MERGED to develop 2026-07-05 (PR #157) · **Owner: Nico**
> **Track ID prefix:** `RC-<1–5>` · **Source / verification record:**
> [IMPROVE-recon-detection-and-canary-2026-07.md](../future/round-2-improvement/IMPROVE-recon-detection-and-canary-2026-07.md)
> — **read its §1 before touching code**: the l-tester report's headline (263 recon paths pass from
> fresh IPs) is TRUE but its root-cause analysis (V1/V3/V4) is mostly WRONG; the real cause is
> low-confidence scoring (`recon::PATH = 25` < `challenge_at = 30`), not regex bypasses. Do not
> re-litigate.
> **Corpus dependency:** Wave B gates on the committed benign corpus from
> [PLAN-fp-baseline-measurement-2026-07.md](../future/round-2-improvement/PLAN-fp-baseline-measurement-2026-07.md)
> (FPM, S-Tester owned, ☐ not started as of 2026-07-05). Wave A is deliberately corpus-independent.

**Objective (intent, not letter):** raise real-world recon/secret-exposure blocking — especially
against *distributed* low-and-slow recon (one path per fresh IP, so per-key accumulation never
trips) — without inflating false positives. Levers: canary tripwires (single-hit block), tiered
scoring for never-legitimate paths, and closing the genuinely-missing signature families.

---

## Wave structure

| Wave | Items | Gate |
|---|---|---|
| **A — unblocked now** | RC-1, RC-5a, RC-5b, RC-3 | none (RC-3 ships with unit-test anchors only; corpus re-validation deferred) |
| **B — corpus-gated** | RC-2, RC-3 corpus re-validation, committee evidence | FPM-1/FPM-2 landed (committed benign corpus + harness) |
| **C — optional/last** | RC-4 | Waves A+B done; release-profile bench budget |

Each item = its own branch/PR, TDD RED-first, workspace zero-warning
([[feedback_test_suite_green_baseline]]).

---

## Wave A — unblocked now

### RC-1 — seed canary paths for never-legitimate routes · **S** · ✅ MERGED 2026-07-05 (PR #157)

Canary infra exists and is verified (2026-07-04): `detectors/canary.rs`, score 100 = single-hit
block at every tier (`scores.rs:446`), runtime-editable via `PUT /api/risk/canary-paths`
(full-replace, cap 256, durable). This item is **default config + tests only** — no detector code.

**Change:** ship a curated default `risk.canary_paths` and flip `detectors.canary.enabled: true`
in the default config. Both prerequisites currently default OFF/empty — both must be set.

**Curated set (zero legitimate callers — exact entries):**
`/.git/config`, `/.git/HEAD`, `/.env`, `/.aws/credentials`, `/.git-credentials`, `/id_rsa`,
`/wp-config.php`, `/terraform.tfstate`, `/actuator/heapdump`, `/actuator/env`, `/.ssh/id_rsa`,
`/server.key`. Consider a `/.git/*` subtree entry if the matcher supports it.

**Never canary** anything with legitimate traffic (`/actuator/health`, `/actuator/info`, any app
route). Canary is a hard block — a wrong entry is an outage.

**RED tests (write first, watch fail):**
- [x] For **each** curated path: single request from a **fresh IP** → 403 with reason `canary`.
- [x] Look-alike legit paths NOT blocked: `/actuator/health`, `/actuator/info`, `/environment`,
      `/gitlab`, `/id_rsa_setup_guide.html` (or similar near-misses per entry).
- [x] `detectors.canary.enabled: false` → curated path NOT blocked (toggle respected).
- [x] Config-validation/guard test: default config parses with the list present and enabled.

**Known limits (document in the PR, don't over-engineer):** canary matches **raw, case-sensitive**
path (`canary.rs:97-135`) — `%2egit` / `//`-prefixed variants slip through; acceptable for a
tripwire (recon scoring + RC-4 back it up). Linear scan, cap 256 — keep the list curated.

**Review follow-ups (rust-reviewer 2026-07-05, warning-level):**
- [ ] **Owner call — `/actuator/env` stays or goes:** reviewer flags Spring Boot Admin /
      config-refresh tooling that polls `/actuator/env` *through the WAF edge* as a plausible legit
      caller → permanent self-block of the org's own monitoring. Mitigated by the REFERENCE.md
      upgrade note + `canary_paths: []` opt-out + mask-persistence honoring pre-upgrade toggles;
      Nico decides keep vs drop before merge.
- [ ] Optional regression test: config-plane round-trip of the opt-out — seed `ConfigStore` with
      (a) a doc lacking `canary_paths` and (b) `canary_paths: []`, assert (a) re-seeds curated and
      (b) stays empty through `activate`/`canonicalize_active_doc`. Reviewer hand-traced this safe
      (text-level YAML merges never materialize the struct) but no test pins it.

### RC-5a — populate top-level `ip` in admin audit events (V9) · **S**

**Rescued item:** the source plan folded this into the audit plan's AU-1, but the fold-in never
happened — `FEAT-audit-coverage-gaps` is archived COMPLETE with no mention of it, and
`crates/aegis-control/src/audit/mod.rs:32` still hard-codes `client_ip: String::new()`
(verified 2026-07-05). This plan owns it now.

**Change:** `AdminChangeEntry::to_audit_event` populates `client_ip` with the actor's client IP
(today it's only buried at `fields.diff.after.value`).

**RED tests:**
- [ ] Unit test: `to_audit_event` on an entry with a known actor IP → event `client_ip` == that IP.
- [ ] Unit test: entry with no recorded IP → sensible fallback (empty or `unknown`), not a panic.

### RC-5b — document V7/V8 as working-as-designed (+ optional metric) · **S** · ✅ DONE (branch docs/rc5b-two-score-model)

- [x] Detection docs: short note explaining the two-score model (per-request SUM vs cumulative
      MAX+decay, [[feedback_two_score_model]]) and the dev XFF collapse (empty `trusted_proxies` →
      all local traffic keys to `127.0.0.1`, [[feedback_dev_xff_single_ip_gates]]) so the next
      black-box report doesn't re-misdiagnose. → `docs/security/risk-scoring.md` "Testing note"
      subsection (branch `docs/rc5b-two-score-model`).
- [x] Optional per-path detector-hit metric: **DECLINED** — per-path detection is already visible
      without a new metric: every fired detector is stamped in `X-WAF-Rule-Id` + audit `rule_id`
      even on allowed requests (documented in the same note). A separate counter would be redundant
      and pull code onto a docs-only branch; skip per YAGNI.

### RC-3 — close the genuinely-missing signatures · **S–M** · ✅ Wave A DONE (branch feat/rc3-recon-signatures)

**Decision (2026-07-05):** ships in Wave A protected by tight-anchor unit tests only; corpus
re-validation is a Wave B checkbox. Blast radius is bounded because these score `recon::PATH = 25`
(no single-hit block).

Add to `RECON_PATHS` (`recon.rs`), grouped as reviewable families:

| Family | Signatures |
|---|---|
| Secrets | `/id_rsa` (bare, no ext), `/.npmrc`, `/.git-credentials`, generic `(?:^\|/)secrets?\.(?:json\|txt\|ya?ml\|env\|config)` (currently only `.ya?ml`) |
| V2 real gaps | `/config.env`, `/aws.env` (bare `.env` preceded by a word — anchor tightly, must NOT match `*.environment`), `/wp-config.txt`; add `.backup\|.gz\|.zip` to the backup-suffix set |
| Exchange/ProxyShell | `/autodiscover/autodiscover\.json`, `/owa/auth/logon\.aspx`, `/Core/Skin/Login\.aspx` |
| WordPress | `/wp-json/` (at least abused `gravitysmtp` + `wp/v2/settings`), `wlwmanifest\.xml`, `/xmlrpc\.php` |
| Misc from the 263 | `/Jenkinsfile`, `jenkins.*config\.xml`, `/\.terraform/` |

Skip: `/.DS_Store`, `/.htaccess` (already present), `/.well-known/security.txt` (legit standard).

**RED tests — every addition, no exceptions:**
- [x] Raw-form positive unit test per signature (25 positives; [[project_ltester_decodes_dataplane_raw]] —
      detectors see raw percent-encoded paths; never validate via the Python harness).
- [x] Negative look-alike test per risky pattern (17 negatives): `.env` family does not match
      `*.environment`; `secrets` regex does not match `/secrets-rotation-guide.html`; webroot-archive
      pattern is backup-word-anchored so legit `/downloads/report.zip` + `/assets/app.js.gz` don't
      fire; Exchange `.json`-only (legit `autodiscover.xml` excluded); WordPress abused subpaths only
      (bare `/wp-json/` + `wp/v2/posts` excluded); bare `/config.xml` excluded (jenkins-anchored).
- [x] Existing recon test module stays green (251 recon tests; workspace 4854, zero warnings).
- [ ] **Deferred to Wave B:** benign-corpus negative run over all new signatures.

**Shipped 2026-07-05 (branch `feat/rc3-recon-signatures`).** Families added to `RECON_PATHS`:
Secrets (`/id_rsa`, `/.npmrc`, `/.git-credentials`, `secrets?.{json,txt,ya?ml,env,config}`),
V2 gaps (`word.env`, `/wp-config.txt`, `.backup` tail, backup-word-anchored archive suffixes),
Exchange (`autodiscover.json`, `owa/auth/logon.aspx`, `Core/Skin/Login.aspx`),
WordPress (`wp-json/{gravitysmtp,wp/v2/settings}`, `wlwmanifest.xml`, `xmlrpc.php`),
Misc (`Jenkinsfile`, jenkins-anchored `config.xml`, `.terraform/`).

---

## Wave B — corpus-gated · **BLOCKED on FPM-1/FPM-2**

Do not start until the S-Tester's committed benign corpus + harness exist. Measurement must happen
at the Rust `EvalContext` level on raw forms (FPM plan §2 traps).

### RC-2 — tiered recon scoring · **M**

The FP-averse `25` (`scores.rs:117`) is right for generic probes but too low for unambiguous
secret/RCE exposure.

- Introduce `recon::SENSITIVE` for the secret-exposure subset: credential files, private keys,
  `terraform.tfstate`, `/actuator/{heapdump,env,configprops}`, `wp-config.php`.
- **Start at 50 + log-only soak** (two hits still needed to block); any value ≥ `block_at = 70`
  (single-hit block) requires corpus evidence + owner sign-off — this is the FP knife-edge.
- Keep `recon::PATH = 25` for generic/ambiguous probes (`/phpinfo.php`, `/actuator` index, swagger).
- Mechanism: tag sensitive patterns with the higher score in the signature table (`scores.rs` +
  `recon.rs` pattern metadata) — no gate/threshold change, composes with existing accumulation.

**RED tests:**
- [ ] Sensitive-tier path from fresh IP reaches the intended verdict at the chosen score.
- [ ] Generic probe still allowed single-hit (tier separation holds).
- [ ] Corpus gate: sensitive tier fires zero times on the benign corpus.
- [ ] Log-only soak evidence recorded before any single-hit-block score goes live.

### RC-3 corpus re-validation · **S**

- [ ] Re-run all Wave A RC-3 signatures against the committed benign corpus; fix or tighten any
      that fire. This closes the deferred checkbox from Wave A.

### Committee evidence · **S**

- [ ] Before/after recon block rate on the 263-path replay from fresh IPs (the committee-facing
      number). Replay must respect the raw-form trap — measure at the data plane, not through a
      decoding client.

---

## Wave C — optional/last

### RC-4 — path normalization for matching (defense-in-depth) · **M**

- Collapse `//`→`/`, resolve `.`/`..`, and match a **percent-decoded copy in addition to** the raw
  form — never replacing raw (raw is the contract for other detectors,
  [[project_hyper_normalizes_framing]], [[project_ltester_decodes_dataplane_raw]]).
- Land as a shared normalized-view helper the detectors read alongside `origin_form_uri` — touches
  hot-path shared plumbing, hence last.

**RED tests:**
- [ ] `//x`, `/./x`, `%2e`-encoded variants normalize to the canonical match.
- [ ] Raw path still available/unchanged for other detectors.
- [ ] Release-profile bench delta within budget (LT-P1 profile) — bench gate per PR.

---

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | Canary false block (a path with real traffic) = outage | curated never-legit list only; look-alike negative tests; exact-match blast radius = the exact string; log-only shadow of the list first if unsure |
| HIGH | RC-2/RC-3 raise FP on benign traffic | RC-2 hard-gated on corpus + log-only soak; RC-3 Wave A limited to tight anchors + negative unit tests, corpus re-validated in Wave B |
| MEDIUM | RC-3 over-broad `.env`/`secrets` regex matches legit paths | tight anchors + negative look-alike tests; prefer specific over greedy |
| MEDIUM | RC-4 normalization perf on hot path | shared cached view, release-profile bench per PR; do last |
| LOW | Encoded/`//` evasion of canary | acknowledged tripwire limitation; recon scoring + RC-4 provide depth |

## Acceptance

- [x] RC-1: curated canary set shipped + toggle on by default; single-hit block from fresh IP
      proven per path; look-alike/legit-path negatives green. (PR #157, merged develop 2026-07-05;
      `/actuator/env` keep-vs-drop still an open owner call — shipped keeping it.)
- [ ] RC-5a: admin audit events carry the actor's real `client_ip` (V9 closed for real this time).
- [ ] RC-5b: V7/V8 documented as designed; optional per-path metric decided.
- [ ] RC-3 (Wave A): all families added with raw-form positive + negative unit tests.
- [ ] RC-2 (Wave B): sensitive tier corpus-gated with soak evidence.
- [ ] RC-3 (Wave B): corpus-clean.
- [ ] Committee-facing: before/after 263-path fresh-IP replay numbers.
- [ ] RC-4 (optional): normalized matching view, benched.
- [ ] Regression: existing recon tests green; workspace zero-warning throughout.

## Suggested PR slicing

1. `feat/rc1-canary-defaults` — RC-1 (tests + default config).
2. `fix/rc5a-audit-client-ip` — RC-5a.
3. `docs/rc5b-two-score-model` — RC-5b (+ metric if included).
4. `feat/rc3-recon-signatures` — RC-3 Wave A (may split secrets/exchange/wordpress if review size
   demands).
5. *(after FPM lands)* `feat/rc2-tiered-recon-scoring`, then corpus re-validation + evidence.
6. *(optional)* `feat/rc4-normalized-path-view`.
