# IMPROVE — Recon detection hardening + canary-path seeding

> **Type:** IMPROVE (from l-tester `CURRENT-STATE-FINDINGS.md`) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `RC-<1–5>` · **Sibling:** [IMPROVE-detection-fp-tuning-2026-07.md](IMPROVE-detection-fp-tuning-2026-07.md)
> (shares the benign/attack corpus harness — build it once, both plans use it).
> **Source report:** `tests/l-tester/reports/CURRENT-STATE-FINDINGS.md` — verified claim-by-claim against
> code 2026-07-04 (verdicts in §1). **Read §1 before touching code — most of the report's root-cause
> diagnosis is wrong even though its headline is right.**

**Objective (intent, not letter):** raise real-world recon/secret-exposure blocking without inflating
false positives — by (a) fixing the *actual* root cause (low-confidence scoring, not regex bypasses),
(b) closing the genuinely-missing signatures, and (c) seeding canary paths for never-legitimate routes
so a single probe blocks even from a fresh IP.

---

## 1. Report verification — what's true, what's not

The report's **empirical headline is TRUE**: replaying 263 recon paths, each from a fresh IP, all
returned an origin response (not blocked). But its **root-cause analysis (V1–V6) is mostly WRONG** —
classic l-tester trap ([[project_ltester_decodes_dataplane_raw]]): the harness reasoned from
black-box behavior, not the detector code.

| ID | Report claim | Verdict | Reality (evidence) |
|---|---|---|---|
| — | 263 recon paths allowed from a fresh IP | **TRUE (empirical)** | but the *cause* is scoring, not bypasses — see the box below |
| V1 | Directory-prefix bypass (`/backend/.git/config` passes) | **FALSE** | recon regexes are substring / `(?:^|/)`-anchored, not root-anchored; `/backend/.git/config` **matches** (`recon.rs:15-16,22`; test `env_in_subdir` `recon.rs:586`) |
| V2 | Suffix-mutation bypass (all `.bak/.old/~/.txt` evade) | **PARTIAL** | backup+tilde rules already catch `.bak/.old/.save/.swp/~` (`recon.rs:50,56`). **Real gaps:** `/config.env`, `/aws.env`, `/wp-config.txt`, and generic `.backup/.gz/.zip` |
| V3 | Case-change bypass (`/Admin/phpinfo.php` passes) | **FALSE** | every path regex carries `(?i)` (`recon.rs:15-196`); case is already handled |
| V4 | `/actuator/*` subtree not covered | **FALSE** | danger subtree explicitly enumerated (`recon.rs:114`) + bare index (`recon.rs:171`); `/actuator/env|heapdump|httptrace|threaddump|configprops` all match (tests `recon.rs:430-434`) |
| V5 | Missing signatures (11 listed) | **PARTIAL (7 of 11 real)** | genuinely absent: `/id_rsa`, `/.npmrc`, `/.git-credentials`, generic `/secrets.{json,txt,…}`, `/autodiscover/*`, `/owa/auth/logon.aspx`, `/wp-json/*`. Already present (report wrong): `/.aws/credentials` (`recon.rs:78`), `/private_key.pem` (`recon.rs:109`), `/.htpasswd` (`recon.rs:21`), `/wp-login.php` (`recon.rs:34`) |
| V6 | Double-slash not normalized | **PARTIAL** | no path normalization exists (TRUE, defense-in-depth gap) — but `//` does **not** defeat `(?:^|/)` anchors; the cited `wlwmanifest.xml`/`xmlrpc.php` pass because they have **no signature at all**, not because of `//` |
| V7 | Risk-score masks per-path gaps | **TRUE** | two-score model (cumulative MAX+decay vs per-request SUM); a source tripping any detector 2-3× hits `block_at=70` → every later request blocks as `risk-score` regardless of path (`data_plane.rs:1311-1345,1619-1687`). Fresh IP starts at 0 → passes |
| V8 | Allowed despite high `risk_score` from loopback = loopback trusted | **theory FALSE, obs TRUE** | no loopback trust anywhere. Real cause: dev `trusted_proxies` empty → XFF ignored → all local traffic keys to `127.0.0.1` (`xff.rs:18-21`, [[feedback_dev_xff_single_ip_gates]]); audit `risk_score` is the *accumulated* score, verdict uses tier thresholds (65 = challenge band, allowed when challenges off) |
| V9 | Admin audit events have empty top-level `ip` | **TRUE** | `AdminChangeEntry::to_audit_event` hard-codes `client_ip: String::new()` (`audit/mod.rs:33`); real IP only at `fields.diff.after.value` |

> ### 🔑 The actual root cause (why 263 paths pass from a fresh IP)
> The recon detector **matches** these paths — it just scores them **25** (`scores.rs:117`,
> `recon::PATH = 25`), which is *below* `challenge_at = 30` and far below `block_at = 70`
> (`config.rs:4863-4873`). So **one** recon probe from a fresh IP scores 25 → **Allow** by design
> (low-confidence, FP-averse). It takes 2-3 recon hits from the *same* key to accumulate past 70 and
> block. Against a real scanner (many paths, one IP) the WAF blocks correctly via accumulation; the
> gap is **distributed low-and-slow recon** — each path from a different IP (the prod logs show GCP
> `34.x/35.x` ranges, ~29 hits each across many IPs), so no single key accumulates. That is a real
> gap, but the fix is **scoring + canary tripwires**, not "fix the prefix/case/subtree bypass" (which
> don't exist).

## 2. The three levers (in priority order)

1. **Confidence/scoring** (RC-2) — the real cause. Split recon into tiers: never-legitimate
   *secret/RCE exposure* paths block harder; generic probes stay low.
2. **Canary tripwires** (RC-1) — instant single-hit block (score 100) for a curated never-legit set,
   defeating the distributed-recon evasion. Fastest win, lowest risk, no regex work.
3. **Coverage** (RC-3) — add the 7 genuinely-missing signature families + the 3 real V2 gaps.

Plus: RC-4 normalization (defense-in-depth), RC-5 the small true fixes (V9) + document V7/V8.

## 3. Staging

### RC-1 — seed canary paths for never-legitimate routes · **S** · START HERE
Canary = score 100 = single-hit block at every tier (`scores.rs:446`, canary verified 2026-07-04).
Runtime-editable via `PUT /api/risk/canary-paths` (full-replace, cap 256, durable). **Two prerequisites:**
`detectors.canary.enabled` defaults **OFF** and `risk.canary_paths` defaults **empty** — both must be set.
- Ship a curated default `risk.canary_paths` + flip `detectors.canary.enabled: true` in default config.
- **Curated set (zero legitimate callers):** `/.git/config`, `/.git/HEAD`, `/.env`, `/.aws/credentials`,
  `/.git-credentials`, `/id_rsa`, `/wp-config.php`, `/terraform.tfstate`, `/actuator/heapdump`,
  `/actuator/env`, `/.ssh/id_rsa`, `/server.key`. Use exact entries; consider `/.git/*` subtree.
- **Do NOT** canary anything with legitimate traffic (`/actuator/health`, `/actuator/info`, any app
  route). Canary is a hard block — a wrong entry is an outage.
- **Known limits (document, don't over-engineer):** canary matches **raw, case-sensitive** path
  (`canary.rs:97-135`) — encoded (`%2egit`) or `//`-prefixed variants slip through; that's fine for a
  tripwire (recon + RC-4 back it up). Linear scan, cap 256 — keep the list curated, not exhaustive.

### RC-2 — tiered recon scoring · **M**
The FP-averse `25` is right for *generic* probes but too low for unambiguous secret exposure.
- Introduce a `recon::SENSITIVE` score (e.g. 50–70, tune with the corpus) for the
  secret/RCE-exposure subset: credential files, private keys, `terraform.tfstate`,
  `/actuator/{heapdump,env,configprops}`, `wp-config.php`. At 50, two hits still needed; at 70, single
  hit blocks — **owner + corpus decide the exact value** (this is the FP knife-edge).
- Keep `recon::PATH = 25` for generic/ambiguous probes (`/phpinfo.php`, `/actuator` index, swagger).
- Mechanism: tag the sensitive patterns with the higher score in the signature table (`scores.rs` +
  `recon.rs` pattern metadata) — no gate/threshold change, so it composes with existing accumulation.
- **Gate on the corpus** (RC shares FP-tuning's harness): sensitive tier must not fire on the benign
  corpus. Log-only soak before the score that single-hit-blocks goes live.

### RC-3 — close the genuinely-missing signatures · **S–M**
Add to `RECON_PATHS` (`recon.rs`), each with a unit test on the **raw** form:
- Secrets: `/id_rsa` (bare, no ext), `/.npmrc`, `/.git-credentials`, generic
  `(?:^|/)secrets?\.(?:json|txt|ya?ml|env|config)` (currently only `.ya?ml`).
- V2 real gaps: catch `/config.env`,`/aws.env` (bare `.env` preceded by a word) and `/wp-config.txt`;
  add `.backup|.gz|.zip` to the backup-suffix set. Anchor tightly — must not match legit `*.environment`.
- Exchange/ProxyShell: `/autodiscover/autodiscover\.json`, `/owa/auth/logon\.aspx`,
  `/Core/Skin/Login\.aspx`.
- WordPress: `/wp-json/` (at least the abused `gravitysmtp` + `wp/v2/settings`), `wlwmanifest\.xml`,
  `/xmlrpc\.php`.
- Misc from the 263: `/Jenkinsfile`, `jenkins.*config\.xml`, `/\.terraform/`. (`/\.DS_Store`,
  `/\.htaccess` already present; `/\.well-known/security\.txt` is a legit standard — skip.)
- **Every addition = raw-form Rust unit test** ([[project_ltester_decodes_dataplane_raw]]); validate
  against the benign corpus so none is a chronic FP.

### RC-4 — path normalization for matching (defense-in-depth) · **M** (careful — do after RC-1/2/3)
- Collapse `//`→`/` and resolve `.`/`..`, and match a **percent-decoded** copy, *in addition to* the
  raw form — never replacing raw (raw is the contract for other detectors,
  [[project_hyper_normalizes_framing]], [[project_ltester_decodes_dataplane_raw]]).
- Scope: affects all path-matching detectors, so land it as a shared normalized-view helper the
  detector reads alongside `origin_form_uri`, guarded + benchmarked (hot path).
- This is the general fix for V6 + encoded canary evasion; lower priority because RC-1/2/3 cover the
  observed real traffic and this touches shared plumbing.

### RC-5 — the small true fixes + documentation · **S**
- **V9:** populate top-level `ip` in admin audit events with the actor's client IP — folds into
  [FEAT-audit-coverage-gaps-2026-07.md](../../issues/archived/FEAT-audit-coverage-gaps-2026-07.md) AU-1 (do it there, not
  twice); cross-referenced here so it isn't lost.
- **V7/V8:** working-as-designed — **document**, don't "fix". Add a short note to the detection docs
  explaining the two-score model and the dev-XFF-collapse ([[feedback_dev_xff_single_ip_gates]],
  [[feedback_two_score_model]]) so the next report doesn't re-misdiagnose. Optional observability:
  a per-path detector-hit metric independent of `risk-score` blocks, so aggregate dashboards stop
  masking per-path ability (V7's one genuinely useful insight).

## 4. Tests (RED-first)

- RC-1: each curated canary path → single request from a **fresh IP** blocks (403) with reason
  `canary`; a look-alike legit path (`/actuator/health`) is **not** blocked; toggle-off → no block.
- RC-2: a sensitive-tier path from a fresh IP reaches the intended verdict at the chosen score;
  generic probe still allowed single-hit; neither fires on the benign corpus.
- RC-3: raw-form unit test per new signature (positive) + benign-corpus negative (no FP).
- RC-4: `//x`, `/./x`, `%2e`-encoded variants normalize to the canonical match; raw path still
  available to other detectors; bench delta within budget.
- Regression: existing recon tests (`recon.rs` test module) stay green; workspace zero-warning
  ([[feedback_test_suite_green_baseline]]).
- **Corpus gate** on every scoring/signature change (shared with FP-tuning plan).

## 5. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | Canary false block (a path with real traffic) = outage | curated never-legit list only; look-alike negative tests; canary is exact-match so blast radius is the exact string; log-only shadow of the list first if unsure |
| HIGH | RC-2/RC-3 raise FP on benign traffic | corpus gate + log-only soak before single-hit-block scores; keep generic tier at 25 |
| MEDIUM | RC-3 over-broad `.env`/`secrets` regex matches legit paths | tight anchors + benign-corpus negative tests; prefer specific over greedy |
| MEDIUM | RC-4 normalization perf on hot path | shared cached view, release-profile bench per PR (LT-P1); do last |
| LOW | Encoded/`//` evasion of canary | acknowledged tripwire limitation; recon + RC-4 provide depth |

## 6. Acceptance

- [ ] §1 verification recorded so the report's V1/V3/V4 misdiagnosis isn't re-litigated.
- [ ] RC-1: curated canary set shipped + toggle on by default; single-hit block from fresh IP proven; no legit-path regression.
- [ ] RC-2: sensitive-tier recon scoring, corpus-gated, soak evidence.
- [ ] RC-3: 7 missing families + 3 V2 gaps added, raw-form tests + corpus-clean.
- [ ] RC-4 (optional/last): normalized matching view, benched.
- [ ] RC-5: V9 handled in the audit plan; V7/V8 documented as designed.
- [ ] Committee-facing: before/after recon block rate on the 263-path replay from fresh IPs.
