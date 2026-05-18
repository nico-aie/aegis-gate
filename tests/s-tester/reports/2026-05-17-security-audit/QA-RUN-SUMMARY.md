---
id: 2026-05-17-aegis-security-audit
date: 2026-05-17T00:00Z
test_mode: source-review
scope:
  - Full audit of `crates/aegis-security/` (~21k LoC across 5 functional groups):
    A) OWASP Top-5 detectors (sqli/xss/path_traversal/ssrf/header_injection/
       command_injection/recon/brute_force/body_abuse)
    B) Other detectors + AI + scores + mask (template_injection/nosql_injection/
       open_redirect/mod/scores/mask/ai/*)
    C) Rule engine + Risk + Pipeline (rules/*/, risk/*, pipeline.rs)
    D) Rate-limit + DDoS + Bots + Behavior + Velocity
    E) Fingerprint + Auth + API security + Challenge + DLP + Threat intel +
       Response filter + Content + GeoIP + IP-rep
  - Cross-referenced against the official Hackathon rules
    (`WAF_Hackathon_2026_offical_rules.pdf`), the v2.3 interop contract
    (`VN_waf_interop_contract_v2.3.md`), and the candidate brief
    (`VN_presen_v2.3.md`).
tester: Claude (5 parallel general-purpose audit agents + spot-verification
                by reading flagged file:line ranges)
---

# Aegis-Gate `aegis-security` full-crate audit — 2026-05-17

**Mode:** Source review only. 5 parallel agents each took one functional
group (~3–5k LoC). Highest-impact findings spot-verified by reading the
cited file:line.

**Scope reminder — what the hackathon grades**:

| Tiêu chí | Điểm | Mostly covered by this crate |
|---|---|---|
| **Security Effectiveness** | **40 / 120 (33%)** | YES — OWASP detectors, AI, response filter |
| **Intelligence & Adaptiveness** | **20 / 120 (17%)** | YES — risk score, velocity, behavior, ladder |
| Architecture & Code Quality | 15 / 120 | partial |
| Extensibility | 10 / 120 | rule engine scopes + hot-reload |

Two of the three top-weighted scoring axes (50% of total points) live
entirely or mostly inside `aegis-security`. Every CRITICAL finding
below directly maps to a documented scoring item.

**Interop contract**: [`Hackathon_Doc/VN_waf_interop_contract_v2.3.md`](../../../../Hackathon_Doc/VN_waf_interop_contract_v2.3.md)
**Official rules**: [`Hackathon_Doc/WAF_Hackathon_2026_offical_rules.pdf`](../../../../Hackathon_Doc/WAF_Hackathon_2026_offical_rules.pdf)

---

## Finding counts

| Severity | Count |
|---|---|
| CRITICAL | 15 |
| HIGH     | ~32 (bundled into 6 domain files) |
| MEDIUM   | ~28 (bundled) |
| Contract gaps (semantic) | 3 |
| **Total** | **78+** |

Largest single bucket of findings of the three audits in this series
(data-plane: 14; proxy-full-crate: 64; this: 78+). Reason: the
hackathon rubric pins per-feature requirements very precisely in §5.2
/ §5.5 / §5.7 and many of those features are either unimplemented or
implemented in a way that misses the contract semantics.

---

## CRITICAL findings index

| ID | Title | Scoring axis hit |
|---|---|---|
| F-CRITICAL-001 | `RiskTracker` keyed by `IpAddr` only — §5.5 demands `{IP + device_fp + session}` | Intelligence 20/120 |
| F-CRITICAL-002 | Rate limiter keyed by `IpAddr` only — §5.2 demands per-IP **AND** per-user-session; distributed credential stuffing trivially evades | Security 40/120 + Intelligence 20/120 |
| F-CRITICAL-003 | `velocity.rs` has NO cross-endpoint sequence engine — Login→OTP→Deposit, withdrawal-after-deposit, rapid-limit-change all unimplemented despite §5.2 | Intelligence 20/120 |
| F-CRITICAL-004 | `behavior.rs` implements 1 of 4 mandated §5.2 signals — zero-depth session, missing-Referer on sensitive routes, <50 ms inter-request all absent | Intelligence 20/120 |
| F-CRITICAL-005 | `ddos.rs` has no per-tier threshold and no fail-close/fail-open per §5.2 + §5.8 — single global threshold, fail-open on all errors regardless of CRITICAL tier | Security 40/120 + Intelligence 20/120 |
| F-CRITICAL-006 | Two risk-threshold sources disagree out of the box: `RiskEngine::classify` hardcodes `30/70` (per spec) while `RiskTracker` default is `40/80` | Intelligence 20/120 |
| F-CRITICAL-007 | Canary endpoints don't actually block IPs — `risk/mod.rs` only sets MAX score when a detector emits the literal tag `"recon_path"`; no path list, no `auto_block` call | Intelligence 20/120 |
| F-CRITICAL-008 | `Pipeline::inbound` SDK trait runs ONLY the rule engine — no detectors, no risk tracker, no canary check, no tier-aware fail-close | Architecture 15/120 |
| F-CRITICAL-009 | Rule `Scope` enum supports only `Global` + `Route(String)` — missing 4 of 6 required scopes per §5.4 (Tier, IP, Session, Device) | Extensibility 10/120 |
| F-CRITICAL-010 | No same-device-different-IP detection — §5.2 #08 Attack Battle scenario "Device fingerprint evasion" unaddressed; no reverse map device→IPs | Security 40/120 + Intelligence 20/120 |
| F-CRITICAL-011 | JA4 implementation sorts ciphers + extensions AND doesn't strip GREASE — Chrome's per-connection GREASE rotation makes the "stable device ID" claim false | Security 40/120 |
| F-CRITICAL-012 | `header_injection.rs` keyword list contains literal `"evil" / "attacker" / "malicious" / "phish"` — official rules call this exact pattern (hardcoded test-corpus matching) an "**immediate disqualification**" class | DISQUALIFICATION RISK |
| F-CRITICAL-013 | `response_filter.rs` strips only `server` + `x-powered-by` headers — misses every §5.7 requirement (X-Debug, X-Internal-*, 5xx body cap, API-key heuristic, IPv6 internal IPs, JSON field masking) | Security 40/120 |
| F-CRITICAL-014 | `brute_force.rs` tracks per-IP only, POST only — official rules separately require detection of password-spraying (1 password × many users) AND credential stuffing (many users × many passwords) | Security 40/120 |
| F-CRITICAL-015 | `bots.rs::classify` never reads the `ja4_fingerprint` field on its own input struct; no ASN, no Tor, no datacenter, no challenge ladder | Security 40/120 |

### HIGH bundles

| File | Mini-findings inside |
|---|---|
| F-HIGH-detectors.md | 9 items: SQLi headers not URL-decoded · path_traversal `(?i)` flag missing on most patterns → uppercase hex bypass · path_traversal headers not scanned · command_injection `${VAR}` FP source · command_injection allow-list misses `${IFS}` tricks · XSS body not entity-decoded · SSRF scheme-bound to `https?://` → relative-URL bypass · body_abuse no decompression-bomb check · recon no OPTIONS/4xx burst detection |
| F-HIGH-rules-engine.md | 6 items: regex recompiled per request · rule list re-sorted per request · linter HARD-REJECTS rules using `RuleAction::RateLimit` (despite it being wired) · cookie value truncated at `=` (use `splitn(2,'=')`) · `BodyMatches` peek 8 KiB only · YAML parser has no document-size bound |
| F-HIGH-rate-limit-ddos.md | 5 items: bucket.rs delegates to broken in-memory backend (cf. F-CRITICAL-007 in proxy audit) · ip_limiter sweep capped at 60 s under DDoS · `tick_rps` races `check` · `auto_block` fires in `observe_only` mode · all DDoS defaults hardcoded |
| F-HIGH-bots-fingerprint.md | 4 items: rDNS NOT forward-confirmed despite "FCrDNS" claim · rDNS cache eviction `clear()` thrashes under DDoS · JA3/JA4 hashed with blake3 instead of MD5/SHA-256 (no IoC compatibility) · `header_order` in device ID hash breaks stability under HTTP/2 HPACK |
| F-HIGH-challenge-auth.md | 6 items: `ChallengeTokens::generate_nonce()` deterministic on `(ip,device,session,ts_ms)` · `auth/jwt::validate()` doesn't verify signature · jwt base64 decoder can panic on malformed input · API-key compare uses `HashMap::get` (not constant-time) · `hmac_sign.verify()` no replay protection · captcha.rs `verify()` always returns `Ok(true)` |
| F-HIGH-response-filter-dlp.md | 5 items: FPE module is a stub (XOR-mod-10, not AES-FF1) · IPv6 internal IPs (`::1`, `fc00::/7`, `fe80::/10`) not detected · DLP has no field-aware JSON masking (`card_number` field per §5.7 ignored) · `inject_security_headers` `.parse().unwrap()` × 5 · `content::is_allowed(Unknown,...)` always returns `true` (allowlist bypass) |

### CONTRACT-GAPS

| ID | Title |
|---|---|
| C-01 | AI detector has no `observe \| enforce` mode despite README claim |
| C-02 | AI confidence extraction `.unwrap_or(1.0)` bypasses the `confidence_threshold` knob for legacy sklearn-shape models |
| C-03 | Scoring ladder (max single hit = 60) doesn't reach default block threshold (80) — no critical detector blocks on its own; contradicts "high-confidence injection → block" expectation |

### MEDIUM bundle

`F-MEDIUM-ALL.md` — ~28 items grouped by domain.

---

## Round-1 + Attack Battle verdict

The official rules (§7) describe Attack Battle: 45 min/team, Red Team
attacks any route. The 8 listed attack vectors mostly map to detectors
that exist — but the SCORING engine on top is so degraded that
detected attacks may not block, and many vectors aren't covered at all:

| Attack Battle vector (§7) | Detection covered? | Will it actually block? |
|---|---|---|
| 01 DDoS L4/L7 (incl. against WAF) | DDoS module exists | ⚠️ NO per-tier; fail-open on errors (F-CRITICAL-005) |
| 02 Bot login + credential stuffing | brute_force per-IP only | ❌ Distributed (F-CRITICAL-014) |
| 03 Relay/proxy attack via Tor/datacenter | partial | ❌ Tor list empty, no ASN wiring (F-CRITICAL-015) |
| 04 Device fingerprint evasion | fingerprint exists | ❌ JA4 sort+GREASE breaks ID (F-CRITICAL-011); no same-device-diff-IP (F-CRITICAL-010) |
| 05 Behavioral bypass (zero-depth) | behavior exists | ❌ Zero-depth signal not implemented (F-CRITICAL-004) |
| 06 Transaction fraud (Login→Deposit) | — | ❌ Velocity engine missing (F-CRITICAL-003) |
| 07 OWASP injection | detectors fire | ⚠️ Scores ladder never reaches block alone (C-03); FPs from `${VAR}` pattern |
| 08 Canary / recon scan | recon detector exists | ❌ Canary doesn't block IP (F-CRITICAL-007); no OPTIONS/4xx detection |

**Score-axis impact estimate** (rough, before fixes):

- **Security Effectiveness** 40/120: ~50% achievable. Detectors fire but block thresholds + tier policy + special-pattern detection are degraded enough that Red Team mutations + fingerprint evasion + sequence attacks will mostly succeed.
- **Intelligence & Adaptiveness** 20/120: ~20% achievable. Risk per `{IP+device+session}` is the headline of this rubric and is implemented as per-IP only; canary doesn't block; velocity sequence missing; behavior signals 1/4.
- **Architecture & Code Quality** 15/120: ~70% achievable. Code is well-structured Rust; the bugs are missing features, not bad code. Pipeline-trait bypass (F-CRITICAL-008) hurts here.
- **Extensibility** 10/120: ~50% achievable. Rule scopes missing (F-CRITICAL-009); linter rejects valid actions (F-HIGH-rules-engine).

Plus the explicit "Forbidden — loại ngay" risk in F-CRITICAL-012:
hardcoded keywords `evil/attacker/malicious/phish` in the
`header_injection` detector match Red-Team test-domain names by name
rather than by attack structure. The official rules call this exact
pattern (matching specific known test payloads) an immediate
disqualification class. If a Red Team picks a benign target hostname
containing the word "evil" (any `evil.example.com` domain) or names
their test fixtures with these substrings, the WAF either FPs (block
legit) or appears to pass only because of corpus-name matching. Either
way, judges scanning the code will see hardcoded fixture names.

---

## Top 5 smallest CRITICALs to fix first

Sorted by `<LoC required / scoring impact>` ratio:

1. **F-CRITICAL-012** (hardcoded `evil` keywords) — 4 LoC delete, removes disqualification risk
2. **F-CRITICAL-006** (threshold defaults disagree) — 2 LoC change (default `40/80` → `30/70`)
3. **F-CRITICAL-007** (canary doesn't block IP) — ~30 LoC (path list + `auto_block` call)
4. **F-CRITICAL-013** (response_filter STRIP_HEADERS) — ~20 LoC (add 4 patterns + prefix scan)
5. **F-CRITICAL-011** (JA4 sort + GREASE) — ~15 LoC (remove `sort_unstable`, add GREASE strip)

The big-ticket fixes that need design work:

- **F-CRITICAL-001 + 002** (key shape: IP+device+session) — touches RiskTracker + IpRateLimiter + all callers. ~200 LoC.
- **F-CRITICAL-003** (velocity sequence engine) — net-new module. ~400 LoC.
- **F-CRITICAL-005** (DDoS per-tier + fail-close) — touches DdosConfig + ddos.rs + callers + tier plumbing. ~150 LoC.

---

## Files

```
QA-RUN-SUMMARY.md                                                          (this file)
F-CRITICAL-001-risktracker-keyed-by-ip-only.md
F-CRITICAL-002-rate-limit-keyed-by-ip-only.md
F-CRITICAL-003-velocity-no-cross-endpoint-sequence.md
F-CRITICAL-004-behavior-3of4-mandated-signals-missing.md
F-CRITICAL-005-ddos-no-per-tier-no-fail-close.md
F-CRITICAL-006-risk-thresholds-30-70-vs-40-80-disagree.md
F-CRITICAL-007-canary-endpoint-doesnt-block-ip.md
F-CRITICAL-008-pipeline-inbound-bypasses-detectors-risk-canary.md
F-CRITICAL-009-rule-scope-enum-missing-tier-ip-session-device.md
F-CRITICAL-010-no-same-device-different-ip-detection.md
F-CRITICAL-011-ja4-sorts-and-no-grease-strip.md
F-CRITICAL-012-header-injection-hardcoded-evil-attacker-keywords.md
F-CRITICAL-013-response-filter-misses-most-of-section-5-7.md
F-CRITICAL-014-brute-force-per-ip-post-only-no-credential-stuffing.md
F-CRITICAL-015-bots-classify-ignores-ja4-no-asn-no-ladder.md
F-HIGH-detectors.md         (9 items)
F-HIGH-rules-engine.md      (6 items)
F-HIGH-rate-limit-ddos.md   (5 items)
F-HIGH-bots-fingerprint.md  (4 items)
F-HIGH-challenge-auth.md    (6 items)
F-HIGH-response-filter-dlp.md (5 items)
F-CONTRACT-GAPS.md          (3 semantic gaps)
F-MEDIUM-ALL.md             (~28 items)
```
