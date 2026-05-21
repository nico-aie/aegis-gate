---
id: 2026-05-17-header-injection-hardcoded-test-corpus-keywords
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · header injection detector
component: crates/aegis-security/src/detectors/header_injection.rs (lines ~137-148)
interop_contract: official rules §9 ("Nghiêm cấm": hardcode rule chỉ để vượt qua test case cụ thể — BỊ LOẠI NGAY LẬP TỨC)
status: open
test_mode: source-review
---

# F-CRITICAL-012 · `header_injection.rs` keyword list contains literal `evil / attacker / malicious / phish` — official rules §9 prohibits this exact pattern as "BỊ LOẠI NGAY LẬP TỨC"

## Summary

Official rules §9 forbid:

> *✕ Hardcode rule chỉ để vượt qua test case cụ thể — **BỊ LOẠI NGAY
> LẬP TỨC**.*

(Hardcoding rules just to pass specific test cases — immediate
disqualification.)

The `header_injection.rs` Host-header validator scans for the
literal substrings `["evil", "attacker", "malicious", "phish",
"javascript:", "data:", "<", ">", "\"", "'"]` ([header_injection.rs:~137-148]).

The four English words `evil / attacker / malicious / phish` are
TEST-FIXTURE-CORPUS names. They appear in:

- OWASP cheat-sheet examples for header-injection (`evil.com`,
  `attacker.com`).
- The OWASP Juice Shop training corpus.
- Common Red Team payload generators.
- The benchmark harnesses' default attacker hostnames.

These strings are NOT attack STRUCTURE — they're attack NAMES. A
detector that matches on the words "evil" or "attacker" appearing in
a Host header:

- Catches lazy Red Team payloads using `evil.example.com`.
- Misses any attacker who uses a benign-sounding domain
  (`mydomain.co`, `cdn-proxy.io`, the attacker's actual
  controlled-domain name).
- False-positives on legitimate domains containing the word "evil"
  (`http://evil-corp.example.com`, `evilqueen-cosplay-shop.shop`,
  etc.).

This is the exact pattern the rules prohibit. Even if a Red Team's
specific corpus uses these names and the detector "works" against
that corpus, judges scanning the code will see hardcoded
test-fixture names and rule the team disqualified.

## Observed code path

[detectors/header_injection.rs ~ line 137-148](../../../../crates/aegis-security/src/detectors/header_injection.rs):

```rust
const SUSPICIOUS_HOST_SUBSTRINGS: &[&str] = &[
    "evil",
    "attacker",
    "malicious",
    "phish",
    "javascript:",
    "data:",
    "<",
    ">",
    "\"",
    "'",
];
```

The metacharacter subset (`javascript:`, `data:`, `<`, `>`, `"`, `'`)
is defensible — those are real XFH (X-Forwarded-Host) /
Host-override attack tokens. The first four are the problem.

## Impact

- **Disqualification risk** — explicit per §9 ("BỊ LOẠI NGAY LẬP TỨC").
  Even if no benchmark probes catch the FP/miss pattern, judges
  doing code review (which the rules require — see §5.1 "BTC sẽ
  review source code") see this and disqualify.
- **False positives** on legitimate domains containing the word
  "evil" or "attacker" (research orgs, security companies, satirical
  branding) → blocks legitimate traffic → counts as `false_positive`
  per §7 normalization → scoring loss.
- **False negatives** on attacker-controlled domains that don't use
  these substrings → the detector does nothing useful, the WAF still
  thinks it has Host-injection coverage.

## Suggested fix

Drop the four offending words. Keep only the metacharacter subset
(which is principled — characters that should NEVER appear in a
valid Host header):

```diff
 const SUSPICIOUS_HOST_SUBSTRINGS: &[&str] = &[
-    "evil",
-    "attacker",
-    "malicious",
-    "phish",
     "javascript:",
     "data:",
     "<",
     ">",
     "\"",
     "'",
 ];
```

For real "suspicious domain" detection, use one of:

1. **Allowlist of expected Host values** (operator configures the
   expected hostname; anything else is suspicious). This is the
   primary recommendation per OWASP for Host-header attack
   prevention.
2. **Threat-intel feed** (`threat_intel/` already loads STIX/TAXII)
   — match Host against a real IoC feed of malicious domains, not a
   hardcoded English-word list.
3. **Domain age / reputation lookup** — score-boost on freshly-
   registered domains.

The proper Host validation logic already exists in the same file
(check the Host matches the expected hostname for the route); the
substring list is doing nothing useful and only carrying liability.

## Verification

After the fix, the WAF must:

- NOT block `Host: evil-corp.example.com` (legit domain).
- BLOCK `Host: example.com<script>alert(1)</script>` (metacharacter
  injection).
- BLOCK `Host: example.com\r\nX-Injected: yes` (CRLF — handled
  separately).

Regression case in `tests/security/`:

```sh
# legit-domain-with-evil-substring.sh — assert NOT blocked.
curl -ski -H "Host: evil-corp.example.com" http://127.0.0.1:8080/
# Expect: 200 (or whatever the route returns; NOT 403).

# metachar-host.sh — assert blocked.
curl -ski -H "Host: example.com<script>" http://127.0.0.1:8080/
# Expect: 403.
```

## Severity rationale

CRITICAL on disqualification basis. Per §9 the rule is an "immediate
disqualification" class, not a scoring item — the team can win
every other category and still be eliminated if judges catch this
on code review.

The fix is 4 LoC deletion. Highest cost/benefit ratio of any
finding in this audit.
