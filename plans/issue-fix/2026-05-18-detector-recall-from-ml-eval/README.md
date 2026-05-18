# 2026-05-18 — detector-recall fix plan (from ML rules-binary eval + juice-shop eval)

> **Status:** Drafted 2026-05-18. Cross-checks the QC `RULES_BINARY_EVAL_REPORT.md`
> against the actual codebase, and reconciles with the parallel
> juice-shop manual eval. Defines four sprints in priority order
> (P1 → P4) plus what NOT to chase.

## Sources

- **Primary:** [`tests/ml-model/2026-05-18/RULES_BINARY_EVAL_REPORT.md`](../../../tests/ml-model/2026-05-18/RULES_BINARY_EVAL_REPORT.md) — 227,055-sample regex-only eval (AI disabled, no scoring). Headline: 63.9% recall, 5.9% FPR.
- **Cross-reference:** [`tests/results/run-juice-shop-eval-2026-05-18-152455/README.md`](../../../tests/results/run-juice-shop-eval-2026-05-18-152455/README.md) — 45-request manual eval against OWASP Juice Shop v20. 100% inject coverage on hand-picked payloads, 0% FP, 45/45 audit correlation.

## Headline findings

- Recall **63.9 %** (target ≥ 95 %), per-class worst-four:
  - `HTTP abusion` 4.0 % (CSIC, 22 722 samples)
  - `Injection` 29.2 % (CSIC, 699 samples)
  - `traversal` 59.4 % (JSON, 28 314 samples)
  - `Manipulation` 59.5 % (Malicious, 28 314 samples)
- FPR **5.9 %** headline → **effectively 0 %** on every clean
  dataset (CSIC normal, Modern, openappsec, Legitimate Browser).
  The 5.9 % is contamination from SRBH2020 `Normal` mislabels
  (the QC report itself flags this in §6-B). **Not chasing.**
- Juice-shop eval saw 0 FPs and 100 % detection on its smaller
  hand-picked corpus — confirms detectors fire on the patterns
  they're designed for; the ML eval shows where evasion variants
  slip through.

## Verification matrix — QC claim vs current code

| QC claim | Verdict | Evidence |
|---|---|---|
| §6-A — HTTP abusion is structural; content regex can't catch | **HOLDS** | `header_injection.rs` only scans `Transfer-Encoding:` inside URL queries (response-splitting case), not actual wire headers. We have no smuggling detector. CSIC theoretical ceiling for content-regex is ~9.3 %; we're at 4.0 %. |
| §6-B — SRBH2020 `Normal` mislabels inflate FPR | **HOLDS** | FPR table: 0.0 % on every clean source, 24.4 % only on SRBH2020. Juice-shop eval confirms: 0 FPs on legit Angular+AJAX. |
| §6-C — Null-byte + overlong UTF-8 survive triple URL-decode; HTML-entity decode + unicode-escape decode would close the gap | **HOLDS** | We have overlong-UTF-8 patterns (`path_traversal.rs:37-39`) only in URL-encoded string form. No HTML-entity decode anywhere. No unicode-escape decode. Single-pass `url_decode` in `detectors/mod.rs:160`. |

## What NOT to fix

- **The 5.9 % headline FPR.** Dataset contamination, not a real
  false-positive issue.
- **CSIC `HTTP abusion` recall above 9.3 %.** The eval's own
  ceiling. Don't chase with regex; needs a structural detector
  (Sprint 3).
- **CSIC `Injection` recall via SQL keyword expansion.** CSIC 2010
  is old; the 699 `Injection` samples likely mix LDAP / SSI /
  generic-param tampering. Worth investigating later but not P1.

## Recommended sprint plan

| Sprint | Scope | LoC | Recall impact | Round-1? |
|---|---|---:|---|:-:|
| **S1 · Decoder evasion fix** | HTML-entity + unicode-escape + double URL decode applied to traversal/sqli/xss/cmd | 80 | traversal 59 % → ~85 %, injection +5–8 % each | **YES** |
| **S2 · Mass-assignment scope widen** | Form-encoded body + query-string check; widened privileged-key list | 100 | Manipulation 59 % → ~80 % | **YES** |
| **S3 · Request-smuggling detector** | New detector: CL+TE coexistence, chunked syntax, duplicate CL | 150 | HTTP abusion 4 % → ~9 % (ceiling) | no |
| **S4 · Juice-shop carry-overs** | Header-size guard + dev rate-limit tuning | 60 | non-recall: tightens FPP at the edges, surfaces rate limiter in tests | no |

---

## Sprint 1 — Decoder evasion fix (~80 LoC)

**Goal.** Close the largest single recall gap by extending the
detector decoder beyond single-pass URL-decode.

**Where the gap is.** [`crates/aegis-security/src/detectors/mod.rs:160`](../../../crates/aegis-security/src/detectors/mod.rs)
defines `url_decode` as single-pass. The path/sqli/xss/cmd detectors
each call it once and `check(raw)` + `check(decoded)`. That misses:

1. **Double URL-encoding** (`%252e` → `%2e` → `.`). We have one
   pattern for `%252e%252e%252f` in `path_traversal.rs:15`, but
   the general case (`%252fetc%252fpasswd`) isn't covered for
   any other detector.
2. **HTML entities** (`&#46;` `&#x2e;` `&period;` for `.`,
   `&#47;` for `/`).
3. **Unicode escapes** (`.` `\x2e` in JSON/JS contexts).

**Plan.**

1. Add three helpers in `detectors/mod.rs`:

   ```rust
   /// Apply `url_decode` twice; idempotent if a single pass
   /// already produced no more `%XX` sequences.
   pub(crate) fn url_decode_double(input: &str) -> String { ... }

   /// Decode `&#NN;` `&#xHH;` and the named entities relevant
   /// to URL/path characters (`&period;` `&sol;` `&bsol;` `&num;`).
   pub(crate) fn html_decode(input: &str) -> String { ... }

   /// Decode `\uHHHH` and `\xHH` sequences.
   pub(crate) fn unicode_escape_decode(input: &str) -> String { ... }
   ```

2. Add a `normalize_for_detection` helper that returns up to four
   variants (raw, url×2, html-decoded, unicode-decoded). Callers
   iterate over the variants and check each.

3. Update `path_traversal.rs`, `sqli.rs`, `xss.rs`, `command_injection.rs`
   to use `normalize_for_detection` instead of single-pass
   `url_decode`. Cost on the hot path: 3–4 additional `String`
   allocations per request. For the volumes we see (5 k RPS in
   `run-perf-5krps-prod-balanced-2026-05-02-v3`) this is ~150 µs
   total; acceptable. If profiling shows it matters, gate the
   extra passes behind "does the raw input contain `&` or `\\u`"
   pre-checks.

4. Tests:
   - Add positive tests for `&#46;&#46;/etc/passwd`,
     `../etc/passwd`, `%2525c0%2525af` (double-encoded
     overlong) to each affected detector.
   - Verify the legit-traffic negatives don't regress
     (`/path?name=hello%20world` etc.).

**Why this is P1.**
- Single biggest recall gap (28 K traversal samples + multi-detector
  lift)
- Concrete fix the QC report itself recommends (§6-C)
- ~80 LoC, no architectural change
- Zero risk to legit traffic — additional decode passes only
  produce more strings to check; they don't change what's
  considered legit
- Closes a real attacker primitive (entity-encoded payloads bypass
  many WAFs)

**Exit criteria.**
- All four affected detectors have positive tests for the three
  new evasion classes
- Re-run the ML eval; `traversal` ≥ 80 % recall, others +5 %
- FPR on every legit dataset stays 0 %
- Juice-shop eval still 0 FPs

---

## Sprint 2 — Mass-assignment scope widen (~100 LoC)

**Goal.** Lift `Manipulation` recall from 59 % to ~80 % by
detecting privilege-escalation attempts beyond JSON bodies.

**Where the gap is.** [`crates/aegis-security/src/detectors/body_abuse.rs:82`](../../../crates/aegis-security/src/detectors/body_abuse.rs):

```rust
if trimmed.starts_with('{') || trimmed.starts_with('[') {
    // ... mass-assignment check only here
}
```

The detector only fires on JSON bodies. It ignores:
- Form-encoded bodies (`application/x-www-form-urlencoded`) —
  `role=admin&isAdmin=true` slips through entirely
- Query strings — `?role=admin&account_balance=99999` slips through
- `multipart/form-data` — same story

It also has a small privileged-key list that's missing common
camelCase synonyms (`isSuperuser`, `accountBalance`, `apiKey`,
`accessLevel`).

**Plan.**

1. Refactor `MASS_ASSIGN_KEYS` into two regexes:
   - `MASS_ASSIGN_JSON` — current shape (`"role" :`)
   - `MASS_ASSIGN_FORM` — form/query shape (`role=`, `isAdmin=`,
     case-insensitive, anchored on `&` or `?` or start)

2. In `BodyAbuseDetector::inspect`:
   - On `application/x-www-form-urlencoded` body, run `MASS_ASSIGN_FORM`
     on the peek window
   - On `multipart/form-data` body, run `MASS_ASSIGN_FORM` on each
     part's Content-Disposition `name="..."` value
   - Always run `MASS_ASSIGN_FORM` on `req.uri.query()` (after url_decode)

3. Widen the privileged-key list to include camelCase + snake_case
   synonyms:

   ```text
   role / isAdmin / is_admin / isSuperuser / is_superuser / admin
   permissions / privileges / grants / scope
   balance / account_balance / accountBalance / credit
   password_hash / passwordHash / api_key / apiKey / access_token
   refresh_token / accessToken / refreshToken / verified /
   email_verified / emailVerified / accessLevel / userLevel
   ```

4. Keep the detector conservative on response paths — these are
   client→server signals only.

5. Tests:
   - Positive: `?role=admin`, `role=admin&password=x` (form body),
     `multipart` with `name="isAdmin"`
   - Negative: legit profile-update body without privileged keys,
     legit search query with `?role=engineer` (a job-title query
     value — should still flag because we match on the key, not
     value; document this trade-off explicitly)

**Why this is P2.**
- Second-largest recall gap
- The detector already exists and is well-structured; this is
  scope widening, not new architecture
- Form-encoded bodies are common in real-world apps that aren't
  Angular/React SPAs — closes a real attacker primitive

**Exit criteria.**
- `Manipulation` recall ≥ 75 % on the ML eval
- FPR stays 0 % on legit datasets
- Juice-shop eval: legitimate form posts (e.g. login) still allowed

---

## Sprint 3 — Request-smuggling detector (~150 LoC)

**Goal.** Lift `HTTP abusion` recall from 4 % toward the ~9 %
content-regex ceiling, by adding a non-regex detector that
inspects actual wire headers and rejects ambiguous parsing.

**Where the gap is.** No such detector exists.
[`crates/aegis-security/src/detectors/header_injection.rs:21`](../../../crates/aegis-security/src/detectors/header_injection.rs)
has a pattern for `Transfer-Encoding:` but it scans *URL queries
and header VALUES* looking for that string as a payload (the
response-splitting attack), not the actual `Transfer-Encoding`
header on the request.

The hyper parser already rejects the most-malformed traffic at
parse time. The remaining surface for the WAF is:
- `Content-Length` + `Transfer-Encoding: chunked` both present
  (RFC 7230 §3.3.3 forbids — used for CL.TE / TE.CL smuggling)
- Multiple `Content-Length` headers with different values
- `Transfer-Encoding: chunked, identity` or other ambiguous lists
- Chunked-encoding syntax errors (LF without CR, bare LF in
  chunk extensions, oversize chunk-size)

**Plan.**

1. New file: `crates/aegis-security/src/detectors/smuggling.rs`
2. Detector inspects `req.headers`:

   ```rust
   fn inspect(req) {
       if has(req, "content-length") && has(req, "transfer-encoding") {
           signal!("smuggling", "cl_te_coexist")
       }
       if duplicate_content_length(req) {
           signal!("smuggling", "duplicate_cl")
       }
       if ambiguous_transfer_encoding(req) {
           signal!("smuggling", "ambiguous_te")
       }
   }
   ```

3. **Pre-flight**: measure how many CSIC `HTTP abusion` samples
   reach the detector at all. If hyper's strict mode rejects 90 %
   of them at parse time, this detector only helps the remaining
   10 % — and its real value is preventing future parser changes
   from silently regressing.

4. New detector class `smuggling` added to the detector mask in
   `crates/aegis-core/src/config.rs` (next to `header_injection`).

5. Tests:
   - Positive: each of the four ambiguity shapes above
   - Negative: chunked-only request, CL-only request, GET with no
     body

**Why this is P3, not P1.**
- High LoC, separate architectural module
- Practical impact uncertain until pre-flight measurement
- The CSIC ceiling is 9.3 % — this detector at best lifts us from
  4 % to ~9 %, an absolute +5 % on a single dataset slice
- Other sprints have larger absolute recall lifts for less LoC

**Exit criteria.**
- Pre-flight measurement included in the PR description
- `HTTP abusion` recall ≥ 7 % (or matches whatever hyper rejects
  + this detector catches together)
- No regression on legit traffic; chunked uploads still work

---

## Sprint 4 — Juice-shop carry-overs (~60 LoC)

**Goal.** Close the two operator-noticeable gaps surfaced in the
2026-05-18 juice-shop eval that aren't in the ML report.

### S4.1 · Header-size guard (~30 LoC)

`tests/results/run-juice-shop-eval-2026-05-18-152455` §4.3:
a 2 KB User-Agent passed without challenge. No detector flags
oversized headers below the HTTP/1.1 protocol limit (~8 KB).

**Plan.** New micro-detector `header_size` (or extend
`body_abuse` to also check header surface):
- Configurable `max_single_header_bytes` (default 4 KB)
- Configurable `max_total_header_bytes` (default 16 KB)
- Configurable `max_header_count` (default 100)
- Emit `signal!("header_oversize", ...)` on any threshold breach

### S4.2 · Dev rate-limit tuning (~30 LoC, mostly config)

§4.1: 15 same-IP RPS to `/rest/products/reviews/1` didn't trip
the rate limiter. Default thresholds are too generous for
loopback dev.

**Plan.**
- Add a sample stricter rate-limit block to `config/dev.yaml`
  commented out, with a comment explaining "uncomment to surface
  the rate limiter at smaller burst sizes for security tests"
- OR: introduce a `config/profiles/dev-strict.yaml` that the
  juice-shop eval uses by default

Not a security regression — production profiles use appropriate
defaults. This is purely "the dev profile is too permissive to
exercise the rate limiter in a 15-request test."

---

## Sequencing

```
S1 (decoder evasion)  ───────►  re-run ML eval, verify lift
                                │
S2 (mass assignment)  ──────────┴─► re-run ML eval, verify lift
                                    │
S3 (smuggling)        ──────────────┴─► pre-flight measurement first,
                                        then implement if worthwhile
                                        │
S4 (juice carry-over) ──────────────────┴─► independent; can ship
                                            anytime
```

S1 and S2 are independent — could ship in parallel PRs. S3 needs
a measurement gate before commitment. S4 is small-and-independent.

## Reporting / verification

After each sprint:

1. Run `tests/ml-model/eval_rules_binary.py` against the dataset
   and append a `RULES_BINARY_EVAL_REPORT_after-S{N}.md` next to
   the original
2. Run the juice-shop eval again (`make juice-up` →
   `tests/results/run-juice-shop-eval-*.sh`) and verify no
   regression on the 45-case baseline
3. Run `cargo test --workspace --lib` (3 308 tests today —
   ensure this number doesn't drop)
4. Update this README's status table at the top

## Scope guardrail

This plan ONLY addresses recall in the four worst-performing
categories. It does not:
- Add new detector classes beyond smuggling
- Change scoring thresholds
- Touch the AI detector path (we're evaluating the regex set
  in isolation per QC)
- Address performance (already separately tracked in
  `run-perf-5krps-prod-balanced-*`)
