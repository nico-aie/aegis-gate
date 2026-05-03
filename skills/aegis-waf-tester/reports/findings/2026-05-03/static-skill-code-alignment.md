---
id: 2026-05-03-static-skill-code-alignment
date: 2026-05-03T17:20Z
severity: INFO
area: docs
component: aegis-waf-tester / SKILL.md
status: open
test_mode: smoke
---

# Static cross-check: skill embedded test plan still lines up with the code

## Summary
With execution-mode blocked (see
`blocked-no-runnable-waf-binary.md`), I did a static-only sweep
over the points where the skill's embedded test plan asserts
specific server contracts, to catch "skill drift" — places where
the test plan would silently fail because it expects a string or
schema the WAF no longer emits. Result: **no drift found**. Filing
this as INFO so it's evidence the static pass actually ran.

## Repro
Static greps from repo root:

1. CSRF reason codes — skill expects `csrf_missing_header` and
   `csrf_mismatch`:
   ```
   crates/aegis-control/src/api/mutation.rs:60: Self::CsrfMissingHeader => "csrf_missing_header",
   crates/aegis-control/src/api/mutation.rs:61: Self::CsrfMismatch    => "csrf_mismatch",
   ```
2. Login error reason — skill expects `invalid_credentials`:
   ```
   crates/aegis-control/src/api/login.rs:168:
     body: error_body("invalid_credentials", "user or password incorrect"),
   ```
3. Blacklist body shape — skill posts
   `{id, kind, value, note, bypass, created_at}`. Server type:
   ```
   crates/aegis-control/src/api/blacklist.rs:28..40
   pub struct AccessListEntry {
       pub id: String,
       pub kind: String,         // ip | cidr | asn | country
       pub value: String,
       pub note: String,
       pub expires_at: Option<DateTime<Utc>>,   // optional, OK to omit
       pub bypass: Vec<String>,
       pub created_at: DateTime<Utc>,
   }
   ```
   Skill omits the optional `expires_at` — fine.
4. Documented endpoint paths — sampled
   `/api/about`, `/api/attacks/top`, `/api/audit/since`,
   `/api/cold-tier`, `/api/gitops/status`, `/api/mtls/connections`,
   `/api/config/version`. Each one is referenced by source file
   doc comments and routing modules under `crates/aegis-control/src/api/`.
5. tests/manual scripts — the skill mentions `tests/manual/`. All
   present:
   ```
   tests/manual/access-list-roundtrip.sh
   tests/manual/csrf-cookie-flow.sh
   tests/manual/fake-country-ips.sh
   tests/manual/viptalk-alert-test.sh
   tests/manual/websocket-bridge.sh
   ```
6. Docs the skill references — both present:
   ```
   docs/operator/upstream-cookbook.md
   docs/security/detectors/README.md
   ```

## Expected
Skill's embedded test plan still exercises live server contracts.

## Actual
Same as expected. No drift.

## Suggested fix
None — this is a passing observation. Re-run this static check the
next time the skill is updated, especially after any rename in
`MutationError` reason strings or `AccessListEntry` field churn.

## Severity rationale
INFO. It's a "test ran, no problem found" record. Useful as
provenance that the static fallback executed and as a snapshot of
which contracts the skill currently depends on, so the next drift
is easier to spot.
