---
id: 2026-05-19-low-reset-failed-toast-easy-to-miss
date: 2026-05-19T12:42Z
severity: LOW
area: dashboard
component: top-risk-buckets / surgical-reset
status: open
test_mode: functional
---

# "Reset failed" toast disappears before the operator can read it

## Summary

When `surgicalReset` rejects on the new Top risk buckets card, the
fallback path calls `window.aegisToast('Reset failed: …', 'err')`.
The toast pops, but on a 5 s polling card the row is repainted with
the same data right after — making it indistinguishable from "I
clicked Reset and the row was rebuilt with a fresh idle counter."
In the Cowork sandbox I never saw the toast region populated when I
polled the DOM 6 s after click; on a live operator screen the toast
is short-lived too.

This is a secondary finding behind
`high-top-risk-buckets-reset-button-broken-csrf.md` — fixing the
CSRF helper makes the "failed" path much rarer, but operator
feedback on failure still matters.

## Suggested fix

- Make the per-row Reset button hold its own per-row error state
  (e.g. a `resetError[id]` map), and render an inline error pill in
  the row's action column when the last reset failed. Persists past
  the next 5 s poll cycle and is impossible to miss.
- Bonus: include the row's full identifier (`ip|device_fp|session`)
  in the error message so the operator can correlate which bucket
  the failure was for when the page has many rows.

## Severity rationale

LOW — UX polish. Doesn't block use; just makes the broken state
above more discoverable.
