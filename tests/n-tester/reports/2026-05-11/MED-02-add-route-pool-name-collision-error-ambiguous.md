---
id: 2026-05-11-add-route-error-ambiguity
date: 2026-05-11T17:24Z
severity: MEDIUM
area: dashboard
component: upstreams · add-route-modal
status: open
test_mode: full-qc
---

# Add Route save failure displays two contradictory error messages at once

## Summary

On Routing & Upstreams → "+ Add route", when a save fails because the
host scope already has a `default: true` catch-all, the modal shows
two error UIs simultaneously:

1. A bottom-right toast that names the real failure cause:
   *"Save failed: route table build failed: config: host scope '\*'
   has 2 `default: true` routes (catch-all, qa-dns-route); at most one
   default per scope is allowed."*
2. An inline hint inside the modal body, attached to the "Forward to"
   block, that names a completely different cause:
   *"Will create pool qa-dns-route with this single member. **— that
   pool name already exists; pick it from the dropdown above
   instead.**"*

The two messages describe different problems. The toast is correct
(catch-all default collision); the inline hint is misleading (the
pool may exist, but that wasn't the failure — and it suggests an
action that wouldn't fix the catch-all collision).

## Repro

1. Sign in, navigate to **Routing & Upstreams**.
2. Click **+ Add route**.
3. Fill Route ID = `qa-dns-route`, leave Host blank (`any host`),
   leave Path `/`, leave Methods unselected.
4. In the "Type a new backend" input, type `example.com:443`.
   Modal auto-expands with Scheme `https` etc.
5. Click **Create route**.
6. Observe: toast and inline hint show the two contradictory
   messages described above.

## Expected

One canonical error surface. If the route table build fails, the
inline hint either disappears or rewrites itself to reflect the
*actual* failure cause. Two contradictory red-bordered messages
make an operator think they have two problems when they have one.

## Actual

Both shown. The inline hint was correct for a different code path
(pool-name collision) that didn't fire; only the toast was correct.

## Suggested fix

The inline-hint logic should be gated on the response code, not
just on local pool-name lookup. Either:

- **A**: clear the inline pool-name hint on any save error and let
  the toast carry the message; or
- **B**: surface the full server error text *inside the modal*
  (replacing the toast) so the operator's eye doesn't need to ping
  bottom-right + the modal body.

Recommend B — modal-anchored error is consistent with the inline
F-02 validation pattern.

## Severity rationale

MEDIUM because it slows the operator down ("which message is
right?") rather than blocking them. The save failed loudly, so no
silent-data loss. UX friction on the high-stakes Add Route flow
puts it above LOW.

