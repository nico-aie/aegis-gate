---
id: 2026-05-12-add-route-couples-pool-route-creation
date: 2026-05-12T13:12Z
severity: MEDIUM
area: dashboard
component: routing-upstreams · add-route-modal
status: open
test_mode: full-qc
---

# Add Route modal silently creates a pool as a side-effect of route creation — operator wanted to create a route, ended up authoring two resources

## Summary

The Add Route modal has one primary CTA (`Create route`), one
subtitle ("How it works"), and one preview line at the bottom
(`ANY */news → znews-route (new · znews.vn:443)`). The
preview's `(new · …)` parenthetical is the ONLY operator-visible
clue that the modal is about to create a **pool** in addition to
the route.

The operator reading this modal sees three fields they
identifiably understand (Route ID / Path / Host) and one
"Forward to" composite control. They expect the modal to do one
thing: create a route. The hidden side-effect — also creating a
pool that didn't exist — is what triggered the operator's
"creates a pool but can not add to route" misreading on the
previous repro.

The two failure modes that surface this confusion:

1. **HIGH-RU-01.** Route + pool are both created with a broken
   `scheme: https + tls: false` combo. Operator sees the route
   exists but the upstream returns 400. They mentally back out
   "modal must have failed half-way", look at "Pools without
   routes" (empty — the route DOES reference the pool), and
   conclude "it created a pool but not a route" — exactly the
   opposite of reality.

2. **Previous-sprint MED-04 (orphan pool).** Route fails to save
   (catch-all collision, validation error). Pool persists with
   `referenced_by_routes: []`. Operator now has an orphan pool
   they didn't know they were creating. Previous-sprint's
   compensating-delete shipped to mitigate this, but the
   underlying coupling design remains.

The Add Route modal is doing two things; the UI pretends it's
doing one. That's the root problem.

## Repro

(Same as HIGH-RU-01 and the operator's original report.)

## Expected

Add Route creates ONLY a route. Pool creation is a separate
explicit action.

## Actual

Add Route's "Forward to" composite control silently authors a
new pool whenever the operator picks the inline-backend path
(vs. the dropdown). The pool's identity inherits the route's
ID, which leads to a name collision the moment the operator
creates a second route pointing at the same backend hostname.

## Suggested fix

**Decouple pool creation from route creation in the UI.** The
backend already supports this — `PUT /api/upstreams/pool/{id}`
is a separate endpoint from `POST /api/routes`. The dashboard
just collapses them into one CTA today.

Two recommended UX shapes, both meet the operator's mental
model:

### Option A — Two-step modal (recommended)

The Add Route modal becomes "Add route". The "Forward to" control
becomes:
- A dropdown of existing pools (always shown).
- A small "Create new pool…" link below the dropdown.

Clicking "Create new pool…" opens a SECOND modal (or expandable
panel) — "Create pool" — that takes pool name, members, scheme,
TLS, host_header, LB strategy. Saving this modal closes it,
selects the new pool in the Add Route dropdown, and the
operator continues with the route they were authoring.

Operator now has a clear two-step mental model:
1. Create pool (if needed)
2. Wire route to pool

The data-plane mutation contract doesn't change. Audit chain
gets two distinct events (`POOL_UPSERT` + `ROUTE_CREATE`)
instead of an ambiguous combined one — which is also better for
forensics.

### Option B — Keep the inline path, but make the side-effect explicit

The current "Forward to inline backend" path stays, but:
- The preview line at the bottom expands to be a full
  two-line "what this modal will do" block:
  ```
  This action will create:
    1. Pool 'znews-route' with member znews.vn:443 (https, TLS)
    2. Route 'znews-route' → pool 'znews-route' (ANY /news)
  ```
- The CTA changes from `Create route` to `Create route + pool`
  when the inline-backend path is in use.

Less work than Option A; less mental-model improvement.

**Recommendation:** ship Option A. The Create Pool modal also
becomes a useful destination from the page top — "I want to
add a pool first, then wire routes to it later" is a real
workflow today that has no entry point.

## Severity rationale

MEDIUM. The current shape **does work end-to-end** — when a
route + pool combo succeeds, the audit chain captures both and
the dashboard shows the route correctly. The friction is in
the failure modes (HIGH-RU-01, HIGH-RU-02) where the
silently-created pool turns the diagnostic into a guessing game.

Once HIGH-RU-01 and HIGH-RU-02 ship, this MED becomes less
operator-visible. But the underlying UX problem — modal does
two things, label promises one — remains. Recommend shipping
the decoupling next.

