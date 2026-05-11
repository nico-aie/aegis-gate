---
id: 2026-05-11-unreferenced-pool-survives-failed-route
date: 2026-05-11T17:24Z
severity: MEDIUM
area: dashboard · admin-api
component: upstreams · add-route-modal
status: open
test_mode: full-qc
---

# Pools created in the Add Route modal persist even when the route save fails

## Summary

The Add Route modal lets operators define a backend (`example.com:443`)
inline; behind the scenes the dashboard creates a pool *and* a route
in one operator action. When the route save fails (catch-all
collision, validation error, etc.), the **pool is already persisted**
but no route references it. The next state the operator sees is
"Pools without routes · 1 UNREFERENCED" — and the modal that just
failed gives no breadcrumb back to clean up that orphan.

Concretely: after MED-02's repro, the `qa-dns-route` pool with two
resolved IPs sits in the "Pools without routes" list, while the
operator believes "the save failed, nothing happened".

## Repro

1. Sign in, navigate to **Routing & Upstreams**.
2. Click **+ Add route**, type Route ID = `qa-dns-route`, leave Host
   blank, leave Path `/`, in "Type a new backend" type
   `example.com:443`. Click **Create route**.
3. Save fails with the catch-all collision toast.
4. Close the modal (Cancel or ×).
5. Observe the page: "1 route → 2 pools (3 members, 1 unreferenced)".
   Expand "Pools without routes" — `qa-dns-route` is there with 2
   members.

## Expected

Either:
- **A** (atomic): pool creation is part of the route transaction;
  rollback on route failure leaves no pool behind.
- **B** (explicit): the modal warns "this will create pool X first
  even if the route validation fails — you may need to delete it
  manually" so the operator can opt in to the two-step write.

## Actual

Silent two-step write. The pool is committed, the route isn't. The
operator has to navigate to "Pools without routes" → Delete and
type the pool name from memory to recover. The dashboard never
mentions it; only the unreferenced count moves up by 1.

## Suggested fix

Atomic (A) is correct: implement the route-create at the API level
as a two-stage transaction (create the pool, attempt the route, if
the route fails delete the pool). The current `/api/upstreams/pool/<id>`
PUT + `/api/routes` POST split makes this trickier than it sounds,
but a server-side endpoint that takes `{route, optional_new_pool}`
in one call would solve it cleanly.

Failing that, (B) — surface a one-line note in the modal: "If the
route save fails after the pool is created, the pool will be left
unreferenced. You can delete it from 'Pools without routes' below."

## Severity rationale

MEDIUM. The orphaned pool doesn't break anything — it doesn't serve
traffic until a route references it — but it accumulates state the
operator doesn't expect, and the cleanup path is non-obvious. In a
GitOps shop where configs round-trip through git, an orphan would
also create a diff against the committed YAML.

