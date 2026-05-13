---
id: 2026-05-12-ux-proposals-routing-upstreams
date: 2026-05-12T13:15Z
severity: INFO
area: dashboard
component: routing-upstreams
status: proposal
test_mode: full-qc
---

# UI/UX redesign proposals — Routing & Upstreams

The operator's repro this sprint surfaced a real conceptual gap
in the page. Today the dashboard collapses two distinct
resources (routes + pools) into one CTA (`+ Add route`), and
the failure modes (HIGH-RU-01 — broken TLS, HIGH-RU-02 — stale
client cache, previous-sprint MED-04 — orphan pool) all share
the same root cause: the operator doesn't have a clean mental
model of "pool" vs "route" because the UI doesn't separate
them.

This doc proposes a focused redesign of the page around an
explicit two-resource model.

---

## RU-P1 — Split the page into two columns: Pools (left) + Routes (right)

**Why.** "Pool" and "route" are different resources with
different lifecycles. A pool can exist without routes (operator
pre-stages backends before wiring traffic). A route always
references one pool. Today both share one route-shaped table,
with "Pools without routes" as a footnote expandable — which
reverses the natural mental model.

**What.** Two-column layout:

```
+------------+ +----------------------------------------+
| Pools (3)  | | Routes (2) · LIVE · AUDIT-MUTATED       |
| + New pool | | + New route                  ▼ Test    |
|            | |                                        |
| stub-pool  | | #1  ANY  */news → znews-route          |
|  auto      | |     LOW · open · IDLE   [Edit][Delete] |
|  1 member  | |                                        |
|            | | #2  ANY  */ catch-all                  |
| znews-route| |     stub-pool · LOW · open · IDLE      |
|  https     | |     FALLBACK [Edit][Delete]            |
|  2 members | |                                        |
|            | |                                        |
+------------+ +----------------------------------------+
```

Click a pool on the left → expand the pool detail in-place
(members, scheme/TLS, LB strategy, health, "routes using me"
backlink). Click a route on the right → expand route detail
(pool reference, path/method matching, tier, auth).

**Size.** Medium. ~6h dashboard refactor. No backend changes
— same `/api/upstreams` + `/api/routes` endpoints.

**Expected impact.** Operator sees "I have N pools and M routes,
each is its own thing". HIGH-RU-01 becomes self-diagnosable
because the pool surface shows the broken `scheme: https, tls:
false` directly. MED-RU-03 (modal-couples-creation) goes away.

---

## RU-P2 — Decouple "Create pool" from "Create route" (closes MED-RU-03)

**Why.** See MED-RU-03 for the conceptual argument.

**What.** Two separate modals:

### `+ New pool` modal
```
+ New pool
─────────────────────────────────────────
Pool name *           [ my-api-pool ]
─────────────────────────────────────────
Members
  + Add member
  • api.example.com:443  weight:1  zone:_  host_header:_  ✕
  • 10.0.1.10:8080       weight:1  zone:_  host_header:_  ✕
─────────────────────────────────────────
Load balancing       [ Round-robin    ▾ ]
Scheme               [ HTTPS (auto-TLS) ▾ ]
                       (consequences shown below)
                     This pool will use TLS handshake to upstream.
                     SNI = host_header, falling back to hostname.

▶ Health check (off · expand to configure)
▶ Circuit breaker (off · expand to configure)
▶ Connection pool (defaults · expand to override)

                                [Cancel] [Create pool]
```

### `+ New route` modal
```
+ New route
─────────────────────────────────────────
Route ID *      [ my-api-route ]
Path *          [ /api/v1 ]    Host (optional)  [ * ]
Methods         [ ANY ▾ ] or [GET][POST]…
─────────────────────────────────────────
Forward to *    [ — pick a pool —              ▾ ]
                 my-api-pool · https · 2 members
                  + Create new pool…   ← opens the modal above
─────────────────────────────────────────
▶ Advanced (match_type, tier, auth, …)

Preview:  ANY /api/v1 → my-api-pool
                                [Cancel] [Create route]
```

The "Forward to" picker is now a pure dropdown. The "+ Create
new pool…" link below opens the Create pool modal as a nested
flow; on save it auto-selects the new pool in the dropdown.

Operators who don't want a route yet (just stage a pool) hit
"+ New pool" directly. Operators who already have a pool wire
a route without creating anything else.

**Size.** Medium. ~4h dashboard. Same backend.

**Expected impact.** Closes MED-RU-03 cleanly. Also surfaces
the Create-pool-then-wire-routes-later workflow that today has
no UI entry point.

---

## RU-P3 — Scheme picker drives TLS automatically (closes HIGH-RU-01 from the UI side)

**Why.** See HIGH-RU-01.

**What.** In the Pool modal, the Scheme dropdown becomes the
canonical TLS control:

| Scheme value | Operator-visible label | TLS state | TLS checkbox |
|---|---|---|---|
| `auto` | Auto (negotiate via TLS toggle) | derived from `tls` flag | shown, editable |
| `http` | HTTP (plain, no TLS) | always off | hidden |
| `https` | HTTPS (TLS, h1/h2 ALPN) | always on | hidden |
| `h2c` | h2c (HTTP/2 cleartext) | always off | hidden |
| `grpc` | gRPC (HTTPS + h2) | always on | hidden |
| `tcp` | Raw TCP tunnel (CONNECT) | n/a | hidden |

When scheme is not `auto`, the TLS checkbox is removed from
the modal (or shown disabled with a "derived from scheme"
hint). The pool save body carries the right `tls` value
automatically.

**Size.** Small. ~1h dashboard. Server change is the
follow-up from HIGH-RU-01 — make `tls` derived rather than
independent.

**Expected impact.** Closes HIGH-RU-01 at the UI surface.
Operators can't accidentally save a mismatched scheme/TLS
combo.

---

## RU-P4 — Pool detail surface: live "is this actually working?" probe

**Why.** After HIGH-RU-01 + HIGH-RU-02 are closed, operators
still don't know whether their pool *actually works* until
they curl through the data plane and read the response. The
dashboard knows the pool's address; it knows the scheme; it
could test for them.

**What.** In the Pool detail view (RU-P1's left-column expand),
add a "Test connection" button:

```
Pool 'znews-route'
  https · 2 members · 0 reqs/min · IDLE
                                                [Test connection]
  Members
   42.112.59.10:443  weight 1  zone -  host_header znews.vn   ✕
   42.112.59.12:443  weight 1  zone -  host_header znews.vn   ✕

  [Test connection] runs a HEAD against the first member with
  the configured scheme + TLS. Reports per-member: TCP connect
  + TLS handshake + first-byte time + upstream status.
```

When clicked:

```
Test result · 12:13:45 PM
  42.112.59.10:443
    TCP connect    OK   13 ms
    TLS handshake  OK   42 ms  (CN: *.znews.vn, exp: 2026-08-20)
    HEAD /         200  88 ms
  42.112.59.12:443
    TCP connect    OK   16 ms
    TLS handshake  OK   47 ms  (CN: *.znews.vn, exp: 2026-08-20)
    HEAD /         200  91 ms
```

If TLS handshake fails:
```
  TLS handshake  FAILED  "tls record overflow" — the upstream
                          may be plain HTTP. Check scheme on
                          the pool.
```

This surfaces HIGH-RU-01 / HIGH-RU-02 / cert expiry / NX-record
/ wrong host_header / firewall / etc. all from one button.

**Size.** Medium. ~half day. New `POST /api/upstreams/pool/{id}/probe`
endpoint that does the multi-stage test from the WAF host
(operators get the WAF's view, not the dashboard's).

**Expected impact.** Pool debugging stops being a "curl through
the data plane + read upstream error" exercise. Operators get a
one-click "is this wired right?" answer.

---

## RU-P5 — Surface the `tls` mismatch as a route-row warning chip

**Why.** Even with HIGH-RU-01 closed for new creates, existing
pools (loaded from `waf.yaml`, GitOps applies, etc.) may carry
the same mismatch. The dashboard should surface it.

**What.** In the Routes table, if a route's pool has
`scheme: "https" | "grpc"` but `tls: false` (or scheme: http
but tls: true), render a small warning chip in the FORWARDS
TO column:

```
FORWARDS TO
znews-route (https · 2 members) ⚠ TLS mismatch
  ↳ 42.112.59.10:443, 42.112.59.12:443
```

Hover/click the chip → tooltip: "Scheme says HTTPS but TLS
flag is false. Upstream connection will be plain HTTP and
will fail against TLS upstreams. Edit pool → toggle TLS on or
switch scheme to 'auto'."

**Size.** Small. ~30 min. Static check on the config GET.

**Expected impact.** Diagnoses the broken-pool case
proactively, even when the operator didn't create it.

---

## RU-P6 — "Test route" button at the page top: simulate a request

**Why.** There's already a `▼ Test route` button at the top of
the page (today an expandable). The previous-sprint shipped
the Rule Simulator (Rules page); the Top Attackers Pivot does
audit-trail filtering; the Investigation page does post-mortem.
But there's no "Test route" surface that actually answers
"which route + pool would a given hypothetical request hit?".

**What.** The `Test route` expandable becomes a richer panel:

```
Test route                                           [ ✕ Close ]
─────────────────────────────────────────────────────────────
Method   [ GET ▾ ]   Host  [ znews.vn      ]
Path     [ /news/foo       ]
Headers  [ + Add header     ]

                                                  [Test route]
─────────────────────────────────────────────────────────────
Result · 13:14:22 PM

  Matched route:    znews-route   (priority #1)
    Path:           /news     prefix
    Host:           *
    Methods:        ANY

  Forwards to:      znews-route (https · 2 members)
                    selected member: 42.112.59.10:443
                    host_header sent: znews.vn

  Detector chain:   (would be skipped; this is a route-resolution test only)
```

Operators can paste hypothetical requests and see which
route fires + which pool + which member. Catches "the
catch-all swallows my /news route" before traffic hits.

**Size.** Medium. ~4h. New `POST /api/routes/resolve` endpoint
(no actual forwarding, just the resolution logic). Dashboard
form.

**Expected impact.** Pre-traffic verification becomes a
dashboard primitive. "Did I author the routes in the right
order?" gets a 1-second answer.

---

## RU-P7 — Pool/route audit-chain timeline below each resource

**Why.** Same shape as the Observability "Per-layer change log"
proposal (OBS-P4 from last sprint). When inspecting a pool, the
operator's first question is "when was this last changed?".

**What.** Each pool detail and route detail expansion gets a
"Recent changes" footer pulling from
`/api/audit/since?resource=/api/upstreams/pool/<name>` (or the
route equivalent). Shows last 5 mutations with timestamp,
actor, action, source (DASHBOARD / GITOPS / YAML), and an
"open in Audit Trail" link to widen the view.

**Size.** Small. ~1h per surface; the Audit Trail filtering
already exists.

**Expected impact.** "Did anyone touch this pool today?" zero-
click answer.

---

## RU-P8 — "Pools without routes" becomes "Unrouted pools" with a clear lifecycle CTA

**Why.** The current "Pools without routes" affordance is a
small expandable below the table that operators easily miss
— and that's exactly where orphan pools live (previous-sprint
MED-04 root cause).

**What.** With RU-P1's two-column layout, "Pools without
routes" goes away as a separate section — every pool is now
visible in the left column. Pools without routes get a small
"unrouted" pill in their summary chip:

```
Pools (3)              + New pool
─────────────────────────────────────
  stub-pool
    auto · 1 member · 1 route
  znews-route
    https · 2 members · 1 route
  test-orphan
    http · 1 member · UNROUTED  ⓘ
```

Hover the `UNROUTED ⓘ` → tooltip: "This pool has no routes
referencing it. Operators sometimes pre-stage pools before
wiring traffic; if this wasn't intentional, consider deleting
it." + a "Delete pool" inline action.

**Size.** Small. ~1h once RU-P1 lands.

**Expected impact.** Orphan pools stop being a hidden state.
Operators clean up after failed route creates without going
hunting.

---

## Priority ordering

| # | Proposal | Effort | Operator impact |
|---|---|---|---|
| RU-P3 | Scheme drives TLS automatically | S | **HIGH** — closes the dashboard half of HIGH-RU-01 |
| RU-P5 | TLS-mismatch warning chip on existing routes | S | **HIGH** — surfaces broken pools already in config |
| RU-P2 | Decouple Create Pool from Add Route modal | M | **HIGH** — closes MED-RU-03 + maps to operator mental model |
| RU-P4 | Pool "Test connection" probe | M | **HIGH** — pre-traffic diagnostics |
| RU-P1 | Two-column page layout (Pools / Routes) | M | Medium — bigger refactor, enables RU-P7/P8 |
| RU-P6 | Page-top "Test route" resolver | M | Medium — pre-traffic route-order debugging |
| RU-P7 | Per-resource audit timeline | S | Medium — provenance |
| RU-P8 | "Unrouted" pill on pools | S | Medium — orphan visibility |

Ship RU-P3 + RU-P5 first — both are <2h and close the
operator's specific repro. Then RU-P2 + RU-P4 for the
conceptual fix + the diagnostic surface. RU-P1 / P6 / P7 / P8
follow as a connected refactor.

