---
id: 2026-05-12-admin-info-bundle
date: 2026-05-12T08:33Z
severity: INFO
area: various
component: pass-observations
status: documented
test_mode: full-qc
---

# INFO — passing observations on the Admin section

## INFO-ADM-01 — Help & Guide FAQ tab is exceptional documentation

The FAQ tab carries 8+ operator-grade Q&A entries that read like
they were written by someone who has actually answered these
questions on call. Examples:

- *"A request shows IP risk = 100 but the action is ALLOW. Bug?
  — No. The IP risk column is the cumulative IP risk score for
  that client IP — it accumulates across requests and decays
  over time (default half-life 5 min). A single request can be
  allowed (it didn't trigger any detector this time) while the
  IP carries high cumulative risk from earlier hits. To make
  cumulative IP risk also block, lower `risk.thresholds.block_at`
  from Traffic Gates → 'Cumulative IP risk thresholds' (next to
  Strike-Block). Watch out for false positives if legitimate
  users share an IP (NAT / corporate proxy)."*
- *"How do I test a route by hostname? — Two options: (1)
  `curl -H 'Host: vnexpress.net' http://127.0.0.1:8080/news` —
  overrides the Host header per request, no DNS changes. (2) For
  HTTPS, `curl --resolve vnexpress.net:8443:127.0.0.1
  https://vnexpress.net:8443/news` — tells curl to send SNI for
  vnexpress.net to localhost. See
  docs/operator/upstream-cookbook.md Recipe 3.5."*
- *"What's the difference between Rate Limit and the DDoS gate?
  — Both are per-IP 'limit + window' gates but with opposite
  enforcement: Rate Limit returns 429 with automatic recovery as
  the window slides — designed for steady-state per-IP API
  budgets where misbehaving clients should back off and retry.
  DDoS gate returns 403 with a 5-minute TTL'd quarantine —
  designed for sustained-burst quarantine where the IP is
  flooding..."*

This is the kind of docs that turn a SOC dashboard from "I
clicked Block, what happens next?" into "I understand the
system." Keep these answers in lockstep with the code.

## INFO-ADM-02 — Settings Config history with versioned audit-chained mutations

Config history #62 shows every mutation in newest-first order
with VERSION / TIME / ACTION / REASON / ACTOR / SOURCE columns
and a `▶` expand affordance. My recent `INCIDENT_ACK` mutations
land here even though the corresponding overlay state didn't
read back (MED-ADM-01) — so the chain is honest even when the
overlay isn't.

The integration with the dashboard's "DASHBOARD" SOURCE chip is
the right shape: operators distinguish "I clicked this in the
UI" from "an automated GitOps apply landed this" without
ambiguity.

## INFO-ADM-03 — Response Filtering toggle round-trip is operator-grade

Flipping a rung in the Settings Response Filtering card:

1. Click the toggle.
2. Toast appears bottom-right within ~50 ms:
   `Response filter · redact_dlp off` (or `on`).
3. The next GET of `/api/response-filter` confirms the new
   state.
4. The Audit chain captures the mutation.
5. Flip back → toast `Response filter · redact_dlp on`,
   API confirms.

The subtitle copy is also operator-grade: *"Hot-reloadable via
audit-mutated PUT /api/response-filter · applied to every
upstream response body via `Pipeline::on_body_frame`"* — operator
knows exactly which endpoint mutates state and which Rust
function applies the filter.

## INFO-ADM-04 — mTLS Allowed SANs has a Test admit probe

The Settings → mTLS Allowed SANs card has a built-in "Test
admission for a candidate SAN" input that lets operators check
whether a hypothetical client cert SAN would be admitted by the
current allow-list before adding it. Smart UX — prevents the
"I added a wildcard that's too broad" mistake.

## INFO-ADM-05 — Reports page has the right minimum viable shape

Four export cards, four download buttons, one subtitle that's
honest about the deferred functionality ("scheduled delivery
not built yet"). No clutter, no fake date pickers. When the
scheduled-delivery feature does land, the natural shape is a
fifth card "Scheduled deliveries" — easy to add without
restructuring.

## INFO-ADM-06 — Help & Guide cross-page links navigate, not just rewrite hash

The 7 "Open <page> →" CTAs on the Get started tab actually do
navigate to the destination page (verified at the SOC-scenario
level last sprint when Top Attackers' Pivot link was identified
as one of the right surfaces). No `#/something` rewrites without
page mount.

## INFO-ADM-07 — Audit Trail captures the action even when the dashboard surface partially fails

MED-ADM-01 shows the ack overlay isn't reading the write back —
but Audit Trail + Config history both capture the `INCIDENT_ACK`
mutation correctly. So even when the dashboard's lifecycle UI
silently fails, the audit chain is honest. This is the right
priority — chain integrity over UI overlay.

