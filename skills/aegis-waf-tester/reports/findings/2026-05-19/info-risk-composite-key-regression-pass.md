---
id: 2026-05-19-info-risk-composite-key-regression-pass
date: 2026-05-19T13:10Z
severity: INFO
area: dashboard + data-plane
component: risk-composite-key
status: open
test_mode: functional
---

# Re-test after dev fix: 7/7 acceptance scenarios pass

## Summary

Re-ran the developer's acceptance checklist after the
`feat/risk-composite-key-data-plane` change pushed the fix for
`high-top-risk-buckets-reset-button-broken-csrf.md`. The card moved
from Traffic Gates to a new "Composite RiskKey view" tab on Top
Attackers (`#/top-attackers?view=riskkey`), and `surgicalReset` now
routes through `window.csrfMutate` instead of the orphan
`window.getCsrfToken`. All seven acceptance scenarios pass.

## Results

**S1 — Two sessions on same IP → two buckets ✅**
Drove `sessionid=alice` (5 SQLi probes) and `sessionid=bob` (8 XSS
probes) against `http://127.0.0.1:8080`. `/api/risk?limit=50`
returned two clients on the same IP (`127.0.0.1`), differentiated
by `session`, alice=5 / bob=8 strikes. The RiskKey-view table on
the dashboard renders both rows with `device_fp: —` and the
truncated session prefix.

**S2 — Surgical reset works + audit fires ✅**
Clicked "Reset bucket" on alice's row. csrfMutate POSTed to
`/api/risk/reset_key` with body
`{"ip":"127.0.0.1","device_fp":null,"session":"alice"}` and got
back `{status:200, ok:true, had_state:true}`. Bob's row remained
(8 strikes), alice's row disappeared (api total dropped from 2 to
1). A `risk_reset_key` audit event landed with
`actor: "admin"`, `resource: "/api/risk/reset_key"`, diff_before
carrying the full composite key, diff_after `{score:0, strikes:0}`.

**S3 — Deep-link survives refresh ✅**
Navigated directly to `#/top-attackers?view=riskkey` from a fresh
tab (after re-login through the actual form, not via fetch). On
mount, the RiskKey table was rendered without a manual tab click,
and the "Composite RiskKey view" tab was active per its
`aria-selected` state.

**S4 — Group by IP toggle ✅**
With the two rows still in the table, clicking "Group by IP"
collapsed them into one summary row: `IP=127.0.0.1`,
`device_fp: —`, `session: —`, `score=100` (max), `strikes=8`
(max), action column shows "2 buckets" instead of "Reset bucket".

**S5 — DDoS still IP-keyed despite session rotation ✅**
Sent 600 sequential requests at ~563 RPS, rotating
`sessionid=rotate-{i%100}` per request. The data plane started
returning 403 for every request after the early ones. Single probe
after the burst confirmed the gate: `X-WAF-Rule-Id: ddos`,
`X-WAF-Action: block`. If DDoS were wrongly composite-keyed each
of the 100 sessions would have its own 1000/10s budget and the
burst would have walked through unblocked; instead the IP-keyed
volumetric guard fired and auto-blocked. Attackers cannot escape
DDoS via cookie rotation.

**S6 — Investigation "Risk score" column + tooltip ✅**
`#/investigation` carries a `<th>Risk score</th>` whose `title`
attribute reads (paraphrased): cumulative score for this request's
RiskKey bucket `{ip, device_fp?, session?}`, decays over time,
two browsers on the same NAT'd IP each carry their own bucket
score, NOT the score of this single request.

**S7 — No regression on plain HTTP ✅**
The data plane is HTTP `:8080` (no TLS). Every one of the 50
clients in `/api/risk?limit=50` has `device_fp` absent from the
JSON (None, serde omit-if-none), and 100% of the RiskKey-view
table rows render `device_fp: —`. Session axis is populated
where a cookie was present. The IP-only bucket on `127.0.0.1`
remains as a floor for cookieless traffic; rotating-session
buckets accumulate independently for the cookie-bearing requests.

## Suggested fix

None — closing the original HIGH finding. Two small follow-ups
worth tracking, both low-priority:

- The 2026-05-19 retest only exercised the HTTP data plane.
  `device_fp` only populates on TLS, so a smoke run against
  `https://127.0.0.1:8443` is still owed before this feature is
  fully exercised end-to-end.
- The `aegis_session` cookie was lost when re-authenticating
  via `fetch()` from the Cowork sandbox (`document.cookie`
  isolation), forcing a re-login through the real form via
  `form.requestSubmit()`. Not a product bug but worth noting in
  the skill so future runs use `form.requestSubmit()` for login
  rather than fetch-POST.

## Severity rationale

INFO — passing regression suite for the dev's fix. The earlier
HIGH finding can be closed.
