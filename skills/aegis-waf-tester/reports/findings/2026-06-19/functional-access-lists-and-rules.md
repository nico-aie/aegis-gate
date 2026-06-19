---
id: 2026-06-19-functional-access-lists-and-rules
date: 2026-06-19T09:00Z
severity: INFO
area: dashboard / data-plane
component: access-lists, rules
status: open
test_mode: functional
target_admin: http://18.140.47.62:9443/
target_data: https://aiagent.waf-exams.info/
---

# Functional QC — Access Lists + Rules (post-login-fix deploy)

Login fix verified: admin logs in and the dashboard mounts cleanly
(single-node cluster). Then exercised the two Policy features end to end.
All test artifacts were cleaned up — blacklist, whitelist, and rules are
back to 0 at end of run.

## Access Lists — PASS (CRUD / CSRF / persistence / UI)
- **Mount + empty state:** clean ("No entries."), Blacklist/Whitelist tabs,
  Add entry, Bulk import, search, live counter bar.
- **Add (UI):** blacklist `cidr 203.0.113.0/24` and whitelist
  `ip 198.51.100.5` with detector-bypass `sqli,xss` — both added, success
  toast, rows render correctly (whitelist shows SQLI/XSS bypass badges).
  TYPE dropdown offers ip / cidr / asn / country.
- **Search filter:** "zzz-no-match" → "No matches… Clear the search to see
  all 1 entries." Correct.
- **Remove (UI):** confirm modal ("audit-mutated and cannot be undone"),
  then row removed for both lists.
- **CSRF gating (API):** `POST /api/blacklist` with **no** `x-csrf-token`
  → 403 `admin_csrf_invalid`; with a **wrong** token → 403
  `admin_csrf_invalid`. Mutations are properly double-submit gated.
- **Persistence (API):** entries returned by `GET /api/blacklist` /
  `/api/whitelist` with full shape
  `{id,kind,value,note,bypass,expires_at,created_at}`; deletions reflected
  immediately.

## Rules — PASS (CRUD / enforcement / edit / disable / delete)
- **Mount + empty state:** templates (Block by path / Block by IP / Allow
  trusted IP / Block suspicious header / Observe only), Simulator tab.
- **Create (UI):** "Block by path" template + custom YAML
  (`path_matches.contains: "/qa-rmgr-test-7788"` → `block.status: 403`).
  Toast "created · applied in 169 ms"; confirmed via `GET /api/rules`.
- **Runtime enforcement (data plane):** **VERIFIED.**
  - `GET /qa-rmgr-test-7788` → **403**, header `x-waf-rule-id:
    qa-rmgr-block-7788`, body `{"error":"blocked","rule_id":...}`.
  - Substring match `/foo/qa-rmgr-test-7788/bar` → **403** (same rule).
  - Clean path `/just-a-normal-path-9999` → **200**, rule `none`.
- **Edit:** changed `block.status` 403 → **429**; data plane then returned
  **429** on the matching path. Edit propagates to enforcement.
- **Disable:** `enabled:false` via API; data plane stopped enforcing
  (consistent 200) after a ~few-second propagation window.
- **Delete:** confirm modal, then `GET /api/rules` count 0 and the data
  plane returns 200 again — enforcement removed.

## Issues found

### MEDIUM — Data plane attributes all traffic to one upstream IP; X-Forwarded-For not honored
The WAF attributes **every** request (mine and the live attack traffic from
other exam users) to a single upstream/proxy IP (`192.177.x.x`); a spoofed
`X-Forwarded-For` had no effect on the attributed client IP, and the
`x-forwarded-*` headers were not present in the audited `request_headers`.
GeoIP also shows "GEOIP DB NOT LOADED".

Net effect for **Access Lists**: IP / CIDR / ASN / country entries are
matched against that single front IP, so per-client-IP blocking cannot
distinguish real clients — the only value that would actually match is the
shared front-proxy IP, and blacklisting it would block *all* traffic. This
also means Top Attackers / per-IP rate limiting see the proxy, not real
clients.

Because of this, **runtime enforcement of an IP/CIDR Access-List entry was
deliberately NOT triggered** in this run — the only way to do so here is to
blacklist the shared `192.177.x.x` front IP, which would briefly block every
user on the shared exam environment. The CRUD/CSRF/persistence path is fully
verified; the IP-match enforcement path was verified structurally (entry
stored + evaluated, HITS counter present) but not fired end-to-end.

Recommendation: confirm the real-client-IP / trusted-proxy configuration
(the WAF should parse `X-Forwarded-For` from the trusted front proxy, or be
positioned to see real client IPs) and load the GeoIP DB if country/ASN
rules are intended to work. If routing all clients through one IP is
intentional for the exam harness, note that Access-List IP rules are inert
by design in that setup. *(If you want, I can run a controlled block of the
front IP for a few seconds to prove the enforcement path — say the word,
since it momentarily affects all traffic.)*

### LOW — Mutations don't auto-refresh the Rules view
After Create, Disable, and Delete, the Rules list/detail did not update on
its own — it showed stale state (e.g. "No operator rules yet / 0 rules"
right after a successful create; the detail header still showed "Disable"
after the rule was disabled) until a manual **Refresh**. The underlying API
state was correct each time. Same pattern as the Access Lists status-bar
counter, which lagged by one poll. Cosmetic, but on a live console it can
make an operator think a mutation didn't take. Suggest re-fetching the
list/detail on mutation success.

### LOW — Disabled-rule enforcement propagation lag
Immediately after Disable (`enabled:false`), the data plane still enforced
the rule (429) for a couple seconds before settling to 200. Expected if the
data-plane rule table refreshes on an interval, but worth documenting so it
isn't mistaken for "disable didn't work."

## Severity rationale
Both features work for their core CRUD + CSRF + (for Rules) live
enforcement. Filed INFO overall as a passing functional round. The MEDIUM is
an environment/topology observation that makes IP-based Access-List
enforcement ineffective as currently deployed; the LOWs are UX polish.
