# Medium findings — 2026-05-07

---

## F-MEDIUM-001 · UUID v4 variant nibble not RFC 4122 compliant

**Component:** `crates/aegis-proxy/src/admin_dispatch.rs` lines 805–812  

The `request_id` written to `waf_audit.log` is formatted as a UUID v4 string. The version nibble (group 3, first hex digit = '4') is correct. The variant nibble (group 4, first hex digit) is NOT masked to the required RFC 4122 variant range (8, 9, a, or b).

**Observed:** `"request_id":"1c418736-8f45-4097-4f0c-9a06172e4264"` — group 4 starts with '4' (invalid variant).

**Fix:**
```rust
// Before:
&h[16..20],   // variant nibble not enforced

// After:
&format!("{:x}{}", (u8::from_str_radix(&h[16..17], 16).unwrap_or(0) & 0x3) | 0x8, &h[17..20]),
```

---

## F-MEDIUM-002 · Scaling page missing mode override controls

**Component:** Dashboard — Scaling page  

The skill page inventory specifies "Mode override (normal / elevated / critical), worker mode, force apply" controls on the Scaling page. None of these controls are present. The page only shows Refresh and "Drain this node" buttons plus three read-only status layers (Workers, Peers, Redis).

**Impact:** Operators cannot change the WAF scaling mode (which affects rate limits and block thresholds) from the dashboard. The only path is via direct API call.

**Fix:** Add the mode override section with normal/elevated/critical selector and a "Force apply" button wired to `POST /api/loadmode`.

---

## F-MEDIUM-003 · `#/routing` hash fragment redirects to Overview

**Component:** Dashboard SPA router  

Navigating directly to `http://127.0.0.1:9443/dashboard/#/routing` renders the Overview page. The correct hash for the Routing & Upstreams page is `#/upstreams`. Any bookmarks, documentation links, or cross-links that use `#/routing` will silently land on Overview.

**Fix:** Add a route alias: `{ path: '/routing', redirect: '/upstreams' }` in the router config.

---

## F-MEDIUM-004 · Settings page missing UI for 4 backend features

**Component:** Dashboard — Settings page; APIs: `/api/admin/sessions`, `/api/admin/break-glass`, `/api/integrations`, `/api/certs`  

All four API endpoints return 200 with valid data, but none are surfaced in the Settings UI:

- `/api/admin/sessions` — session list + terminate session (security operations)
- `/api/admin/break-glass` → `{"active":false,"expires_at":null,"reason":null}` — break-glass toggle
- `/api/integrations` → grafana/alertmanager/gitops/prometheus URLs (all null, wirable)
- `/api/certs` → cert list (one cert loaded: localhost/aegis-gate.local, 357d remaining)

**Impact:** Operators cannot terminate sessions, enable break-glass, configure integrations, or inspect cert expiry from the dashboard. All require direct API calls.

**Fix:** Add four new Settings sections: Active Sessions (with terminate), Break-Glass toggle, Integrations form (grafana/alertmanager/gitops/prometheus), and Cert freshness card.

---

## F-MEDIUM-005 · Access Lists missing search input and expiry picker

**Component:** Dashboard — Access Lists page  

The "Add entry" inline form has: type selector (ip/cidr/asn/country ✓), value field ✓, note field ✓, bypass field ✓ — but is missing:

1. **Search/filter input** — no way to search a large blacklist by value, note, or type.
2. **Expiry date picker** — entries can only be created as "never expires". The API supports an `expires_at` field but the UI has no control for it.
3. **Bulk import** — the skill inventory lists "bulk import" as an expected control; not present.

**Fix:** Add a search input above the list table, an optional expiry date-time picker in the add form, and a bulk import button (CSV format: `kind,value,note,bypass,expires_at`).

---

## F-MEDIUM-006 · Reports page has 2 of 4 types "not wired yet"

**Component:** Dashboard — Reports page  

| Report | Status |
|---|---|
| Audit trail (last 200 events) | ✓ Download CSV |
| Audit trail (last 1000 events) | ✓ Download CSV |
| Top attackers (last 7d) | ❌ "not wired yet" |
| Compliance snapshot | ❌ "not wired yet" |

The page subtitle also notes "scheduled delivery not built yet".

**Fix:** Wire up Top Attackers report via `/api/attacks/top?window=604800` and Compliance snapshot via `/api/config` + `/api/detectors`. Add scheduled delivery option (daily/weekly email or webhook) in a future iteration.

---

## F-MEDIUM-007 · Rule delete button triggers native confirm() dialog, freezes tab

**Component:** Dashboard — Rules page  

Clicking the red trash icon on a rule triggers a browser-native `window.confirm()` dialog. During testing, this froze the Chrome tab for 30+ seconds (the browser extension's message pump is blocked by the synchronous confirm). The tab became unresponsive until the dialog was dismissed.

**Fix:** Replace `window.confirm()` with a custom React confirmation modal (already used elsewhere in the dashboard for destructive actions, e.g., blacklist remove).

---

## F-MEDIUM-008 · Scaling page shows stale "DOWN" peer with no ID or heartbeat

**Component:** Dashboard — Scaling page; Redis peer registry  

The Scaling page Layer 2 (Cluster peers) shows one peer entry with:
- No node ID (blank)
- No last heartbeat timestamp  
- Status: DOWN  

This is a stale Redis record from a prior run that was never cleaned up. It causes unnecessary alarm for operators.

**Fix:** Add a TTL to peer heartbeat keys in Redis (e.g., 2× the heartbeat interval). Peers that have not sent a heartbeat within the TTL should be automatically evicted from the registry rather than shown as DOWN indefinitely.

---

## F-MEDIUM-009 · SLO error budget exhausted (secondary effect of F-CRITICAL-002)

**Component:** Health & SLOs page; `data_plane_availability` SLO  

The `data_plane_availability` SLO shows 16.00% actual vs 99.90% target — 0% error budget remaining. Three DataPlaneAvailability alerts are firing (1h PAGE + 6h TICKET + 72h TICKET). This is a direct secondary effect of the AI over-firing issue (F-CRITICAL-002).

**Note:** This is listed as a separate medium finding because even after F-CRITICAL-002 is resolved, the SLO burn window data will persist and the alerts may remain firing until the burn window clears. The team should manually acknowledge/resolve the alerts and verify the SLO recovers after the threshold fix.

**Fix:** After resolving F-CRITICAL-002, verify the alert channel (currently returning 401 UNAUTHORIZED from VipTalk) is correctly configured so resolved alerts can be acknowledged.
