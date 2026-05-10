# Phase 3 — MEDIUM fixes

> Source: `tests/n-tester/reports/findings/2026-05-07/F-MEDIUM-ALL.md` (M001–M009)
>
> Each item below has: short summary · proposed fix · acceptance · effort.
> Items marked **independent** can be parallelized; items marked **chain** depend on a prior item.

---

## M001 · UUID v4 variant nibble not RFC 4122 compliant *(independent)*

**Where:** `crates/aegis-proxy/src/admin_dispatch.rs:805-812`

**Today** — the UUID is built from a blake3 hash, with the version nibble masked to `4` but the variant nibble (group 4, first hex digit) left as-is. That violates RFC 4122 §4.1.1 which requires the variant to be one of `8`, `9`, `a`, `b`.

**Proposed fix** (one line):

```rust
let request_id = format!(
    "{}-{}-4{}-{}{}-{}",
    &h[0..8],
    &h[8..12],
    &h[13..16],
    // Mask top two bits to 0b10xx so the variant nibble is 8/9/a/b.
    format!("{:x}", (u8::from_str_radix(&h[16..17], 16).unwrap_or(0) & 0x3) | 0x8),
    &h[17..20],
    &h[20..32],
);
```

**Test:** existing UUID-format test should be updated to also assert the variant nibble matches `[89ab]`. Add a regression case using a hash that historically produced an invalid variant.

**Effort:** ~15 min. **Independent.**

---

## M002 · Scaling page missing mode override controls *(independent)*

**Where:** Dashboard — Scaling page

**Today** — the page shows three read-only status layers (Workers, Peers, Redis) plus a "Drain this node" button. The skill page inventory specifies normal/elevated/critical mode override + worker mode + force-apply controls; none present.

**Proposed fix:**

1. Add a "Load mode" card at the top of the Scaling page with three pill buttons (`normal | elevated | critical`) showing the current mode + a "Force apply" button.
2. Wire to `POST /api/loadmode { mode: "elevated", reason: "..." }` (audit-mutated, CSRF-gated).
3. Show a confirmation modal before applying critical (irreversible without manual revert).

**Test:** Cypress/Playwright integration test that flips through the three modes and verifies the audit chain records each transition.

**Effort:** ~1.5 hours. **Independent.**

---

## M003 · `#/routing` redirects to Overview *(independent — pairs with L004)*

**Where:** Dashboard SPA router

**Today** — the Routing & Upstreams page lives at `#/upstreams`. Bookmarks / docs using `#/routing` silently land on Overview.

**Proposed fix:** Add a redirect alias in the router config:

```js
// In the router's route table:
{ path: '/routing', redirect: '/upstreams' },
```

**Test:** Manual verification — `http://127.0.0.1:9443/dashboard/#/routing` lands on the Routing & Upstreams page.

**Effort:** ~5 min. **Independent.** (Closes M003 + L004 simultaneously.)

---

## M004 · Settings page missing UI for 4 backend features *(independent — can parallelise)*

**Where:** Dashboard — Settings page

**Today** — `/api/admin/sessions`, `/api/admin/break-glass`, `/api/integrations`, `/api/certs` all return 200 with valid data, but none are surfaced.

**Proposed fix** — add four sections to Settings (in order of operator value):

1. **Active Sessions** — table with `user`, `created_at`, `last_seen`, `ip`, `user_agent`, "Terminate" button per row. Wire to `GET /api/admin/sessions` + `DELETE /api/admin/sessions/{id}`.
2. **Break-glass** — toggle + reason input + expiry (default 60 min). Wire to `POST /api/admin/break-glass { active: true, expires_at: ..., reason: "..." }`.
3. **Integrations** — form for `grafana_url / alertmanager_url / gitops_url / prometheus_url`. Wire to `PUT /api/integrations`.
4. **Certs** — read-only card showing each cert's `subject`, `not_after`, `days_remaining`. Wire to `GET /api/certs`.

**Test:** Each section has an end-to-end test: load → mutate → reload → assert state changed.

**Effort:** ~3 hours. **Independent.** Largest single Phase 3 item.

---

## M005 · Access Lists missing search + expiry picker + bulk import *(independent)*

**Where:** Dashboard — Access Lists page

**Today** — the inline add form has type/value/note/bypass but no search, no expiry, no bulk import. The API supports `expires_at`.

**Proposed fix:**

1. Add a search input above the table (filter by `value`, `note`, `kind`).
2. Add an optional `expires_at` date-time picker in the add form.
3. Add a "Bulk import" button that accepts a CSV: `kind,value,note,bypass,expires_at`. Validates client-side, then sends one `POST /api/blacklist` per row (or a batch endpoint if available).

**Test:** Add 5 entries via bulk import, verify they all appear; use search to filter by note prefix.

**Effort:** ~2 hours. **Independent.**

---

## M006 · Reports page 2/4 not wired *(independent)*

**Where:** Dashboard — Reports page

**Today** — Audit trail (200 / 1000 events) reports work; "Top attackers (last 7d)" and "Compliance snapshot" show "not wired yet".

**Proposed fix:**

1. **Top attackers (7d)**: wire to `GET /api/attacks/top?window=604800` + render as CSV (`ip, country, asn, blocks, last_seen, top_detector`).
2. **Compliance snapshot**: wire to `GET /api/config` + `GET /api/detectors` and render a JSON or PDF snapshot of the active compliance modes, detector mask, tier policy, and any currently-firing compliance violations.

Defer scheduled delivery (page subtitle currently disclaims it) to a follow-up — out of scope for this fix pass.

**Test:** Click each report button → CSV downloads with non-empty rows after `make mock-load-attacks`.

**Effort:** ~1.5 hours. **Independent.**

---

## M007 · Rule delete uses native `confirm()` — freezes Chrome tab *(independent)*

**Where:** Dashboard — Rules page

**Today** — clicking the trash icon triggers `window.confirm()` which blocks Chrome's message pump for 30+ seconds when extensions are installed.

**Proposed fix:** Replace with the existing custom React confirmation modal pattern (used elsewhere in the dashboard, e.g. for blacklist remove). The modal already handles the cancel / confirm flow + audit-mutated mutation.

**Test:** Click trash, see the React modal, confirm, see the rule deleted in the table without the tab freezing.

**Effort:** ~30 min. **Independent.** Easy win.

---

## M008 · Stale Redis peer with no ID / heartbeat *(independent)*

**Where:** `crates/aegis-proxy/src/cluster.rs` (peer registry) + Redis cluster keys

**Today** — peer entries stay in Redis indefinitely; the dashboard shows phantom DOWN peers from prior runs.

**Proposed fix:** Add a TTL on the peer heartbeat key. Existing heartbeat interval is presumably ~30s; set TTL to 2× that. Peers that don't refresh within 60s drop out of the registry. Operators won't see ghost DOWN entries.

**Concrete change** (search for the heartbeat publish path):

```rust
// In the heartbeat publisher:
redis.set_ex(format!("peer:{}", node_id), payload, 2 * heartbeat_interval).await?;
```

**Test:** Boot two WAFs, kill one without graceful shutdown, wait 90s, confirm the killed peer disappears from the Scaling page (vs persisting as DOWN).

**Effort:** ~45 min. **Independent.**

---

## M009 · SLO error budget exhausted *(chain — depends on C002)*

**Where:** Health & SLOs page; SLO burn-window machinery

**Today** — `data_plane_availability` SLO at 16% (budget 0%) due to AI over-firing (F-CRITICAL-002). This is a secondary effect; closing C002 will halt new burn but the historical window persists.

**Proposed fix sequence:**

1. **Wait** for C002 to land + verify production traffic shows healthy block rate (<5% on synthetic clean).
2. **Manually acknowledge** the firing alerts in the dashboard so they stop paging.
3. **Verify** the alert channel itself works:
   - Currently VipTalk channel returns 401 — likely a stale auth token. Cross-check `cfg.alerts.viptalk.token` against the live channel credentials.
4. After 24-72h of healthy data, the burn windows roll forward and the SLO recovers automatically.

**Test:** After C002 ships + 24h, confirm `data_plane_availability` actual climbs above 99.9%.

**Effort:** ~30 min of operator action (ack alerts, fix VipTalk token); no code change beyond C002. **Chain — depends on C002.**

---

## Sequencing notes for Phase 3

**Parallelizable** (any order, any contributor): M001, M002, M003, M004, M005, M006, M007, M008.

**Chain**: M009 (waits for Phase 1's C002).

**Recommended PR groupings:**

1. `fix(misc): UUID variant + #/routing alias + native confirm` (M001 + M003 + M007 — small + independent)
2. `feat(dashboard): Scaling page mode override` (M002)
3. `feat(dashboard): Settings page sessions/break-glass/integrations/certs` (M004)
4. `feat(dashboard): Access Lists search + expiry + bulk import` (M005)
5. `feat(dashboard): Reports — top attackers + compliance snapshot` (M006)
6. `fix(cluster): peer heartbeat TTL` (M008)
7. (post-C002) Manual operator action for M009

**Total estimated effort:** ~10 hours of focused work. Spread across 7 PRs makes review tractable.
