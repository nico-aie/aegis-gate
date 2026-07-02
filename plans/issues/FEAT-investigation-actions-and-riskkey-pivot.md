# Investigation page — end in actions, not dead ends: Simulator replay, drawer parity, risk-key counts + pivot

**Status:** 🔵 PLANNED (nothing implemented)
**Date:** 2026-07-02
**Scope agreed with Nico:** Simulator replay + Copy-as-cURL/Block/Whitelist drawer parity + risk-key unique counts + risk-key pivot. Everything else from the research (time-range chips, live risk card, node badges, CSV export) is out of scope here — see "Noticed, deferred".

---

## Verified groundwork (checked against `develop`, 2026-07-02)

- `PageInvestigation` (`pages.jsx:11704`): default view (detector/bot strip +
  last-200 audit table) + pivot view (ip / request_id / rule_id). Pivots
  filter **server-side** via `AuditFilter` (`admin_get.rs:449`,
  `/api/audit/since?ip=|rule_id=|request_id=`), with a client-side
  defence-in-depth pass for old binaries (`pages.jsx:11772`).
- **`fields.risk_key` coverage is complete where it matters**: stamped on
  EVERY allow (`accept.rs:2301`), detector blocks (`data_plane.rs:1322`),
  cumulative risk-score blocks (`:1634`), challenges (`:1769`) and 429s
  (`:4396`). Shape: `{ip, device_fp, session_present, key_hash}`; raw
  session never leaks (test-pinned, `data_plane.rs:3603`).
- **`key_hash` is a stable 16-hex bucket id** (`blake3(ip|device_fp|session)`
  truncated to 16, `data_plane.rs:4156`) — deterministic across nodes
  (fleet-merged rows group correctly) and unambiguous against the existing
  `detectKind` patterns (UUID / 32+-hex request ids / dotted IPs).
- The RequestDetail drawer **already renders** `key_hash`
  (`pages.jsx:861-868`) — inert text today.
- Investigation's drawer has ONE action ("Pivot on this IP",
  `pages.jsx:12144`); the Live Feed drawer has Block IP / Whitelist /
  Copy-as-cURL via `quickAccessListAdd` + `copyAsCurl`, both **defined
  locally inside `PageLiveFeed`** (`pages.jsx:1097-1147`) — must be
  extracted to share.
- Simulator (post PR #114) accepts method / path / body / Host / headers /
  peer_ip — an audit event (at Debug+ verbosity, via `request_echo_fields`)
  carries all of these; at default Info verbosity it still carries
  method/path/peer IP, enough for a useful replay.
- `POST /api/risk/reset_key` exists (`admin_dispatch.rs:162`) — surgical
  single-bucket reset (node-scoped by design).
- Fleet path: `render_fleet_since(&events, limit, &filter)`
  (`admin_get.rs:499`) applies `AuditFilter` post-merge, so a new filter
  field automatically works on fleet-merged reads.

## Phases

### P1 — `risk_key` server-side audit filter (backend, TDD)

1. `AuditFilter` (`aegis-control/src/api/audit.rs`): add
   `risk_key: Option<String>`; a row matches when
   `event.fields.risk_key.key_hash == filter.risk_key`
   (case-insensitive compare; rows without the field never match).
2. Parse `risk_key=` in the `/api/audit/since` handler
   (`admin_get.rs:449`, next to ip/rule_id/request_id).
3. TDD (RED first): filter matches by key_hash; row without `risk_key`
   field doesn't match; combines AND with other filter fields; fleet
   `render_fleet_since` honors it post-merge.

### P2 — risk-key counts + pivot (frontend)

1. Pivot summary (`pages.jsx:11820` `summary` memo): count distinct
   `fields.risk_key.key_hash` → "Unique risk keys" card next to
   "Unique IPs" (`1 IP / 4 risk keys` = multiple devices/sessions behind
   one NAT — the composite key's whole point). Add a "Top buckets" table
   (key_hash → count, device_fp short + session yes/no axes) beside the
   detector breakdown when pivoting on an IP.
2. New pivot kind `risk_key`: dropdown option + `detectKind` auto-detect
   `/^[0-9a-f]{16}$/i` (checked BEFORE the request_id 32+-hex rule);
   `useAuditLogApi` gains a `riskKey` param → `risk_key=`.
3. Client-side defence-in-depth filter for old binaries (extend the
   existing `pages.jsx:11772` memo with the risk_key arm).
4. Entry points: drawer `key_hash` (`pages.jsx:864`) becomes
   "Pivot on this risk key"; key hashes in the Top-buckets table are
   clickable pivots.
5. UI honesty note on a risk-key pivot: row scores are values *at event
   time*, not the live bucket state.

### P3 — drawer action parity (frontend)

1. Extract `quickAccessListAdd` + `copyAsCurl` from `PageLiveFeed`
   (`pages.jsx:1097-1147`) into shared helpers (same file, module scope —
   they only need `window.accessListAdd` / clipboard + toast).
2. Investigation drawer footer gains **Copy as cURL**, **Block IP**,
   **Whitelist** (identical semantics/labels as Live Feed; Block/Whitelist
   audit-mutated via existing CSRF'd endpoints; keep "Pivot on this IP").

### P4 — "Replay in Simulator" (frontend)

1. Shared prefill channel: a small module-scope store (or
   `sessionStorage` key `aegis:simulator-prefill`) holding
   `{method, path, body?, host?, headers?, peer_ip}`.
2. Drawer button "Replay in Simulator" builds the prefill from the event
   (method/path from `fields`; peer IP from `client_ip`; headers/body
   from the redacted echo when present — strip `[redacted]` values) and
   navigates to `#/rules` with the Simulator tab active.
3. `RuleSimulator` consumes + clears the prefill on mount and (nice-to-
   have) auto-runs one simulate. Answers "would this request still be
   blocked after my rule change?" — the investigate → tune → verify loop.
4. Add the same button to the Live Feed drawer (same component, free).

### P5 — optional, LAST: "Reset this bucket" on a risk-key pivot

`POST /api/risk/reset_key` wired to a confirm-modal button on the
risk-key pivot header. Mutation (CSRF), node-scoped by design (say so in
the tooltip — matches the risk-reset scope contract). Defer if review
prefers read-only scope for this PR.

## TDD

- **P1 (Rust, RED→GREEN):** the four filter tests above in
  `api/audit.rs` (+ fleet render test where `render_fleet_since` lives).
- **P2–P4 (JSX):** no runtime harness — `build.sh` (hook-guard) + manual
  pass; keep new hooks aliased (`*P` in pages.jsx) and any shared helpers
  hook-free. Auto-detect regex gets a cheap Rust-side guard only if a
  16-hex collision with future id shapes appears (not expected).
- Manual script: pivot `203.0.113.7` → unique-keys card + top buckets;
  click a bucket → risk-key pivot filters server-side; drawer → cURL /
  Block / Whitelist / Replay in Simulator → Simulator opens prefilled and
  verdict matches the original action (same rules/mask).

## Acceptance

- [ ] `/api/audit/since?risk_key=<16hex>` returns only rows whose
      `fields.risk_key.key_hash` matches (local + fleet paths).
- [ ] IP pivot shows "Unique risk keys" + top-buckets; counts consistent
      with the events table.
- [ ] Pasting a 16-hex hash auto-detects as risk_key and pivots.
- [ ] Drawer key_hash pivots on click.
- [ ] Investigation drawer: Copy as cURL / Block IP / Whitelist behave
      identically to Live Feed.
- [ ] Replay in Simulator prefills method/path/peer-IP (+ headers/body at
      Debug+ verbosity) and produces a verdict.
- [ ] `cargo test --workspace` green; `build.sh` green; bundle < 800 KB.

## Risks

- **Redacted echo in replay** (LOW): `[redacted]` header values pasted
  into the simulator would change detector outcomes — strip redacted
  entries from the prefill and note "sensitive headers omitted".
- **Coverage gaps** (LOW, accepted): early-path rows (blacklist,
  connect-denied) and admin/system events carry no `risk_key` and won't
  match a risk-key pivot; document in the pivot hint.
- **reset_key blast radius** (LOW): single bucket, node-scoped, existing
  endpoint; confirm-modal + tooltip. Deferrable (P5).

## Noticed, deferred (do NOT lose)

- **Param-name mismatch bug:** `useAuditLogApi` sends `from`/`to`;
  backend parses `ts_from`/`ts_to` (`admin_get.rs:453`) — hook time
  params silently ignored. Fix alongside future time-range chips.
- Shareable pivot URLs (page reads `#/investigation?pivot=` deep-links
  but never writes the hash on manual pivot).
- Live cumulative-risk card via `GET /api/risk/<ip>`; node badges +
  node-selector parity (PR #115 follow-through); CSV/JSON export;
  path/UA pivot kinds (needs AuditFilter extension).

## Estimated complexity: LOW-MEDIUM
- P1 ~1h (TDD filter) · P2 ~2-3h · P3 ~1h · P4 ~2h · P5 ~1h (optional)
