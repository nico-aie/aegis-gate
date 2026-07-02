# Access lists — surface (don't block) same-entry-on-both-lists conflicts

**Status:** 🔵 PLANNED
**Date:** 2026-07-02
**Reported by:** Nico ("are we good if a user adds the same item to both whitelist and blacklist?")

---

## Findings (verified in code, 2026-07-02)

**Runtime is correct + deterministic — blacklist wins.** The data plane
checks the blacklist first (`data_plane.rs:458`) and returns the 403 early
(`:487`) BEFORE the whitelist is consulted (`:498`). A source on both lists is
blocked — fail-closed, which is the right precedence. (Exception: a blacklist
entry under a `set_profile` **log_only** override falls through and the
whitelist then applies — consistent, since log_only means "don't block".)

**The gap is silence, not correctness.** No cross-list awareness anywhere:
- `AccessListStore` is per-list; `put()` (`blacklist.rs:356`) validates only
  the entry itself.
- `handle_access_list_post` (`admin_mutate.rs:4353`) mutates one store and
  never reads the sibling — even though `services` holds BOTH
  (`services.blacklist` / `services.whitelist`, `dashboard_services.rs:82-83`).
- The dashboard shows no conflict indicator in either list.

Realistic failure: an operator whitelists an IP expecting trust, doesn't know
it's also blacklisted (added earlier / by a threat-feed / automation), and
can't understand the continuing 403s. The config is contradictory and nothing
says so.

Entry shape (`blacklist.rs:201`): `{ id, kind, value, note, expires_at,
bypass }`. `kind ∈ {ip, cidr, asn, country}`. `id`s are independent per list,
so conflict detection must match on **(kind, normalized value)**, not id.
Stores expose `.list()` / `.get(id)`.

## Design

Additive + non-blocking. Do NOT change the enforcement path or hard-reject the
add (operators legitimately stage entries, and CIDR/country overlaps are
intentional). A conflict is a **warning**, surfaced on add and in the list view.

Scope conflict detection to **exact (kind, value) equality** — normalized
(trim; uppercase for `country`; the rest byte-exact). Do NOT attempt
CIDR-contains / ASN-membership / country-covers-IP overlap analysis: that's a
different, error-prone feature and out of scope here. State that boundary in
the response + docs so it isn't mistaken for full overlap detection.

## Phases

### P1 — sibling-conflict lookup (backend, TDD)

1. Add `AccessListStore::find_by_value(kind, value) -> Option<AccessListEntry>`
   (normalized match), TDD in `blacklist.rs`: exact hit, kind-mismatch miss,
   country case-insensitive, trims, absent → None.
2. In `handle_access_list_post`, after a successful `put`, look up the entry's
   `(kind, value)` in the **sibling** store (blacklist add → check whitelist,
   and vice-versa). Still return **201**; when a sibling match exists, add a
   `conflict` object to the response:
   ```json
   { "ok": true, "entry": {...},
     "conflict": { "list": "blacklist", "id": "...",
       "effect": "blacklist wins at request time — this whitelist entry has no effect until the blacklist entry is removed",
       "match": "exact value; CIDR/country overlap is not analyzed" } }
   ```
   The `effect` string is precedence-aware (names whichever list wins =
   always blacklist). TDD the handler wiring where feasible; at minimum unit-
   test `find_by_value` + a small helper that builds the conflict object from
   (added-kind, added-value, sibling-store) so the logic is covered without a
   full HTTP harness.
3. No change to `put`, `matches`, `match_whitelist_trust`, or the data plane.

### P2 — dashboard surfacing (frontend)

1. `accessListAdd` already returns the parsed JSON; when `resp.conflict` is
   present, show a warning toast: "Also on the {list} list — blacklist wins at
   request time; this entry won't take effect until the {list} entry is
   removed."
2. Access Lists view: compute the cross-list `(kind, value)` intersection from
   the two loaded lists and badge each conflicting row ("⚠ also blacklisted" /
   "⚠ also whitelisted", tooltip states blacklist precedence). Frontend-only
   derivation — no extra endpoint.
3. Keep it a badge, not a blocker: the row still renders/edits normally.

### P3 — docs

`docs/operator/traffic-gates.md` (access-list section): state the precedence
explicitly ("blacklist is evaluated before whitelist; a source on both lists
is blocked") and the exact-match caveat (no CIDR/country overlap analysis).

## TDD

- **P1 (Rust, RED→GREEN):** `find_by_value` cases above + conflict-builder
  helper (exact match → conflict names the sibling + blacklist-wins effect;
  no match → None; the effect string always names blacklist as the winner
  regardless of which list was added to).
- **P2/P3 (JSX/docs):** no runtime harness — `build.sh` hook-guard + manual:
  add an IP to blacklist, then whitelist the same IP → warning toast + badge
  on both rows; confirm the request is still blocked (unchanged enforcement).
- `cargo test --workspace` green baseline holds.

## Acceptance

- [ ] Adding a value already on the sibling list returns 201 with a `conflict`
      object naming the sibling entry + the blacklist-wins effect.
- [ ] No conflict object when the value isn't on the sibling list.
- [ ] Enforcement unchanged — a both-lists source is still blocked (blacklist
      precedence; no data-plane edit).
- [ ] Dashboard: warning toast on conflicting add + ⚠ badge on both rows.
- [ ] Docs state precedence + exact-match caveat.
- [ ] `cargo test --workspace` green; `build.sh` green.

## Risks / non-goals

- **CIDR / country / ASN overlap** (e.g. blacklist `10.0.0.0/8` + whitelist
  `10.1.2.3`) is NOT detected — only exact (kind, value) equality. Called out
  in the response + docs so it isn't mistaken for full overlap analysis. A
  future track could add containment analysis if operators ask.
- Zero change to the security-critical enforcement ordering — purely additive
  observability.

## Estimated complexity: LOW
- P1 ~1.5h (TDD) · P2 ~1.5h · P3 ~20m
