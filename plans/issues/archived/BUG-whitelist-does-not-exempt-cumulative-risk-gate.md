# BUG — whitelisting an IP does not stop `risk-score` blocks (whitelist only skips detectors, not the cumulative IP-risk gate)

- **Type:** BUG (access-list semantics / request decision pipeline)
- **Severity:** 🟠 MEDIUM-HIGH — an operator adds a trusted IP to the whitelist to stop it being blocked, but the IP keeps getting `risk-score` 403s. The whitelist visibly "works" (hit counter climbs) yet the source stays blocked, so the operator has no working lever short of resetting the IP's risk bucket by hand. Breaks the core operator mental model: *whitelist = trust this source*.
- **Status:** 🟢 Fixed — TDD: new `WhitelistTrust` classification + data-plane exemption. Archive on merge.
- **Found:** 2026-06-22, operator report (IP `192.177.62.55` whitelisted with empty `bypass`, still `BLOCK` / `risk-score`, IP RISK 100, 49 whitelist hits).
- **Fixed:** 2026-06-22 — see [Resolution](#resolution).
- **Area:** `crates/aegis-control/src/api/blacklist.rs` (`AccessListStore` matcher); `crates/aegis-proxy/src/data_plane.rs` (`handle_data_request_inner` — whitelist match site + cumulative-risk gate).

## Summary

A whitelist match short-circuits **only the detector chain**. The cumulative
IP-risk gate (the rung that emits `action: block`, `rule: risk-score`) runs
*downstream* of the whitelist bypass and never consulted it. So an IP that had
already accumulated cumulative risk (e.g. from earlier attack traffic) keeps
getting `risk-score` 403s after being whitelisted — the whitelist suppresses new
detector signals but does nothing about the reputation already in the bucket.

Worse, the per-entry `bypass` column (`[]`, `["all"]`, `["sqli","xss"]`) was
**inert at runtime** — read nowhere in the data plane. Empty, `all`, and a
specific detector list all behaved identically (skip the whole detector chain),
so there was no setting an operator could choose to get "fully trust this
source."

## Root cause (confirmed in code)

Trace for a whitelisted IP in `handle_data_request_inner`
(`crates/aegis-proxy/src/data_plane.rs`):

1. `on_whitelist = whitelist.matches(...).is_some()` — a pure boolean; the
   matched entry's `bypass` field is never read.
2. `bypass_detectors = on_whitelist || rule_allow` → detector chain skipped,
   `signals = []`.
3. The `if !signals.is_empty()` block (per-request detector block + malicious
   score record) is skipped entirely — whitelisting adds no new risk, but also
   clears none.
4. The request still falls into the **cumulative-risk gate**: `level =
   risk.level_with_for_key(...)` is computed from the *existing* composite-key
   score and, when it is `Block`, emits the `risk-score` 403
   (`data_plane.rs`, gate `match level { Block => … }`).

The whitelist bypass covered step 2 only. Nothing exempted step 4.

`AccessListStore::matches` returns `Option<String>` (entry id) and discards the
`bypass` field, so the data plane had no way to distinguish a full-trust entry
from a partial one even if it wanted to.

## Resolution

Make the previously-inert `bypass` column drive a real trust decision, and let
**full trust** exempt the IP from the cumulative IP-risk gate.

1. **New classification — `WhitelistTrust`** (`aegis-control/src/api/blacklist.rs`):
   - `Full` — empty `bypass` (the dashboard's default "Add to whitelist") **or**
     `bypass: ["all"]` (case-insensitive). Trust unconditionally: skip detectors
     **and** exempt from the cumulative IP-risk gate.
   - `Detectors([...])` — a specific list (e.g. `["sqli","xss"]`). Partial trust:
     detectors are skipped (unchanged behavior) but the cumulative gate **still
     enforces** on accumulated reputation.
   - `WhitelistTrust::from_bypass(&[String])` + `is_full()`.

2. **Matcher** — `AccessListStore::match_whitelist_trust(...)` returns the matched
   whitelist entry's `WhitelistTrust` instead of just its id. Both it and the
   existing `matches()` now funnel through one private `first_match` helper, so
   kind/expiry matching + hit-recording stay in exactly one place (and the
   whitelist hit counter still increments identically).

3. **Data plane** (`data_plane.rs`): the whitelist match site derives
   `whitelist_full_trust`; the cumulative-risk gate forces `level = Allow` when
   it is set, short-circuiting the lookup so neither a `risk-score` block nor a
   risk challenge can fire for a full-trust source. Decay
   (`record_clean_with_key`) still drains the bucket over time, and detectors are
   already skipped, so a full-trust source records no new malicious score.

### Why exempt rather than hard-clear the bucket

Forcing `level = Allow` makes the request pass without destroying the IP's
accumulated risk state / audit history; the bucket then decays naturally via the
existing clean path. A whitelisted source therefore stops being blocked
immediately, and its reputation drains on its own — no special "clear on match"
side effect that would surprise anyone reading the risk timeline.

### Tests (TDD)

`aegis-control/src/api/blacklist.rs` unit tests:

- `whitelist_trust_full_for_empty_bypass`
- `whitelist_trust_full_for_all_keyword_case_insensitive`
- `whitelist_trust_detectors_for_specific_list`
- `match_whitelist_trust_classifies_matched_entry` (empty-bypass IP → `Full`)
- `match_whitelist_trust_returns_detectors_for_partial_entry`
- `match_whitelist_trust_returns_none_on_miss`
- `match_whitelist_trust_records_hit_like_matches` (hit-counter parity with `matches`)

All 25 access-list tests pass; `aegis-proxy` builds clean; no new clippy warnings
from the changed code.

## Operator-facing behavior after the fix

- Add an IP to the whitelist with **no bypass** (default) → it is fully trusted:
  detectors skipped **and** exempt from `risk-score`. The previously-stuck IP
  goes green on its next request.
- `bypass: ["all"]` → same full trust, stated explicitly.
- `bypass: ["sqli","xss"]` → partial trust: a source you expect to trip those
  detectors is suppressed, but it can still be `risk-score`-gated if its
  cumulative reputation crosses the tier threshold.

## Notes / future work

- Per-detector *selective* suppression (only silence `sqli`/`xss` while still
  running the rest of the chain) is still not implemented — a `Detectors` entry
  currently skips the whole detector chain, same as before. What changed is the
  **full-vs-partial trust distinction now controls the cumulative gate**. Wiring
  `Detectors([...])` into `run_all_filtered` for true per-class masking is a
  follow-up.
- The strike-block gate (`risk-strikes`) and volumetric gates (blacklist, DDoS,
  rate-limit) intentionally still override whitelist — a whitelisted IP hammering
  the API can't escape strike/volumetric protection. Only the
  detector + cumulative-risk enforcement is now whitelist-exemptable.
