# Future: bot classifier — verification + enforcement

**Status:** planned / not started. The bot classifier ships today as an
**observational, opt-in gate** (`cfg.bots.enabled`, default `false`):
it labels each request `human / verified / suspect / malicious` from
**UA + ASN** signals and feeds Investigation → "Bot classification mix"
+ the audit `fields.bot_category`. It does **not** block, challenge, or
contribute to the risk score, and two of its buckets never fire because
their signals aren't wired. Contract: **not required** (bonus surface).

Source: `crates/aegis-security/src/bots.rs`, listener call in
`crates/aegis-proxy/src/accept.rs`. Docs: `docs/security/bot-management.md`.

## What's missing (in priority order)

### 1. Reverse-DNS good-bot verification → makes `verified` fire
- **Today:** `BotSignals.reverse_dns` is hardcoded `None` in the
  listener, so the GoodBot rule (Googlebot/Bingbot/… via rDNS) is
  unreachable — verified crawlers read as `unknown`.
- **Work:** forward-confirmed reverse DNS (FCrDNS): PTR-lookup the peer
  IP, forward-A-lookup the returned name, set `reverse_dns` only when it
  resolves back to the same IP (avoids the BOTS-01 trust-boundary
  bypass). Must be **async + cached + short-timeout**, classify `None`
  on the first request until the lookup resolves — DNS on the hot path
  is the main risk.
- **Cross-ref:** already cataloged in
  [`unwired-stubs-catalog.md`](./unwired-stubs-catalog.md) →
  "BotClassifier — `reverse_dns` population in proxy".
- **Effort:** medium-high. **Risk:** medium (hot-path DNS).

### 2. JS-challenge-pass signal → makes `human` fire
- **Today:** `has_js_challenge_pass` is hardcoded `false`, so the Human
  rule (cookies + JS-pass) never fires; real users read as `unknown`.
- **Work:** thread the challenge-engine's pass result (cookie-bound)
  into `BotSignals.has_js_challenge_pass`.
- **Effort:** medium. **Risk:** low.

### 3. Per-class action mapping → turn observational into enforcement
- **Today:** `bot_category` is read only by the dashboard aggregator —
  no per-class block/challenge.
- **Work:** an `action_mapping` (`known_bad → block`, `likely_bot →
  challenge`, `good_bot → allow_rate_limited`, `human → allow`,
  `unknown → tier_default`), applied in the data plane.
- **Caveat:** scanner UAs already block/score via the `recon` detector,
  so decide whether bot-class owns that path or defers — avoid
  double-counting / double-blocking. Bot classification currently runs
  **post-decision** in the listener; enforcing by class means moving (or
  duplicating) the classify call to **before** the decision point.
- **Effort:** medium-high. **Risk:** medium (changes the decision path).

### 4. ASN table + ladder maintenance
- `bots.rs::ASN_TABLE` is ~25 hand-maintained entries (cloud/hosting/
  residential/mobile). Cloud ASNs not in the table classify `Unknown`.
- The ladder was calibrated 2026-05-21 (Hosting +35 so cookieless cloud
  reaches the LikelyBot bar of 50). Revisit if the FP/TP balance shifts.
- Optionally make the table config-driven (`cfg.bots.asn_classifications`).

## Explicitly out of scope (decided 2026-05-21)

- **JA4 "baseline" / known-bad JA4 list.** Low ROI: a useful list needs
  a live threat feed; a baseline-deviation model is research-grade. Not
  contract-required. The dashboard message that implied a JA4 baseline
  was the *only* setup was incorrect and has been fixed — classification
  is UA + ASN, not JA4.

## Sequencing suggestion

(2) JS-pass is the cheapest "make a dead bucket work"; (1) rDNS is the
higher-value-but-riskier good-bot win; (3) enforcement is the biggest
behavioral change and should land last, after (1)+(2) make the verdicts
trustworthy. None are required for the hackathon.
