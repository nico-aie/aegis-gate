# Bot Classification

> **Status (2026-05-21): PARTIAL.** A hardcoded rule-set classifier
> ships in [`crates/aegis-security/src/bots.rs`](../../crates/aegis-security/src/bots.rs)
> and its verdict is surfaced on the dashboard (Investigation → "Bot
> classification mix") and recorded in the audit `fields.bot_category`.
> It is **observational today** — it does not run a dedicated
> block/challenge action by bot class. Several signals described in the
> "Planned" section below are **not wired** (reverse-DNS verification,
> JS-challenge-pass, threat-intel labels, a config block, a model
> backend). This doc describes **what actually runs**; the enterprise
> design is at the end, clearly marked.

## Purpose

Label each request `human | good_bot (verified) | likely_bot (suspect)
| known_bad (malicious) | unknown`, to tell friendly crawlers
(Googlebot, Bingbot) from hostile automation (scanners, scrapers,
credential stuffers) from humans.

## What actually runs (`bots.rs`)

Per request, the **listener** (`aegis-proxy/src/accept.rs`) builds
`BotSignals` and calls `BotClassifier::classify()`. The verdict maps to
the dashboard mix as: GoodBot→`verified`, LikelyBot→`suspect`,
KnownBad→`malicious`; **Human and Unknown are not counted** (recorded
as `null`). The verdict is only computed on **allow** responses
(blocked requests carry their own audit fields).

Classification is **UA + ASN based**, evaluated in this order:

| Rule | Verdict | Wired? |
|---|---|---|
| UA contains a scanner token (`sqlmap`, `nikto`, `nmap`, `masscan`, `dirbuster`, `gobuster`, `hydra`, `medusa`, `havij`, `w3af`) | `known_bad` (malicious) | ✅ |
| Known-bad JA4 cipher hash | `known_bad` | ⚠️ list is **empty** — never matches |
| Reverse-DNS matches a good-bot domain (`*.googlebot.com`, …) | `good_bot` (verified) | ❌ `reverse_dns` is **stubbed `None`** — never fires |
| ≥3 failed challenges | `likely_bot` | ✅ (when challenge data present) |
| Cookies **+** passed JS challenge | `human` | ❌ `has_js_challenge_pass` **stubbed `false`** — never fires |
| No UA, or UA < 20 chars | `likely_bot` | ✅ |
| **Signal-score ladder ≥ 50** | `likely_bot` | ✅ (ASN part needs the GeoIP ASN DB) |
| otherwise | `unknown` | — |

### The signal-score ladder

```
Datacenter ASN  +40
Hosting ASN     +35     # AWS / GCP / Azure / Cloudflare / OVH / Hetzner / DO / …
no cookies      +15
each failed challenge +10
─────────────────────────
≥ 50  →  likely_bot (suspect)
```

So a **cookieless request from a cloud/hosting ASN = 35 + 15 = 50 →
`suspect`** — *but only when the GeoIP ASN DB is loaded* (otherwise the
ASN is `Unknown` and contributes 0). A hosting request **with** cookies
(35) stays `unknown` — session continuity is treated as benign. ASN
classes come from the small built-in table in `bots.rs::ASN_TABLE`.

## Setup — making the mix populate

1. **Load the GeoLite2-ASN database** (the main lever). Set
   `geoip.asn_db` (absolute path recommended) and build with the
   `geoip` feature (default on). Confirm with
   `GET /api/geoip/status` → `db_loaded: true`. Without it, cloud/
   hosting traffic can't reach the ladder and stays `unknown`.
2. **Scanner-UA traffic** (`sqlmap`, `nikto`, …) classifies as
   `malicious` automatically — no setup.
3. **No/short UA** → `suspect` automatically.

There is **no "JA4 baseline" to load** — the dashboard message that
said so was incorrect (corrected 2026-05-21). Classification is UA +
ASN, not JA4 fingerprint matching.

## Known limitations (not wired today)

- **`verified` (good bots) never fires** — reverse-DNS lookups aren't
  performed in the data plane (`reverse_dns` is always `None`), so
  Googlebot/Bingbot read as `unknown`. Wiring forward-confirmed
  reverse-DNS is a planned follow-up (see below).
- **`human` never fires** — `has_js_challenge_pass` isn't fed from the
  challenge flow.
- **JA4** is captured on TLS but only checked against an empty
  known-bad list — it doesn't classify anything today.
- The classifier is **observational** — it records `bot_category` and
  drives the dashboard mix; there is no dedicated per-class
  block/challenge enforcement path (the `action_mapping` below is a
  plan, not a feature).

## Planned (enterprise design — NOT yet implemented)

The following describe the intended v2 design and are **not** in the
current build:

- A `bot_management:` config block (per-bot UA + rDNS patterns, TTLs,
  `action_mapping`).
- Forward-confirmed reverse-DNS good-bot verification.
- Threat-intel (STIX `bot` indicator) labels.
- A model-backed classifier (feature-gated).
- An `enabled` toggle + per-class action mapping
  (`known_bad: block`, `likely_bot: challenge`, `good_bot:
  allow_rate_limited`).

```yaml
# PLANNED shape — does not exist in config today.
bot_management:
  enabled: true
  good_bots:
    googlebot: { ua_contains: "Googlebot", rdns_patterns: ["*.googlebot.com"] }
  action_mapping:
    known_bad: block
    likely_bot: challenge
    good_bot:  allow_rate_limited
    human:     allow
    unknown:   tier_default
```

## See also

- [`device-fingerprinting.md`](./device-fingerprinting.md) — JA4/JA3 capture.
- Dashboard: Investigation → "Bot classification mix".
- Help → Bot classifier setup (in-product quick guide).
