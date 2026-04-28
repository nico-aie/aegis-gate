# Bot Management (v2, enterprise)

> **Enterprise addendum.** Classifies traffic into `human | good_bot |
> likely_bot | known_bad` using fingerprints, behavior, reputation, and
> verification signals. Feeds
> [`challenge-engine.md`](./challenge-engine.md) and
> [`risk-scoring.md`](./risk-scoring.md).

## Purpose

Distinguish friendly crawlers (Googlebot, Bingbot, AhrefsBot with
verification) from hostile automation (scraping bots, credential
stuffers, vulnerability scanners) and from humans — with different
treatment for each.

## Classes

| Class | Treatment |
|---|---|
| `human` | No challenge, no challenge friction |
| `good_bot` | Allowed (with verification) + rate-limited |
| `likely_bot` | Challenge escalated |
| `known_bad` | Block |
| `unknown` | Treated per tier default |

## Signals

- **JA4 / JA3 / h2 fingerprint** (see [`device-fingerprinting.md`](./device-fingerprinting.md))
- **HTTP header order + UA entropy**
- **Reverse-DNS + forward-confirm** for good-bot verification
  (Googlebot, Bingbot, LinkedInBot, etc.)
- **Threat-intel labels** (STIX `bot` indicators)
- **Behavioral pattern** — session depth, think time, mouse/keyboard
  telemetry when available
- **Failed-challenge history**
- **ASN + IP reputation**

## Good-bot verification

For verifiable bots (Googlebot, Bingbot, AhrefsBot, DuckDuckBot,
Applebot, LinkedInBot, Twitterbot), the WAF performs a forward-confirmed
reverse-DNS check:

1. PTR lookup on the client IP
2. Verify the PTR matches an approved pattern (`*.googlebot.com`)
3. Forward-lookup the PTR; verify the A/AAAA includes the client IP

Result is cached per IP with a TTL. Unverified clients claiming to be
Googlebot via UA alone are classified `likely_bot` and challenged.

## Classifier

A small gradient-boosted model or hand-tuned rule set takes the
signals and outputs a class + confidence. v2 ships the rule-set
classifier by default; a model-backed classifier is feature-gated
because of binary-size and licensing concerns.

```rust
pub struct BotClassifier {
    fp_index: FingerprintIndex,
    rev_dns: ReverseDnsCache,
    intel: FeedIndex,
    rules: BotRuleSet,
}
```

## Output

The request context carries:

```rust
pub struct BotInfo {
    pub class: BotClass,
    pub confidence: u8,
    pub reasons: Vec<&'static str>,
    pub verified_as: Option<String>, // "googlebot" ...
}
```

Consumers:

- `challenge-engine` escalates likely_bot to PoW, known_bad to block
- `rule-engine` exposes `bot_class` condition
- `audit-logging` records class + reasons
- `traffic-management` can steer good_bot traffic to a cache-heavy pool

## Configuration

```yaml
bot_management:
  enabled: true
  good_bots:
    googlebot:
      ua_contains: "Googlebot"
      rdns_patterns: ["*.googlebot.com", "*.google.com"]
    bingbot:
      ua_contains: "bingbot"
      rdns_patterns: ["*.search.msn.com"]
  rdns_cache_ttl_s: 86400
  default_class_on_unknown: unknown
  action_mapping:
    known_bad: block
    likely_bot: challenge_pow
    good_bot:  allow_rate_limited
    human:     allow
    unknown:   tier_default
```

## Implementation

- `src/bot/classifier.rs` — orchestrator
- `src/bot/rdns.rs` — forward-confirmed reverse DNS + cache
- `src/bot/good_bots.rs` — builtin verified-bot list
- `src/bot/features.rs` — signal extraction
- `src/bot/model.rs` — optional model backend (feature-gated)

## Performance notes

- RDNS is cached; cache hits are O(1)
- Rule-set classifier runs a fixed-order evaluation, early exit on
  high-confidence match
- Model backend (when enabled) uses a fixed-size feature vector,
  sub-microsecond inference
