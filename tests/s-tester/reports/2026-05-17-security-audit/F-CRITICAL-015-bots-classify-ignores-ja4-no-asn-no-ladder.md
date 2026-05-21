---
id: 2026-05-17-bots-classify-ignores-ja4-no-asn-no-ladder
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · bot management
component: crates/aegis-security/src/bots.rs
interop_contract: official rules §5.2 #05 (ASN classification) + §5.2 #08 (JA3/JA4) + §5.2 #04 (challenge ladder)
status: open
test_mode: source-review
---

# F-CRITICAL-015 · `bots.rs::classify` never reads its own `ja4_fingerprint` field; no ASN / Tor / datacenter classification; no challenge ladder

## Summary

`BotSignals` (the input to `bots.rs::classify`) carries
`ja4_fingerprint: Option<String>` at [bots.rs:17](../../../../crates/aegis-security/src/bots.rs#L17), but
`classify()` NEVER reads the field. The fingerprint is computed
upstream, passed in, and discarded.

The classifier uses ONLY:
- User-Agent substring match (against a hardcoded list).
- Reverse-DNS suffix match (not forward-confirmed — see F-HIGH-bots-fingerprint).

That misses every signal the official rules require:

| §5.2 requirement | Status |
|---|---|
| #05 ASN classification (residential / datacenter / Tor) | ❌ Missing — no ASN field on `BotSignals` |
| #05 Tor exit list lookup | ❌ Missing (Tor list also empty by default per F-HIGH-bots-fingerprint) |
| #08 JA3/JA4 fingerprint match | ❌ Field present but never read |
| #04 Challenge ladder (JS Challenge → CAPTCHA → Block) | ❌ Missing — flat 5-tier classification, no progression |

## Impact

- **Attack Battle scenario 03** (Relay/proxy attack via Tor/VPN/
  datacenter) — uncovered. Source from Tor exit → not detected.
  Source from AWS datacenter IP → not detected.
- **Attack Battle scenario 04** (Device fingerprint evasion) —
  JA4 collected but not consulted; rotation undetected.
- **§5.2 #04 challenge ladder** — required (BẮT BUỘC). Without it,
  the WAF's only response to a suspected bot is "block" — no
  graduated response (challenge first, escalate to block on failure).
- **Security Effectiveness (40/120) + Intelligence (20/120)** —
  both rubrics enumerate these signals as scored.

## Observed code path

[bots.rs:17](../../../../crates/aegis-security/src/bots.rs#L17):

```rust
pub struct BotSignals {
    pub user_agent: Option<String>,
    pub ja4_fingerprint: Option<String>,
    pub rdns: Option<String>,
    // No ASN field.
    // No JA3 field.
    // No Tor flag.
    // No datacenter flag.
}
```

[bots.rs:73-91](../../../../crates/aegis-security/src/bots.rs#L73-L91) — `classify()`:

```rust
pub fn classify(signals: &BotSignals) -> BotClass {
    let ua = signals.user_agent.as_deref().unwrap_or("");
    if KNOWN_BAD_UA.iter().any(|p| ua.contains(p)) { return BotClass::Automated; }
    if let Some(rdns) = &signals.rdns {
        if rdns.ends_with("googlebot.com") { return BotClass::GoodBot; }
        ...
    }
    BotClass::Unknown
}
// signals.ja4_fingerprint — NEVER READ.
// signals.asn         — DOESN'T EXIST.
```

## Suggested fix

### Add ASN + JA-fingerprint + datacenter/Tor flags to BotSignals

```diff
 pub struct BotSignals {
     pub user_agent: Option<String>,
     pub ja4_fingerprint: Option<String>,
+    pub ja3_fingerprint: Option<String>,
     pub rdns: Option<String>,
+    pub asn: Option<u32>,
+    pub asn_classification: Option<AsnClassification>,    // residential | datacenter | tor | vpn | unknown
+    pub headers_h2_fp: Option<String>,                    // HTTP/2 SETTINGS fingerprint
 }
```

### Implement multi-signal classify with weighted score

```rust
pub fn classify(signals: &BotSignals, known_bot_ja_db: &JaIocDb) -> BotClass {
    let mut score = 0i32;
    let mut reasons = vec![];

    // UA — strongest signal when present.
    if let Some(ua) = &signals.user_agent {
        if KNOWN_BAD_UA.iter().any(|p| ua.contains(p)) {
            return BotClass::Automated;     // confident, no ladder
        }
        if ua.is_empty() || ua.len() < 10 {
            score += 30;
            reasons.push("ua_short_or_empty");
        }
    } else {
        score += 40;
        reasons.push("no_ua");
    }

    // JA4/JA3 IoC match.
    if let Some(ja4) = &signals.ja4_fingerprint {
        if known_bot_ja_db.matches(ja4) {
            score += 50;
            reasons.push("ja4_ioc_match");
        }
    }

    // ASN classification.
    match signals.asn_classification {
        Some(AsnClassification::Tor)        => { score += 60; reasons.push("tor_exit"); }
        Some(AsnClassification::Datacenter) => { score += 30; reasons.push("datacenter"); }
        Some(AsnClassification::Vpn)        => { score += 20; reasons.push("vpn"); }
        _ => {}
    }

    // rDNS FCrDNS verification (see F-HIGH-bots-fingerprint for forward-confirm).
    if let Some(rdns) = &signals.rdns {
        if is_good_bot_rdns_verified(rdns, signals.peer_ip) {
            return BotClass::GoodBot;
        }
    }

    // Score → tier.
    match score {
        0..=29   => BotClass::Likely_Human,
        30..=59  => BotClass::Suspect,
        60..=89  => BotClass::Likely_Bot,
        _        => BotClass::Automated,
    }
}
```

### Implement challenge ladder

`challenge/ladder.rs` already partially exists; wire bot
classification into it:

```rust
pub fn select_action(bot: BotClass, risk: u32, prior_challenge_outcome: Option<ChallengeOutcome>) -> Action {
    use BotClass::*;
    use ChallengeOutcome::*;
    match (bot, risk, prior_challenge_outcome) {
        // Confident bot → straight to block.
        (Automated, _, _) => Action::Block,

        // Good bot → allow.
        (GoodBot, _, _) => Action::Allow,

        // Likely bot + medium risk → first challenge JS.
        (Likely_Bot, 30..=70, None) => Action::JsChallenge,
        // ... they passed JS → upgrade to CAPTCHA on next suspicion.
        (Likely_Bot, _, Some(JsSolved)) if risk > 70 => Action::Captcha,
        // ... they failed JS → block.
        (Likely_Bot, _, Some(JsFailed)) => Action::Block,

        // Suspect + high risk → CAPTCHA.
        (Suspect, 60.., _) => Action::Captcha,

        // Likely human → allow.
        (Likely_Human, ..30, _) => Action::Allow,

        _ => Action::Allow,
    }
}
```

### Plumb ASN from `ip_rep::asn` into BotSignals

```rust
// data_plane.rs:
let asn_class = ip_rep::asn::classify(peer.ip(), &state.asn_db, &state.tor_exit_list);
let signals = BotSignals {
    user_agent: req.headers().get(USER_AGENT)...,
    ja4_fingerprint: ctx.ja4.clone(),
    ja3_fingerprint: ctx.ja3.clone(),
    rdns: state.rdns_cache.lookup(peer.ip()).await,
    asn: asn_class.asn,
    asn_classification: Some(asn_class.kind),
    headers_h2_fp: ctx.h2_fp.clone(),
};
let bot_class = bots::classify(&signals, &state.ja_ioc_db);
let action = challenge::ladder::select_action(bot_class, risk, prior_challenge);
```

Cross-fix: F-HIGH-bots-fingerprint (rDNS FCrDNS), F-HIGH-stateful
(Tor exit list loaded), F-CRITICAL-011 (JA4 stability).

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Source from a datacenter IP (per ASN classifier):
curl -ski --interface 198.51.100.5 -A "Mozilla/5.0 (X11; Linux x86_64)" \
    "$HOST/login" -d "user=alice"
# Expect: 429 challenge (JS or CAPTCHA depending on risk).

# Source with known-bad JA4:
# (use a tls client that emits a specific JA4 IoC)
# Expect: 403 block.

# Source from Tor exit:
curl -ski --interface <known tor exit IP> "$HOST/"
# Expect: 403 block or 429 challenge.
```

Regression cases in `tests/security/bots/`.

## Severity rationale

CRITICAL. The bot classifier ignores its own input fields,
guarantees `BotClass::Unknown` for any modern attacker that runs a
real browser engine (chrome-shaped UA, no rDNS), and provides no
challenge ladder. Three §5.2 sub-clauses (#04, #05, #08) all touch
this module. Implementation ~200 LoC + cross-module plumbing.
