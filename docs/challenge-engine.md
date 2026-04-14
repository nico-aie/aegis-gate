# Challenge Engine (v2)

> **v1 → v2:** the challenge engine is now a **progressive escalation state
> machine** with pluggable CAPTCHA providers (Turnstile, hCaptcha,
> reCAPTCHA v3) at the top of the ladder, and a **human-confidence score**
> that persists across sessions. Token replay is blocked via single-use nonces.

## Purpose

For requests in the "grey" risk band (see [`risk-scoring.md`](./risk-scoring.md))
— not high enough to block outright, not low enough to trust — issue a
challenge the client must complete before reaching the backend. Each
success raises a persistent human-confidence score.

## Escalation ladder

```
 None → JS → PoW → CAPTCHA → Block
```

Level selection is driven by `(risk_score, human_confidence, bot_class, tier)`:

- New identity, low risk: `JS`
- Known grey bot, medium risk: `PoW`
- Known-bad ASN or repeated failures: `CAPTCHA`
- CAPTCHA failed twice: `Block`

The active level is stored in the challenge cookie; downgrades are not
allowed within the cookie TTL (prevents clients cycling levels to find
an easy one).

## Challenge types

### JS challenge

HTML page with trivial JS that sets a cookie and reloads. Defeats naive
scripted clients that don't execute JavaScript. Very low friction for
real browsers.

### Proof-of-work (PoW)

Client computes `sha256(challenge || nonce)` until the hash has N leading
zero bits (default 20). Difficulty is configurable per tier. Measured to
take ~1 second on a modern laptop.

Implementation: client-side JS loop + Web Worker for non-blocking UX.
Server verification is O(1).

### CAPTCHA

Integrated via a `CaptchaProvider` trait:

```rust
#[async_trait]
pub trait CaptchaProvider: Send + Sync {
    fn widget_html(&self, site_key: &str) -> String;
    async fn verify(&self, response: &str, client_ip: IpAddr) -> Result<bool>;
}
```

Shipped providers:

| Provider | Backend URL | Notes |
|----------|-------------|-------|
| Turnstile | `challenges.cloudflare.com/turnstile/v0/siteverify` | No PII, recommended default |
| hCaptcha  | `hcaptcha.com/siteverify`                           | Enterprise accounts available |
| reCAPTCHA v3 | `www.google.com/recaptcha/api/siteverify`        | Score-based; threshold tunable |

The provider's verification API is called from the WAF (not the browser)
so keys are never exposed.

## Tokens

Challenge state is tracked via an HMAC-signed cookie:

```
waf_chal = <issued_at>.<client_id>.<level>.<nonce>.<hex_mac>
```

- `client_id` is hashed from `(ip, device_fp)` so cookies don't transfer
- `level` is the passed challenge level; not downgradable
- `nonce` is **single-use**: after the challenge is passed, the nonce is
  recorded in the state backend with a TTL equal to the token TTL, so
  replaying the same cookie yields a fresh challenge
- HMAC uses SHA-256 with a rotating secret from the secrets provider (see [`secrets-management.md`](./secrets-management.md))

## Human-confidence score

Passing any challenge increments `human_confidence` for the client id.
Decays over time. When confidence is high, challenges are waived even if
the risk score drifts upward briefly — reduces friction for returning
legitimate users.

Persisted in the state backend (shared across cluster nodes).

## Replay protection

- **Nonce set**: single-use nonces in Redis with TTL
- **Level-monotone**: cookie level cannot decrease
- **IP-bound**: `client_id` includes the IP; moving networks invalidates
  the cookie

## Configuration

```yaml
challenge:
  secret: "${secret:vault:kv/data/waf#challenge_secret}"
  token_ttl_s: 3600
  escalation:
    js:      { enabled: true }
    pow:     { enabled: true, difficulty_bits: 20 }
    captcha:
      enabled: true
      provider: turnstile
      site_key:   "${secret:env:TURNSTILE_SITE_KEY}"
      secret_key: "${secret:env:TURNSTILE_SECRET}"
  human_confidence:
    initial: 0
    max: 100
    grant_js: 10
    grant_pow: 30
    grant_captcha: 60
    decay_per_hour: 5
```

## Implementation

- `src/challenge/js_challenge.rs` — HTML + cookie
- `src/challenge/pow.rs` — hash verifier
- `src/challenge/captcha.rs` — `CaptchaProvider` + implementations
- `src/challenge/token.rs` — HMAC token + nonce replay check
- `src/challenge/escalation.rs` — state machine
- `src/challenge/confidence.rs` — persistent score, decay

## Performance notes

- JS challenge is static HTML: near-zero server cost
- PoW verification is a single SHA-256 hash
- CAPTCHA verify is a non-blocking HTTPS call; cached per token
- Nonce check is one Redis `SET NX EX` call (p99 sub-ms)
