---
id: 2026-05-17-ssrf-via-alert-receiver-bot-token
date: 2026-05-17T00:00Z
severity: CRITICAL
area: SLO dispatch · alert receivers
component: crates/aegis-control/src/slo/dispatch.rs:136-166 · crates/aegis-control/src/api/alert_receivers.rs:227-272 (validate_kind)
interop_contract: Round-1 admin operations safety · ASVS / OWASP A10 SSRF
status: open
test_mode: source-review
---

# F-CRITICAL-015 · Unauthenticated SSRF via alert-receiver `bot_token` interpolated into URL path with no escaping

## Summary

VipTalk alert dispatch constructs the request URL by `format!`-ing
the operator-supplied `bot_token` into the URL path:

[slo/dispatch.rs:138-142](../../../../crates/aegis-control/src/slo/dispatch.rs#L138-L142):

```rust
let url = format!("{api_base}/v1/bot/{bot_token}/sendMessage");
```

The `api_base` comes from env (limited operator-control risk); the
`bot_token` flows from `PUT /api/alert-receivers` operator input
and is NOT URL-encoded or character-restricted. Receiver validation
([alert_receivers.rs:244-272](../../../../crates/aegis-control/src/api/alert_receivers.rs#L244-L272))
checks `kind` and that fields are non-empty, but doesn't constrain
the `bot_token` character set.

An "operator" who can set the receiver to:

```json
{
  "kind": "viptalk",
  "bot_token": "../../../latest/meta-data/iam/security-credentials/admin"
}
```

— makes the WAF subsequently issue:

```
POST http://api.viptalk.example/v1/bot/../../../latest/meta-data/iam/security-credentials/admin/sendMessage
```

Worse, a `bot_token` of `x@http://169.254.169.254/latest/meta-data`
pivots the host portion (HTTP URL parsing varies — some libs interpret
`{user_info}@{host}` after a path-overflow).

Combined with **F-CRITICAL-002 in proxy audit** (admin listener has
NO auth gate — anyone reaching the admin port can PUT alert receivers):

**Unauthenticated remote attacker → AWS metadata IAM credentials.**

The WAF runs with whatever IAM role is attached to its EC2 instance.
On a typical "WAF runs as IRSA / EC2 role" deployment, that role may
have access to KMS / Secrets Manager / S3 buckets containing
production data.

## Observed code path

[slo/dispatch.rs:136-166](../../../../crates/aegis-control/src/slo/dispatch.rs#L136-L166):

```rust
async fn dispatch_viptalk(receiver: &Receiver, alert: &SloAlert) -> Result<()> {
    let api_base = std::env::var("AEGIS_VIPTALK_API_BASE")
        .unwrap_or_else(|_| "https://api.viptalk.io".into());
    let bot_token = &receiver.bot_token;   // operator-controlled, unvalidated
    let url = format!("{api_base}/v1/bot/{bot_token}/sendMessage");
    let client = reqwest::Client::new();
    let _ = client.post(&url).json(&alert.format_text()).send().await;
    Ok(())
}
```

[api/alert_receivers.rs:244-272](../../../../crates/aegis-control/src/api/alert_receivers.rs#L244-L272) — `validate_kind`:

```rust
fn validate_kind(kind: &str, fields: &serde_json::Value) -> Result<()> {
    match kind {
        "viptalk" => {
            require_field(fields, "bot_token")?;   // existence check only
            require_field(fields, "channel_id")?;
            Ok(())
        }
        ...
    }
}
```

No character set restriction, no URL-encode at dispatch time.

## Impact

- **Unauthenticated SSRF** — combined with F-CRITICAL-002 (no admin
  auth) means anyone reaching the admin port can fire arbitrary HTTP
  requests from the WAF process.
- **Cloud credential exfiltration** — AWS IMDS, GCP metadata, Azure
  IMDS all on link-local 169.254. WAF likely has IAM permissions
  worth attacking.
- **Internal-service pivoting** — same primitive accesses internal
  HTTP services not exposed to the internet.
- **Information disclosure** — the WAF's outbound HTTP traffic now
  includes attacker-chosen payloads.

## Suggested fix

Three layers of defense:

### 1. Percent-encode the bot_token at dispatch

```diff
-let url = format!("{api_base}/v1/bot/{bot_token}/sendMessage");
+use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
+let bot_token_enc = utf8_percent_encode(bot_token, NON_ALPHANUMERIC).to_string();
+let url = format!("{api_base}/v1/bot/{bot_token_enc}/sendMessage");
```

### 2. Validate character set at receiver-set time

```diff
 "viptalk" => {
     require_field(fields, "bot_token")?;
+    let token = fields["bot_token"].as_str().ok_or(Error::InvalidField)?;
+    // VipTalk tokens are URL-safe base64; reject anything else.
+    if !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':') {
+        return Err(Error::InvalidField);
+    }
     require_field(fields, "channel_id")?;
     Ok(())
 }
```

### 3. Constrain ALL receiver webhook URLs to https + non-loopback / non-internal

Per Agent C HIGH M-?:
- `Slack { webhook_url }` currently accepts `file:///etc/passwd`, `http://localhost:6379` (no scheme/CIDR check).
- Similar issue on `Webhook { url }`, `Generic { endpoint }`.

```rust
fn validate_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).map_err(|_| Error::InvalidUrl)?;
    if parsed.scheme() != "https" {
        return Err(Error::SchemeNotAllowed);
    }
    let host = parsed.host_str().ok_or(Error::InvalidUrl)?;
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        if addr.is_loopback() || addr.is_private() || is_link_local(addr) {
            return Err(Error::HostNotAllowed);
        }
    }
    Ok(())
}
```

Apply at PUT time + at dispatch time (defense in depth).

### 4. Outbound-HTTP allowlist

Operator config:

```yaml
slo:
  allowed_outbound_hosts:
    - api.viptalk.io
    - hooks.slack.com
    - api.pagerduty.com
```

Reject any dispatch URL whose host isn't on the list. This blocks
attacks even if bot_token validation has gaps.

## Verification

```sh
HOST="http://127.0.0.1:9443"

# Set a malicious bot_token (assumes F-CRITICAL-002 not yet fixed):
curl -sk -X PUT "$HOST/api/alert-receivers" -d '{
  "receivers":[{"kind":"viptalk","bot_token":"../../../latest/meta-data/","channel_id":"x"}]
}' -i
# After fix: 400 Bad Request "bot_token contains disallowed characters".
# Today: 200, receiver saved.

# Fire an alert. Wireshark the outbound HTTP — after fix, no IMDS
# request should be issued.
```

Regression test: dispatch with bot_token = `"../foo"`, intercept
the outbound URL, assert no `..` in the path.

## Severity rationale

CRITICAL. Unauthenticated SSRF (when paired with F-CRITICAL-002)
that lands on cloud credentials and internal services. Trivial fix
(~20 LoC for percent-encode + char restriction). The compounding
with admin no-auth makes this the single most exploitable bug in
the audit set.
