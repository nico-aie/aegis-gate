# Secrets Management (v2, enterprise)

> **Enterprise addendum.** Secrets never live in `waf.yaml`. They are
> referenced via `${secret:provider:path[#field]}` and resolved at
> compile time by a pluggable provider stack. Rotation is push-based
> when the provider supports it.

## Purpose

Eliminate secrets from config files, Git, and process environment
(optionally), and enable automatic rotation without restarts.

## Reference syntax

```
${secret:<provider>:<path>[#field]}
```

Examples:

- `${secret:env:OIDC_SECRET}`
- `${secret:file:/etc/waf/keys/admin.key}`
- `${secret:vault:kv/data/waf/tls#key}`
- `${secret:aws_sm:prod/waf/db#password}`
- `${secret:gcp_sm:projects/p/secrets/waf-jwt/versions/latest}`
- `${secret:azure_kv:https://v.vault.azure.net/secrets/waf/abc}`
- `${secret:pkcs11:slot=0;label=waf-key}`

## Providers

| Provider | Notes |
|---|---|
| `env` | Process env var — simplest, least secure |
| `file` | Read from disk (restricted perms), watched for rotation |
| `vault` | HashiCorp Vault KV v2 + dynamic creds |
| `aws_sm` | AWS Secrets Manager + KMS |
| `gcp_sm` | GCP Secret Manager + version pin |
| `azure_kv` | Azure Key Vault |
| `pkcs11` | HSM-backed private keys (cryptoki) — private material never leaves the HSM |

## Lifecycle

1. Config loader sees a `${secret:...}` reference
2. Provider resolves the reference, returns a `Secret` wrapper
3. Compile/validate step uses the secret (certs, HMAC keys, DB creds)
4. Secret wrapper zeroizes on drop (`zeroize` crate)
5. Provider subscribes to rotation notifications where supported

## Rotation

- **Vault**: lease renewal + pre-expiry re-resolve
- **AWS SM / GCP SM**: periodic poll or event subscription
- **File**: `notify` watcher
- **PKCS#11**: session renewal

On rotation, the config loader re-runs the compile/validate pipeline
for affected subsystems (TLS, HMAC, upstream mTLS) and atomically
swaps. No full config reload needed.

## Never-exposed handling

- Secrets never logged, even at trace level
- Secrets never surfaced through `/api/config` (redacted to
  `${secret:...}` reference string)
- Secrets never included in audit events; only the reference name
- `Debug` impls redact secret fields

## Access audit

Every secret read is audit-logged as an `operational` event with:

- Reference (provider + path, never value)
- Consumer subsystem (TLS / HMAC / upstream / …)
- Outcome (success / failure / stale)

Failures page oncall.

## Configuration

```yaml
secrets:
  providers:
    vault:
      address: "https://vault.internal:8200"
      auth: { method: kubernetes, role: waf }
      mount: "kv"
    aws_sm:
      region: "us-east-1"
  cache:
    ttl_s: 300
    stale_on_error_s: 3600
```

## Implementation

- `src/config/secrets.rs` — reference parser
- `src/secrets/provider.rs` — `SecretProvider` trait
- `src/secrets/{env,file,vault,aws_sm,gcp_sm,azure_kv,pkcs11}.rs`
- `src/secrets/cache.rs` — bounded TTL cache with `zeroize`
- `src/secrets/rotate.rs` — rotation orchestrator

## Performance notes

- Secret resolution is **off the hot path** — it runs at config
  load and rotation time, never per request
- Cache TTL avoids hammering providers during rolling restarts
- HSM signing is the slowest operation but only used for rare ops
  (TLS handshake under PKCS#11 mode, certificate issuance)
