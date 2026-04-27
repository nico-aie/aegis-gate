# Configuration Guide

This folder contains the WAF configuration files. The main config is `waf.yaml` and custom rules live in `rules/`.

```
config/
├── README.md          # This guide
├── waf.yaml           # Main WAF configuration
└── rules/
    └── example.yaml   # Example custom rules
```

---

## Quick Reference

```sh
# Validate config (catches errors before starting)
waf validate --config config/waf.yaml

# Start the WAF with this config
waf run --config config/waf.yaml
```

---

## waf.yaml — Section by Section

### 1. Listeners

Controls which ports the WAF binds to.

```yaml
listeners:
  data:                          # Data plane — client traffic enters here
    - bind: "0.0.0.0:8443"      # Public TLS port
      tls: true
    - bind: "0.0.0.0:8080"      # Plaintext (dev only — disable in production)
      tls: false
  admin:
    bind: "127.0.0.1:9443"      # Admin dashboard + API (localhost only)
```

| Field | Description |
|-------|-------------|
| `data[].bind` | IP:port for client traffic. Use `0.0.0.0` for all interfaces. |
| `data[].tls` | `true` = TLS termination, `false` = plaintext. |
| `admin.bind` | IP:port for the admin dashboard. **Keep on localhost in production.** |

**Tip:** In production, remove the plaintext `:8080` listener and only expose `:8443` with TLS.

---

### 2. Routes

Routes map incoming requests to upstream pools. Matched in priority order: **exact > prefix**, then first-match wins.

```yaml
routes:
  - id: login                    # Unique identifier
    host: "api.example.com"      # Optional — match Host header
    path: "/login"               # Path to match
    match_type: exact            # exact | prefix
    methods: [POST]              # Optional — restrict HTTP methods
    upstream: auth-pool          # Which upstream pool handles this
    tier_override: critical      # Optional — override security tier

  - id: catch-all                # Always have a catch-all as the last route
    path: "/"
    match_type: prefix
    upstream: backend-pool
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique route identifier (used in logs and metrics) |
| `host` | No | Match requests with this `Host` header |
| `path` | Yes | URL path to match |
| `match_type` | Yes | `exact` = exact match, `prefix` = path prefix |
| `methods` | No | List of allowed HTTP methods (default: all) |
| `upstream` | Yes | Name of the upstream pool to forward to |
| `tier_override` | No | Security tier: `critical`, `high`, `medium`, `low` |

**Security tiers** control how aggressively the security pipeline inspects traffic:
- **critical** — full inspection, strictest rate limits (login, auth, payments)
- **high** — full inspection (API endpoints)
- **medium** — standard inspection (user-facing pages)
- **low** — minimal inspection (static assets, health checks)

---

### 3. Upstreams

Upstream pools define the backend servers the WAF proxies to.

```yaml
upstreams:
  auth-pool:
    members:
      - addr: "127.0.0.1:3001"  # Backend server address
        weight: 1                # Load balancing weight
    lb: round_robin              # Load balancing strategy
    health:                      # Health checking (optional)
      path: "/healthz"
      interval: "10s"
      timeout: "3s"
    circuit_breaker:             # Circuit breaker (optional)
      error_rate_threshold: 0.5  # Open circuit at 50% error rate
      open_duration: "30s"       # Stay open for 30s before retrying

  backend-pool:
    members:
      - addr: "127.0.0.1:3002"
        weight: 3                # Gets 75% of traffic
      - addr: "127.0.0.1:3003"
        weight: 1                # Gets 25% of traffic
    lb: weighted_round_robin
```

**Load balancing strategies:**

| Strategy | Description |
|----------|-------------|
| `round_robin` | Rotate evenly across all members |
| `weighted_round_robin` | Rotate proportional to weight |
| `random` | Random selection |
| `least_conn` | Fewest active connections |
| `ip_hash` | Consistent hashing by client IP (sticky sessions) |

---

### 4. State Backend

Where the WAF stores runtime state (rate-limit counters, risk scores, etc.).

```yaml
state:
  backend: in_memory             # in_memory | redis
  # redis:                       # Uncomment for multi-node deployments
  #   url: "redis://localhost:6379"
```

| Backend | When to use |
|---------|-------------|
| `in_memory` | Single node, dev, or when Redis is unavailable. Fast but lost on restart. |
| `redis` | Multi-node clusters. Shared rate-limit counters and risk scores. |

---

### 5. Rules

Custom security rules evaluated by the rule engine.

```yaml
rules:
  paths:                         # Directories to load rule files from
    - "config/rules/"
  max_rule_count: 10000          # Safety limit
  strict_compile: false          # true = fail on any lint warning
```

Rule files are YAML arrays. See `config/rules/example.yaml`:

```yaml
- id: "sqli-strict-1"           # Unique rule ID
  priority: 100                  # Higher = evaluated first
  scope:
    tier: critical               # Only apply to critical-tier routes
  when: "method == 'POST' && path matches '^/api/' && body contains_any sqli_signatures"
  then:
    action: block                # allow | block | challenge | rate_limit | log
    status: 403
    reason: "sqli detected"
  tags: ["owasp:a03"]           # For metrics and audit
```

**Rule actions:**

| Action | Effect |
|--------|--------|
| `allow` | Immediately allow (skip remaining rules) |
| `block` | Return error response (default 403) |
| `challenge` | JS challenge or CAPTCHA |
| `rate_limit` | Apply a rate-limit bucket |
| `log` | Log and continue (non-terminal) |

---

### 6. Rate Limiting

Per-IP or per-key rate limits.

```yaml
rate_limit:
  buckets:
    - id: global-ip              # Unique bucket ID
      scope: global              # global | route
      key: ip                    # What to rate-limit by (ip, header, etc.)
      algo: sliding_window       # sliding_window | token_bucket
      limit: 100                 # Max requests
      window: "1m"               # Time window

    - id: login-ip               # Stricter limit for login route
      scope: route
      key: ip
      algo: sliding_window
      limit: 5
      window: "1m"
```

**Algorithms:**

| Algorithm | Description |
|-----------|-------------|
| `sliding_window` | Smooth sliding window counter. Best for most use cases. |
| `token_bucket` | Burst-friendly. Allows short bursts then rate-limits. |

---

### 7. Risk Scoring

Accumulates risk signals per request. Higher score = more suspicious.

```yaml
risk:
  weights:                       # Points added per signal type
    bad_asn: 15                  # Known-bad ASN
    bad_ja4: 10                  # Suspicious TLS fingerprint
    failed_auth: 20              # Failed authentication
    detector_hit: 25             # OWASP detector triggered
    bot_unknown: 10              # Unknown bot classification
    repeat_offender: 15          # IP with recent blocks
  decay_half_life: "5m"          # Risk score decays over time
  thresholds:
    challenge_at: 40             # Score ≥ 40 → JS challenge
    block_at: 80                 # Score ≥ 80 → block
    max: 100                     # Cap
```

The **challenge ladder** escalates based on risk score:
1. Score 0–39: **Allow**
2. Score 40–79: **Challenge** (JS or CAPTCHA)
3. Score 80+: **Block**

---

### 8. Detectors

OWASP security detectors. Enable/disable individually.

```yaml
detectors:
  sqli:             { enabled: true }   # SQL injection
  xss:              { enabled: true }   # Cross-site scripting
  path_traversal:   { enabled: true }   # Directory traversal (../)
  ssrf:             { enabled: true }   # Server-side request forgery
  header_injection: { enabled: true }   # CRLF / response splitting
  body_abuse:       { enabled: true }   # Oversized body / deep JSON
  recon:            { enabled: true }   # Scanner probes / admin paths
  brute_force:      { enabled: true }   # Repeated failed auth
```

**Tip:** Keep all detectors enabled. To suppress false positives, create an `allow` rule targeting the specific path/IP rather than disabling the whole detector.

---

### 9. DLP (Data Loss Prevention)

Scan response bodies for sensitive data.

```yaml
dlp:
  patterns: []                   # Add patterns here (see below)
  max_scan_bytes: 2097152        # Max bytes to scan (2 MB)
```

Example patterns:

```yaml
dlp:
  patterns:
    - name: credit-card
      regex: '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
      action: mask               # mask | block | alert | fpe
    - name: ssn
      regex: '\b\d{3}-\d{2}-\d{4}\b'
      action: fpe                # Format-Preserving Encryption
  max_scan_bytes: 2097152
```

| Action | Effect |
|--------|--------|
| `mask` | Replace with `****` |
| `block` | Block the response entirely |
| `alert` | Log alert but pass through |
| `fpe` | Format-Preserving Encryption (AES-FF1) — preserves data format |

---

### 10. Observability

Prometheus metrics and access logging.

```yaml
observability:
  prometheus:
    path: "/metrics"             # Metrics endpoint path on admin listener
  access_log:
    format: json                 # combined | json | template
    sink: stdout                 # stdout | file path
```

**Access log formats:**

| Format | Description |
|--------|-------------|
| `combined` | Apache combined log format |
| `json` | Structured JSON (recommended for SIEM) |
| `template` | Custom template string |

---

### 11. Audit

Tamper-evident audit logging.

```yaml
audit:
  sinks: []                      # SIEM sinks (see below)
  chain:
    enabled: true                # SHA-256 hash chain for tamper detection
  retention: "90d"               # How long to keep audit events
  pseudonymize_ip: false         # true = hash client IPs in audit logs
```

**Adding SIEM sinks:**

```yaml
audit:
  sinks:
    - type: jsonl
      path: /var/log/aegis/audit.ndjson
    - type: syslog
      target: udp://siem.corp.com:514
    - type: splunk_hec
      url: https://splunk.corp.com:8088
      token: "${secret:env:SPLUNK_TOKEN}"
      index: waf
      source_type: aegis
```

Available sink types: `jsonl`, `syslog`, `cef`, `leef`, `ocsf`, `splunk_hec`, `ecs`, `kafka`.

---

### 12. Admin Dashboard Authentication

Protects the admin dashboard at `:9443`.

```yaml
admin:
  bind: "127.0.0.1:9443"
  dashboard_auth:
    password_hash_ref: "${secret:env:AEGIS_ADMIN_PASSWORD_HASH}"
    csrf_secret_ref: "${secret:env:AEGIS_CSRF_SECRET}"
    session_ttl_idle: "30m"          # Idle timeout
    session_ttl_absolute: "8h"       # Max session lifetime
    ip_allowlist:                     # Only these IPs can access admin
      - "127.0.0.1/32"
      - "::1/128"
    totp_enabled: false               # Set true + enroll TOTP for 2FA
    login_rate_limit:
      per_ip:
        limit: 5
        window: "1m"
      per_user:
        limit: 10
        window: "15m"
    lockout:
      threshold: 10                   # Lock after 10 failed attempts
      window: "15m"
      duration: "15m"                 # Lock duration
```

**Setting up admin credentials:**

```sh
# 1. Generate password hash
waf admin set-password
# Enter password → get PHC hash string
# Set as environment variable:
export AEGIS_ADMIN_PASSWORD_HASH='$argon2id$v=19$m=...'

# 2. Generate CSRF secret (any random string)
export AEGIS_CSRF_SECRET=$(openssl rand -hex 32)

# 3. Optional: enable TOTP
waf admin enroll-totp --issuer "Aegis" --account "admin"
# Then set totp_enabled: true in config
```

**Secret references** (`${secret:env:NAME}`) are never resolved in config exports or API responses — they stay as references for security.

---

## Common Configuration Patterns

### Development (minimal)

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8080"
      tls: false
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: dev
upstreams:
  dev:
    members:
      - addr: "127.0.0.1:3000"
    lb: round_robin
state:
  backend: in_memory
```

### Production (hardened)

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8443"
      tls: true
  admin:
    bind: "127.0.0.1:9443"

# No plaintext listener!
# All detectors enabled
# SIEM sinks configured
# Compliance profiles set
# Admin auth with TOTP

compliance:
  modes: [pci, soc2]

audit:
  chain: { enabled: true }
  retention: "365d"
  sinks:
    - type: jsonl
      path: /var/log/aegis/audit.ndjson
    - type: syslog
      target: tls://siem.corp.com:6514
```

### Adding a new backend service

1. Add members to `upstreams`:
   ```yaml
   upstreams:
     my-new-service:
       members:
         - addr: "10.0.1.50:8080"
       lb: round_robin
   ```

2. Add a route:
   ```yaml
   routes:
     - id: my-new-service
       path: "/my-service/"
       match_type: prefix
       upstream: my-new-service
       tier_override: high
   ```

3. Validate: `waf validate --config config/waf.yaml`

---

## Environment Variables

| Variable | Used In | Purpose |
|----------|---------|---------|
| `AEGIS_ADMIN_PASSWORD_HASH` | `admin.dashboard_auth.password_hash_ref` | argon2id password hash |
| `AEGIS_CSRF_SECRET` | `admin.dashboard_auth.csrf_secret_ref` | CSRF double-submit secret |
| `SPLUNK_TOKEN` | `audit.sinks` | Splunk HEC token |

Secret references use the format `${secret:env:VARIABLE_NAME}` and are never exposed in API responses or config exports.
