# External Authentication (v2, new)

> **New in v2.** Data-plane authentication for protected routes:
> **ForwardAuth** subrequests (nginx `auth_request` / Traefik ForwardAuth),
> **JWT validation** with JWKS cache, **OIDC** session cookies, HTTP
> Basic, and per-route IP allowlists. Distinct from control-plane auth
> ([`rbac-sso.md`](./rbac-sso.md)).

## Purpose

Let the WAF gate backend traffic on authentication outcome so backends
don't have to reimplement the same checks. Enforcement happens in the
security pipeline, before any upstream contact.

## ForwardAuth

Per route, issue a subrequest to an external auth service with the
original request's headers. On 2xx, forward; on 401/403, reject; copy
whitelisted response headers onto the forwarded request.

```yaml
auth:
  type: forward
  endpoint: "http://auth.internal/verify"
  method: GET
  copy_request_headers: ["authorization", "cookie", "x-forwarded-*"]
  copy_response_headers: ["x-user-id", "x-tenant-id", "x-scopes"]
  timeout_ms: 200
  failure_mode: fail_close
```

Failure mode honors the route tier:

- CRITICAL default: fail-close
- Others default: operator's choice

## JWT validation

```yaml
auth:
  type: jwt
  issuer: "https://idp.example.com/"
  audience: "api.example.com"
  jwks_uri: "https://idp.example.com/.well-known/jwks.json"
  algorithms: [RS256, ES256]
  leeway_s: 30
  required_claims: { scope: "read:api" }
  claim_to_header:
    sub: "x-user-id"
    tenant_id: "x-tenant-id"
```

- JWKS fetched on first use, cached via `moka` with TTL + stale-on-error
- Signature validated via `jsonwebtoken`
- `nbf`, `exp`, `aud`, `iss` checked with configurable leeway
- Claims projected into the `RequestContext` for rule-engine consumption
  (`JwtClaim` condition) and forwarded as headers to the upstream

## OIDC (session cookie)

For browser traffic. The WAF can act as an OIDC RP on data-plane routes:

- First visit → redirect to IdP
- Callback → exchange code, mint HMAC-signed session cookie
- Subsequent requests → validate cookie, project claims

Shares the PASETO / HMAC token infrastructure with
[`challenge-engine.md`](./challenge-engine.md).

## HTTP Basic

For internal APIs or bootstrap scenarios. Credentials verified against
a password file (bcrypt/argon2) or a configured secret reference. Not
recommended for public traffic.

## IP allow/deny per route

Reuses [`ip-reputation.md`](./ip-reputation.md) primitives:

```yaml
auth:
  type: ip_acl
  allow: ["10.0.0.0/8"]
  deny: ["0.0.0.0/0"]
```

## Layering

Auth runs after IP reputation and rate limiting, before the rule engine
and upstream forward. Outcomes feed into risk scoring: repeated auth
failures boost the risk of the client id.

## Configuration (per-route reference)

```yaml
routes:
  - id: api_admin
    host: "api.example.com"
    path: "/admin/"
    match: prefix
    upstream_ref: admin_pool
    auth: { ref: admin_jwt }

auth:
  admin_jwt:
    type: jwt
    issuer: "https://idp.example.com/"
    audience: "admin-api"
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    algorithms: [RS256]
```

## Implementation

- `src/auth/forward.rs` — `ForwardAuthClient` (hyper client)
- `src/auth/jwt.rs` — validator + JWKS cache (`moka`)
- `src/auth/oidc_rp.rs` — OIDC relying party
- `src/auth/basic.rs` — HTTP Basic
- `src/auth/ip_acl.rs` — per-route CIDR check
- `src/auth/mod.rs` — orchestrator + failure-mode enforcement

## Performance notes

- JWT validation: one crypto verify + cached JWKS lookup; µs range
- ForwardAuth adds a network hop; cached for idempotent flows by
  `(authorization_hash → decision)` with short TTL (disabled by default)
- JWKS refresh is background; the hot path never blocks on fetch
