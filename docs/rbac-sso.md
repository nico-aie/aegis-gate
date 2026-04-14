# RBAC & OIDC SSO (v2, enterprise)

> **Enterprise addendum.** Control-plane access (dashboard + admin API)
> is gated by OIDC SSO and role-based access control. Distinct from
> data-plane auth ([`external-auth.md`](./external-auth.md)).

## Purpose

Operators log in via the corporate IdP. Roles are derived from IdP
group claims. Every mutation is attributed to a real actor, with
time, IP, and reason, and logged to the tamper-evident admin change
log.

## Roles

| Role | Permissions |
|---|---|
| `viewer` | Read-only dashboard + API (`GET`) |
| `operator` | viewer + mutate non-security config (routes, upstreams, quotas) |
| `admin` | operator + mutate security config (rules, tenants, tokens, auth) |
| `auditor` | Read-only audit log + change history, no dashboard mutate |
| `break_glass` | Emergency admin with short TTL and dual-control requirement |

Roles are declared in `rbac.roles`; every admin API handler is wrapped
with `require_role!(...)`.

## OIDC flow

1. User visits `https://waf.example.com:9443/`
2. Unauthenticated → redirect to IdP `/authorize`
3. IdP callback posts code to `/auth/callback`
4. WAF exchanges code for ID token + userinfo
5. WAF maps IdP groups → roles via `role_mapping`
6. WAF mints a PASETO v4 session cookie (HMAC, short TTL, refreshable)

## Role mapping

```yaml
admin:
  oidc:
    issuer: "https://idp.example.com"
    client_id: "waf-admin"
    client_secret: "${secret:env:OIDC_SECRET}"
    redirect_uri: "https://waf.example.com:9443/auth/callback"
    groups_claim: "groups"
    role_mapping:
      "waf-admins":       admin
      "waf-ops":          operator
      "waf-view":         viewer
      "waf-audit":        auditor
      "waf-break-glass":  break_glass
```

## Tenants

Tokens for tenant-scoped users carry a `tenant_id` claim. See
[`multi-tenancy.md`](./multi-tenancy.md).

## Sessions

- PASETO v4 local token (symmetric, HMAC-authenticated)
- 1-hour session TTL, sliding refresh up to 8 hours
- `session_id` stored in state backend for revocation
- Idle timeout + hard lifetime
- Logout revokes session immediately

## API tokens

Service accounts use long-lived API tokens:

- Issued by an `admin` via `POST /api/tokens`
- Scoped to roles + tenants + IP allowlist
- Stored as `argon2(hash)` in the state backend
- Rotatable, revocable; revocation is immediate via state backend watch
- Audit-logged on issue, rotate, and revoke

## Change approval (optional)

For critical mutations, enforce **dual control**:

```yaml
admin:
  change_approval:
    enabled: true
    approvers_required: 2
    self_approval: false
    scope: ["rules.mutate", "tenants.mutate", "auth.mutate"]
```

A mutation enters `pending` state; a second admin approves via the
dashboard or `PUT /api/changes/{id}/approve`. `break_glass` bypasses
this with an explicit audit note.

## Admin change log

Every mutation (approved or direct) produces a high-severity
admin-change record (see [`audit-logging.md`](./audit-logging.md)):

- Actor (OIDC `sub` + IdP + IP + user agent)
- Target + diff
- Reason (required)
- Approver (when applicable)

Admin-change log is a **separate hash chain** from the detection log.

## Configuration

```yaml
admin:
  oidc: { ... }
  rbac:
    roles:
      viewer:   { scope: "read" }
      operator: { scope: ["read", "mutate:non_security"] }
      admin:    { scope: ["read", "mutate:*"] }
      auditor:  { scope: ["read:audit"] }
  session:
    ttl_s: 3600
    idle_timeout_s: 900
    hard_lifetime_s: 28800
  ip_allowlist: ["10.0.0.0/8"]
  break_glass:
    enabled: true
    ttl_s: 900
    require_second_approver: true
```

## Implementation

- `src/dashboard/auth.rs` — OIDC RP + session issuance
- `src/dashboard/rbac.rs` — `require_role!` macro + scope checks
- `src/dashboard/tokens.rs` — API token issue/revoke
- `src/dashboard/change_approval.rs` — pending/approve flow
- `src/dashboard/break_glass.rs` — emergency path

## Performance notes

- PASETO verify is one HMAC — µs range
- Group → role mapping is a pre-built `HashMap`
- Session revocation check is one state-backend `GET` per request,
  pipelined with rate limiter
