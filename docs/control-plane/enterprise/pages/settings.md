# Page — Settings

> Admin-facing knobs that don't belong on a configuration page —
> auth, sessions, theme, dashboard preferences. Anything that
> reshapes the data plane lives in Tier Config or via `PUT
> /api/config`, not here.

## Route

`GET /dashboard/settings`

## Sections

```
┌──────────────────────────────────────────────────────────────┐
│ Settings                                                      │
├──────────────────────────────────────────────────────────────┤
│ ▸ Account                                                     │
│   - Change password (re-auth required)                        │
│   - TOTP enrollment / reset / recovery codes                  │
│   - Active sessions (list + revoke)                           │
├──────────────────────────────────────────────────────────────┤
│ ▸ Authentication policy                                       │
│   - IP allowlist                                              │
│   - Session idle TTL / absolute TTL                           │
│   - Login rate-limit / lockout                                │
│   - mTLS toggle + CA upload                                   │
├──────────────────────────────────────────────────────────────┤
│ ▸ Dashboard                                                   │
│   - Theme: Light / Dark / System                              │
│   - Density: Comfortable / Compact                            │
│   - Cmd-K palette enabled                                     │
│   - Show legacy shell at /dashboard/legacy                    │
├──────────────────────────────────────────────────────────────┤
│ ▸ Integrations                                                │
│   - Grafana URL (used by Analytics page)                      │
│   - Alertmanager / Slack / PagerDuty receivers (read-only)    │
│   - GitOps repo + branch (read-only)                          │
├──────────────────────────────────────────────────────────────┤
│ ▸ Danger zone                                                 │
│   - Break-glass override                                      │
│   - Rotate session secret                                     │
│   - Force re-login of all sessions                            │
└──────────────────────────────────────────────────────────────┘
```

## Endpoints

| Action | Endpoint | Notes |
|--------|----------|-------|
| Change password | `POST /api/admin/password` | Re-auth required (CSRF + current password) |
| Enroll TOTP | `POST /api/admin/totp/enroll` | Returns provisioning URI + recovery codes |
| Reset TOTP | `POST /api/admin/totp/reset` | Re-auth required + recovery code |
| List sessions | `GET /api/admin/sessions` | Existing |
| Revoke session | `DELETE /api/admin/sessions/{id}` | CSRF |
| Update auth policy | `PUT /api/admin/policy` | Subset of `WafConfig.admin.dashboard_auth` |
| Read theme prefs | client-only `localStorage` | Not synced to server in v1 |
| Get integrations | `GET /api/integrations` | Read-only mirror of config |
| Break-glass override | `POST /api/admin/break-glass` | Re-auth + reason + 1h TTL |
| Rotate session secret | `POST /api/admin/secrets/session/rotate` | Invalidates all sessions; re-auth required |

## Account section detail

- **Change password** — opens a modal: current password, new
  password, confirm. Server runs argon2id verify on the current
  value, then hashes the new one and writes it via
  `SecretProvider`. On success, all other sessions are revoked.
- **TOTP enrollment** — modal with QR code + plain-text URI +
  recovery codes (download as `.txt`). Operator types one valid
  TOTP back to confirm.
- **Active sessions** — table with id, IP, user-agent, last seen,
  expiry. Revoke button per row.

## Auth policy section detail

Form-bound to `WafConfig.admin.dashboard_auth`. Live-validates and
shows a unified diff before save. Some fields (e.g. `mtls.ca_ref`)
are secret references — the UI shows the reference key, never the
value. Editing the secret value is delegated to the secrets
backend (etcd/file/vault) — the UI shows a "Manage in
$secret_provider" link.

## Danger zone

Each control:

- Requires explicit confirm with the action name typed back.
- Requires TOTP re-prompt if TOTP is enabled.
- Writes a high-severity admin audit entry.

## Compliance overlays

- FIPS profile disables non-FIPS theme/font choices: no-op for v1,
  but the section header shows a "FIPS-locked" pill if engaged.
- PCI/HIPAA profiles enforce minimum TTLs and password complexity
  policy server-side; client-side validation surfaces the same
  error before submit.

## Telemetry

- Reuses `waf_admin_requests_total{endpoint=...}` metrics.
- Theme/density choices are local-only and NOT phoned home.
