# Milestone D-M4 — Configuration Management

**Goal.** Rule Manager, Tier Config, Blacklist, Whitelist, Settings.
This is the most mutation-heavy milestone — every save flows
through CSRF + audit chain.

**Crate touched.** `aegis-control` plus a tiny extension to
`aegis-core::config` for the new admin `dashboard.legacy_shell`
and `prometheus_url` fields (already added in D-M1 and D-M3
respectively).

**Verification.** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`.

**References.**
- [`docs/dashboard-enterprise/pages/rule-manager.md`](../../docs/dashboard-enterprise/pages/rule-manager.md)
- [`docs/dashboard-enterprise/pages/tier-config.md`](../../docs/dashboard-enterprise/pages/tier-config.md)
- [`docs/dashboard-enterprise/pages/blacklist.md`](../../docs/dashboard-enterprise/pages/blacklist.md)
- [`docs/dashboard-enterprise/pages/whitelist.md`](../../docs/dashboard-enterprise/pages/whitelist.md)
- [`docs/dashboard-enterprise/pages/settings.md`](../../docs/dashboard-enterprise/pages/settings.md)

---

## New endpoints

| Method | Path |
|--------|------|
| POST | `/api/rules/validate` |
| GET | `/api/rules/{id}` |
| PUT | `/api/rules/{id}` |
| GET | `/api/rules/{id}/stats?window=` |
| GET | `/api/rules/top?window=&limit=` |
| GET | `/api/tiers` |
| GET | `/api/tiers/{name}` |
| PUT | `/api/tiers/{name}` |
| GET | `/api/tiers/{name}/stats?window=` |
| GET / POST / PUT / DELETE | `/api/blacklist[/...]` |
| POST | `/api/blacklist/bulk` |
| GET / POST / PUT / DELETE | `/api/whitelist[/...]` |
| POST | `/api/whitelist/bulk` |
| POST | `/api/admin/password` |
| POST | `/api/admin/totp/enroll` |
| POST | `/api/admin/totp/reset` |
| GET | `/api/admin/sessions` |
| DELETE | `/api/admin/sessions/{id}` |
| PUT | `/api/admin/policy` |
| GET | `/api/integrations` |
| POST | `/api/admin/break-glass` |
| POST | `/api/admin/secrets/session/rotate` |

## Tasks

### D-M4-T4.1 Rule Manager page

- Files: `assets/dashboard/pages/rules.js`,
  `src/api/rules.rs` (extend existing).
- Implements the list / detail / DSL / diff / stats tabs.
- Validate-before-save flow (`POST /api/rules/validate`).
- GitOps mode awareness: when `cfg.gitops.enabled`, Save is
  intercepted by the existing GitOps PR flow; the UI shows the
  PR link in a toast.
- Tests: validator returns errors on a malformed rule; Save
  writes an admin audit entry with the diff.

### D-M4-T4.2 Rule validator endpoint

- File: `src/api/rules.rs`
- Reuses `aegis-security`'s parser + linter + dry-run evaluator
  (already exposed publicly per existing `aegis-control` deps).
- Pure function; never mutates state.
- Test: golden cases for ok / errors / warnings.

### D-M4-T4.3 Rule stats endpoint

- File: `src/api/rules.rs`
- Per-rule rolling counters from the audit subscriber, keyed
  by `rule_id` field on `AuditEvent`.

### D-M4-T4.4 Tier Config page

- Files: `assets/dashboard/pages/tiers.js`,
  `src/api/tiers.rs`.
- List + detail editor (Pipeline / Routes / Stats tabs).
- Saves go through the existing `PUT /api/config` validator —
  this endpoint constructs a partial-config patch and reuses
  the same `validate_then_apply` path.

### D-M4-T4.5 Blacklist / Whitelist endpoints

- Files: `src/api/blacklist.rs`, `src/api/whitelist.rs`.
- Backed by the existing CIDR list / threat-intel store in
  `aegis-security`. The store already supports add / remove /
  query — we just expose REST.
- Bulk import is transactional: validate all entries first,
  then apply atomically; on partial failure return per-line
  outcomes.
- Compliance check: PCI/HIPAA profile clamps whitelist
  `expires_at` ≤ profile-defined max TTL.
- Tests: add/remove round trip; bulk partial-failure;
  compliance clamp; audit chain entry per mutation.

### D-M4-T4.6 Blacklist / Whitelist UI

- Files: `assets/dashboard/pages/blacklist.js`,
  `assets/dashboard/pages/whitelist.js`.
- List, add modal, bulk import modal, hits/bypasses drawer.
- Confirm modal on `bypass: ["all"]` whitelist entries with
  TOTP re-prompt when TOTP is enabled.

### D-M4-T4.7 Settings page

- Files: `assets/dashboard/pages/settings.js`,
  `src/api/admin.rs`.
- Five sections: Account, Authentication policy, Dashboard,
  Integrations, Danger zone.
- Re-auth modal for password change and Danger zone actions.

### D-M4-T4.8 Admin self-service endpoints

- File: `src/api/admin.rs`
- Password change: argon2id verify of current → hash new →
  write via SecretProvider → revoke other sessions.
- TOTP enroll / reset reuses the existing `admin_auth::totp`
  module.
- `PUT /api/admin/policy` reuses the existing config validator
  for the `dashboard_auth` subset.
- `POST /api/admin/break-glass` writes a 1h-TTL marker in etcd;
  the GitOps loader honours it; the dashboard shows a banner.
- Tests: password change end-to-end; break-glass marker
  creation + expiry.

### D-M4-T4.9 Sessions list / revoke

- File: `src/api/admin.rs`
- Already most of this lives in `admin_auth::session`. Add
  `list_active()` returning every session for the principal.
- Revoke deletes the etcd entry; replicas pick up via watcher.

### D-M4-T4.10 Integrations endpoint

- File: `src/api/admin.rs`
- Read-only mirror of `cfg.admin.integrations`: Grafana URL,
  Alertmanager URL, GitOps repo, etc.

## Exit gate

- All five pages CRUD operations work end-to-end with audit
  entries.
- Compliance overlays clamp values where required (PCI / HIPAA
  TTL caps, FIPS cipher restrictions).
- Per-page integration tests:
  - Rule Manager: validate / save / disable / delete.
  - Tier Config: save valid + reject invalid.
  - Blacklist / Whitelist: CRUD + bulk + compliance clamp.
  - Settings: password change, TOTP reset, session revoke,
    break-glass on/off.
- ≥ 36 new tests added; existing 1,477 still green.

## Implement-Progress.md update

```
## Last Completed
- Task: D-M4 Configuration management pages
- Crate: aegis-control
- Status: DONE

## Next Task
- Task: D-M5-T5.1 Tracking page
- Plan: plans/dashboard-enterprise/milestone-5-tracking.md
```
