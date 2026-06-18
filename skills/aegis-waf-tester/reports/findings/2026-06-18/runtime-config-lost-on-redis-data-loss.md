---
id: 2026-06-18-runtime-config-lost-on-redis-data-loss
date: 2026-06-18T08:05Z
severity: MEDIUM
area: data-plane
component: shared-config-store / upstreams / routes
status: open
test_mode: full-qc
---

# Runtime-added pools & routes silently lost when Redis restarts empty

## Summary
Upstream pools and routes created at runtime (via the admin API / dashboard)
are held in the Redis-backed shared config store. They survive a **WAF process
restart** (re-hydrated from Redis on boot), but they are **silently lost when
Redis itself restarts without its data** (no persistence): the shared config
store comes back empty and the WAF reverts to the on-disk file baseline
(`config/dev.yaml`), which defines only `stub-pool` + the catch-all route. No
error, no alert, no auto-restore from last-known-good — the extra config just
disappears.

Observed live: before the test the WAF had 4 pools (`stub-pool`, `sec-pool`,
`sec-http-pool`, `sample`) and 2 routes (`catch-all`, `SEC` → `sec-team.waf-exams.info`).
After `docker stop aegis-cluster-redis` + `docker start` (the dev Redis has no
AOF/RDB persistence, so it returned empty), only `stub-pool` + `catch-all`
remained.

## Repro
1. At runtime, add a pool + route via the API (they are not in `dev.yaml`):
   `PUT /api/upstreams/pool/<id>`, `PUT /api/routes/<id>`. Confirm they appear
   in `GET /api/upstreams/config` and `GET /api/routes`.
2. Restart the WAF process only → config still present (re-hydrated from Redis). ✔
3. Restart Redis so it loses its dataset
   (`docker stop aegis-cluster-redis && docker start aegis-cluster-redis`;
   dev Redis has no persistence).
4. `GET /api/upstreams/config` → only the file-baseline pools remain; runtime
   pools/routes are gone.

## Expected
At least one of: (a) the shared config store is persisted (Redis AOF/RDB or a
periodic on-disk snapshot) so a Redis bounce re-hydrates it; (b) on detecting an
empty/younger shared store, the WAF restores from its last-known-good local
snapshot instead of silently reverting to the file baseline; (c) a loud
`config_store_empty` / `config_reverted_to_baseline` audit+alert so an operator
knows runtime config was dropped.

## Actual
Silent revert to `dev.yaml` baseline; no audit event surfaced naming the drop;
runtime config unrecoverable except by manual re-entry or `waf restore` from a
prior snapshot.

## Suggested fix
- Enable persistence on the deployed Redis (AOF) for the shared config store, and
  document it as a requirement, OR
- Persist a local last-known-good snapshot of the shared config doc (the
  `waf snapshot` envelope already exists — B4-T1/T2) and re-apply it when the
  shared store returns empty/older than the local snapshot, OR
- At minimum, emit a high-severity audit event + health flag when the shared
  config store is detected empty and the WAF falls back to the file baseline.

## Severity rationale
MEDIUM. In production with a persistence-configured Redis this likely does not
trigger, and the WAF stayed up and kept serving on the file baseline (no crash,
no traffic outage on the surviving route). But silent loss of operator-authored
routing/upstream config on a dependency bounce — with no alert and no
auto-restore — is a real durability/observability gap that can take a protected
backend offline (its route vanishes) without anyone noticing. Recoverable, so
not HIGH.

## Test-side note
This was triggered by the QA Redis-failure test (`docker stop/start
aegis-cluster-redis`). The operator's runtime-added `SEC` route + `sec-pool` /
`sec-http-pool` / `sample` pools (→ `sec-team.waf-exams.info`) were dropped and
need to be re-added (dashboard) or restored from a `waf snapshot` if one exists.
