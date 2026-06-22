# BUG — live-added hostname pool members never get a DNS refresh task (stale until restart)

- **Type:** BUG (upstream / DNS resolution lifecycle)
- **Severity:** 🟠 MEDIUM-HIGH — a pool member added by hostname through the dashboard (or any post-boot config path) is resolved to an IP exactly once and then frozen. If the upstream remaps that hostname to a new server IP, traffic keeps going to the stale IP until the WAF process restarts. Boot-configured hostnames are unaffected (they auto-refresh on TTL).
- **Status:** 🟢 Fixed — branch `fix/dns-refresh-reconcile-live-hostnames` (TDD: RED `6d40403` → GREEN `fba3277`). Archive on merge.
- **Found:** 2026-06-22, code review of the hostname-member resolution path
- **Fixed:** 2026-06-22 — see [Resolution](#resolution).
- **Area:** `crates/aegis-proxy/src/upstream/` — `dns_refresh` (Phase 2 background refresh) vs `dns_resolve` (Phase 1 one-shot); admin PUT + cluster-reload config paths.

## Summary

Pool members can be addressed by hostname (`api.example.com:443`) as well as
`IP:port` (`MemberAddrSpec::Hostname` vs `::Ip`, `crates/aegis-core/src/config.rs:2927`).
The operator-authored hostname is **retained** in `config:waf:doc`; the IP is only a
derived, in-memory runtime artifact (`Member.addr`). Two layers keep it fresh:

- **Phase 1 — one-shot resolve** (`upstream/dns_resolve.rs`): runs at boot, at dashboard
  PUT, and on cluster config activation. Resolves the hostname to IP member(s) for the
  current apply only.
- **Phase 2 — background TTL refresh** (`upstream/dns_refresh.rs`): a per-pool task that
  re-resolves on the DNS TTL and atomic-swaps the pool when the IP set changes, emitting a
  `pool_dns_resolved` audit event. **This is the only mechanism that picks up an upstream
  DNS remap without a restart.**

The bug: **Phase 2 tasks are spawned at boot only.** A hostname member added to a pool
*after* boot (dashboard PUT, or any path that lands a new doc version) gets Phase 1's
one-shot resolve and then **no refresh task** — it is pinned to the IP captured at PUT
time and stays static until the next process restart.

This is a documented scope guard, not an unknown defect — see the module header at
`crates/aegis-proxy/src/upstream/dns_refresh.rs:41-47`:

> ## Scope guard
> Phase 2 spawns refresh tasks at boot only. Dashboard PUTs that add a new hostname to a
> pool **don't** spawn a new refresh task today — the new hostname gets Phase 1's one-shot
> resolution at PUT time and stays static until the next process restart. Phase 2.5 /
> Phase 3 will lift this restriction.

Raising it as a tracked bug because the operator-visible behavior is a silent
inconsistency: two pool members that look identical in the dashboard (both hostnames)
behave differently depending on whether they existed at boot.

## Root cause (confirmed in code)

`spawn_pool_refresh` is invoked from exactly **one** call site — the boot wiring:

- `crates/aegis-proxy/src/run.rs:956` — `dns_refresh::spawn_pool_refresh(...)`, inside the
  boot upstream setup (~`run.rs:944-984`). This walks the boot config's pools, and for
  each pool that has ≥1 hostname member, spawns one background refresh task holding the
  original `DnsRefreshSpec` / `HostnameSpec` (`dns_refresh.rs:77-101`).

The two post-boot config paths resolve hostnames but **never spawn (or respawn) a refresh
task**:

- **Dashboard / admin PUT** — `crates/aegis-proxy/src/admin_mutate.rs:296`,
  `validate_upstream_resolvable` → `dns_resolve::expand_hostname_members(pools)`. This is a
  Strict one-shot resolve used only to reject typos with a 400; the result is discarded and
  the doc keeps the hostname. No `spawn_pool_refresh`.
- **Cluster config activation / reload** — `crates/aegis-proxy/src/config_source/reload.rs:479`,
  `expand_hostname_members_with_policy(..., SoftSkip)` inside `apply_cfg_change_to_upstreams`.
  Per-node one-shot re-resolution on every doc version. No `spawn_pool_refresh`.

Grep confirms the single spawn site:

```
$ grep -rn "spawn_pool_refresh" crates/
crates/aegis-proxy/src/run.rs:956:    ... dns_refresh::spawn_pool_refresh(
crates/aegis-proxy/src/upstream/dns_refresh.rs:215: pub fn spawn_pool_refresh(...)   // definition
```

So after boot, the refresh-task population is frozen. Adding a hostname member updates the
doc and resolves it once, but the new pool/member has no task watching its TTL.

## Impact

- **A hostname member added live is not resilient to upstream DNS remaps.** If the upstream
  rotates the A record to a new server IP (cloud LB replacement, K8s Service re-IP, failover,
  blue/green cutover), the WAF keeps dialing the old IP.
- **Failure mode at the edge:** health checks + circuit breaker (`upstream/health.rs`,
  `probe.rs`) will mark the dead old IP unhealthy and fail closed on it — they do **not**
  discover the new IP (only DNS re-resolution does). If every member of the pool is a
  stale live-added hostname, the pool goes fully unhealthy and requests to it fail until
  manual intervention or restart.
- **Silent inconsistency:** two identical-looking hostname members in the same pool behave
  differently (boot member auto-refreshes; live-added member is frozen). No dashboard signal
  distinguishes them, and `refresh_seconds` set on a live-added member is silently inert.
- **Scope:** affects only hostname members added/changed after boot. Boot-configured
  hostnames are fine. Literal `IP:port` members are out of scope (never auto-refreshed by
  design — operator pinned an IP).

## Reproduction

1. Boot the proxy with a pool that has **no** hostname members (IP-only, or a different
   pool).
2. Via the dashboard, add a hostname member to a pool — e.g. `api.example.com:443` (ideally
   one with a short TTL and multiple/rotating A records). Confirm it resolves and serves
   traffic.
3. Change the authoritative DNS for `api.example.com` to a different IP (or rotate the
   cloud LB / K8s Service so the A record changes). Wait past the record TTL.
4. **Observed:** the WAF keeps connecting to the original IP; no `pool_dns_resolved` audit
   event fires for that pool; traffic eventually fails as the old IP is decommissioned.
   **Expected:** within ~TTL the member re-resolves to the new IP and the pool swaps,
   exactly as a boot-configured hostname member would.
5. Control: a hostname member present in the **boot** config, given the same DNS remap,
   does re-resolve and emits `pool_dns_resolved`.

## Suggested fix

Make the post-boot config paths reconcile the set of refresh tasks against the active doc,
so a live-added hostname behaves identically to a boot-configured one.

1. **Extract a reconcile entry point.** Refactor the boot loop around `run.rs:956` into a
   reusable `reconcile_dns_refresh(pools, ...)` that, given the current pool set, ensures
   exactly one refresh task per pool-with-hostnames: spawn for newly-appearing pools/hostname
   members, and stop tasks for pools whose hostname members were removed. Track live task
   handles in a registry (pool name → `JoinHandle` / cancel token) so it's idempotent.
2. **Call it from the apply path, not just boot.** The natural seam is
   `apply_cfg_change_to_upstreams` (`config_source/reload.rs:479`), which already runs on
   every node for every doc version (PUT-originated and peer-converged alike) and already
   does the one-shot `expand_hostname_members_with_policy`. Reconciling refresh tasks there
   covers both the originating node and peers, and rides the existing convergence machinery
   — no separate signal needed.
   - This composes with the `apply_and_swap` reload-helper guard concern: the cluster
     watcher hand-lists each `apply_cfg_change_to_*`; the new reconcile must be wired into
     that list (and the structural guard test extended) so it can't silently regress to
     node-local-until-restart — the same failure class as the zero-trust / copilot misses.
3. **Honor per-member `refresh_seconds` on live-added members** once a task exists (today
   it's parsed and stored but only consumed by Phase 2, so it's inert for live-added members).
4. **Regression test.** In an in-memory/redis cluster: boot a pool without hostnames, PUT a
   hostname member, then change what the resolver returns and assert the pool's member IP
   set updates within the TTL window (and that a `pool_dns_resolved` audit event fires) —
   without a restart. Mirror the existing Phase 2 refresh tests but drive the member in via
   the PUT/apply path rather than boot config.

## Workaround (until fixed)

Restart the WAF process after adding a hostname member via the dashboard — boot then spawns
the refresh task. Or pin the member as a literal `IP:port` if the upstream IP is stable and
operators accept manual updates on remap. Neither is satisfactory for runtime operator edits;
hence the bug.

## Resolution

Implemented on `fix/dns-refresh-reconcile-live-hostnames` (TDD). Rather than
spawn-and-forget at boot, a new **`DnsRefreshManager`**
(`crates/aegis-proxy/src/upstream/dns_refresh.rs`) owns the per-pool refresh
tasks and reconciles them against the operator-authored upstreams on **every**
config apply:

- `spec_fingerprint(&DnsRefreshSpec)` — hashes the spec's hostname members
  (host/port/refresh_seconds/weight/zone/host_header), the re-resolution surface.
- `plan_reconcile(tracked, desired)` — pure, fully unit-tested planner returning
  `spawn` / `respawn` / `stop` / `keep`. A desired hostname pool not currently
  tracked → `spawn` (the case-3 fix); changed hostname members → `respawn`
  (covers the "add a 2nd hostname to an existing pool" sibling case); removed →
  `stop`; unchanged → `keep` (idempotent, no churn).
- `DnsRefreshManager::reconcile(&upstreams)` — applies the plan (spawn via the
  existing `spawn_pool_refresh`, abort handles on stop/respawn).

Wired through the **existing** `reload::apply_cfg_change_to_upstreams` (new
optional manager arg), reconciling *after* the registry apply so the new task's
first-tick seed reflects the freshly-installed IPs. Both watcher paths
(redis config-plane `ApplyTargets`, file/etcd `FoldedReloadTargets`) already call
that one helper, so the structural guard `apply_and_swap_invokes_every_reload_helper`
stays satisfied without a new helper. Boot now calls `manager.reconcile` instead
of the inline spawn loop; `derive_applied_dns_seed` moved into the module as
`derive_applied_seed`. `None` manager (resolver failed to build at boot) preserves
the prior degraded mode.

**Tests** (`dns_refresh::tests`): fingerprint stability/change, the four plan
buckets + a mixed/sorted case, and a manager end-to-end test asserting a
live-added pool spawns a task, re-reconcile is idempotent, and removal stops it.
Full `aegis-proxy` lib suite green (962 passed).

**Out of scope (tracked separately):** a DNS rotation re-applies the task's
captured `base` pool config (lb/health/cb/connection), so a base-only PUT made
between rotations can be reverted on the next tick. The fingerprint deliberately
ignores base-only edits (matches existing boot-task behaviour); fixing the
base-clobber is a distinct follow-up.

## Related

- Same "post-boot config mutation doesn't get fully wired on every node" failure class as
  [`archived/BUG-console-route-mutation-not-fleet-convergent.md`](./archived/BUG-console-route-mutation-not-fleet-convergent.md)
  — there the write side skipped the versioned doc; here the doc is written but the
  DNS-refresh side-effect of the apply is missing.
- Reload-helper completeness guard (every `apply_cfg_change_to_*` must be wired into both the
  cluster and file watchers, enforced by a structural test) — the fix should extend that guard
  to cover refresh-task reconciliation.
