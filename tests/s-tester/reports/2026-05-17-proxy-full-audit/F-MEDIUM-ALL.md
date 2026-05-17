---
id: 2026-05-17-medium-bundle-proxy-full-audit
date: 2026-05-17T00:00Z
severity: MEDIUM
area: multiple
component: per-item — see Component line
interop_contract: latent / posture / non-contract correctness
status: open
test_mode: source-review
---

# F-MEDIUM bundle — 15+ MEDIUM-grade findings from the proxy full-crate audit

Items grouped by domain. Each is small enough to land in a single
"post-CRITICAL hardening" PR.

---

## Protocol / transforms

### M-01 · CORS `Vary: Origin` clobbers upstream `Vary` header
**Component:** [transform/cors.rs:108, 148](aegis-gate/crates/aegis-proxy/src/transform/cors.rs#L108)
Uses `headers.insert(VARY, ...)` instead of `.append(...)`. If
upstream already sent `Vary: Accept-Encoding`, the WAF clobbers it
with `Vary: Origin`. Cache correctness downstream is impacted.
Fix: `.append` and de-dupe.

### M-02 · `transform/vars.rs` variable parser is too permissive
**Component:** [transform/vars.rs:24](aegis-gate/crates/aegis-proxy/src/transform/vars.rs#L24)
Accepts `-` and `.` in variable names; legitimate variables look
like `$header.x-forwarded-for` but the parser also accepts
`$jwt.sub-claim`. Behaviour difference is subtle; document or
tighten.

### M-03 · `responses.rs` helpers `unwrap()` on static `Response::builder`
**Component:** [responses.rs:43, 47-48, 64, 109, 113, 121, 140](aegis-gate/crates/aegis-proxy/src/responses.rs)
Multiple `.unwrap()` on response builders with pure-static inputs.
Safe today (no dynamic header injection vector) but the helpers
are `pub(crate)` and a future caller passing a dynamic value will
panic. Replace with `.expect("static body")` for documentation.

### M-04 · CONNECT tunnel `set_nodelay(true)` only on upstream side
**Component:** [tcp_tunnel.rs:413](aegis-gate/crates/aegis-proxy/src/tcp_tunnel.rs#L413)
Nagle disabled on upstream socket but not on the client socket
(which is wrapped via `hyper::upgrade::on`). Asymmetric latency
profile on tunnels.

### M-05 · CONNECT tunnel error path discards partial byte counts
**Component:** [tcp_tunnel.rs:430](aegis-gate/crates/aegis-proxy/src/tcp_tunnel.rs#L430)
On `Err`, returns `(0, 0)` for client→upstream and upstream→client
bytes. Audit fidelity bug — operators can't distinguish "100 MB
through then RST" from "0 bytes ever". TODO comment acknowledges.

### M-06 · `traffic.rs` `sample_rate` truncation (also in dead code)
**Component:** [traffic.rs:172](aegis-gate/crates/aegis-proxy/src/traffic.rs#L172)
`(cfg.sample_rate * 100.0) as u64` truncates `0.005` → `0`, so
"0.5%" sampling never fires. Fix: `(sample_rate * 1_000_000.0) as u64`
and `counter % 1_000_000`. Latent because module is dead code (see
F-CRITICAL-006); fix when wiring.

---

## Routing / listener

### M-07 · Route `tier_override.unwrap_or(Tier::Low)` is unsafe default
**Component:** [route/mod.rs:438](aegis-gate/crates/aegis-proxy/src/route/mod.rs#L438)
A route with no explicit tier silently becomes `Low`. §10 risk
thresholds are tier-gated; an operator who forgot the tier
unknowingly opts into the lowest threshold (most permissive).
Document explicitly OR default to `Medium`.

### M-08 · `route/host.rs` regex compile has no size cap on the input string
**Component:** [route/host.rs:31-34](aegis-gate/crates/aegis-proxy/src/route/host.rs#L31-L34)
Operator-supplied pattern is compiled with no length cap. A 100 KB
regex pattern slows boot + uses memory. Low risk because routes
come from a trusted admin, but worth a 4 KB length cap on the
pattern string.

### M-09 · Two `rustls` provider-init paths race
**Component:** [listener/tls.rs:138-152](aegis-gate/crates/aegis-proxy/src/listener/tls.rs#L138-L152) + [listener/tls_policy.rs:48-68](aegis-gate/crates/aegis-proxy/src/listener/tls_policy.rs#L48-L68)
Both paths lazy-init the ring CryptoProvider via separate
`OnceLock`s. If another crate has installed aws-lc-rs as default,
the second init silently no-ops. Workspace-level init at boot
removes the ambiguity.

### M-10 · `listener/acceptor.rs` doesn't set `SO_REUSEPORT`
**Component:** [listener/acceptor.rs:20](aegis-gate/crates/aegis-proxy/src/listener/acceptor.rs#L20)
Fine for single-process. Hot-restart relies on fd-passing rather
than `SO_REUSEPORT`, so it's intentional — but documenting the
choice would prevent the next person from "fixing" it.

---

## Admin / auth

### M-11 · `format_csrf_cookie` ships `Path=/` rather than `Path=/admin`
**Component:** [admin_auth/csrf.rs:59-62](aegis-gate/crates/aegis-control/src/admin_auth/csrf.rs#L59-L62)
The CSRF cookie ships with `Path=/`, so every data-plane request
on the same hostname will carry it too. Doesn't break security (the
cookie is intentionally readable to JS) but leaks the token to
data-plane upstreams via the forwarded `Cookie:` header.

### M-12 · `AEGIS_INSECURE_COOKIES=1` env opt-out has no boot-time warning
**Component:** [admin_auth/csrf.rs:66-71](aegis-gate/crates/aegis-control/src/admin_auth/csrf.rs#L66-L71)
If accidentally set in production, session + CSRF cookies ship
without `Secure` flag — tokens fly over plain HTTP if the operator
also drops HTTPS. Add a `tracing::warn!("AEGIS_INSECURE_COOKIES=1
set; cookies will NOT be marked Secure. Dev-only.")` at boot.

### M-13 · `AEGIS_DRAIN_TOKEN` compared with non-constant-time `==`
**Component:** [admin_mutate.rs:2210-2218](aegis-gate/crates/aegis-proxy/src/admin_mutate.rs#L2210-L2218)
Token-stuffing attacker can use response-timing oracle to recover
the token byte-by-byte (slow but possible over LAN). Use the same
`constant_time_eq` pattern that `admin_auth::csrf::validate` uses.

### M-14 · `handle_route_test` doc comment claims session-gated but isn't
**Component:** [admin_dispatch.rs:584, 589-666](aegis-gate/crates/aegis-proxy/src/admin_dispatch.rs#L584)
"session-gated by the dispatcher" — per F-CRITICAL-002 the
dispatcher does no session check. The comment lies. Either fix the
comment or fix the gate (preferably the latter via the F-CRITICAL-002
middleware).

---

## Lifecycle / load

### M-15 · `supervisor.rs` is misnamed
**Component:** [supervisor.rs](aegis-gate/crates/aegis-proxy/src/supervisor.rs)
The file is a config-file watcher with hot-reload. NO process
supervision (PID monitoring, restart with backoff, health-probe,
signal forwarding) lives here. The README's "process supervisor"
framing is misleading: a panic in the main task simply takes the
process down and only an external `systemd` (or equivalent) would
restart it. Rename to `config_watcher.rs` or document.

### M-16 · `supervisor.rs` notify debounce is a fixed 100ms sleep, not a real debouncer
**Component:** [supervisor.rs:228](aegis-gate/crates/aegis-proxy/src/supervisor.rs#L228)
Multiple rapid editor writes (vim's atomic-rename, two writes in
the same second) each fire a reload event, all of which then incur
the 100 ms sleep serially in `while let Some` and trigger N
back-to-back reloads. Use `tokio::time::interval` with
`MissedTickBehavior::Skip` or a proper debouncer.

### M-17 · Supervisor `blocking_send` swallows channel-closed error silently
**Component:** [supervisor.rs:194-196](aegis-gate/crates/aegis-proxy/src/supervisor.rs#L194-L196)
`tx.blocking_send(res)` ignores `SendError`. If the receiver task
exits (e.g. due to an upstream panic), the watcher keeps firing
into a dead channel for process lifetime. Log on first error and
shut down the watcher.

### M-18 · `dr.rs::restore` accepts `{}` and would wipe entire config
**Component:** [dr.rs:36-49](aegis-gate/crates/aegis-proxy/src/dr.rs#L36-L49)
`dry_run_validate` only checks YAML well-formedness, not WafConfig
schema. Combined with F-CRITICAL-006 (dr.rs is dead code), latent.
If the module is wired in per the F-CRITICAL-006 recommendation, the
schema check MUST land first.

### M-19 · `traffic.rs::CanarySplitter::pick` panics on empty `entries`
**Component:** [traffic.rs:55-65](aegis-gate/crates/aegis-proxy/src/traffic.rs#L55-L65)
Returns `entries.last().unwrap()`; constructor at line 22 has no
empty-check. Latent — module is dead code. Fix when wiring.

### M-20 · `traffic.rs::RetryBudget::try_retry` not atomic
**Component:** [traffic.rs:108-125](aegis-gate/crates/aegis-proxy/src/traffic.rs#L108-L125)
Two threads can both see `ratio < max_ratio` and both increment,
exceeding budget. Use `fetch_update` CAS loop. Latent — dead code.

---

## State / upstream / secrets

### M-21 · `secrets/mod.rs::SecretValue::Drop` only zeroes original buffer
**Component:** [secrets/mod.rs:58-68](aegis-gate/crates/aegis-proxy/src/secrets/mod.rs#L58-L68)
Once `expand_secrets` interpolates the value into a result `String`,
the resolved cleartext lives in a fresh allocation that's never
zeroed. The "automatic memory clearing" claim only holds for
unmoved `SecretValue` instances. Either keep secrets in
`SecretValue` end-to-end or document the limitation.

### M-22 · `state/redis.rs` has no TLS / no AUTH env split
**Component:** [state/redis.rs](aegis-gate/crates/aegis-proxy/src/state/redis.rs) (RedisConfig at line 41-50)
No `rediss://` handling, no CA bundle env var. Password-in-URL is
the only auth path (no AUTH env var split). For production Redis
behind TLS, falls back to insecure. Add `tls: bool`, `ca_path`,
`password` fields.

### M-23 · `upstream/registry.rs` hard-codes circuit-breaker `min_requests`
**Component:** [upstream/registry.rs:181-190](aegis-gate/crates/aegis-proxy/src/upstream/registry.rs#L181-L190)
`min_requests = 10` regardless of operator config. `PoolConfig.circuit_breaker`
exposes `error_rate_threshold` + `open_duration` but ignores
`min_requests`. README implies per-pool breaker tuning; this drops
one knob silently.

### M-24 · `upstream/lb.rs::pick_p2c` has subtle bias on small n
**Component:** [upstream/lb.rs:50-58, 91-131](aegis-gate/crates/aegis-proxy/src/upstream/lb.rs#L50-L58)
`pick_p2c` indexes via `seed * golden_ratio + nanos` mod n; the
second pick uses `seed / n * 0x9E3779B1 % n`. For small n (n < 4),
the second pick is correlated with the first. Minor for n ≥ 5.

### M-25 · `config_source/etcd_source.rs` doesn't detect roll-back YAML
**Component:** [config_source/etcd_source.rs:268-271](aegis-gate/crates/aegis-proxy/src/config_source/etcd_source.rs#L268-L271)
`last_yaml == yaml` short-circuit happens BEFORE schema parse. After
a hot-reload of detector mask via `PUT /api/detectors`, the live
config has the new mask but `last_yaml` still equals the old etcd
value. A roll-back to the previous YAML won't re-apply because
`last_yaml` no longer matches what's live. Could surprise operators.

### M-26 · DNS refresh `SoftSkip` can leave pool members empty at boot
**Component:** [upstream/dns_refresh.rs:251-263](aegis-gate/crates/aegis-proxy/src/upstream/dns_refresh.rs#L251-L263)
If resolution fails on tick 1 with `SoftSkip`, the pool stays at
its boot state (possibly empty). Registry validator rejects empty
pools (`PoolValidationError::EmptyMembers`), but `new_ip_set ==
last_applied_ip_set` (both empty) → no apply happens → pool stays
unconfigured silently. Hard-fail at boot when SoftSkip leaves a
pool empty, OR fall back to a "resolve at boot time, panic-or-fail
fast" mode.

### M-27 · `cluster_lease/heartbeat.rs` no jitter between nodes
**Component:** [cluster_lease/heartbeat.rs:108-112](aegis-gate/crates/aegis-proxy/src/cluster_lease/heartbeat.rs#L108-L112)
N nodes started at the same time synchronize heartbeats. Add jitter
(±10% of interval) to avoid thundering-herd on the lease backend.

---

## Severity rationale

All MEDIUM because:
- Each affects a narrow case (specific dev opt-out, specific
  backend, specific edge route), OR
- Each is latent because the affected module is dead code (M-06,
  M-18, M-19, M-20), OR
- Each is correctness fragility rather than active bug (M-01, M-03,
  M-08, M-09).

None alone justifies an individual file. Bundled for one-pass
review and a single hardening PR.
