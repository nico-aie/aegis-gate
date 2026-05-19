# Plan — fix QC findings from 2026-05-17 s-tester audits + audit-rail rework

> **Source reports:**
> - `tests/s-tester/reports/2026-05-17-entry-cli-dataplane-audit/` (9 findings)
> - `tests/s-tester/reports/2026-05-17-proxy-full-audit/` (10 CRITICAL + 23 HIGH + 3 contract gaps + 15+ MEDIUM)
>
> **Verification mode:** source-spot-check by 2 parallel Explore agents (one per report) reading each finding's cited file:line and classifying CONFIRMED / PARTIAL / FALSE_POSITIVE / STALE.
>
> **Outcome:** 16 confirmed CRITICAL bugs, 1 PARTIAL (severity overstated), 2 FALSE_POSITIVE, 3 confirmed contract gaps. HIGH bundle (28 items) not yet individually verified — spot-check during the relevant phase.

## Verification matrix

### entry-cli-dataplane-audit — 9/9 CONFIRMED

| ID | Severity | Status | Smallest-effort fix |
|---|---|---|---|
| F-CRITICAL-001 | CRIT | CONFIRMED | Route `/__waf_control/*` responses through `stamp_interop_response` |
| F-CRITICAL-002 | CRIT | CONFIRMED | Have rate-limit / strike-block / blacklist / risk-score block paths consult `interop_modes` like the detector branch already does |
| F-CRITICAL-003 | CRIT | CONFIRMED | Fail-fast (or fail-loud + retry) on audit sink open error at boot |
| F-CRITICAL-004 | CRIT | CONFIRMED | Promote 1 MiB cap from `const MAX_BODY_BYTES` to `cfg.proxy.max_body_bytes` with sane defaults |
| F-HIGH-001 | HIGH | CONFIRMED | `.path()` → `.path_and_query()` in audit-path capture |
| F-HIGH-002 | HIGH | CONFIRMED | Default `trusted_proxies` should be empty `[]`; opt-in not opt-out |
| F-HIGH-003 | HIGH | CONFIRMED | Wrap upstream body read in `Limited<_>` with configurable cap |
| F-HIGH-004 | HIGH | CONFIRMED | Swap `blake3(peer:nanos:path)` → `uuid::Uuid::new_v4()` |
| F-HIGH-005 | HIGH | CONFIRMED | Hold `RwLock` across the reset-callbacks loop, snapshot config under it |

### proxy-full-audit — 7/10 CRITICAL confirmed, 1 partial, 2 false positive, 3/3 contract gaps confirmed

| ID | Severity | Status | Smallest-effort fix |
|---|---|---|---|
| F-CRITICAL-001 | CRIT | CONFIRMED | Wire `data_plane::handle_data_request` into the H3 service (~80 LoC) |
| F-CRITICAL-002 | CRIT | CONFIRMED | Add session middleware to admin dispatch (~200 LoC; biggest item in the plan) |
| F-CRITICAL-003 | CRIT | CONFIRMED | Call `totp::verify` after password verify in `api/login.rs` |
| F-CRITICAL-004 | CRIT | CONFIRMED | Derive `actor` from session, not `X-Actor` header (5 LoC) |
| F-CRITICAL-005 | CRIT | CONFIRMED | Swap blake3-clock-counter token gen for `OsRng` 256-bit tokens |
| F-CRITICAL-006 | CRIT → **HIGH/MED** | PARTIAL | Either wire shed/quota/dr/traffic into the data plane or remove from README+architecture; design call needed |
| F-CRITICAL-007 | CRIT | CONFIRMED | `decode_bucket` must honor stored timestamp (10 LoC) — bug acknowledged in source comment |
| F-CRITICAL-008 | CRIT | CONFIRMED | Wrap `member.inflight` in RAII `InflightGuard` |
| F-CRITICAL-009 | CRIT → **NIL** | **FALSE_POSITIVE** at cited line. Separate `.unwrap()` at `cors.rs:138` is worth removing as hardening (3 LoC) |
| F-CRITICAL-010 | CRIT → **NIL** | **FALSE_POSITIVE** — `HeaderValue::from_str` rejects `\n` so the attack fails closed; QC agent self-corrected mid-doc |
| F-CONTRACT-001 | gap | CONFIRMED | WS no-healthy → `circuit_breaker` not `block` |
| F-CONTRACT-002 | gap | CONFIRMED | CONNECT unreachable → surface `timeout` / `circuit_breaker` action |
| F-CONTRACT-003 | gap | CONFIRMED | Either wire `cfg.upstreams` hot-reload from file/etcd, or fix the README claim |

### HIGH bundles (28 items, F-HIGH-protocol / admin / stateful / lifecycle)

Not individually verified yet. Plan to spot-check during Phase 4 when the cluster is being touched.

## Phasing — small-first, big-impact-first

Order picked so each phase ships independently, lands the smallest-LoC scoring wins first, and front-loads the items that unblock Round-1 scoring.

### Phase 1 — small CRITICALs that move the Round-1 needle (target: <300 LoC total)

These are the "smallest CRITICALs to fix immediately" the QC tester called out plus the trivially-small ones.

1. **F-CRITICAL-001 (control endpoints missing 6 headers)** — `accept.rs:1097-1110` short-circuit must also call `stamp_interop_response` before returning. Inside the same closure as the data-path stamping. ~20 LoC.
2. **F-CRITICAL-003 (audit sink fail-silent)** — `run.rs:1701-1711` `MinimalJsonlSink::open()` error should either panic with a clear message OR retry once with `OpenOptions::create(true)` before falling back. ~10 LoC.
3. **F-CRITICAL-004 (1 MiB body cap)** — promote `const MAX_BODY_BYTES` to `ProxyConfig.max_body_bytes` with default 10 MiB, configurable per-route via `route.max_body_bytes`. ~50 LoC including config wiring + tests.
4. **F-HIGH-001 (audit path strips query)** — single-line change `.path()` → `.path_and_query().map(|q| q.as_str()).unwrap_or("")` in `accept.rs:1089`. ~5 LoC.
5. **F-HIGH-004 (request-id entropy)** — `accept.rs:1235-1243` `blake3(peer:nanos:path)` → `uuid::Uuid::new_v4().to_string()`. Add `uuid = { version = "1", features = ["v4"] }` to the crate. ~10 LoC.
6. **F-CRITICAL-007 (token bucket never refills)** — `state/in_memory.rs:286-292` `decode_bucket()` must read the stored nanos and reconstruct `Instant`. The comment at line 288-290 already says "In a real impl…". ~15 LoC + unit test that asserts refill after window.
7. **F-CRITICAL-009 hardening** (drive-by, not the original cited bug) — `cors.rs:138` `.unwrap()` → `.ok().unwrap_or_else(|| HeaderValue::from_static("null"))`. ~3 LoC.

**Estimated total: ~115 LoC + tests.** Each fix is independent and individually committable. Phase target: 1-2 days.

### Phase 2 — `log_only` mode must apply to ALL block paths (F-CRITICAL-002)

The detector branch at `data_plane.rs:644-660` consults `interop_modes` + `mode_for_rule()` correctly. Replicate that pattern in the four other block paths:

- Rate-limit block (`data_plane.rs:365-428`)
- Strike-block (around `risk_block` invocation)
- Blacklist block (`is_blacklisted` decision)
- Risk-score block (`level()` returns `Block`)

Each path needs: (1) compute action mode via `mode_for_rule("ratelimit")` / etc., (2) emit audit event regardless of mode, (3) when mode is `LogOnly`, allow the request to proceed instead of returning 429/403.

**Estimated: ~80 LoC + integration test per branch.** Phase target: 1 day.

### Phase 3 — admin auth gate (the big one)

F-CRITICAL-002 + 003 + 004 + 005 are interdependent — fix them together so the auth chain is internally consistent.

- **F-CRITICAL-002** — Add `admin_session_middleware` to the admin dispatch in `accept.rs:875-901`. Reject requests without a valid session cookie + IP allowlist match. Mutations require `csrf_token` header matching session-bound token.
- **F-CRITICAL-003** — `api/login.rs` adds TOTP verify step between password verify and session issue. Honor `admin.dashboard_auth.totp_enabled`.
- **F-CRITICAL-004** — Mutation handlers derive `actor` from `session.user_id`, NOT `X-Actor` header. `X-Actor` is dropped at the gateway.
- **F-CRITICAL-005** — `admin_auth/csrf.rs` token gen uses `rand::rngs::OsRng` for both CSRF and session IDs. Sessions stored in `SessionStore` with HMAC signature over `(user_id, issued_at, csrf_token_hash)`.

**Estimated: ~250 LoC + auth-chain integration tests. Highest-risk phase — touches every admin endpoint.** Phase target: 2-3 days. Pre-Phase-3: spec the session middleware shape in a follow-up plan doc; don't start coding until shape is reviewed.

### Phase 4 — H3 pipeline wire-up (F-CRITICAL-001 from report B)

`listener/http3.rs:261` calls `proxy::handle_request()` directly; wire it through `data_plane::handle_data_request()` so QUIC traffic gets the same security pipeline + audit + 6 headers as H1/H2.

This needs a small bridge: H3 doesn't have a TCP `peer.ip()`; use `connection.remote_address()` to populate the `Peer` struct. Stamp `X-WAF-*` headers in the H3 response builder.

**Estimated: ~80 LoC + H3 integration test.** Phase target: 1 day.

### Phase 5 — remaining HIGH + contract gaps

Lower-priority but real:
- **F-HIGH-002** (loopback in trusted_proxies default) — change `default_trusted_proxies()` to return `vec![]`. Operators who want XFF resolution opt-in by configuring proxies.
- **F-HIGH-003** (upstream body unbounded) — `forward.rs:511-516` wrap `into_body().collect()` in `Limited<_>` with config-driven cap (default 10 MiB, configurable per-pool).
- **F-HIGH-005** (reset_state atomicity) — `control.rs:264-282` acquire a single `RwLock<ResetGuard>` write-lock around the subsystem-callback loop. Data plane reads the guard's read-lock at request entry.
- **F-CONTRACT-001/002/003** — three semantic gaps; small individually but each requires a spec-trace and a few tests.

**Estimated: ~150 LoC + tests across 6 changes.** Phase target: 2 days.

### Phase 6 — F-CRITICAL-008 RAII guard + F-CRITICAL-006 dead code call

- **F-CRITICAL-008** — Introduce `struct InflightGuard<'m>(&'m Member)` whose `Drop` decrements `member.inflight`. `proxy.rs:300-312` replaces the manual inc/dec. ~30 LoC.
- **F-CRITICAL-006 (downgraded)** — Design call: (a) wire `shed.rs` / `quota.rs` / `dr.rs` / `traffic.rs` into the data plane (probably ~500 LoC across 4 modules + tests), or (b) remove them + scrub README/Architecture claims. **My take:** load-shedding is genuinely valuable for Round-3 resilience scoring, so wire `shed.rs` (smallest of the four) and document the other three as "Phase-2 — not yet wired" in README. ~200 LoC for shed alone; defer quota/dr/traffic.

**Estimated: ~230 LoC + tests.** Phase target: 2 days.

### Phase 7 — audit-rail / Redis rework

**Verdict:** keep JSONL as primary storage. Don't move primary to Redis.

**Reasoning:**
- JSONL is the authoritative per-node compliance trail; Redis would break per-node durability if the cluster failover loses unreplicated entries.
- The 60k-RPS audit-drop problem is the broadcast-channel cap, NOT the storage backend. Redis on loopback (~50µs/op) is no faster than JSONL append for the same per-event work; moving primary storage to Redis just relocates the bottleneck.
- The audit chain-hash trust model assumes events are written durably to the local node before being broadcast — Redis async replication violates this.

**What to actually do:**

7a. **Fix the immediate 60k-RPS drop**: make `AuditBus` capacity configurable (today: hard-coded). Bump default from current value to 100,000 — enough to absorb 1,000 seconds of 100-event/s lag. ~20 LoC + config wiring. **This alone fixes the dashboard-drop problem the user surfaced.**

7b. **Add Redis Stream as optional secondary sink** for multi-node cluster dashboards:
- New `crates/aegis-control/src/audit/sinks/redis.rs` mirroring `jsonl.rs`'s shape.
- Config grows `audit.sinks[].redis: { url, stream_key, maxlen }`.
- `run_persist_task` fans out to all configured sinks; JSONL stays primary.
- Dashboard's `GET /api/audit/since` adds optional `?cross_node=true` mode that calls `XREAD` against the Redis stream so an operator on node A sees events from nodes B+C.
- `MAXLEN ~ N` caps the stream automatically — no separate retention job.
- ~150 LoC + tests.

7c. **Don't migrate any existing storage to Redis.** The current JSONL retention + rotation + chain-hash + dashboard `/api/audit/since` paths all stay unchanged. Redis is purely additive, opt-in via config.

**Estimated: ~170 LoC + tests.** Phase target: 1-2 days. Lands AFTER Phase 5 because the contract gaps + HIGH-protocol fixes may touch audit-emit sites.

## Out of scope

- **F-CRITICAL-010 (WS smuggling)** — false positive. Document why in `plans/future/unwired-stubs-catalog.md` so the next static auditor doesn't re-raise it.
- **F-CRITICAL-009 cited bug** — false positive at the original line; we're doing the drive-by hardening on `cors.rs:138` instead.
- **Quota / DR / Traffic wiring** — deferred (only `shed.rs` wires in Phase 6).
- **HIGH bundles** (28 items) — individually verify and triage as we touch the relevant areas during phases 4-6; not a separate phase.

## Verification per phase

For each phase before moving to the next:
1. `cargo build -p aegis-bin` clean.
2. `cargo test --workspace` clean (no regressions in the 3,269 currently-green tests).
3. New unit/integration tests for the fixed bug.
4. Boot the WAF on `config/dev.yaml` and `config/profiles/prod-balanced.yaml`; check the boot log surfaces the fix's expected log line.
5. For Phase 1-3 (Round-1-impacting): run the OC harness contract smoke at `tests/hackathon/run.sh` and confirm header / audit / log_only contract assertions pass.

## Files touched (estimated)

```
Phase 1: ~7 files
  crates/aegis-proxy/src/accept.rs
  crates/aegis-proxy/src/run.rs
  crates/aegis-proxy/src/data_plane.rs
  crates/aegis-proxy/src/state/in_memory.rs
  crates/aegis-proxy/src/transform/cors.rs
  crates/aegis-core/src/config.rs   (max_body_bytes config field)
  crates/aegis-bin/Cargo.toml       (uuid dep)

Phase 2: 1-2 files
  crates/aegis-proxy/src/data_plane.rs

Phase 3: ~8 files (admin auth gate touches every mutation entry)
  crates/aegis-proxy/src/accept.rs
  crates/aegis-control/src/admin_auth/{csrf.rs, session.rs}
  crates/aegis-control/src/api/{login.rs, mutation.rs}
  crates/aegis-control/src/admin_dispatch.rs
  crates/aegis-proxy/src/admin_mutate.rs
  + config schema updates

Phase 4: ~3 files
  crates/aegis-proxy/src/listener/http3.rs
  crates/aegis-proxy/src/data_plane.rs   (Peer adapter for H3)

Phase 5: ~6 files
  crates/aegis-proxy/src/data_plane.rs  (default_trusted_proxies)
  crates/aegis-proxy/src/upstream/forward.rs
  crates/aegis-control/src/interop/control.rs
  + contract-gap fixes spread across data_plane.rs / ws / tcp_tunnel

Phase 6: ~5 files
  crates/aegis-proxy/src/proxy.rs   (InflightGuard)
  crates/aegis-proxy/src/shed.rs    (wire-up call sites)
  crates/aegis-proxy/src/data_plane.rs   (shed hook)
  README.md / docs/architecture/  (document deferred dr/quota/traffic)

Phase 7: ~4 files
  crates/aegis-core/src/audit.rs   (AuditBus cap config)
  crates/aegis-control/src/audit/sinks/redis.rs   (new)
  crates/aegis-control/src/audit/sinks/mod.rs   (register redis)
  crates/aegis-control/src/api/audit.rs   (cross_node mode)
```

## Decision points needing user input before starting

1. **Phase 3 (admin auth)** — biggest risk surface. Sketch the session-middleware design as a separate doc before coding?
2. **F-CRITICAL-006 (dead modules)** — wire `shed.rs` only, or also `quota.rs` (body limits)? My take: shed only this round.
3. **Phase 7 audit-rail** — go with my recommendation (JSONL primary + optional Redis Stream secondary + bump broadcast cap), or did you have a different shape in mind?
