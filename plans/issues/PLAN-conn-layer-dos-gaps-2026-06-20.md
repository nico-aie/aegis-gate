# Connection-layer DoS gaps — RUDY body-read deadline + accept-time connection cap

**Status:** 🟢 P1 + P2 shipped (TDD, `develop`, 2026-06-20) · P3 deferred
**Filed:** 2026-06-20
**Reporter:** s-tester
**Severity:** 🔴 High — maps to BTC Attack Vector #01 (DDoS L4&7 / Slowloris / RUDY / connection exhaustion), Round 3 Attack Battle
**Source report:** [`tests/s-tester/reports/20260620_connection_layer_dos_gaps_report.md`](../../tests/s-tester/reports/20260620_connection_layer_dos_gaps_report.md)
**Related:** [`PLAN-perf-throughput-cliff-2026-06-20.md`](./PLAN-perf-throughput-cliff-2026-06-20.md) (load-shedder placement) — **both gaps sit *before* the shedder**, so the shed-before-body fix does not close them.

## TL;DR

The s-tester report is **file:line-accurate and both gaps are real** (re-verified against
HEAD on `develop`, 2026-06-20). Two admission holes sit *upstream* of the load-shedder, so
they survive every per-request defense:

1. **GAP 1 — RUDY:** the client body is buffered with `http_body_util::Limited::new(body, max_body_bytes).collect().await` and **no timeout** ([`data_plane.rs:927`](../../crates/aegis-proxy/src/data_plane.rs#L927)). A slow-POST trickle (1 byte / few-s) pins a tokio task + resources indefinitely. The semantically-correct knobs **already exist but are enforced nowhere**: `QuotaConfig.read_timeout` (→408) and `total_deadline` (→504) ([`config.rs:2067-2074`](../../crates/aegis-core/src/config.rs#L2067)).
2. **GAP 2 — connection exhaustion:** `accept_loop` accepts + `tokio::spawn`s **unconditionally** ([`accept.rs:1516`](../../crates/aegis-proxy/src/accept.rs#L1516)); `InFlightCounter::admit()` only **counts** for the SIGUSR2 drain, it does **not cap** ([`hotbin.rs:510`](../../crates/aegis-proxy/src/hotbin.rs#L510)). An attacker opens many TLS connections and burns fd/CPU(crypto)/mem before any L7 logic (incl. the shedder) runs.

`DecisionTag::timeout()` already exists and maps to `X-WAF-Action: timeout`
([`interop/headers.rs:190`](../../crates/aegis-control/src/interop/headers.rs#L190)) — the report's action mapping is correct and contract-compliant (v2.6 §3-4).

### Corrections / nuances to fold in (where the report is imprecise)

- **Line drift:** the body collect is at **`data_plane.rs:927`**, not `:866`. The report
  predates today's shed-before-body merge (#70). Re-anchor before editing.
- **`QuotaConfig` is per-route, not global** (`routes[].quota: Option<QuotaConfig>`,
  [`config.rs:1841`](../../crates/aegis-core/src/config.rs#L1841)). The report says "wire
  QuotaConfig into ProxyContext" — but the existing body cap actually comes from a
  **proxy-global** `cfg.proxy.max_body_bytes` resolved into `ProxyContext.max_body_bytes`
  ([`data_plane.rs:332`](../../crates/aegis-proxy/src/data_plane.rs#L332),
  [`proxy.rs:138`](../../crates/aegis-proxy/src/proxy.rs#L138)). **Decision required** (see P1).
- **`check_request_quota` is dead code** — called from **tests only**, never on the request
  path ([`quota.rs:42`](../../crates/aegis-proxy/src/quota.rs#L42)). So URI/header/body
  quota enforcement *also* doesn't route through it today (body cap is inline; URI/header
  caps are enforced by hyper's builder). `write_timeout` is likewise unused. Opportunity to
  wire the whole struct, or scope tight to the two timeouts. Tight scope recommended (YAGNI).
- **Two accept loops exist:** `accept_loop` (data plane, [`accept.rs:1462`](../../crates/aegis-proxy/src/accept.rs#L1462)) and
  `admin_accept_loop` (admin dashboard, [`accept.rs:249`](../../crates/aegis-proxy/src/accept.rs#L249)). The cap belongs on the **data** loop. Admin is the
  public-by-contract dashboard — leave it out of scope (it has its own auth/fail2ban story).
- **Pattern to copy:** `ProxyContext` already owns a `tokio::sync::Semaphore`
  (`streaming_permits`, [`proxy.rs:213`](../../crates/aegis-proxy/src/proxy.rs#L213)) — model `conn_limit` on it.

---

## ✅ Shipped 2026-06-20 (`develop`, TDD)

- **P1 (GAP 1)** — `commit fix: enforce request-body read deadline`. Took **Option A**:
  new proxy-global `proxy.read_timeout` (humantime, default 30s), populated into
  `ProxyContext.read_timeout`, wraps `Limited::new(..).collect()` in
  `tokio::time::timeout` → `408` + `DecisionTag::timeout("slow-body")`. 413/400 arms
  preserved. Tests: `slow_post_body_times_out_with_408`,
  `complete_post_body_is_not_falsely_timed_out`.
- **P2 (GAP 2)** — `commit fix: accept-time connection cap`. New `proxy.max_connections`
  (default 20_000; `validate()` rejects 0). `ProxyContext.conn_limit` Semaphore acquired
  via `try_acquire_owned()` in `accept_loop` **before** admit/spawn; reject closes at TCP
  + `continue` (reject-before-admit); permit rides the task. Reject log is `debug` (a
  `warn` would self-DoS under flood). Tests: `over_cap_connection_is_rejected_and_not_admitted`,
  `ended_connections_release_permit_and_inflight_slot` (drain-safety),
  `validate_rejects_zero_max_connections`.
- **P3** — total request deadline → 504: **still deferred** (needs SSE/WS-upgrade
  exclusion + cancellation-safety review; do after a bench pass).

> Note: the connection cap applies to the **data** `accept_loop` only; `admin_accept_loop`
> was intentionally left out of scope. `accept_loop`'s signature is unchanged — the cap
> rides `ProxyContext`, so `run.rs` needed no edit.

---

## P1 — GAP 1: enforce a request-body read deadline (RUDY → 408)

**Goal:** wrap the body buffer in `read_timeout`; on elapse return `408` with
`DecisionTag::timeout("slow-body")` so `X-WAF-Action: timeout` is stamped (contract §3-4).

**Design decision — where does `read_timeout` come from?**
- **Option A (recommended, ships fast):** add a proxy-global `read_timeout: Duration` to
  `ProxyContext`, sourced like `max_body_bytes` (from a new `cfg.proxy.read_timeout`, default
  30s = `QuotaConfig::default().read_timeout()`). Mirrors the existing body-cap plumbing; no
  per-route resolution churn. Reuses the *semantics* of the already-declared knob.
- **Option B (fuller):** resolve the matched route's `Option<QuotaConfig>` (it's resolved at
  [`data_plane.rs:424`](../../crates/aegis-proxy/src/data_plane.rs#L424)) and fall back to a proxy-global default. More config surface; defer
  unless per-route slow-POST tuning is actually needed.

Recommend **A** now; leave a TODO for B.

**Steps (TDD):**
1. **RED** — add a test in `data_plane` tests: a body stream that stalls past `read_timeout`
   yields a `408` + `DecisionTag::timeout(...)`; a normal (even near-cap) body still passes.
   Use a controllable slow body (`futures` `stream::pending` after a few bytes, or a manual
   `Body` impl) — avoid wall-clock flake by injecting a tiny `read_timeout`.
2. Add `read_timeout` to `ProxyContext` + `cfg.proxy.read_timeout` (humantime, default 30s).
3. Wrap the collect at [`data_plane.rs:927`](../../crates/aegis-proxy/src/data_plane.rs#L927):
   ```rust
   let collected = tokio::time::timeout(
       upstream_ctx.read_timeout,
       http_body_util::Limited::new(body, max_body_bytes).collect(),
   ).await;
   let body_bytes = match collected {
       Err(_elapsed) => {
           let resp = Response::builder()
               .status(hyper::StatusCode::REQUEST_TIMEOUT) // 408
               .header("content-type", "application/json")
               .body(crate::body::full(Bytes::from(
                   serde_json::json!({"error":"request_body_timeout"}).to_string())))
               .unwrap();
           return (resp, DecisionTag::timeout("slow-body"));
       }
       Ok(Ok(c)) => c.to_bytes(),
       Ok(Err(e)) => { /* keep the existing LengthLimitError / body_read_error arm */ }
   };
   ```
4. **GREEN** + confirm the existing 413/`body-too-large` and `body-read-error` arms are
   preserved (don't regress LengthLimitError handling).

**Why not also `total_deadline` (504) now?** Defense-in-depth, but it requires wrapping the
whole `handle_data_request` future at the call site ([`accept.rs:1885`](../../crates/aegis-proxy/src/accept.rs#L1885)) and reasoning about
cancellation safety of everything inside (detectors, upstream forward, streaming upgrades —
SSE/WS must be **excluded** or they'd be killed mid-stream). **Scope to P3** (below) to keep
P1 small and low-risk. `read_timeout`→408 is the direct RUDY fix.

**Acceptance:**
- Body 1 byte / 5s → `408` + `X-WAF-Action: timeout` within ~`read_timeout`; no unbounded task.
- Normal POST (incl. large near-cap) still passes — no false timeout.
- Existing body-cap (413) and read-error (400) behavior unchanged.

---

## P2 — GAP 2: connection cap at accept (connection exhaustion)

**Goal:** bound concurrent data-plane connections with a `Semaphore`, acquired **before**
`tokio::spawn`, rejecting excess cheaply at the TCP layer — **without breaking the SIGUSR2
drain.**

**Steps (TDD):**
1. **RED** — unit test on the admission rule (not the full socket loop): with a
   `Semaphore::new(N)`, after N held permits `try_acquire_owned()` fails; and the
   reject path does **not** touch the in-flight counter. (A loop-level test can use a
   `TcpListener` on `127.0.0.1:0` opening N+M sockets and asserting M are closed pre-TLS.)
2. Add `conn_limit: Arc<tokio::sync::Semaphore>` to `ProxyContext` (next to
   `streaming_permits`/`inflight`), init `Semaphore::new(cfg.proxy.max_connections)`; add
   `cfg.proxy.max_connections` (default e.g. 20_000 — pick from `ulimit -n` headroom).
3. In `accept_loop` ([`accept.rs:1516`](../../crates/aegis-proxy/src/accept.rs#L1516)), **before** cloning `conn_inflight` / spawning:
   ```rust
   let permit = match upstream_ctx.conn_limit.clone().try_acquire_owned() {
       Ok(p) => p,
       Err(_) => {
           conn_reject_metric.inc();   // new observability counter
           drop(stream);               // close at TCP — no TLS, no admit()
           continue;                   // MUST be before conn_inflight.admit()
       }
   };
   // ... existing clones ...
   tokio::spawn(async move {
       let _permit = permit;           // RAII: released when connection task ends
       let _admit  = conn_inflight.admit(); // unchanged — drain gauge
       // ... TLS handshake / serve_connection ...
   });
   ```
4. Add a `conn_reject` metric (mirror `proxy_protocol_metrics` style) for the dashboard.
5. (Optional, cheap) explicit `listen(backlog)` via `socket2`/`TcpSocket` + document
   `somaxconn` / `ulimit -n` requirements in deploy docs. **Defer unless trivial.**

**`try_acquire_owned` + `continue` (not `acquire().await`):** blocking the accept loop would
dam new connections into the OS backlog (still fd cost) — `try_acquire` rejects instantly,
the "reject cheap at the door" principle. Per-request (post-TLS) overload stays the
shedder's job (503).

### ⚠️ Drain (SIGUSR2 handover) safety — mandatory invariants

`InFlightCounter` (gauge for drain, [`hotbin.rs:496`](../../crates/aegis-proxy/src/hotbin.rs#L496)) and the new `conn_limit` (admission cap)
share a lifetime (the connection) but are **independent**. To not hang handover:
1. **A rejected connection must NOT call `conn_inflight.admit()`** — `continue` happens
   *before* the admit clone/spawn. Admitting then rejecting inflates the drain gauge → the
   `wait until in-flight == 0` handover waits forever.
2. **`_permit` and `_admit` are both RAII, both moved into the task, both drop on task end**
   (clean close, panic, or cancel) — no slot leak.
3. Drain stops accepting new connections at the handover layer, so no new `try_acquire`
   runs during drain; held permits release as old connections close, in phase with the
   in-flight count → 0. No conflict.
4. **Do not change `InFlightCounter` semantics** — the cap is a layer *added before* `admit()`.

**Acceptance:**
- Open > `max_connections` concurrently → excess closed at TCP (no TLS handshake), crypto
  CPU does not spike; connections within the cap serve normally.
- **Drain regression (required):** SIGUSR2 with a mix of rejected + serving connections →
  `InFlightCounter` reaches 0, handover completes, **no hang**. (Proves invariant #1.)
- Connection-flood no longer collapses p99/goodput of legitimate traffic (with the shedder).

---

## P3 — (defense-in-depth) total request deadline → 504

Wrap `handle_data_request` at [`accept.rs:1885`](../../crates/aegis-proxy/src/accept.rs#L1885) in `tokio::time::timeout(total_deadline, …)`
returning `504` + `DecisionTag::timeout("deadline")` for any hang source (slow upstream,
stuck detector). **Must exclude streaming upgrades** (SSE/WebSocket, long-lived by design) —
either branch before the wrap for upgrade requests or use a deadline that only covers the
buffered-request phase. Lower priority than P1/P2; do after they land and bench clean.

---

## Config summary

```yaml
proxy:
  read_timeout: "30s"      # P1 — NEW proxy-global (reuses QuotaConfig.read_timeout semantics) → 408
  max_connections: 20000   # P2 — NEW concurrent-connection cap on the data listener
  # total_deadline: "30s"  # P3 — defer
```
- P1 reuses an existing *semantic* knob but plumbs it proxy-global (Option A); no per-route
  schema needed now.
- P2 adds one field with a safe default.

## File / line map (re-verified 2026-06-20, HEAD `develop`)

| Thing | File:line |
|---|---|
| Body collect **no timeout** (RUDY) | [`data_plane.rs:927`](../../crates/aegis-proxy/src/data_plane.rs#L927) |
| `max_body_bytes` source (proxy-global pattern to mirror) | [`data_plane.rs:332`](../../crates/aegis-proxy/src/data_plane.rs#L332) · [`proxy.rs:138`](../../crates/aegis-proxy/src/proxy.rs#L138) |
| `QuotaConfig` (read_timeout/total_deadline declared, 0 enforce) | [`config.rs:2056-2074`](../../crates/aegis-core/src/config.rs#L2056) |
| `routes[].quota` (per-route, optional) | [`config.rs:1841`](../../crates/aegis-core/src/config.rs#L1841) |
| `check_request_quota` (dead — tests only) | [`quota.rs:42`](../../crates/aegis-proxy/src/quota.rs#L42) |
| `DecisionTag::timeout` → `X-WAF-Action: timeout` | [`interop/headers.rs:190`](../../crates/aegis-control/src/interop/headers.rs#L190) |
| `accept_loop` (data; accept+spawn unconditional) | [`accept.rs:1462`](../../crates/aegis-proxy/src/accept.rs#L1462), body [`:1516`](../../crates/aegis-proxy/src/accept.rs#L1516) |
| `conn_inflight.admit()` (count-only) | [`accept.rs:1550`](../../crates/aegis-proxy/src/accept.rs#L1550) |
| `admin_accept_loop` (out of scope) | [`accept.rs:249`](../../crates/aegis-proxy/src/accept.rs#L249) |
| `InFlightCounter::admit` / Guard Drop (drain gauge) | [`hotbin.rs:510`](../../crates/aegis-proxy/src/hotbin.rs#L510) / [`:537`](../../crates/aegis-proxy/src/hotbin.rs#L537) |
| `ProxyContext` (`inflight`, `streaming_permits` Semaphore pattern) | [`proxy.rs:46`](../../crates/aegis-proxy/src/proxy.rs#L46) / [`:213`](../../crates/aegis-proxy/src/proxy.rs#L213) |
| Load-shedder (runs after TLS+body; doesn't cover these) | [`data_plane.rs:873`](../../crates/aegis-proxy/src/data_plane.rs#L873) |

## References
- BTC Rulebook §7 (vector #01); Interop Contract v2.6 §3-4 (`timeout` action).
- OWASP Slow HTTP DoS (Slowloris/RUDY): defend with body read deadline + connection cap, not request-rate limiting.

---

*Verdict: report confirmed; both gaps real and upstream of the shedder. Fix order: **P1**
(body read deadline → 408, small/local) → **P2** (accept-time conn cap, drain-safe) → **P3**
(total deadline → 504, defense-in-depth). Watch the per-route-vs-global quota choice (P1) and
the reject-before-admit ordering (P2 drain safety).*
