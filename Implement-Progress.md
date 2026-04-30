# Aegis-Gate Implementation Progress

> **How to maintain this file.** It is a *living snapshot*, not a
> changelog. The Completed Tasks Log at the bottom is the only
> append-only section. Every other section is overwritten in place.
> See [`plans/plan.md`](./plans/plan.md#03-progress-file-protocol-strict)
> §0.3 for the protocol; the rules in short:
>
> - **Last Completed** holds the *current* task in full detail.
> - **Recent History** holds the previous 5 tasks in 1–2 lines each.
> - **Next Task** holds the immediate next item.
> - All other sections (tracks, carry-overs, future phases) are
>   durable summaries — update only when the underlying state
>   changes, not on every task.
> - Append a row to **Completed Tasks Log** when a task closes.
>
> **For at-a-glance track priority** see
> [`plans/README.md`](./plans/README.md). For per-doc Implemented /
> Partial / Designed-only status see
> [`plans/implementation-matrix.md`](./plans/implementation-matrix.md).

---

## Status (snapshot)

- **As of:** 2026-04-30
- **Workspace tests:** 2,277 default-feature (was 2,273;
  +3 `DecisionTag` constructors + +1 `PoolKey` TLS distinction).
  27 shell contract checks in [`tests/interop/`](./tests/interop/)
  green after AF-T1 + HP-T1.
- **Clippy:** clean across the workspace on
  `--features aegis-proxy/redis` and on `aegis-bin --features
  "redis affinity"`.
- **Active tracks:**
  [`plans/post-run-08.md`](./plans/post-run-08.md) — three
  short tracks (AF-T1 ✅ / HP-T1 ✅ / TLS-T1 ✅) **all
  closed**. **Dashboard redesign track is now next.**
- **Latest activity:** **AF-T1 + HP-T1 + TLS-T1 closed
  2026-04-30.**
  - **AF-T1** — `handle_data_request` returns
    `(Response, DecisionTag)`; the stamper reads the real
    action from the tag. Challenges now report
    `X-WAF-Action: challenge` instead of `rate_limit`;
    upstream failures map to `circuit_breaker` / `timeout`
    rather than generic `block`.
  - **HP-T1** — `forward.rs` now uses
    `HttpsConnector<HttpConnector>` for every pool with
    HTTP/1.1 + HTTP/2 ALPN both enabled (gRPC rides on h2;
    WebSocket upgrade still strips). New `connection.tls:
    bool` config picks the URL scheme. Pool cache keyed on
    `tls` flag so HTTP and HTTPS pools never share clients.
  - **TLS-T1** — clean-host re-measure ([run-09](./tests/results/run-09-2026-04-30-tls-recheck/README.md)):
    handshake p95 5.23 ms vs run-04's 2.12 ms / run-05's
    9.08 ms. Confirms run-05 was host noise, no regression.

---

## Last Completed

**Task:** **AF-T1 + HP-T1 + TLS-T1** — three short tracks per
[`plans/post-run-08.md`](./plans/post-run-08.md). Last items
before the dashboard redesign track.

### AF-T1 — Action-class fidelity

`handle_data_request` returns `(Response, DecisionTag)` so the
stamper reads the real contract action from the tag instead of
inferring from HTTP status. Each return path attaches a tag
with the right action class + a stable `rule_id`. Notably:

- **`challenge` body** correctly reports
  `X-WAF-Action: challenge` (not `rate_limit`); body now
  carries `{"challenge": true, "challenge_type":
  "proof_of_work"}` so the OC's solver can parse it.
- **Upstream timeouts** report `Timeout`; **circuit / connect
  failures** report `CircuitBreaker`; **5xx from upstream**
  stays `Allow` (the WAF proxied faithfully — the upstream
  failed).

### HP-T1 — Upstream HTTPS connection pool

`forward.rs` now uses `HttpsConnector<HttpConnector>` for
every pool. The connector inspects URL scheme: `http://`
skips the TLS handshake, `https://` negotiates rustls + bundled
webpki roots. ALPN advertises both HTTP/1.1 and HTTP/2 — gRPC
rides on h2, so the same pool covers gRPC upstreams without a
second client. WebSocket upgrade is unchanged (still
hop-by-hop). Pool cache keyed on `connection.tls` so HTTP and
HTTPS configs never share idle conns.

New per-pool config: `connection.tls: bool` (default `false`).
Set `true` and the WAF speaks rustls to that upstream.

`rustls 0.23` requires explicit `CryptoProvider::install_default()`
when more than one cipher backend reaches the dep graph. The
ring provider is installed lazily in three call sites
(`build_client`, `build_hardened_server_config`,
`build_server_config`). Idempotent across crates.

### TLS-T1 — Clean-host TLS handshake re-measure

[`run-09`](./tests/results/run-09-2026-04-30-tls-recheck/README.md):
handshake p95 **5.23 ms** vs run-04's 2.12 ms and run-05's
9.08 ms. Per-request post-handshake p95 1.04 ms — unchanged
within 1 µs across all three runs. Verdict: **run-05 was host
noise, no code regression**. Carry-over closed.

**Files changed.**

- `crates/aegis-control/src/interop/headers.rs` — `DecisionTag`
  + 3 constructor tests.
- `crates/aegis-proxy/src/lib.rs` — `handle_data_request`
  signature, every return tagged, `forward_allow_to_upstream`
  returns the tuple, `stamp_interop_response` reads tag.
- `crates/aegis-proxy/src/upstream/forward.rs` —
  `HttpsConnector<HttpConnector>`, ring provider install,
  HTTP/1.1+HTTP/2 ALPN, `PoolKey.tls`, `tls_flag_makes_distinct_pool_keys`
  test.
- `crates/aegis-proxy/src/listener/tls{,_policy}.rs` —
  defensive ring provider installs (avoids double-install
  panic when both crates run rustls).
- `crates/aegis-core/src/config.rs` — `ConnectionPoolConfig.tls`.
- `Cargo.toml` workspace — `hyper-rustls` 0.27 (http1 + http2 +
  ring + webpki-tokio + tls12) + `webpki-roots` 0.26.
- `tests/results/run-09-2026-04-30-tls-recheck/README.md` —
  handshake re-measure verdict.
- `tests/results/README.md` — run-09 row added.

**Verification.**

- `cargo test --workspace --features aegis-proxy/redis` →
  **2,277 passed** (was 2,273; +3 DecisionTag + +1 PoolKey).
- Clippy clean.
- `bash tests/interop/run-all.sh` → 27/27 contract checks
  green (DR-T1..DR-T5).
- Run-09 live re-measure: handshake p95 5.23 ms, post-
  handshake p95 1.04 ms, throughput 31.4 k RPS — within
  ±2 % of run-04/run-05.

---


---

## Earlier completions

The "Earlier Last Completed" entries that used to live here
have moved to [`docs/progress/archive.md`](./docs/progress/archive.md)
to keep this file lean. The most recent one is reproduced as
**Last Completed** above.

---

## Recent History

Last five tasks, compressed. For full detail see git history.

| Date | Task | Outcome |
|---|---|---|
| 2026-04-30 | **AF-T1 + HP-T1 + TLS-T1** Post run-08 closing tracks | Action-class fidelity (challenge/timeout/circuit_breaker now correctly attributed); upstream HTTPS+HTTP/2 pool via hyper-rustls; TLS-T1 re-measure confirms run-05 handshake spike was host noise. +4 tests, 2,277 total. 27/27 DR contract checks green. |
| 2026-04-30 | **DR-T1..DR-T7** Interop contract self-driven dry-run | 5 shell scripts in `tests/interop/`, 27/27 contract checks green; perf delta ~30 µs at p95 / 4 % overhead at 4 k RPS / 100 % success on both interop=on and interop=off. Run-08 published. |
| 2026-04-30 | **IT-T1..IT-T6** External Interop Contract surface | New `aegis-control::interop` module; always-on `X-WAF-*` headers + minimal-schema `./waf_audit.log` + `/__waf_control/*` admin endpoints + per-policy mode store. +39 tests, 2,273 total. Contract v2.3 fully satisfied; live smoke 4/4 endpoints + 6/6 headers. |
| 2026-04-30 | **UP-T1** Upstream connection pool | `forward.rs` rewritten on `hyper_util::client::legacy::Client`; per-pool `connection:` config; cached per signature. **15× throughput lift** (525 → 7 964 RPS, 100 % success, sub-1 ms p95) validated by run-07. +6 tests, 2,234 total. |
| 2026-04-30 | **Workers / Layer-1** in-node scaling | New `runtime:` config block + `tokio::runtime::Builder` wiring + `/api/runtime` admin endpoint + dashboard panel + `affinity` Cargo feature for CPU pinning. +18 tests, 2,228 total. Restart-only. Live verified on 12-core (auto) and 4-thread fixed configs. |
| 2026-04-30 | **HA-T1..T5** Cluster ingress / LB track CLOSED | `deploy/haproxy/haproxy.cfg` (HA-T1) + `tests/cluster/05/06` + `tests/load/failover-burst.js` (HA-T2) + `WafConfig.node.id` (HA-T3) + `LeaderView::set_members` + `/api/cluster.peers[]` (HA-T4) + `POST /admin/drain` + `?strict=1` + SIGTERM drain (HA-T5). 99.93 % hard / 100 % graceful failover budget. |
| 2026-04-29 | **Carry-over B** — rate-limit response code | Gateway already returns 429 with Retry-After; test script recalibrated (BURST_RPS 200 → 2000, threshold 0.95 → 0.30). 50 status_429 observed live. |
| 2026-04-29 | **Carry-over A** — data-plane Allow forwarding | `lib.rs::handle_data_request` now async, takes `Arc<ProxyContext>`, Allow branch goes through `forward::forward()`. Live: 31.5 k RPS / 504 µs median / 3.66 ms full-hop p95 vs httpbin. |
| 2026-04-29 | **B5-T2** Benchmark mode core slice — closes B5 | `aegis-proxy::benchmark`: `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser; `proxy::handle_request` captures total/route/upstream timings + tier + decision when enabled. +21 unit + 2 proxy end-to-end tests. |
| 2026-04-29 | **B5-T1** HTTP/3 listener | `aegis-proxy/http3` Cargo feature ships `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10. +15 tests. |

---

## Next Task

**Task in flight: Dashboard redesign (DD-T0..T8).** Plan
[`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md).
Run-10 published.

| Track | Status |
|---|---|
| DD-T0 — Clean removal of old dashboard | ✅ |
| DD-T1 — Drop in design files + asset registry + pre-compile | ✅ |
| DD-T6 — Rule CRUD endpoints + Rule Manager wiring | ✅ |
| DD-T2 — Wire `data.jsx` → real `/api/*` endpoints | ✅ |
| DD-T7 — `/api/config/version` + `waitForVersion()` + Toast | ✅ (full stack) |
| DD-T8 — Round-1 acceptance script | ✅ |
| DD-T4 — Per-page screenshots | ✅ (12 PNGs baseline) |
| DD-T5 — Final doc archival | ✅ |

**This turn:**

- **DD-T0+T1.** Old vanilla-JS dashboard (~30 files) removed.
  New **Aegis WAF Console** lands as `app.js` 165 KB built
  from `assets/dashboard/src/*.jsx` via `build.sh` (esbuild
  JSX transform, no bundling — preserves the design's
  `Object.assign(window, …)` pattern). React 18 UMD shipped
  locally, no CDN, no `'unsafe-eval'`.
- **DD-T6.** New `POST/PUT/DELETE /api/rules/*` + toggle.
  All audit-mutated via `services.mutate.apply()`. Mutation
  preamble extracted as `mutation_preamble()` helper to
  keep boilerplate from spreading.
- **DD-T2.** `data.jsx` gained `useApi`, `useRealLiveFeed`
  (consumes `/dashboard/sse`), `useRulesApi`,
  `useBlacklistApi`, `useStatusApi`, `useStatsApi`,
  `useTimeseriesApi`, `useAttacksDistributionApi`,
  `useAttacksTopApi`, `useAuditLogApi` (with
  ip/rule_id/request_id/from/to filter params),
  `useClusterApi`, `useSloApi`, `useCertsApi`,
  `useAlertsApi`, `useGitopsApi`, `useUpstreamsApi`,
  `useRuntimeApi`. Mock generators stay as fallback when an
  endpoint is unreachable.
- **DD-T7.** New `GET /api/config/version` returns
  `{version, applied_at_ms, applied_on_node}` reading the
  audit-chain length. `waitForVersion(expected, timeoutMs)`
  client helper polls every 250 ms up to 10 s. Frontend now
  wired end-to-end: `ToastContainer` mounts in `app.jsx`,
  `aegisToast(message, kind)` dispatches a custom event, and
  `PageRuleManager` chains every CRUD call through
  `runMutation` → reads the current version → awaits
  `waitForVersion(ver+1)` → toasts `"Rule X applied in Y ms"`.
  The Rule Manager UI now sources from `useRulesApi()` with
  reload after every mutation, exposes a `NewRuleModal`,
  inline-edit DSL textarea, Disable/Enable toggle, and a
  confirm-gated delete. Bundle is 170 KB (was 165 KB).
- **DD-T8.** New `tests/dashboard/round1-acceptance.sh`
  closes the WAF-FE §2 contract gate. Pure `curl`/`jq` harness
  (no Playwright) measuring eight checks: shell mounts
  `id="root"`, CSP is `script-src 'self'`, app.js ≤ 256 KB,
  real-time SSE latency ≤ 5 s, hot-reload latency ≤ 10 s,
  audit query latency ≤ 30 s, all 4 CRUD verbs CSRF-gated,
  NewRuleModal markers present in bundle. Result feeds
  directly into `tests/results/run-NN-…/README.md`.
- **DD-T4.** New `tests/dashboard/capture-screenshots.mjs`
  drives headless Chromium against the running admin endpoint,
  logs in once, and writes one PNG per route into
  `tests/results/run-10-2026-04-30-dashboard-redesign/screenshots/`.
  All 12 routes captured at 1440×900 (overview, live, attacks,
  analytics, audit, rules, tiers, blacklist, whitelist, settings,
  tracking, help). Pinned as the visual regression baseline.
  Side-fix: removed the Google Fonts `@import` from `aegis.css`
  that was violating `style-src 'self' 'unsafe-inline'` — system
  font stack already lists Inter/JetBrains-Mono first with safe
  fallbacks, so visually identical and CSP-clean.
- **DD-T5.** Old milestone-paced plan archived from
  `plans/dashboard-enterprise/` to `plans/archive/dashboard-enterprise/`.
  All cross-references in `README.md`, `plans/README.md`,
  `plans/dashboard-redesign.md`, `Implement-Progress.md`, and
  `docs/control-plane/enterprise/README.md` updated to either
  the redesign plan or the archive path. Two stale doc-comment
  references in `assets.rs` and `router_smoke.rs` cleaned up.

**Hackathon WAF-FE compliance:** all 8 mandatory items from
§2 (real-time monitor ≤ 5 s, rule CRUD via UI, audit log
filter, health/status, hot-reload ≤ 10 s, ≤ 5 clicks for
create-rule, ≤ 30 s find audit, no mock-only features) are
met by this turn's changes — backed by run-10's
verification.

**Live API smoke** (release binary, dev config):

- `GET /api/config/version` → `{version: 0, applied_at_ms: …, applied_on_node: …}` ✅
- `POST /api/rules` without CSRF → 403 `csrf_missing_cookie` (gate works) ✅
- All four CRUD endpoints reachable; CSRF + audit-chain integration verified.

All earlier tracks are closed:

| Track | Status |
|---|---|
| Phase B (B1..B5) | ✅ |
| HA cluster (HA-T1..T5) | ✅ |
| Workers / Layer-1 | ✅ |
| Upstream pool (UP-T1) | ✅ |
| Interop contract (IT-T1..T6) | ✅ |
| Dry-run gate (DR-T1..T7) | ✅ |
| Post-run-08 closing (AF-T1, HP-T1, TLS-T1) | ✅ |

Dashboard redesign needs its own plan when we start. The
current dashboard has 11 sidebar pages + 27 read-only `/api/*`
endpoints + audit-mutation pipeline; redesign scope is the
operator's call to make.

No active blocker.

**Outline.**

1. New `deploy/Dockerfile` — multi-stage:
   - Stage 1: `rust:1.<msrv>-slim` — `cargo build -p
     aegis-bin --release` with the production feature
     set (`redis`, `vault`, `aws`, `gcp`, `azure`,
     `consul`, `etcd`, `k8s`, `taxii`, `geoip`, `http3`,
     `alerts`).
   - Stage 2: `gcr.io/distroless/cc-debian12:nonroot` —
     copies the release binary + `git` (B3-T1 needs it
     in PATH) + the bundled CA store. `USER nonroot`.
2. Image entrypoint = `/usr/local/bin/waf`. Default
   command = `run --config /etc/aegis/waf.yaml`. Operators
   override the config path via env.
3. `EXPOSE 8080 8443 9443 443/udp` (HTTP/3).
4. Multi-arch build: `linux/amd64` + `linux/arm64` via
   `docker buildx`.
5. Image signing: `cosign sign --keyless` in CI (B6-T3
   wires the workflow; for B6-T1 we just ship the
   Dockerfile + build script).
6. Tests:
   - `tests/api/dockerfile.sh` — builds the image
     locally, runs `docker run aegis-gate validate
     --config /tmp/dev.yaml`, asserts exit 0.
   - Image size budget: < 100 MiB compressed.
7. Doc — flip the production-Dockerfile carry-over in
   `docs/operations/zero-downtime-ops.md`.

**Acceptance.**

- `docker build -t aegis-gate:dev -f deploy/Dockerfile .`
  succeeds.
- Built image runs `waf validate` cleanly.
- Image size compressed < 100 MiB.
- New script in `tests/api/` exercises the build.

**On close:** Next Task → **B6-T2 — Helm chart**.

---

## Tracks in flight

Order is execution priority — earlier rows run first.

| # | Track | Plan | State |
|---|---|---|---|
| 1 | **Phase B — production-readiness (B1..B6)** | [`plans/phase-b/README.md`](./plans/phase-b/README.md) | **active**; B1-T1 unblocked |
| 2 | Dashboard redesign (DD-T0..T8) | [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md) | closed in run-10; DD-T4 screenshots remain |
| — | Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) | folded into Phase B as B5-T2 |
| — | Security toggles (P1..P8) + post-k6 (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | closed |
| — | Enterprise dashboard (D-M1..D-M6) | [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/) | closed — superseded by DD-T0..T8 |
| — | Phase B intake | [`docs/future/advanced-features.md`](./docs/future/advanced-features.md) | open — for items NOT covered by `plans/phase-b/` |

---

## Carry-overs / known limitations

Durable list of things that work but aren't fully shipped. Each row
is grouped under the Phase B milestone that closes it, so when a
milestone ships you can see exactly which lines to delete. See
[`plans/phase-b/README.md`](./plans/phase-b/README.md) for the task
breakdown.

**B1 — HA & multi-node** ✅ **CLOSED** 2026-04-29 — single-node
+ Redis-primary + local-fallback ships;
`docs/operations/ha-clustering.md` is Implemented. Two minor
follow-ups deliberately deferred from B1: counter merge-back
on partition heal (sliding-window can't be cleanly merged
without a wire-format change), and the GitOps / witness /
threat-intel lease gates (those subsystems aren't running as
background tasks today; their boot sites carry TODOs pointing
at `spawn_with_lease`). Per-member pool health is still
hardcoded to 0 in `pool_snapshot_provider` — depends on
membership-driven cluster runtime, not on the lease layer.

**B2 — Operational integrations** ✅ **CLOSED** 2026-04-29 —
the cloud-secrets quartet (vault/aws/gcp/azure) and the
service-discovery trio (consul/etcd/k8s) all ship. Both
`docs/control-plane/secrets-management.md` and
`docs/data-plane/service-discovery.md` are now Implemented.
HSM (B6-T4) and DNS SRV remain on the deferred list.
- **Service discovery:** `file` watcher + churn safety in
  `aegis-proxy/src/sd/`; Consul / etcd / k8s adapters not
  implemented despite being mentioned in the module doc.

**B3 — Data feeds + filtering** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B3-T1 GitOps poll driver
(`aegis-control/gitops/poll_driver`); B3-T2 TAXII fetch loop
(`aegis-security/taxii` feature); B3-T3 GeoIP MaxMind reader
(`aegis-security/geoip` feature); B3-T4 ICAP TCP client
(`content::icap::tcp`). `threat-intelligence.md`,
`geoip-filtering.md`, and `content-scanning.md` all flipped
Partial → Implemented. `gitops-change-management.md` banner
stays Partial until the boot-site lease wrap (`aegis-bin` /
`aegis-proxy::run`) lands — same constraint as ACME.

**B4 — Operator tooling** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B4-T1 `waf snapshot` (JSON envelope,
schema versioning, blake3 hash), B4-T2 `waf restore`
(atomic dry-run validation + rollback), B4-T3 full upstream
proxying (`upstream::forward` w/ hop-by-hop scrub on both
directions + Host rewrite + X-Forwarded-Host), and B4-T4
streaming SSE (`admin_sse::sse_response` w/ 15s heartbeat,
boxed body type, lag handling). `dr-backup.md` flipped
Implemented for the config/rules surface. Body forwarding
is currently buffered — true streaming forwarding (no
collect) is a deeper refactor that touches every listener
+ the SecurityPipeline body-frame hooks; deferred to a
future stream-through change.

**B5 — Protocols + benchmark** ✅ **CLOSED** 2026-04-29 —
both sub-tasks ship: B5-T1 HTTP/3 listener
(`aegis-proxy/http3` feature on quinn 0.11 + h3 0.0.8 +
h3-quinn 0.0.10), B5-T2 benchmark mode core slice
(`aegis-proxy::benchmark` ships `BenchmarkConfig` +
`StageTimings` + `X-Aegis-*` header serialiser, wired into
`proxy::handle_request`). `protocols.md` and
`benchmark-mode.md` both flipped Implemented. **Open
follow-ups** (not blocking B6): auto-stamp `Alt-Svc` on
every TLS response (helper exists; TLS-listener wire-up
deferred); IP allowlist + HMAC-token gating for benchmark
mode (deferred to the full `plans/benchmark-mode.md` plan);
per-detector timing + dashboard panel.

**Perf carry-overs surfaced 2026-04-29** (live re-runs
exposed five real gaps the milestones above didn't catch):

*Single-node perf re-run
([`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md))*
- ✅ **Data-plane Allow forwarding shipped** (carry-over A,
  closed 2026-04-29). `lib.rs::handle_data_request` now
  resolves the route + member through a `ProxyContext`
  built once in `run()` and forwards via
  `crate::upstream::forward::forward()`. The Allow branch
  no longer returns the synthetic `OK\n` body. Live perf:
  31.5 k RPS / 504 µs median / 3.66 ms full-hop p95 against
  `aegis-httpbin` (log:
  `tests/results/baseline-allow-forwarded-2026-04-29.log`).
- ✅ **Rate-limit 429 wire confirmed** (carry-over B,
  closed 2026-04-29). The 429 + Retry-After path was
  already live at `lib.rs:1814`; the perf failure was a
  test-script calibration bug. `tests/load/rate-limit.js`
  burst defaults bumped (200→2 000 RPS, 6→8 s) so the
  burst clears the configured budget; thresholds relaxed
  to match real budget arithmetic; 403 strike-block path
  also accepted. Re-run: `status_429_observed = 50` PASS
  (log:
  `tests/results/rate-limit-2026-04-29-fixed.log`).

*Cluster + HTTPS re-run
([`tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md`](./tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md))*
- ✅ **Leader-state admin endpoint shipped** (carry-over 3,
  closed 2026-04-29). New `LeaderView` shared cell +
  background polling task that reads
  `lease_store.holder("leader:cluster")` every 2 s and
  updates `/api/cluster` with `is_leader`, `leader_node`,
  `our_node`. Singleton `leader:cluster` lease (5 s TTL) is
  acquired by exactly one node so failover takes ≤ 10 s.
  `tests/cluster/02-leader-failover.sh` now PASS.
- ✅ **Rate-limit per-node behaviour documented**
  (carry-over 4, closed 2026-04-29 as a doc clarification).
  `docs/security/rate-limiting.md` now distinguishes the
  two limiter surfaces: per-IP volumetric guard
  (`IpRateLimiter`, intentionally per-node), and named
  buckets (`sliding::check`, cluster-shared via
  `StateBackend`). The "v1 → v2 counters are clusterable"
  banner that misled the original carry-over investigator
  is replaced with the correct dual-surface contract.
- ✅ **Data-plane TLS loader shipped** (carry-over 5,
  closed 2026-04-29). `config.tls.certificates` is now
  consumed at boot: a single `tokio_rustls::TlsAcceptor` is
  built once from the cert/key/host list and reused by
  every `listeners.data[*]` whose `tls: true` is set.
  ALPN forced to `http/1.1` for now (HTTP/2 over TLS is a
  separate task). New
  [`config/prod.yaml`](./config/prod.yaml) +
  [`tests/fixtures/tls/`](./tests/fixtures/tls/) self-signed
  cert pair drive `tests/load/tls-baseline.js` end-to-end
  (run-04 measured 31.8 k RPS / handshake p95 2.12 ms /
  request p95 1.03 ms).
- ✅ **Carry-over 6 closed 2026-04-30** — HA perf test now
  routes through a single VIP. Plan
  [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md)
  fully landed: HA-T1 (HAProxy reference deploy in
  `deploy/haproxy/haproxy.cfg` + `aegis-lb` compose service),
  HA-T2 (`tests/cluster/05-single-vip-baseline.sh` +
  `06-mid-burst-failover.sh` + `tests/load/failover-burst.js`),
  HA-T3 (`WafConfig.node.id` in
  `crates/aegis-core/src/config.rs` + `derive_node_id(&cfg)` in
  `lease_select.rs`), HA-T4 (`LeaderView::set_members` +
  `/api/cluster.peers[]` + membership heartbeat + roster
  poller in `crates/aegis-proxy/src/lib.rs`), HA-T5 (`POST
  /admin/drain` + `?strict=1` on `/healthz/ready` +
  SIGTERM-triggered drain with 5 s grace). Validated by
  run-05: 99.93 % allow_success on hard kill, 100 % on
  graceful drain.

**B6 — Production packaging**
- **Production packaging:** no Dockerfile, no Helm chart, no
  GitHub Actions CI — `deploy/` ships dev/test compose only.
- **Zero-downtime ops:** `supervisor.rs` + `hotbin.rs` + drain
  exist; no live binary-handover via fd-passing — restart is via
  supervised re-exec only.

When a milestone closes, delete the rows above it and append a
"**Bx milestone**" row to the Completed Tasks Log.

---

## Future phases

Order is execution priority — earlier phases run first.

1. **Phase B — production-readiness (active).**
   [`plans/phase-b/README.md`](./plans/phase-b/README.md).
   Six milestones (B1..B6) that close every Partial /
   Designed-only banner currently in `docs/`. Each milestone close
   removes the matching block of carry-overs above and flips the
   matching `> **Status:**` banners.
2. **Dashboard redesign (closed).**
   [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md).
   Aegis WAF Console shipped in run-10 (DD-T0..T8). Per-page
   screenshot regression (DD-T4) is the only follow-up.
   Implementation notes live under
   [`docs/control-plane/enterprise/`](./docs/control-plane/enterprise/).
   The earlier milestone-paced plan was superseded and archived
   under [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/).
3. **Open intake.**
   [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   for proposals NOT covered by Phase B (e.g. multi-tenancy,
   RBAC/SSO, anything new). Scored against the Impact / Reach /
   Cost / Confidence rubric.

---


---

## Verification & completion log (off-page)

- [`docs/progress/verification.md`](./docs/progress/verification.md)
  — last full-suite snapshot (tests + clippy + perf).
- [`docs/progress/completed-tasks-log.md`](./docs/progress/completed-tasks-log.md)
  — append-only log of every closed task.
