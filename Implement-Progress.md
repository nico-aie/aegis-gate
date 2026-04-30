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
- **Workspace tests:** **2,199 default-feature** (post-CI-T*
  console-API integration; net delta from 2,277 reflects the
  dashboard redesign cleanup that retired the old vanilla-JS
  test fixtures).
- **Clippy:** clean across the workspace on
  `--features aegis-proxy/redis` and on `aegis-bin --features
  "redis affinity alerts geoip"`. Two pre-existing rust-1.94
  lints in untouched files (`tests/dod.rs`, `src/api/risk.rs`)
  remain.
- **Active tracks:** **Phase B — only B6 packaging remains
  (B6-T1 production Dockerfile is in flight).** All other
  tracks closed in this session: dashboard redesign
  (DD-T0..T8), Aegis WAF Console API integration
  (CI-T1..T8), HA cluster (HA-T1..T5), interop contract
  (IT-T1..T6 + DR-T1..T7), post-run-08 (AF-T1, HP-T1, TLS-T1).
- **Latest activity:** **CI-T7 + CI-T8 closed 2026-04-30**
  (SLO eval + dispatch + burn windows; geo enrichment for
  `/api/attacks/top`).
  - **CI-T7** — periodic `engine.evaluate()` task in
    `aegis-proxy::run` calls `slo::dispatch::send_alert`
    every 30 s; with `--features alerts` the dispatcher
    delivers to VipTalk via HTTPS. `BudgetStatus` carries
    per-window burn rates so `/api/slo` returns real
    `burn_1h` / `burn_6h` / `burn_3d` instead of zeros.
  - **CI-T8** — `Attacker` row gains optional `country` +
    `asn`. `AttacksHandler::set_geo_lookup(...)` accepts any
    `aegis_security::geoip::GeoIpLookup` impl; proxy wires
    a real `MaxMindReader` under `--features geoip` from
    new `cfg.geoip.country_db` / `asn_db` paths. Overview
    page renders blips only for IPs with real geo (was
    falling back to the mock fixture).

---

## Last Completed

**Task:** **CI-T7 + CI-T8** — close the SLO and geo-enrichment
items deferred during CI-T4 / CI-T1. See
[`plans/console-api-integration.md`](./plans/console-api-integration.md).

### CI-T7 — SLO evaluation + dispatch + burn-rate windows

The SLO engine has been fed samples since CI-T4, but
`engine.evaluate()` was never called in production — alerts
never fired and VipTalk delivery (built but disconnected) never
ran. CI-T7 closes the loop.

- **Periodic eval task** spawned in `aegis-proxy::run` runs
  `engine.evaluate()` every 30 s and pipes each newly-fired
  alert through `aegis_control::slo::dispatch::send_alert(...)`.
- **VipTalk delivery is now production-reachable.** With
  `aegis-bin --features "redis alerts"` (new feature alias of
  `aegis-control/alerts`), `dispatch::send_viptalk` POSTs to
  `https://api.viptalk.org/v1/bot/<token>/sendMessage`. Without
  the feature, dispatch logs the alert and counts it as
  "external" so an off-box dispatcher (Alertmanager, sidecar)
  can pick it up.
- **`BudgetStatus.burn_rates: Vec<BurnRate>`** — one entry per
  burn-rate window declared on the `SloObjective`. Computed
  alongside the budget snapshot using the same arithmetic as
  `evaluate()`, surfaced through `/api/slo` so the dashboard's
  `burn_1h` / `burn_6h` / `burn_3d` fields render real numbers
  instead of placeholder zeros.

### CI-T8 — Geo enrichment for /api/attacks/top

The MaxMind GeoIP reader has shipped since B3-T3 but only fed
the rule engine. CI-T8 plumbs it into the dashboard.

- **`Attacker` row gains `country: Option<String>` + `asn:
  Option<u32>`** with `serde(skip_serializing_if = "Option::is_none")`
  so the API stays clean when no DB is loaded.
- **`AttacksHandler::set_geo_lookup(Arc<dyn GeoIpLookup>)`** —
  accepts any impl of the always-compiled trait. `enrich_attackers()`
  parses each identifier; public IPs get country + ASN,
  fingerprint identifiers (`fp:<ja4>`) skip the lookup.
- **New `cfg.geoip` block** — `country_db` + `asn_db` (both
  optional `PathBuf`). Plumbed in proxy under
  `cfg(feature = "geoip")` so builds without `maxminddb` stay
  slim. New cargo feature aliases:
  `aegis-bin/geoip → aegis-proxy/geoip → aegis-security/geoip`.
- **Dashboard Overview** drops the lying mock-fixture blips —
  the `WorldMap` now shows only attackers with real `country`.
  Pill toggles between `N geo-tagged` (DB loaded) and
  `geo DB not loaded` (default state) so the operator sees
  honest state.

**Files changed (CI-T7 + CI-T8).**

- `crates/aegis-control/src/slo.rs` — `BurnRate` struct,
  `BudgetStatus.burn_rates`, `budget_status()` per-window
  burn-rate computation. Test fixture updated.
- `crates/aegis-control/src/api/tracking.rs` —
  `SloResponse::from_budget_status` populates `burn_1h/6h/3d`.
- `crates/aegis-control/src/api/attacks.rs` — `Attacker.country`
  + `asn`, `AttacksHandler.geo` slot + `set_geo_lookup` setter
  + `enrich_attackers()` invoked before caching `render_top()`.
- `crates/aegis-proxy/src/lib.rs` — periodic SLO eval+dispatch
  task (30 s interval, calls `dispatch::send_alert` per fired
  alert); GeoIP reader wiring under `cfg(feature = "geoip")`.
- `crates/aegis-proxy/Cargo.toml` — new `geoip` feature
  (alias of `aegis-security/geoip`).
- `crates/aegis-bin/Cargo.toml` — new `alerts` + `geoip`
  features (aliases of `aegis-control/alerts` + `aegis-proxy/geoip`).
- `crates/aegis-core/src/config.rs` — new `GeoIpConfig`
  struct (`country_db` + `asn_db`), wired into `WafConfig.geoip`.
- `crates/aegis-control/assets/dashboard/src/pages.jsx` —
  Overview consumes real `country`/`asn`; blips render only
  for IPs with geo; pill reflects `geo DB not loaded` /
  `N geo-tagged` honestly.

**Verification.**

- `cargo test --workspace` → **2,199 passed** (no
  regressions). Clippy clean.
- `cargo build -p aegis-bin --release --features "redis alerts geoip"` → green.
- Live smoke: `/api/slo` returns `burn_1h`/`burn_6h`/`burn_3d`
  fields populated from the engine; `/api/attacks/top` row
  shape includes optional `country`/`asn`. With no MaxMind DB
  configured, rows omit the fields cleanly.

### Run-11 — full control-panel acceptance (2026-04-30)

End-to-end run-through of the dashboard after CI-T1..T10 closed.
Full report: [`tests/results/run-11-2026-04-30-control-panel-acceptance/README.md`](./tests/results/run-11-2026-04-30-control-panel-acceptance/README.md).

- 22/22 dashboard-consumed endpoints return real JSON ✅
- `make openapi-test` → 25/25 OpenAPI shape checks ✅
- `make protocols-test` → h1 ✅ h2 ✅ WS ✅ gRPC ✅ (h3 skip — curl-side)
- Round-1 acceptance → 8/8 contract checks (RT 61 ms / hot-reload 52 ms / audit 30 ms) ✅
- 12 fresh per-page screenshots committed
- SLO engine **fired 3 real alerts** during the run (Tracking
  page screenshot) — proves CI-T7 dispatch loop works in production
- Test-harness fixes: round1-acceptance now logs in via /admin/login
  (was relying on /dashboard/ setting CSRF), uses portable `ms_now()`
  instead of `date +%s%3N`, and streams the bundle to a tempfile
  to avoid broken-pipe under `set -o pipefail`

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
| 2026-04-30 | **CI-T9 + CI-T10** OpenAPI spec + h2 wire-up | Hand-written `docs/control-plane/api.openapi.yaml` (1,217 lines, 30 endpoints, 30 schemas, 3 security schemes) + `tests/api/openapi-shape.sh` 25-check contract test. CI-T10 swapped data-plane TLS `http1::Builder` for `hyper_util::auto::Builder` so ALPN-negotiated h2 actually serves over h2; flipped explicit ALPN downgrade back to `[h2, http/1.1]`. Closed real client-compat gap (HTTP/2 + gRPC both unblocked). |
| 2026-04-30 | **CI-T7 + CI-T8** Console API integration — SLO eval + geo enrichment | Periodic engine.evaluate task wired to slo::dispatch::send_alert (VipTalk delivery on `--features alerts`); BudgetStatus carries per-window burn rates → /api/slo populates burn_1h/6h/3d. Attacker rows gain country+ASN from MaxMindReader (`--features geoip`); Overview blips drop the mock fixture. 2,199 tests. |
| 2026-04-30 | **CI-T1..T6** Aegis WAF Console — live API integration | All 12 dashboard pages now read live `/api/*` instead of mock JS constants. New `/api/routes`, `PUT /api/mode`, `POST /api/alerts/{id}/ack`. Real /api/slo + /api/certs + /api/gitops/status + /api/alerts (was placeholder). Plan: `plans/console-api-integration.md`. |
| 2026-04-30 | **DD-T0..T8** Aegis WAF Console redesign | Replaced 11-page vanilla-JS SPA with pre-compiled React 18 (~180 KB bundle); 17 real-API hooks; Rule CRUD with hot-reload toast; CSP `script-src 'self'`; Round-1 acceptance script + 12 baseline screenshots; Hackathon WAF-FE §2 contract closed. Run-10 published. |
| 2026-04-30 | **AF-T1 + HP-T1 + TLS-T1** Post run-08 closing tracks | Action-class fidelity; upstream HTTPS+HTTP/2 pool via hyper-rustls; TLS-T1 re-measure confirms run-05 handshake spike was host noise. 27/27 DR contract checks green. |
| 2026-04-30 | **DR-T1..DR-T7 + IT-T1..IT-T6** Interop contract + dry-run | `aegis-control::interop` module; always-on `X-WAF-*` headers + minimal-schema `./waf_audit.log` + `/__waf_control/*` + per-policy mode store. 27/27 contract checks green. ~30 µs p95 overhead / 4 % at 4 k RPS. |
| 2026-04-30 | **UP-T1** Upstream connection pool | hyper-util pooled Client; **15× throughput lift** (525 → 7 964 RPS). |
| 2026-04-30 | **Workers / Layer-1** in-node scaling | `runtime:` config + tokio Builder wiring + `/api/runtime` + dashboard panel + `affinity` Cargo feature. |
| 2026-04-30 | **HA-T1..T5** Cluster ingress / LB | HAProxy reference deploy + cluster smoke tests + `node.id` + leader-poll membership + `/admin/drain` + `?strict=1` readiness. 99.93 % hard / 100 % graceful failover. |
| 2026-04-29 | **Carry-overs A + B** | Data-plane Allow forwarding wired; rate-limit returns 429 (test recalibrated). 31.5 k RPS / 504 µs median. |
| 2026-04-29 | **B5-T1 + B5-T2** Protocols + benchmark mode | HTTP/3 listener (quinn 0.11) + benchmark mode core slice with `X-Aegis-*` header serialiser. |

---

## Next Task

**Task in flight: B6-T1 — production Dockerfile.** Plan
[`plans/phase-b/README.md` § B6](./plans/phase-b/README.md#b6--production-packaging).
Last remaining Phase B item; everything else (B1..B5,
HA-T1..T5, IT-T1..T6 + DR-T1..T7, AF-T1/HP-T1/TLS-T1, DD-T0..T8,
CI-T1..T8) is closed.

**This turn closed CI-T7 + CI-T8** (SLO eval+dispatch+burn
windows, geo enrichment for `/api/attacks/top`). The Aegis
WAF Console redesign + every supporting backend surface is
now production-grade — full detail in **Last Completed**
above.

**Earlier turn — DD-T0+T1.** Old vanilla-JS dashboard (~30 files) removed.
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
| 1 | **Phase B — production-packaging (B6)** | [`plans/phase-b/README.md`](./plans/phase-b/README.md) | **active**; B1..B5 closed; B6-T1 in flight |
| — | Dashboard redesign (DD-T0..T8) | [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md) | closed in run-10 |
| — | Console API integration (CI-T1..T8) | [`plans/console-api-integration.md`](./plans/console-api-integration.md) | closed |
| — | HA cluster (HA-T1..T5) | [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md) | closed in run-05 |
| — | Interop contract (IT-T1..T6) | [`plans/interop-contract.md`](./plans/interop-contract.md) | closed |
| — | Interop dry-run (DR-T1..T7) | [`plans/interop-dry-run.md`](./plans/interop-dry-run.md) | closed in run-08 |
| — | Post-run-08 (AF-T1, HP-T1, TLS-T1) | [`plans/post-run-08.md`](./plans/post-run-08.md) | closed |
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
