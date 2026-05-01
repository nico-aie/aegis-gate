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

- **As of:** 2026-05-01
- **Workspace tests:** **163 in `aegis-core`** + **855 in
  `aegis-control`** + **424 in `aegis-proxy` lib** (**461 with
  `--features etcd`**) + **888 in `aegis-security`** + **41 in
  `aegis-bin`** (default features). aegis-proxy: +4 from
  PRE-T1's `responses::tests` (json round-trip, cache-control
  threading, fallback contract, security-headers application).
  **Dashboard bundle 182,090 B** (178 KB).
  Workspace total ~2,434 default-feature.
  **`aegis-proxy/src/lib.rs`: 5569 → 5484 (PRE-T1) → 4900
  (PRE-T2)** lines, cumulative −669. Submodules:
  `responses.rs` 213, `data_plane.rs` 616. Both under the
  800-line guideline. PRE-T3 next: `admin/sse.rs`.
- **Clippy:** `aegis-control` + `aegis-proxy` libs both clean
  under `-D warnings` after OTEL-T3's lint sweep
  (`RESERVED_RULE_IDS.contains`, `WafError::Io` redundant
  closure, `BuiltPools` type alias, two `strip_prefix` cleanups,
  one needless borrow on `from_config`). Some pre-existing
  rust-1.94 lints may still surface in test-only files
  (`aegis-control/tests/dod.rs`) under non-default feature
  combos; lib clippy is the gate.
- **Active tracks:** **Console config pages (CC-T\*)** — CC-T1.1
  + CC-T2.1 + CC-T2.1.b + CC-T2.2 + **CC-T1.2** closed today.
  Alert-receivers track is fully end-to-end (backend + dashboard
  card); upstreams track now has its read-side dashboard surface
  (config view + per-pool detail). Remaining: **CC-T1.1.b**
  (upstream PUT/DELETE + proxy hot-swap — heaviest item),
  **CC-T3** (i18n / OpenAPI / docs / acceptance round-trip).
  **Phase B B6 packaging** still has B6-T4 (HSM) + B6-T5
  (fd-pass) deferred. **Scaling config (SC-T\*)** parked.
- **Latest activity:** **PRE-T2 (extract `data_plane.rs`)
  closed 2026-05-01.** Second slice of the proxy refactor.
  Four data-plane functions moved out of
  `aegis-proxy/src/lib.rs` into a new `data_plane.rs`
  submodule (616 lines): `handle_data_request` (the
  `#[tracing::instrument]` wrapper), `handle_data_request_inner`
  (rate-limit → tier → detectors → risk → forward/block),
  `forward_allow_to_upstream` (route resolve + CB +
  upstream forward), and `blocked_response` (block-path
  helper). All `pub(crate)` for entry points; private
  helper kept private. **`lib.rs` 5484 → 4900 lines** (−584
  in this slice; cumulative −669 from the 5569 baseline).
  Test counts unchanged (424 default / 461 etcd).
  - **PRE-T1 (2026-05-01)** — Extracted `responses.rs`
    (~213 lines, 6 helpers + 4 tests).
  - **MTLS-T6 (2026-05-01)** — Read-only mTLS observability
    backend. New `aegis-control::identity_tracker` +
    `api::mtls` (4 read endpoints). CA summary works
    immediately; connections/failures empty until MTLS-T2/T3.
  - **MTLS-T1 (2026-05-01)** — Plan + types-only first slice.
    New `plans/mtls.md` (12-slice roadmap). `cfg.tls.client_auth`
    schema + `aegis-core::identity::ClientIdentity` enum.
    Until MTLS-T2 lands rustls wiring, `client_auth` is
    parsed but ignored.
  - **CC-T (per-handler hot-reload — TLS certs, 2026-05-01)** —
    Closes the LAST operator-loud cfg-driven hot-reload
    surface. New `apply_cfg_change_to_tls` helper +
    `TlsReloadOutcome` (NoResolver / Applied / SkippedEmpty /
    Failed). **Hot-reload now covers** routes + upstreams +
    detector mask + compliance clamp + ip rate-limit + TLS
    certs.
  - **CC-T (per-handler hot-reload — rate-limit, 2026-05-01)** —
    `IpRateLimiter` wraps `Inner.cfg: ArcSwap<IpRateLimitConfig>`
    + `set_config` method. Per-IP timestamp state preserved.
  - **CC-T (per-handler hot-reload — routes, 2026-05-01)** —
    `RouteTable` wrapped in `Arc<ArcSwap<CompiledRouteTable>>`
    + `apply` method. `apply_cfg_change_to_routes` helper
    rebuilds + atomic-swaps `ProxyContext.route_table` on
    reload. Validation failure emits `routes_reload_failed`
    and keeps live table intact.
  - **CC-T (config hot-reload plumbing, 2026-05-01)** —
    `aegis_proxy::run` takes `Arc<ArcSwap<WafConfig>>` +
    `ConfigReloadSource` enum. Boot-snapshots via
    `cfg_swap.load_full()`; watchers call the shared
    `apply_cfg_change_to_mask` helper. Activated yesterday's
    CC-T compliance-clamp-on-reload + ETCD-T1's etcd watcher
    in one slice.
  - **CC-T (compliance-on-reload + boot, 2026-05-01)** — New
    `apply_live_mask_with_compliance` in
    `aegis-control::api::detectors_persist` runs the clamp on
    the live `SharedDetectorMask` state.
  - **ETCD-T1 (2026-05-01)** — Config-from-etcd loader.
    `AEGIS_CONFIG_SOURCE=etcd` boot path under `etcd` Cargo
    feature; `spawn_watcher` activated by today's plumbing.
  - **OTEL-T1 + T2 + T3 (2026-05-01)** — Live OTLP exporter
    + hot-path instrumentation (`handle_data_request`,
    `AuditedMutate::apply`, `forward_allow_to_upstream`). Audit
    gap "OTel tracing 0%" fully closed. Jaeger shows parent-
    child trees with `action` / `tier` / `upstream` / `outcome`
    attributes; Grafana → Jaeger exemplar cross-link lights up
    on first traffic.
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

## Last Completed

**Task:** **PRE-T2 (extract `data_plane.rs`)** — Second slice
of the proxy refactor (`plans/proxy-refactor.md`). Pure
structural extraction, **zero behaviour change**.

### What landed

Four functions moved out of `aegis-proxy/src/lib.rs` into a
new `data_plane.rs` submodule:

- `handle_data_request` — `pub(crate) async fn`. The
  `#[tracing::instrument]` wrapper that owns the OTEL-T3
  root span and records the resolved `action` after the
  inner returns.
- `handle_data_request_inner` — `pub(crate) async fn`. The
  per-request logic: rate-limit → tier classification →
  detector run → risk eval → forward / block.
- `forward_allow_to_upstream` — `pub(crate) async fn`.
  Route resolve + circuit-breaker gate + pool member pick
  + body forward via `upstream::forward::forward()`.
- `blocked_response` — private `fn`. Helper every block
  path uses to build the 403 + emit the audit-chain entry.

Call site in `lib.rs::accept_loop` rebound via
`use data_plane::handle_data_request;` — byte-identical.
No tests moved (the data-plane tests live in
`lib.rs::tests::run_binds_and_serves_200` and exercise full
proxy boot rather than data-plane internals; they stay
attached to `aegis_proxy::run` until PRE-T7 lifts run).

### File sizes

- `aegis-proxy/src/lib.rs`: **5484 → 4900 lines** (−584 in
  this slice; cumulative −669 from the 5569 baseline).
- `aegis-proxy/src/data_plane.rs` (new): **616 lines**
  (under the 800-line guideline).
- `aegis-proxy/src/responses.rs` (PRE-T1): 213 lines
  unchanged.

### Verification

- `cargo build -p aegis-bin --features production` → clean.
- `cargo clippy -p aegis-proxy --features etcd --lib --
  -D warnings` → clean.
- `cargo test -p aegis-proxy --lib` → **424 / 0 / 0**
  default / **461** etcd. **3/3 stable parallel runs.**
- All other crates unchanged: aegis-control 855,
  aegis-core 163, aegis-bin 41, aegis-security 888.

### What's next

Per `plans/proxy-refactor.md`:

- **PRE-T3** — extract `admin/sse.rs` (~30 min, ~300
  lines). `/dashboard/sse` streaming endpoint, well-isolated.
- **PRE-T4** — extract `admin/login.rs` (~30 min, ~400
  lines).
- **PRE-T5** — extract `admin/get_handlers.rs` (~1.5 h,
  ~1200 lines). Big chunk.
- **PRE-T6** — extract `admin/mutation_handlers.rs` (~1.5 h,
  ~1500 lines). Bigger chunk.
- **PRE-T7** — extract `run.rs` (~1 h, ~700 lines), leave
  `lib.rs` as a thin facade.
- **PRE-T8** — verify (no file > 800 lines, all tests pass).

After PRE-T8: resume MTLS-T track with the deferred
MTLS-T6 frontend, then MTLS-T2's rustls wiring.

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
| 2026-05-01 | **PRE-T2 (extract `data_plane.rs`)** Second slice of proxy refactor | Pure structural extraction, zero behaviour change. Four functions moved out of `aegis-proxy/src/lib.rs` (5484 → **4900 lines**) into new `data_plane.rs` (616 lines): `handle_data_request` + `handle_data_request_inner` + `forward_allow_to_upstream` + `blocked_response`. `pub(crate)` entry points + by-name `use` keep call site byte-identical. No test additions (data-plane tests live in `lib.rs::tests::run_binds_and_serves_200`, stay attached to `aegis_proxy::run` until PRE-T7). 424 default / 461 etcd unchanged. 3/3 stable parallel runs. PRE-T3 (admin/sse.rs, ~300 lines) next. |
| 2026-05-01 | **PRE-T1 (extract `responses.rs`)** First slice of proxy refactor | Pure structural extraction, zero behaviour change. 6 response-builder helpers moved out of `aegis-proxy/src/lib.rs` (5569 → **5484 lines**) into new `responses.rs` (213 lines) — all `pub(crate)`, by-name `use` keeps the 166 call sites byte-identical. +4 unit tests (json round-trip, cache-control threading, fallback contract, security-headers application). aegis-proxy 420 → 424 default / 457 → 461 etcd. 3/3 stable parallel runs. PRE-T2 (extract `data_plane.rs`, ~700 lines) next. |
| 2026-05-01 | **MTLS-T6 (read-only console observability — backend)** Tier-1 mTLS observability + CA bundle pre-flight | New `aegis-control::identity_tracker` (sliding-window per-principal counter + `parse_ca_bundle` via rustls_pemfile + x509_parser). New `aegis-control::api::mtls` (4 render fns + 9 tests). DashboardServices gains `identity_tracker: Option<Arc<...>>`. 4 GET dispatch arms in aegis-proxy/lib.rs (`/api/mtls`, `/connections`, `/failures`, `/ca-summary`). Empty-state until MTLS-T2/T3 fire `record_request` / `record_failure`; CA summary works immediately. +21 aegis-control tests (834 → 855). aegis-proxy unchanged. **Operator-flagged:** `aegis-proxy/src/lib.rs` 5569 lines — `plans/proxy-refactor.md` (PRE-T1..T8) queued next. |
| 2026-05-01 | **MTLS-T1 (config schema + identity types)** Server-side mTLS plan + Slice 1 | New `plans/mtls.md` (12 slices). `cfg.tls.client_auth: Option<ClientAuthConfig>` with mode (disabled/optional/required), ca_bundle, allowed_sans, apply_to (admin/data, default `[admin]`). Validation: non-disabled mode requires both ca_bundle + non-empty apply_to. New `aegis-core::identity::ClientIdentity` enum (Anonymous/Mtls/Spiffe) with kind+principal+is_authenticated helpers. **Types only — no behaviour change.** +18 tests in aegis-core (145 → 163). Ship order plans MTLS-T6 (read-only console observability) BEFORE MTLS-T2's rustls wiring so operators see the dashboard before the handshake change. |
| 2026-05-01 | **CC-T (per-handler hot-reload — TLS certs)** Live cert rotation from file + etcd | Existing `DynamicResolver`'s `Arc<ArcSwap<CertStore>>` already supported swap; boot path lifted resolver out of the match arm so watchers can call `swap`. New `apply_cfg_change_to_tls` helper + `TlsReloadOutcome::{NoResolver, Applied { cert_count }, SkippedEmpty, Failed { reason }}`. Empty `tls.certificates` is **skip-not-clear** (clearing would crash live handshakes); failure keeps old store live + emits `tls_reload_failed`. +7 tests (5 reload + 2 supervisor end-to-end). aegis-proxy 413 → 420 default / 450 → 457 etcd. Rotate certs in waf.yaml → live in ~100 ms; in-flight handshakes complete on old store. |
| 2026-05-01 | **CC-T (per-handler hot-reload — rate-limit)** Live IP rate-limit reload from file + etcd | `IpRateLimiter.Inner.cfg` wrapped in `ArcSwap<IpRateLimitConfig>` + new `set_config` method. Hot-path adds one ArcSwap load per request (~5 ns). Per-IP timestamp state preserved across swap. New `apply_cfg_change_to_rate_limit` helper + shared `derive_ip_rate_cfg` selector. Both watchers emit `rate_limit_reloaded` events. +9 tests (3 limiter + 5 reload + 1 supervisor end-to-end). aegis-proxy 407 → 413 default / 444 → 450 etcd. aegis-security 885 → 888. Edit `cfg.rate_limit.buckets[0]` → live in ~100 ms. |
| 2026-05-01 | **CC-T (per-handler hot-reload — routes)** Live route table reload from file + etcd | `RouteTable` refactored to wrap `Arc<ArcSwap<CompiledRouteTable>>` + new `apply()` method (mirrors `PoolRegistry`). Hot-path: one `ArcSwap::load` per request (~5 ns). New `apply_cfg_change_to_routes` helper called by both watchers; validation failure emits `routes_reload_failed` and keeps the live table intact. +8 tests (3 route, 3 reload-helper, 2 supervisor end-to-end). aegis-proxy 399 → 407 default / 436 → 444 etcd. Edit `routes:` in waf.yaml → live in ~100 ms. |
| 2026-05-01 | **CC-T (config hot-reload plumbing)** File + etcd watchers wired through `aegis_proxy::run` | `aegis_proxy::run` now takes `Arc<ArcSwap<WafConfig>>` + `ConfigReloadSource` (None / File / Etcd). Boot snapshot via `cfg_swap.load_full()` so existing read sites unchanged. Watchers (file `notify` debounced ~100ms, etcd REST poll ~5s) call shared `config_source::reload::apply_cfg_change_to_mask` to re-derive base mask + clamp + emit `config_reload` + `compliance_clamp_applied` events. Activates both yesterday's CC-T compliance-clamp-on-reload AND ETCD-T1's etcd watcher in one slice. +5 reload-helper unit tests. aegis-proxy 394 → 399 default / 431 → 436 etcd. Per-request route/upstream reads still boot-snapshotted (separate follow-up). |
| 2026-05-01 | **CC-T (compliance-on-reload + boot)** Detector-mask compliance clamp on hot-reload + boot | New `apply_live_mask_with_compliance(mask, modes)` helper in `aegis-control::api::detectors_persist` mirrors the existing snapshot-rehydrate clamp but operates on live `SharedDetectorMask` state. Boot path wires it before snapshot-load — closes sibling first-boot gap where `cfg.detectors` + `compliance.modes` could silently disable a PCI-pinned class. Supervisor's `watch_loop` re-derives base mask from new cfg + clamps + emits `compliance_clamp_applied` audit event alongside existing `config_reload`. +6 unit tests (`live_apply_*`) + 1 supervisor end-to-end. aegis-control 828 → 834, aegis-proxy 393 → 394 (default) / 430 → 431 (`--features etcd`). Hot-reload wire dormant pending `Arc<ArcSwap<WafConfig>>` plumbing; boot-time wire active. |
| 2026-05-01 | **ETCD-T1** Config-from-etcd loader | New `aegis-proxy::config_source::etcd_source` (cfg-gated under `etcd`); `AEGIS_CONFIG_SOURCE=etcd` boot path fetches `/aegis/config/waf` via etcd v3 `/v3/kv/range` and runs the same `WafConfig::validate`. Pure-lookup test pattern eliminates env-var-mutation flakes between `sd::etcd::tests` and the new module. 19 unit tests; aegis-proxy 430 / 393 (etcd / default), aegis-bin 41 (+4). Watcher dormant pending `Arc<ArcSwap<WafConfig>>` plumbing in `aegis-proxy::run`. |
| 2026-05-01 | **OTEL-T1 + T2 + T3** Live OTLP exporter + hot-path instrumentation | T1 added `aegis-bin/otel` feature scaffold + `init_or_default(&cfg)` single-call subscriber init; T2 wired the real OTLP gRPC pipeline (4 crates: opentelemetry 0.24 + opentelemetry_sdk + opentelemetry-otlp 0.17 + tracing-opentelemetry 0.25) with service-resource + sample-ratio sampling + batch SDK; T3 added `#[tracing::instrument]` to `handle_data_request` (server kind, records action+tier), `AuditedMutate::apply` (internal kind, records actor+request_id+outcome), `forward_allow_to_upstream` (client kind, records upstream+member+outcome). Audit gap "OTel tracing 0%" fully CLOSED. Clippy `-D warnings` green on aegis-control + aegis-proxy libs. 828 + 393 tests. |
| 2026-05-01 | **PROM-T1 + T2 + T3 + GRAFANA-T1 + DURABLE-T1 + T2 + CC-T1.1.b + CC-T1.2 + CC-T1.audit + CC-T2.\* + CC-T3 + HU-T\*** Audit-driven gap closure | Closed audit gap #3 (Prometheus instrumentation) end-to-end (`waf_requests_total`, `waf_upstream_members_*`, `waf_detector_hits_total`, `waf_state_backend_ops_total`, `waf_audit_events_total`); shipped Grafana stack with 3 file-provisioned dashboards; durable audit chain via NDJSON daily-rotation + retention TTL; persisted detector mask with compliance clamp on rehydrate; full upstreams CRUD round-trip (backend hot-swap via `PoolRegistry`, dashboard editor, end-to-end audit script); alert-receivers card on Tracking page with kind-aware modal; OpenAPI spec extended 30→37 paths / 39→52 schemas. Dashboard bundle slimmed 241→178 KB via esbuild minification. |
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

**Operator priorities all closed today:** upstreams CRUD
end-to-end (CC-T1.1.b + CC-T1.2 + CC-T1.audit), Grafana setup
(GRAFANA-T1), and OTel tracing wired through hot paths
(OTEL-T1 + T2 + T3). Audit gaps #3 (Prometheus instrumentation)
+ #4 (OTel 0%) are now fully closed.

### Top of queue — PRE-T (proxy refactor) BEFORE more mTLS slices

Operator flagged `aegis-proxy/src/lib.rs` size during MTLS-T6
(now 5569 lines, ~7× the 800-line guideline). New plan
`plans/proxy-refactor.md` documents PRE-T1..T8:

1. **PRE-T1** — extract `responses.rs` (~120 lines).
2. **PRE-T2** — extract `data_plane.rs` (~700 lines).
3. **PRE-T3** — extract `admin/sse.rs` (~300 lines).
4. **PRE-T4** — extract `admin/login.rs` (~400 lines).
5. **PRE-T5** — extract `admin/get_handlers.rs` (~1200 lines).
6. **PRE-T6** — extract `admin/mutation_handlers.rs` (~1500 lines).
7. **PRE-T7** — extract `run.rs` (~700 lines), leave `lib.rs`
   as a thin facade.
8. **PRE-T8** — verify (no file > 800 lines, all tests pass,
   git-stat shows file moves only).

**Pure structural refactor — zero behaviour change.** ~6-8 h
total, but every subsequent mTLS slice (T2 rustls wiring, T3
identity extraction, T4 policy, T7 SAN allowlist mutations,
T8 mode toggle, …) lands in a focused submodule rather than
inflating a 5500-line file further.

### After PRE-T8 — resume MTLS-T

Per `plans/mtls.md` ship order, MTLS-T6 backend already
shipped. The remaining slices land in the new module
structure:

1. **MTLS-T6 frontend** (deferred from this turn) — dashboard
   `<PageMtls>` + `useMtlsApi()` hook + nav entry + i18n.
   Lands AFTER PRE-T8 so the JSX changes don't coordinate
   with a moving target on the Rust side. ~1-2 h.
2. **MTLS-T2** — rustls inbound wiring with
   `WebPkiClientVerifier` + `ClientTrustStore`. ~2 h.
3. **MTLS-T3** — identity extraction from
   `peer_certificates()`. Pure sync function. ~1.5 h.
4. **MTLS-T4 → T11** — policy / audit / hot-reload / 5-tier
   console UI / break-glass / per-route auth_required.

### Other queued items (parked, not blocking MTLS-T)

- **Redis Cluster slot-hashing** — designed-only; ~4-6 h.
- **Hot-reload of `cfg.risk` thresholds** — `/api/risk/*`
  PUT already provides live-control; cfg-driven gap is
  small. ~2-3 h.
- **Disable-TLS-at-runtime** — needs listener-loop drain
  coordination. Operators restart today.

### Broader compliance enforcement at boot (deferred)

`aegis_control::compliance::apply` runs only in `cmd_validate`
today — runtime boot doesn't enforce non-detector adjustments
(audit retention floor, TLS provider lock-in, PII pseudonymize).
Larger blast radius (every cfg field a PCI/FIPS profile rewrites);
separate slice from the detector-mask clamp.

### Tokio runtime metrics (deferred)

`aegis_runtime_active_workers` / `aegis_runtime_blocking_queue_depth`
need the `tokio_unstable` build flag and are gated on a
follow-up that re-evaluates the unstable surface area against
our supportability bar. Runtime dashboard's reserved panel
stays a documented placeholder until that lands.

### Bundle slimming (deferred — was top-of-queue, dropped)

Bundle is at **178 KB** after the esbuild minification pass,
giving 78 KB of CSP / round-1-acceptance budget headroom. No
further slimming is needed unless a heavyweight feature lands
that pushes back near the budget.

### Recommendation

**Run `PRE-T1..T8` next as one focused PR.** Zero behaviour
change, ~6-8 h total, every subsequent mTLS / dashboard /
control-plane slice lands cleanly afterward. The longer we
defer the split, the more handler bodies accrete in the
monolith — every new slice makes the eventual refactor harder.
Once PRE-T8 lands clean, resume the mTLS track with the
deferred MTLS-T6 frontend, then MTLS-T2's rustls wiring.

---

### Earlier in this session

The "Outline / Acceptance" block below predates today's CC-T*
work and is left in place as a reference for the closed Phase
B B6-T1 production Dockerfile task. Implement-Progress is in
mid-protocol-drift after a heavy multi-task session; the
single source of truth for closed tasks is
[`docs/progress/completed-tasks-log.md`](./docs/progress/completed-tasks-log.md).

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
| 2 | **Console config pages (CC-T*)** — upstreams editor + alert-channel mgmt | [`plans/console-config-pages.md`](./plans/console-config-pages.md) | **plan-only — awaiting confirmation**. CC-T1 (upstreams CRUD) → CC-T2 (alert receivers in Tracking page) → CC-T3 (i18n / OpenAPI / docs) |
| 3 | Scaling configuration (SC-T*) — three-layer worker/cluster/state surface | [`plans/scaling-config.md`](./plans/scaling-config.md) | **parked plan — awaiting confirmation**. Surfaces existing L1/L2/L3 model in Console; adds `/api/state` health endpoint |
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
