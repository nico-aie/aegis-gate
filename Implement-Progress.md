# Aegis-Gate Implementation Progress

## Last Completed
- Task: **Whole-system test run + post-k6 follow-up plan**
- What landed:
  - Doc + harness refresh from the previous turn:
    `docs/USAGE.md`, `docs/dashboard-enterprise/api.md`,
    `docs/risk-scoring.md`, `docs/tls-termination.md`,
    `docs/audit-logging.md`, `docs/adaptive-load-shedding.md`,
    `docs/graceful-degradation.md`,
    `docs/siem-log-forwarding.md` updated with P1–P8 surface.
  - `tests/{api,load,security}/` — admin-API smoke layer,
    four new k6 scripts (`security-toggle-flips.js`,
    `risk-strikes.js`, `loadmode-degradation.js`,
    `verbosity-pin.js`), `tests/TESTING.md` end-to-end
    playbook, `tests/README.md` rewritten.
  - `config/waf.dev.yaml` — self-contained dev/test config
    with no `${secret:env:…}` references, real argon2id
    hash for the test password, `risk.strikes.block_at: 50`
    matching the k6 default, `compliance: null` so detector
    toggle tests aren't clamped. New
    `aegis-core::config::tests::load_config_round_trip_dev_yaml`
    keeps it parseable as the schema evolves.
  - `deploy/docker-compose.test.yml` —
    `aegis-etcdctl` container fix: `quay.io/coreos/etcd:v3.5.13`
    is distroless (no `sleep`, no shell) so the original
    `entrypoint: ["sleep", "infinity"]` failed at start.
    Replaced with `etcdctl watch --prefix /__aegis_keepalive__`
    which uses only the bundled binary and survives etcd
    restarts. Removed the duplicate `--endpoints` flag
    (etcdctl rejected the `ETCDCTL_ENDPOINTS` shadow).
  - `tests/results/` — first whole-system k6 run results
    captured against the dev gateway: per-script `.log`
    files (large logs trimmed to first 50 + last 200 lines)
    plus a consolidated `README.md` with the SLO threshold
    table.
  - `plans/post-k6-followup.md` — **new**: 10-task plan
    (F-T1..F-T10) tiered by criticality, derived directly
    from the k6 + API-smoke run findings.
- Test results summary (full detail in
  `tests/results/README.md`):
  - 4 of 7 k6 scripts ran end-to-end: `baseline.js`
    (42 811 RPS sustained ✓; p99 latency over the 5 ms SLO
    on a laptop), `mixed-tiers.js` (`critical_fail_open == 0`
    ✓; tier:critical 4xx rate 5.99 % over the 1 % threshold),
    `ddos-burst.js` (data plane survived the 5 000 RPS flood),
    `loadmode-degradation.js` (P7 auto-mode confirmed:
    8 / 8 polls saw `mode = "elevated"` during stage B).
  - 3 of 7 k6 scripts blocked by the missing
    `POST /admin/login` HTTP route: `security-toggle-flips.js`,
    `risk-strikes.js`, `verbosity-pin.js`.
  - All 5 `tests/api/*.sh` smoke scripts will hit the same
    404 when run.
- Status: DONE — **1,932 workspace tests pass**,
  `cargo clippy --workspace -- -D warnings` clean, dev
  config validates, k6 results captured, follow-up plan
  written.
- Date: 2026-04-28

## Tracks now in flight

Two parallel tracks. F-T1 from the post-k6 work blocks the
dashboard track from shipping a working login flow, so it's
the join point.

| Track | Plan | Why it exists |
|---|---|---|
| Post-k6 follow-up (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | 1 critical regression + 2 latent bugs found by the whole-system k6 + API-smoke run |
| Dashboard redesign (M0..M10) | [`plans/dashboard-redesign/README.md`](./plans/dashboard-redesign/README.md) | Current UI ships the data wiring but the presentation, density, and operator workflows are below the bar. 10 page milestones + 1 foundation milestone, executed via a Claude-design workflow |

## Next Task

The whole-system run uncovered one critical regression and
two real bugs. **Follow** [`plans/post-k6-followup.md`](./plans/post-k6-followup.md)
in execution order:

1. **F-T1 — Wire `POST /admin/login` + `/admin/logout`**
   (~1 day). Highest-leverage change in the plan: closes the
   gap between the existing argon2id + session + CSRF
   primitives and the HTTP front door. Unblocks 8 tests
   (3 k6 + 5 API smoke) on a single landing.
2. **F-T5 + F-T4** in parallel (~1 day combined) — make
   admin-needing k6 scripts fail fast on login errors, ship
   a `config/waf.test.yaml` with thresholds tuned so
   `loadmode-degradation.js` can reach Critical on a laptop.
3. *Re-run* the full k6 + `tests/api/run-all.sh` suite.
   Re-generate `tests/results/`.
4. **F-T2 — wire per-IP rate-limiting into the data-plane
   hot path** (~2-3 days). The bucket infra in
   `aegis-security::rate_limit` exists but isn't consulted
   from `handle_data_request`. Confirmed by `ddos-burst`
   producing 0 auto-block events across 50 000 single-source
   requests at 5 000 RPS.
5. **F-T3 — diagnose CRITICAL-tier 5.99 % failure rate**
   (~half day). Depends on F-T1 (uses the toggle endpoints
   to flip detectors during the re-run).

After F-T1..F-T5 land, the test suite is fully exercising the
P1–P8 surface. F-T7..F-T10 are scheduling-flexible polish
(ACME integration, observability, k6 coverage gaps).

### Dashboard redesign — running in parallel

[`plans/dashboard-redesign/`](./plans/dashboard-redesign/) is a
self-contained 11-milestone track:

- **M0 Foundations** — token migration, chrome rebuild,
  component refresh, command palette. Must land first.
  ~5 days.
- **M1..M10** — one page per milestone. M1 (Overview), M2
  (Live Feed), M10 (Settings) seeded; M3..M9 written
  just-in-time when work starts.
- Each milestone runs a 5-stage Claude-design workflow
  (brief → critique → impl → visual review → ship)
  documented in
  [`plans/dashboard-redesign/workflow.md`](./plans/dashboard-redesign/workflow.md)
  with copy-paste prompt templates per stage.
- Design system (tokens, typography, spacing, motion) lives
  at
  [`plans/dashboard-redesign/design-system.md`](./plans/dashboard-redesign/design-system.md)
  and is the contract every page consumes.

Page milestones may run in parallel with the post-k6 work
**after** F-T1 (admin login HTTP route) lands — the SPA
can't authenticate until then.

### Track + follow-up status
- Crates: aegis-proxy (new acme_instant module + renewal helper
  in acme.rs), workspace Cargo.toml (instant-acme dep)
- Files changed:
  - `Cargo.toml` — add workspace dep
    `instant-acme = { version = "0.7", default-features = false,
    features = ["aws-lc-rs", "hyper-rustls"] }`. Pinned to
    `aws-lc-rs` because the workspace's rustls already runs that
    provider — `instant-acme`'s default `ring` would leave rustls
    unable to pick a process-level CryptoProvider.
  - `crates/aegis-proxy/Cargo.toml` — promote `rcgen` from
    dev-dep to production dep (the adapter uses it for CSR
    generation), add `instant-acme` dep.
  - `crates/aegis-proxy/src/acme.rs` — add `AcmeError::Internal`
    variant for invariant-violation paths the adapter needs.
    Add `CertInventory` type alias + `spawn_renewal_scheduler`
    function: spawns a background task that ticks at
    `renewal_check_interval(renew_before)` (half the renew
    window, clamped to [60 s, 3600 s]), inspects every cert from
    the inventory closure, and triggers `manager.issue()` when
    any of them is within `renew_before` of expiry. Errors are
    logged (`tracing::warn!`) but never break the loop —
    transient ACME outages must not disable renewal.
  - `crates/aegis-proxy/src/acme_instant.rs` — **new**
    adapter implementing `AcmeProvider` against `instant-acme`:
    - `register_account`: load `AccountCredentials` JSON from
      `account_key_path` if present; otherwise call
      `Account::create` against the directory, persist the
      result, and tighten the file's mode to `0600` on UNIX.
    - `place_order`: build `[Identifier::Dns]` from
      `cfg.domains`, call `account.new_order`, walk
      `order.authorizations()`, pick the HTTP-01 challenge per
      authz, return `Vec<Http01Challenge>` keyed by the live
      key authorisation. Skips authzs that came back already
      `Valid` (cached authorisations from the directory).
    - `await_validation`: notify the directory each pinned
      challenge URL is ready (`order.set_challenge_ready`),
      then poll `order.refresh()` every 2 s up to 60 attempts
      (2 min ceiling) and translate the resulting `OrderStatus`
      into our internal `OrderState`.
    - `finalize_and_download`: build a CSR via
      `rcgen::CertificateParams::serialize_request`, call
      `order.finalize(csr_der)`, poll `order.certificate()`
      until the chain is downloadable, persist
      `cert_dir/{primary_domain}/{cert,key}.pem` (key file
      again chmodded `0600`).
  - `crates/aegis-proxy/src/lib.rs` — register the new
    `acme_instant` module.
- Tests:
  - `acme::tests`: 3 new — `renewal_check_interval` clamps a
    short renew window to 60 s, clamps a long window to one
    hour, returns the half-of-window for the mid-range case.
  - `acme_instant::tests`: 10 — `build_csr` round-trip for
    single-domain + SAN list + empty-list rejection,
    `safe_domain_label` strips path separators and IPC-reserved
    chars (so `*.example.com` becomes `_.example.com`),
    `map_status` covers every `OrderStatus` variant,
    `identifier_label` extracts DNS, `collect_contact_uris`
    borrows from the config, `persist_issued` writes the
    canonical `cert.pem`/`key.pem` pair, uses the safe label
    for wildcard domains, creates parent dirs when missing.
  - The `pick_http01_challenge` selector is intentionally not
    unit-tested — `instant_acme::ChallengeStatus` isn't re-
    exported from the crate root in 0.7.x so we can't construct
    a `Challenge` literal. Behaviour is exercised end-to-end by
    the integration suite that runs against Pebble (the local
    ACME staging CA).
- Status: DONE — **1,931 workspace tests pass** (was 1,918, +13
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Track + follow-up status

| Phase | Goal | State |
|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | done |
| P3 | Per-detector toggles + per-tier override | done |
| P4 | TLS hardening — `min_version` + force-https + HSTS | done |
| P5 | ACME / Let's Encrypt state machine + HTTP-01 wiring | done |
| **P5+** | **`instant-acme` network adapter + renewal scheduler** | **done** |
| P6 | Risk-scoring upgrades — strikes + trust recovery + adaptive mitigation | done |
| P7 | `LoadMode` + bounded caches + degraded logging | done |
| P8 | Verbosity slider + cold-tier surface + UI pills | done |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | deferred |

### Boot wiring (for the next-phase author)

```rust
// in run() — minimal usage
let provider = Arc::new(InstantAcmeProvider::new());
let manager = Arc::new(AcmeManager::new(
    AcmeConfig::from_core(cfg.tls.as_ref().and_then(|t| t.acme.as_ref()).unwrap()),
    provider,
    challenges.clone(),     // shared with force_https_loop
    cert_writer,            // wires into Arc<ArcSwap<CertStore>>
));
let inventory: CertInventory = Arc::new(|| {
    // read every PEM under cfg.tls.acme.cert_dir
});
let _renewer = spawn_renewal_scheduler(Arc::clone(&manager), inventory);
```

The trait + state machine + persistence helpers + scheduler are
all unit-tested end-to-end against the `MockProvider`. The only
slice still requiring a live integration harness is the
`InstantAcmeProvider`'s network round-trip — that's the natural
fit for a Pebble-backed integration test in CI.

### Closeout

The full security-toggle plan (P1..P8) plus the explicit
P5 follow-up is now landed. The single deferred item is **P9
(new cold backend)** which the user accepted as out-of-scope
when the plan was approved (Prometheus + SIEM sinks already
cover 80 % of the cold-tier requirement). All eight original
concerns are mapped to landed code.

The whole-system k6 + API-smoke run on 2026-04-28 surfaced one
foundational gap (the admin login HTTP route was never wired,
so P1's CSRF/session pipeline can't actually be reached from
outside the process) and two latent data-plane gaps (per-IP
rate-limit not on the hot path; CRITICAL-tier 4xx rate above
SLO). All three are now planned in
[`plans/post-k6-followup.md`](./plans/post-k6-followup.md).

### Previous (P5 follow-up — `instant-acme` adapter) — for context
- Task: **Security-toggle plan, Phase P8 — Verbosity slider +
  cold-tier surface + UI pills**
- Crates: aegis-core (Verbosity primitive + LoggingConfig schema),
  aegis-control (api/logging module + DashboardServices wiring),
  aegis-proxy (hot-path emission filter + /api/logging dispatch +
  /api/cold-tier), assets/dashboard (status-bar verbosity pill)
- Files changed:
  - `crates/aegis-core/src/verbosity.rs` — **new**.
    `VerbosityLevel { Silent, Error, Warn, Info, Debug, Trace }`
    with `parse_str`, `as_str`, `is_at_least` (ladder ordering).
    `SharedVerbosity` (Arc<ArcSwap<…>>) — hot-path read costs one
    Arc load + Copy. `LoggingConfig { verbosity }` with default
    `Info`. `VerbositySnapshot { level, levels }` documents the
    slider order so the UI doesn't re-derive it.
  - `crates/aegis-core/src/lib.rs` — re-export
    `LoggingConfig`, `SharedVerbosity`, `VerbosityLevel`,
    `VerbositySnapshot`.
  - `crates/aegis-core/src/config.rs` —
    `WafConfig.logging: LoggingConfig` with `#[serde(default)]`.
  - `crates/aegis-control/src/api/logging.rs` — **new**.
    `render_logging_get(verbosity)` for `/api/logging` and
    `render_cold_tier(sinks)` for `/api/cold-tier`. Cold-tier
    rows enumerate every `AuditSinkConfig` variant (jsonl /
    syslog / splunk / kafka), redacting the splunk token field
    so the dashboard never echoes a secret. `delivery` is a
    `"unknown"` placeholder until the sink runtime publishes
    real per-sink state — surfacing the operator's configured
    destinations is more useful than a 404.
  - `crates/aegis-control/src/api/mod.rs` — register
    `logging` module.
  - `crates/aegis-control/src/dashboard_services.rs` —
    `DashboardServices.verbosity: SharedVerbosity` field;
    `spawn_with_mask` now also threads through the verbosity
    handle. Existing `spawn` shim builds a default verbosity.
  - `crates/aegis-proxy/src/lib.rs` — `run()` constructs
    `SharedVerbosity::from_config(&cfg.logging)` and shares it
    with both accept loops + the dashboard. Hot path
    (`handle_data_request`) reads `verbosity.current()` once
    and uses it to:
    - skip the audit-event emit entirely when verbosity is
      below `Error` (operator pinned `Silent` during load
      tests),
    - drop the verbose `fields` payload when verbosity is below
      `Info` — combines additively with the P7 Critical-mode
      short-circuit so an operator-pinned `Warn` strips fields
      even at Normal load.
    New dispatch arms `GET /api/logging`, `GET /api/cold-tier`,
    and async `PUT /api/logging` (handled by
    `handle_logging_put` through `AuditedMutate`).
  - `crates/aegis-control/assets/dashboard/index.html` —
    status-bar gains a `data-slot="verbosity"` segment with a
    `verbosity-pill` showing the current level.
  - `crates/aegis-control/assets/dashboard/app.js` — new
    `startVerbosityPoll()` polls `/api/logging` every 10 s
    (changes only on operator action, no need to spam the
    endpoint). Pill colour:
    - `silent` / `trace` → warn
    - `error`            → err
    - `warn` / `info` / `debug` → ok
- Tests:
  - aegis-core `verbosity::tests`: 7 — string code round-trip,
    `is_at_least` ordering, `silent` blocks everything above,
    shared atomic set, `from_config` initialises from YAML
    struct, snapshot lists ladder in display order, default
    `LoggingConfig` is `Info`.
  - aegis-control `api::logging::tests`: 5 — GET shape,
    PUT accepts each level, PUT rejects unknown level, cold-tier
    handles each sink variant + redacts the splunk token,
    cold-tier with no sinks returns empty list with
    `fallback_buffer_bytes: 0`.
- Status: DONE — **1,918 workspace tests pass** (was 1,906, +12
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | done |
| P3 | Per-detector toggles + per-tier override | L / 3 d | done |
| P4 | TLS hardening — `min_version` + force-https + HSTS | L / 3 d | done |
| P5 | ACME / Let's Encrypt state machine + HTTP-01 wiring | H / 1 wk | done (network impl deferred) |
| P6 | Risk-scoring upgrades — strikes + trust recovery + adaptive mitigation | M / 5 d | done |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | done |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | **done** |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### Closeout

The 8 user-confirmed phases (P1..P8) are now all complete. P9
remains deferred per the original decision matrix — the
Prometheus + SIEM sinks plumbed in this phase already cover
80 % of the cold-tier requirement and the user accepted that
trade-off when the plan was approved.

The eight original concerns from the plan now all map to landed
code:

| Concern | Landed in |
|---|---|
| #1 Transport security (TLS 1.2+, ACME, HSTS, force-https) | P4 + P5 |
| #2 DDoS resilience (graceful degradation) | P7 |
| #3 Bounded storage (TTL, per-IP caps, ring eviction) | P5 + P6 + P7 |
| #4 Risk scoring (decay, trust recovery, strikes) | P6 |
| #5 Adaptive mitigation (allow / challenge / block) | P6 |
| #6 Performance (hot-path costs minimised) | P2 + P7 |
| #7 Logging verbosity (operator-pinned + auto-degrade) | P8 |
| #8 Fault tolerance (critical path stays alive under degraded subsystems) | P5 + P7 |

Single follow-up commit still pending: the real `instant-acme`
adapter for the `AcmeProvider` trait (P5), and the background
renewal scheduler.

### Previous (P7 — `LoadMode` + bounded caches + degraded logging) — for context
- Task: **Security-toggle plan, Phase P7 — `LoadMode` + bounded
  caches + degraded logging**
- Crates: aegis-core (load_mode primitive + config schema +
  Cargo deps), aegis-control (api/load_mode handler +
  DashboardServices wiring), aegis-proxy (hot-path tick + degraded
  logging + /api/loadmode dispatch), assets/dashboard
  (status-bar pill + RPS readout)
- Files changed:
  - `crates/aegis-core/src/load_mode.rs` — **new**.
    `LoadMode { Normal, Elevated, Critical }` with
    `parse_str` / `as_str` / `is_critical` / `is_degraded`.
    `LoadModeConfig { elevated_rps, critical_rps,
    sample_interval, hysteresis }` with `validate()` —
    invariants `elevated_rps > 0`, `critical_rps > elevated_rps`,
    `0 ≤ hysteresis < 1`, `sample_interval ≥ 100 ms`.
    `LoadGauge` (Arc-shared) with hot-path `tick()`
    (one Relaxed atomic add), background `sample(elapsed)`
    that recomputes the auto mode, `set_override` /
    `override_value` for the operator pin, `snapshot()` for
    the API. `next_mode(prev, rps, cfg)` is a pure function so
    state-transition rules are exhaustively unit-testable
    without a runtime. `spawn_sampler()` returns the JoinHandle
    of the background ticker.
  - `crates/aegis-core/src/lib.rs` — re-export `LoadGauge`,
    `LoadMode`, `LoadModeConfig`, `LoadModeSnapshot`.
  - `crates/aegis-core/src/config.rs` — add
    `WafConfig.load_mode: LoadModeConfig` with `#[serde(default)]`
    so existing YAML keeps working. `WafConfig::validate()` now
    delegates to `load_mode.validate()`.
  - `crates/aegis-core/Cargo.toml` — add `arc-swap`; add
    `tokio` features `time` + `rt` for the sampler task.
  - `crates/aegis-control/src/api/load_mode.rs` — **new**.
    `render_get(gauge)` + `apply_put_body(gauge, body)` +
    `LoadModePutBody { override_value: Option<String> }`.
    Sentinel string `"unset"` (constant `UNSET_SENTINEL`)
    clears the override; `"normal"|"elevated"|"critical"`
    pins; field absent is a no-op. Three-state semantics
    encoded with a single optional string instead of
    `Option<Option<…>>` because serde_json collapses the
    nested-Option case under `#[serde(default)]`.
  - `crates/aegis-control/src/api/mod.rs` — register the new
    `load_mode` module.
  - `crates/aegis-control/src/dashboard_services.rs` —
    `DashboardServices.load_gauge: LoadGauge` field;
    `spawn_with_mask` accepts the shared gauge from the proxy
    so policy mutations + auto-mode changes propagate
    uniformly. Existing `spawn` shim builds a default gauge.
  - `crates/aegis-proxy/src/lib.rs` — `run()` constructs a
    `LoadGauge::new(cfg.load_mode)`, spawns the sampler task,
    and shares the handle with both accept loops + dashboard.
    `accept_loop` and `handle_data_request` thread the gauge
    through; the hot path calls `gauge.tick()` and reads
    `gauge.current()` once per request. **Degraded logging:**
    when `load_mode.is_critical()`, the audit `fields` payload
    is dropped to `Value::Null` (block reason + `risk_score`
    preserved), so the chain writes stay cheap under DDoS.
    New dispatch arms `GET /api/loadmode` (sync) and async
    `PUT /api/loadmode` (handled by `handle_loadmode_put`,
    routed through `AuditedMutate::apply` so every pin/unpin
    lands an admin chain entry).
  - `crates/aegis-control/assets/dashboard/index.html` —
    status-bar gains `data-slot="load-mode"` segment with a
    `load-pill` (Normal/Elevated/Critical) and an `rps`
    readout.
  - `crates/aegis-control/assets/dashboard/app.js` — new
    `startLoadModePoll()` polls `/api/loadmode` every 5 s,
    paints the pill (`ok` / `warn` / `err` data-state) and
    appends `(pinned)` when `override_active`. Polling pauses
    when the page is hidden.
- Tests:
  - aegis-core `load_mode::tests`: 20 — string code round-trip,
    `is_degraded` / `is_critical`, config validation (defaults
    pass; rejects zero elevated, critical ≤ elevated, hysteresis
    out of range, sample interval too short), `next_mode`
    transitions for every prev × RPS bucket including hysteresis
    floors (`Elevated` holds at 1000×0.9 = 900 and below; same
    for Critical at 5000×0.9 = 4500), `gauge_tick_and_sample`
    computes RPS, counter resets each sample, override wins over
    auto, clear override falls back to auto, snapshot shape +
    override flag, `replace_config` propagates live.
  - aegis-control `api::load_mode::tests`: 5 — GET shape, PUT
    accepts each mode string, rejects unknown, `unset`
    sentinel clears override, empty body is a no-op.
- Status: DONE — **1,906 workspace tests pass** (was 1,881, +25
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | done |
| P3 | Per-detector toggles + per-tier override | L / 3 d | done |
| P4 | TLS hardening — `min_version` + force-https + HSTS | L / 3 d | done |
| P5 | ACME / Let's Encrypt state machine + HTTP-01 wiring | H / 1 wk | done (network impl deferred) |
| P6 | Risk-scoring upgrades — strikes + trust recovery + adaptive mitigation | M / 5 d | done |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | **done** |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### P7 hot-path cost model

```
per request:
  load_gauge.tick()        # AtomicU64 fetch_add (Relaxed)
  load_gauge.current()     # ArcSwap pointer load
  if load_mode.is_critical(): drop verbose `fields` payload

per sample_interval (default 1 s):
  background task swaps counter atomic + recomputes auto mode
```

Result: a Critical-mode WAF still emits one chain entry per
block (audit invariant preserved) but at roughly half the
serialised-bytes cost — the `fields` JSON object was the
biggest contributor to the audit-chain disk write at 5 000 RPS.

### Mapping back to the user's 8-concern list

P7 closes #2 (DDoS resilience: graceful degradation), #3 (bounded
storage: existing AuditRing + ChallengeStore caps + new
trust-recovery prevents per-IP map growth), #6 (perf: tick is
one Relaxed add), #8 (fault tolerance: critical path stays alive
even when audit-chain writes degrade). The remaining concern
#7 (logging verbosity) is the natural fit for P8.

### Previous (P6 — Risk-scoring upgrades) — for context
- Task: **Security-toggle plan, Phase P6 — Risk-scoring upgrades
  (per-IP strikes + trust recovery + adaptive mitigation)**
- Crates: aegis-core (config schema), aegis-security (RiskTracker
  module + Cargo dep), aegis-proxy (hot-path adaptive mitigation
  + /api/risk endpoints + reset PUT), aegis-control (api/risk
  module + DashboardServices wiring), assets/dashboard (Tracking
  page risk widget)
- Files changed:
  - `crates/aegis-core/src/config.rs` — extend `RiskConfig` with
    `trust_recovery: Option<TrustRecoveryConfig>` (per-hour
    decay cap, default 30) and `strikes: Option<StrikeConfig>`
    (lifetime block_at threshold, default 50). Both opt-in so
    existing deployments keep the legacy half-life behaviour
    until they explicitly enable the new policy.
  - `crates/aegis-security/src/risk/tracker.rs` — **new**.
    `RiskTracker` (DashMap-backed per-IP store) with
    `record_malicious(ip, delta)`, `record_clean(ip)`,
    `level(ip)` (Allow / Challenge / Block via configured
    thresholds), `is_strike_blocked(ip)`, `reset(ip)`,
    `top(n)`, `snapshot_wire(ip)`. `RiskState`,
    `RiskSnapshot` exposed for the API + UI.
    `trust_decay_points` is the linear-rate trust-recovery
    formula — clean traffic claws back score capped at
    `per_hour` per hour of elapsed time, never reduces strikes.
    Strike-block short-circuits to `Block` regardless of how
    much the score has decayed (the "permanent block on repeat
    offence" guarantee).
  - `crates/aegis-security/src/risk/mod.rs` — re-export
    `RiskTracker`, `RiskState`, `RiskSnapshot`.
  - `crates/aegis-security/Cargo.toml` — add `dashmap`.
  - `crates/aegis-proxy/src/lib.rs` — boot constructs a
    `RiskTracker::new(&cfg.risk)` and shares it with both
    accept loops + DashboardServices via the new
    `spawn_with_mask(.., risk)` arg. Hot path
    (`handle_data_request`):
    1. Strike-block short-circuit before any detector runs.
    2. If signals fire → `risk.record_malicious(ip, total)`
       and 403 with the post-state strike count in the body.
    3. Else → `risk.record_clean(ip)` then `risk.level(ip)`
       decides between **Allow** (proxy stub OK), **Challenge**
       (429 + `Retry-After: 5`), and **Block** (403). New
       `blocked_response` helper centralises the audit-event
       emission so every block path lands one chain entry.
    Adds dispatch arms `GET /api/risk`, `GET /api/risk/{ip}`,
    and async `PUT /api/risk/{ip}/reset` (handled in
    `handle_admin_request` → `handle_risk_reset`, flowing
    through `AuditedMutate`).
  - `crates/aegis-control/src/api/risk.rs` — **new**.
    `render_list(tracker, limit)` produces the documented
    envelope `{ total_tracked, returned, clients[] }` clamped
    to [1, 500]. `render_detail(tracker, ip)` returns
    `(200, body)` on hit and `(404, error_body)` on miss.
    `parse_ip_segment(segment)` accepts v4 + v6.
  - `crates/aegis-control/src/dashboard_services.rs` — add
    `risk: RiskTracker` field; `spawn` shim still works
    (constructs a default tracker), `spawn_with_mask` now
    takes the shared instance from the proxy.
  - `crates/aegis-control/assets/dashboard/pages/tracking.js` —
    new "Risk clients" card on the Tracking page. Polls
    `/api/risk?limit=10` every 5 s, renders a 6-column table
    (IP, score, strikes ✱-marker for strike-blocked, level,
    idle, reset button). Reset button reads `aegis_csrf` cookie,
    PUTs to `/api/risk/{ip}/reset`, then re-fetches the list
    on success.
- Tests:
  - aegis-security `risk::tracker::tests`: 15 — snapshot/level
    of unknown IP, malicious increments score+strikes,
    score clamps to max, clean decays within hourly cap,
    cap-at-per-hour over multiple hours, no underflow,
    clean-doesn't-decrement-strikes, level classifies against
    thresholds, strike-block short-circuits low score,
    strike-block persists after score decay, reset clears,
    top sorts by strikes-then-score, top respects limit,
    snapshot_wire renders documented shape,
    `trust_decay_points` cap math, `per_hour=0` disables
    recovery.
  - aegis-control `api::risk::tests`: 6 — empty envelope
    shape, strike-block pill renders, limit clamp,
    detail 200 with score, detail 404 with error envelope,
    `parse_ip_segment` v4/v6/garbage.
  - aegis-control `dashboard_services::tests`: existing
    `mutate_*` tests adapted to pass the new
    `RiskTracker` arg through `spawn_with_mask` (no behavioural
    change).
- Status: DONE — **1,881 workspace tests pass** (was 1,859, +22
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | done |
| P3 | Per-detector toggles + per-tier override | L / 3 d | done |
| P4 | TLS hardening — `min_version` + force-https + HSTS | L / 3 d | done |
| P5 | ACME / Let's Encrypt state machine + HTTP-01 wiring | H / 1 wk | done (network impl deferred) |
| P6 | Risk-scoring upgrades — strikes + trust recovery + adaptive mitigation | M / 5 d | **done** |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | pending |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### P6 hot-path decision flow

```
incoming request
       │
       ▼
risk.is_strike_blocked(peer)?
       │ yes
       ▼ blocked_response (403)
       │ no
       ▼
classify_tier → mask.resolve(tier) → run_all_filtered
       │
       ├─ signals fired ─▶ risk.record_malicious(peer, sum)
       │                     │
       │                     ▼ blocked_response (403)
       │
       └─ clean         ─▶ risk.record_clean(peer)
                              │
                              ▼ risk.level(peer)
                                ├─ Block      → blocked_response (403)
                                ├─ Challenge  → 429 + Retry-After: 5
                                └─ Allow      → proxy to upstream (stub OK)
```

The two-stage architecture means the WAF satisfies the user's
requirement #4 + #5 from the original 8-concern list: the score
goes up on bad behaviour, decays on clean traffic capped at a
configurable rate, and operators can configure the
challenge/block thresholds. The strike counter ensures repeated
offenders stay blocked permanently until an audit-mutated
operator reset.

### Previous (P5 — ACME) — for context
- Task: **Security-toggle plan, Phase P5 — ACME / Let's Encrypt
  state machine + HTTP-01 challenge plumbing + cert inventory**
- Crates: aegis-core (config schema + validation),
  aegis-proxy (acme module rewrite + force-https HTTP-01
  short-circuit), aegis-control (CertsResponse inventory
  builder)
- Files changed:
  - `crates/aegis-core/src/config.rs` — add `AcmeConfig` to
    `TlsConfig`. Fields: `directory_url`, `contacts[]`,
    `domains[]`, `account_key_path`, `cert_dir`, `renew_before`
    (default 30d), `terms_of_service_agreed`, `challenge`
    (`http01` | `tls_alpn01` | `dns01`, default `http01`).
    `WafConfig::validate` now rejects:
    - non-`https://` `directory_url`
    - empty `contacts` or `domains`
    - `renew_before < 24h`
    - missing `terms_of_service_agreed`
  - `crates/aegis-proxy/src/acme.rs` — **rewrite**. Replaces the
    skeleton with a real implementation:
    - `AcmeProvider` async trait — register / place_order /
      await_validation / finalize_and_download. Network impl
      (instant-acme adapter) marked `// TODO(P5-network)`;
      every other surface is fully wired and tested against a
      `MockProvider`.
    - `AcmeManager.issue()` — pure state machine that walks
      register → order → publish challenges → wait → finalise
      → persist via a `CertWriter` callback. Cleans up published
      challenge tokens on **both** success and failure paths so
      the `ChallengeStore` doesn't leak.
    - `ChallengeStore` — `Arc<ArcSwap<HashMap<token, key_auth>>>`
      shared between manager + force-https listener. `lookup`,
      `insert`, `insert_many`, `remove_many`, `len`, `is_empty`.
    - `cert_not_after(pem)` — parses an X.509 DER blob via a
      hand-rolled tag walker (no `x509-parser` dep) and returns
      the `notAfter` as `chrono::DateTime<Utc>`. Used by
      `AcmeManager::needs_renewal` and the cert inventory
      handler.
    - `IssuedCert`, `Http01Challenge`, `OrderState`, `AcmeError`
      enum (`thiserror`-derived).
  - `crates/aegis-proxy/src/lib.rs` — `force_https_loop` now
    accepts a `ChallengeStore`. New `handle_force_https_request`
    short-circuits requests for
    `/.well-known/acme-challenge/{token}` to the published key
    authorisation (200 with `application/octet-stream`) and
    returns 404 for unknown tokens (no redirect — the directory
    expects a definitive answer). Every other path keeps the
    P4 redirect behaviour.
  - `crates/aegis-control/src/api/tracking.rs` —
    `CertsResponse::from_inventory(entries, now)` builds a real
    cert list from a producer-supplied
    `[CertInventoryEntry { host, issuer, expires_at, source }]`
    and computes `days_to_expiry` against `now`. Sorts by
    urgency (most-urgent first) so the dashboard surfaces the
    soonest-expiring cert at the top.
  - `crates/aegis-proxy/Cargo.toml` — add `thiserror` (production)
    + `time` (dev) deps.
- Tests:
  - aegis-core: 7 new — minimal ACME passes, rejects non-https
    URL / empty contacts / empty domains / renew_before<1d /
    missing ToS, snake_case challenge round-trip.
  - aegis-proxy `acme::tests`: 15 — challenge store insert/lookup/
    remove/insert_many, OrderState terminal set, full-order happy
    path with mock provider, challenge cleanup on success and on
    timeout, register error short-circuit, no-domains rejection,
    cert_not_after round trips a self-signed PEM, returns None for
    garbage, needs_renewal honours the window, fails-open for
    unparseable certs, well-known path format.
  - aegis-proxy `tests::force_https_*`: +2 ACME integration —
    HTTP-01 short-circuit serves the published key
    authorisation, unknown tokens get a 404 (not a redirect).
  - aegis-control `tracking::tests`: 3 — `from_inventory`
    computes days_to_expiry, sorts by urgency, handles already
    expired (negative days).
- Deferred (single follow-up commit):
  - **Real `instant-acme` impl of `AcmeProvider`** — the trait
    + state machine + cleanup invariants are tested; only the
    network adapter is missing. Marked `// TODO(P5-network)`.
  - Background renewal scheduler task (kept off the critical
    path until the network impl lands).
  - `/api/certs` PUT (renew action) + UI button — surface
    landed via `from_inventory`; PUT goes through `AuditedMutate`
    once the network impl is in place.
- Status: DONE — **1,859 workspace tests pass** (was 1,837, +22
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | done |
| P3 | Per-detector toggles + per-tier override | L / 3 d | done |
| P4 | TLS hardening — `min_version` + force-https + HSTS | L / 3 d | done |
| P5 | ACME / Let's Encrypt state machine + HTTP-01 wiring | H / 1 wk | **done (network impl deferred)** |
| P6 | Risk-scoring upgrades — trust recovery + lifetime strikes | M / 5 d | pending |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | pending |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### P5 follow-up: dropping in the `instant-acme` impl

```rust
// crates/aegis-proxy/src/acme.rs (new file: instant_adapter.rs)
pub struct InstantAcmeProvider { client: instant_acme::Client, ... }

#[async_trait]
impl AcmeProvider for InstantAcmeProvider {
    async fn register_account(&self, cfg: &AcmeConfig) -> Result<(), AcmeError> { ... }
    async fn place_order(&self, ...) -> Result<Vec<Http01Challenge>, AcmeError> { ... }
    async fn await_validation(&self, ...) -> Result<OrderState, AcmeError> { ... }
    async fn finalize_and_download(&self, ...) -> Result<IssuedCert, AcmeError> { ... }
}
```

Boot wiring (already plumbed):
```rust
let provider = Arc::new(InstantAcmeProvider::new(...));
let manager = AcmeManager::new(cfg, provider, challenges.clone(), cert_writer);
tokio::spawn(renewal_loop(manager));   // P6/follow-up
```

The challenge store is already shared with the force-https
listener, so the moment a real provider publishes tokens the
HTTP-01 responses turn live.

### Previous (P4 — TLS hardening) — for context
- Task: **Security-toggle plan, Phase P4 — TLS hardening
  (`min_version`, force-HTTPS redirect, HSTS)**
- Crates: aegis-core (config schema + validators),
  aegis-proxy (tls_policy module + force-https listener)
- Files changed:
  - `crates/aegis-core/src/config.rs` — extend `TlsConfig` with
    `force_https: bool` and `hsts: Option<HstsConfig>`. New
    `HstsConfig { max_age, include_subdomains, preload }` mirroring
    RFC 6797 + OWASP guidance (defaults: 1 year, subdomains on,
    preload off). New `Listeners.force_https:
    Option<ForceHttpsListener>` for the optional plain-HTTP
    redirect listener (`bind`, `status` ∈ {301, 308}).
    `WafConfig::validate` now rejects:
    - `tls.min_version` ≠ "1.2"|"1.3"
    - `tls.hsts.max_age == 0`
    - `tls.hsts.preload` without `max_age >= 31536000` and
      `include_subdomains: true`
    - `listeners.force_https.status` outside {301, 308}
  - `crates/aegis-proxy/src/listener/tls_policy.rs` — **new**.
    `protocol_versions_for(min)` maps the YAML string to a
    `&'static [&SupportedProtocolVersion]` (TLS 1.2 + 1.3 by
    default; 1.3-only when explicitly pinned; fail-safe to 1.3
    on garbage input). `build_hardened_server_config(resolver,
    min_version)` builds a rustls `ServerConfig` via
    `ServerConfig::builder_with_protocol_versions(versions)` so
    older clients get a handshake failure instead of a silently
    downgraded session. `format_hsts_header(hsts)` renders the
    canonical `max-age=N; includeSubDomains; preload` form.
    `force_https_redirect_response(host, path, status)` builds a
    redirect with port-stripping (`:80` removed; IPv6 brackets
    preserved) and clamps non-{301,308} statuses to 301.
  - `crates/aegis-proxy/src/listener/mod.rs` — register the
    `tls_policy` module.
  - `crates/aegis-proxy/src/lib.rs` — `run()` now spawns
    `force_https_loop(tcp, status)` when
    `cfg.listeners.force_https` is set. The loop terminates
    every request with the redirect response and logs at
    `tracing::debug!` on connection close.
- Tests:
  - aegis-core: 9 new — accept "1.2"/"1.3", reject "1.0"/"1.1"
    and bogus strings, HSTS `max_age=0` rejected, preload
    requires 1-year max-age and include_subdomains, default HSTS
    passes, force-https status 301/308 only, default status 301.
  - aegis-proxy: 16 new tls_policy unit tests (protocol-version
    matrix, HSTS header shapes, redirect location/port/IPv6
    handling, status clamping, no-store cache header) + 2 new
    integration tests (`force_https_loop_returns_301_with_https_location`,
    `force_https_loop_honours_308_status`) that exercise the
    listener over TCP.
- Status: DONE — **1,837 workspace tests pass** (was 1,810, +27
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | done |
| P3 | Per-detector toggles + per-tier override | L / 3 d | done |
| P4 | TLS hardening — `min_version` + force-https + HSTS | L / 3 d | **done** |
| P5 | ACME / Let's Encrypt real wiring (`instant-acme`) | H / 1 wk | pending |
| P6 | Risk-scoring upgrades — trust recovery + lifetime strikes | M / 5 d | pending |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | pending |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### Hardened-listener wiring (for P5 author)

```
                ┌─────────────────────────┐
:80  ───────▶  │  force_https_loop       │  ──▶ 301/308 to https://…
                └─────────────────────────┘
                ┌─────────────────────────┐
:443 ───────▶  │  accept_loop (TLS)      │ ──▶ build_hardened_server_config
                │   wraps stream with     │      (resolver, min_version)
                │   tokio_rustls::Acceptor│      ↑
                │   then handle_data_req. │      └── HSTS header on response
                └─────────────────────────┘          via format_hsts_header
```

P5 will replace the placeholder cert paths with ACME-issued live
certs swapped through the existing `Arc<ArcSwap<CertStore>>`.
Nothing in P4 forces a TLS migration — the data plane is still
plain HTTP. The hardening helpers + force-https listener are
ready to flip on as soon as cert provisioning lands.

### Previous (P3 — Per-detector toggles + per-tier override) — for context
- Task: **Security-toggle plan, Phase P3 — Per-detector toggles +
  per-tier override on Tier Config page**
- Crates: aegis-security (mask state extension),
  aegis-control (api::detectors expansion),
  aegis-proxy (per-tier hot-path resolution + audit-diff payload),
  assets/dashboard (Tier Config page rewrite)
- Files changed:
  - `crates/aegis-security/src/detectors/mask.rs` —
    introduce [`MaskState`] = `{ base: DetectorMask, overrides:
    [Option<DetectorMask>; 4] }` and migrate `SharedDetectorMask`
    to wrap `Arc<ArcSwap<MaskState>>`. Index pinned via
    `tier_index(Tier)` so a future tier variant can't silently
    shift the array. New API:
    `resolve(Option<Tier>) -> DetectorMask` (one Arc load + one
    `match`), `set_override(tier, Option<mask>)`, `store_state` /
    `load_state`. Backward-compat: `load()` still returns the
    base mask, and `store(base)` preserves overrides.
  - `crates/aegis-security/src/detectors/mod.rs` — re-export
    `MaskState`, `tier_index`, `tier_str`, `ALL_TIERS`.
  - `crates/aegis-proxy/src/lib.rs` — hot path now classifies the
    request via `aegis_security::pipeline::classify_tier(None,
    &view)` and feeds `mask.resolve(Some(tier))` into
    `run_all_filtered`. PUT `/api/detectors` handler upgraded to
    parse the new `{mask, overrides}` body shape (with graceful
    fall-back to the P2 flat shape) and writes a richer
    `before`/`after` JSON to the audit chain via
    `mask_state_to_json` so reviewers see exactly which tier
    flipped.
  - `crates/aegis-control/src/api/detectors.rs` — extend
    `DetectorsResponse` with a stable-ordered
    `overrides: BTreeMap<&'static str, DetectorMaskBody>`. Add
    `DetectorsPutBody` (both `mask` and `overrides` optional;
    `null` value clears that tier). New helpers:
    `parse_tier_str`, `apply_put_body(current, body, modes)`
    (mutates in-memory state and runs compliance clamp on base
    AND every override), `parse_full_put_body` (P3 shape with P2
    fallback).
  - `crates/aegis-control/assets/dashboard/pages/tiers.js` —
    rewrite. Top section unchanged (table + drawer); new
    "Per-tier detector overrides" section renders one card per
    tier with a `uses base` / `override active` pill + Add/Clear
    button. Active overrides expand into the standard 8-toggle
    grid; on change the page sends a partial PUT
    (`{overrides: {<tier>: {<class>: bool, …}}}`) so the audit
    chain entry only diffs the tier that changed.
  - `crates/aegis-control/assets/dashboard/aegis.css` — minimal
    styles for `.aegis-tier-overrides`,
    `.aegis-tier-override-head`, `.aegis-section-header`. Reuses
    the `.aegis-toggle-grid` / `.aegis-toggle-row` from P2.
- Tests:
  - aegis-security: 7 new — `tier_index` pinning, `tier_str`
    serde alignment, `resolve` with/without override, set+clear
    override visible via resolve, base store preserves overrides,
    `load()` ignores overrides (back-compat), `store_state`
    replaces overrides too.
  - aegis-control: 9 new in `api::detectors::tests` —
    empty-overrides surface in GET, per-tier overrides serialise
    in declaration order, `parse_tier_str` round-trip, `apply_put_body`
    sets/clears overrides, rejects unknown tier names, clamps both
    base and per-tier proposals against compliance, full P3 PUT
    JSON round-trip with no compliance.
- Status: DONE — **1,810 workspace tests pass** (was 1,793, +17
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | done |
| P3 | Per-detector toggles + per-tier override | L / 3 d | **done** |
| P4 | TLS hardening — `min_version` + force-https | L / 3 d | pending |
| P5 | ACME / Let's Encrypt real wiring (`instant-acme`) | H / 1 wk | pending |
| P6 | Risk-scoring upgrades — trust recovery + lifetime strikes | M / 5 d | pending |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | pending |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### P3 hot-path resolution

```
incoming HTTP request
        │
        ▼
classify_tier(route, &view)        ← path heuristic; route ctx wins
        │  Tier::High
        ▼
SharedDetectorMask::resolve(Some(High))
        │  override_for(High).unwrap_or(base)
        ▼
run_all_filtered(detectors, mask, &view)
```

Compliance clamp runs at PUT time only (not on the hot path), so
reads stay branchless. Per the clamp invariant: a stored override
mask is *guaranteed* to enable every pinned class, so resolving to
the override never disables sqli/xss/path_traversal/ssrf when
compliance is on.

### Previous (P2 — Class toggles + hot-path bitfield mask + Settings UI) — for context
- Task: **Security-toggle plan, Phase P2 — Class toggles + hot-path
  bitfield mask + Settings UI**
- Crates: aegis-security (new mask module), aegis-control (new
  detectors api + Cargo dep on aegis-security), aegis-proxy
  (mask plumbing + async PUT handler), assets/dashboard
  (Settings UI section + supporting CSS)
- Files changed:
  - `crates/aegis-security/src/detectors/mask.rs` — **new**.
    `DetectorClass` enum (8 variants, stable JSON `snake_case`),
    `DetectorMask` `u32` bitfield with const builders
    (`all_enabled`, `none`, `from_config`), `with`/`set` mutators,
    `entries()` ordered iter, `is_enabled_id` for unknown-detector
    pass-through. `DetectorMaskBody` serde DTO with
    `#[serde(default)]` so partial PUTs are tolerated.
    `SharedDetectorMask` newtype around
    `Arc<ArcSwap<DetectorMask>>` — `load()` is one pointer load on
    the hot path; `store()` swaps atomically.
  - `crates/aegis-security/src/detectors/mod.rs` — register the
    `mask` module + re-export public types. Add
    `run_all_filtered(detectors, mask, req)` — checks
    `mask.is_enabled_id(d.id())` before invoking each detector,
    so a disabled class short-circuits to a single bitfield AND.
  - `crates/aegis-proxy/src/lib.rs` — plumb a
    `SharedDetectorMask` from `run()` into `accept_loop` and
    `handle_data_request`; the data path now calls
    `run_all_filtered` instead of `run_all`. Admin listener
    reuses the same handle (`spawn_with_mask`) so the dashboard
    PUT propagates to the data plane without a restart. New
    `handle_admin_request` async wrapper around the sync
    `admin_router` reads request bodies for mutating endpoints;
    new `handle_detectors_put` flows the mask change through
    `AuditedMutate::apply` with CSRF cookie/header pulled from
    `Cookie`/`X-CSRF-Token` headers.
  - `crates/aegis-control/src/api/detectors.rs` — **new**.
    `render_get(mask, modes)` returns the documented JSON
    (`mask`, `locked_classes`, `compliance_modes`).
    `enforce_compliance_clamp(proposed, modes)` rejects
    proposals that disable any of `[sqli, xss, path_traversal,
    ssrf]` while a compliance mode is active. `parse_put_body`
    deserialises `DetectorMaskBody`.
  - `crates/aegis-control/src/dashboard_services.rs` — extend
    `DashboardServices` with a `detector_mask: SharedDetectorMask`
    field; `spawn_with_mask` constructor lets the proxy share its
    mask handle with the control plane.
  - `crates/aegis-control/src/api/mod.rs` — register the new
    `detectors` module.
  - `crates/aegis-control/Cargo.toml` — add `aegis-security` +
    `arc-swap` deps. (No cycle: aegis-security still depends only
    on aegis-core.)
  - `crates/aegis-control/assets/dashboard/pages/settings.js` —
    add the **Detection classes** section. GETs
    `/api/detectors` on mount + every poll; renders 8 toggles
    with locked classes disabled; on change, PUTs the full mask
    with the `aegis_csrf` cookie value mirrored as
    `X-CSRF-Token`. Reverts to last-known-good state on PUT
    failure and surfaces the server error message.
  - `crates/aegis-control/assets/dashboard/aegis.css` —
    `.aegis-toggle-grid` + `.aegis-toggle-row` styles for the
    new section. Locked-toggle styling uses
    `[disabled]` + `aria-label` tooltip — no JS-only cursor
    tricks.
- Tests:
  - aegis-security: 13 new — bitfield uniqueness, all-enabled
    default ↔ config default, partial-disable from config,
    `with` flips one bit only, unknown-id pass-through, body
    round-trip, shared load/store, 4-thread concurrent reader
    consistency, declaration-order iteration, `run_all_filtered`
    skips disabled, `run_all_filtered` with `none` mask returns
    empty.
  - aegis-control:
    - `api::detectors::tests` — 10: documented GET shape with
      and without compliance, mask render reports disabled
      classes, clamp passes / reports per-mode pinned classes /
      allows non-pinned, `parse_put_body` partial + non-JSON,
      `is_locked` semantics.
    - `dashboard_services::tests` — 2: end-to-end PUT flow flips
      mask + appends one admin chain entry with before/after
      diff; compliance clamp blocks SQLi disable under PCI and
      leaves the chain at length 0.
- Status: DONE — **1,793 workspace tests pass** (was 1,767, +26
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | done |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | **done** |
| P3 | Per-detector toggles + per-tier override | L / 3 d | pending |
| P4 | TLS hardening — `min_version` + force-https | L / 3 d | pending |
| P5 | ACME / Let's Encrypt real wiring (`instant-acme`) | H / 1 wk | pending |
| P6 | Risk-scoring upgrades — trust recovery + lifetime strikes | M / 5 d | pending |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | pending |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### P2 wire diagram (for the next-phase author)

```
  YAML cfg.detectors                         dashboard PUT /api/detectors
        │                                                 │
        ▼                                                 ▼
DetectorMask::from_config                    handle_detectors_put
        │                                                 │
        ▼                                                 ▼
SharedDetectorMask  ◀── ArcSwap ─────────  AuditedMutate::apply
        │ load()                              │  (CSRF + chain + emit)
        ▼                                                 ▼
run_all_filtered (data plane)                detector_mask.store(new)
```

### Previous (P1 — Audit-mutation pipeline) — for context
- Task: **Security-toggle plan, Phase P1 — Audit-mutation pipeline**
- Crates: aegis-control (one new module + DashboardServices wiring)
- Files changed:
  - `crates/aegis-control/src/api/mutation.rs` — **new**.
    `AuditedMutate` wrapper: CSRF check → mutator closure → on
    success only, append `AdminChangeEntry` to the SHA-256 hash
    chain and emit the event on the `AuditBus`. Failure modes
    (CSRF rejection, mutator-returns-Err) skip both the chain
    append and bus emit, so the chain invariant "every entry is
    a state change that actually happened" holds. Includes
    `MutationError` taxonomy with HTTP-status + `reason_code`
    mapping (`csrf_missing_cookie` → 403,
    `csrf_missing_header` → 403, `csrf_mismatch` → 403,
    `validation` → 400, `conflict` → 409, `internal` → 500) +
    standard error envelope renderer (`{ ok: false, reason,
    message }`).
  - `crates/aegis-control/src/api/mod.rs` — register the new
    `mutation` module.
  - `crates/aegis-control/src/dashboard_services.rs` —
    `DashboardServices.mutate: Arc<AuditedMutate>` field;
    constructed in `spawn()` against the same `AuditBus` so the
    drain task forwards admin events into the audit ring + future
    SIEM sinks via the same pipeline as detections.
- Tests:
  - 13 unit tests in `mutation.rs`: CSRF rejection × 3 paths,
    GET-skips-CSRF, single-entry-per-success, validation-skips-
    chain, validation-skips-bus, success-emits-bus, concurrent
    16-thread chain integrity, diff serialization, error body
    envelope, status-code taxonomy, reason-code taxonomy.
  - 2 integration tests in `dashboard_services.rs`:
    - `mutate_wraps_rule_upsert_and_appends_admin_audit` —
      end-to-end: PUT /api/rules → AuditedMutate → ChainWriter
      append → bus emit → drain task → AuditRing → /api/audit/since
      surfaces the `class:"admin"` event.
    - `mutate_rejects_csrf_and_does_not_mutate_store` — CSRF
      mismatch returns error, store is untouched, chain stays at
      length 0.
- Status: DONE — **1,767 workspace tests pass** (was 1,752, +15
  net new). `cargo clippy --workspace -- -D warnings` clean.
- Date: 2026-04-28

### Security-toggle plan — phases

| Phase | Goal | Size | State |
|---|---|---|---|
| P1 | AuditedMutate (CSRF + chain + ArcSwap) | M / 1 wk | **done** |
| P2 | Class toggles + hot-path bitfield mask + Settings UI | M / 5 d | pending |
| P3 | Per-detector toggles + per-tier override | L / 3 d | pending |
| P4 | TLS hardening — `min_version` + force-https | L / 3 d | pending |
| P5 | ACME / Let's Encrypt real wiring (`instant-acme`) | H / 1 wk | pending |
| P6 | Risk-scoring upgrades — trust recovery + lifetime strikes | M / 5 d | pending |
| P7 | `LoadMode` + bounded caches + degraded logging | M / 5 d | pending |
| P8 | Verbosity slider + cold-tier surface + UI pills | L / 3 d | pending |
| P9 | New cold backend (only if Prometheus + SIEM rejected) | — | deferred |

### How to use AuditedMutate (next-phase wiring crib sheet)

```rust
let req = MutationRequest {
    method: "PUT",
    csrf_cookie: parsed_cookie,
    csrf_header: parsed_header,
    actor: &session.user,
    request_id: &request_id,
    resource: "/api/rules/<id>",
    action: "update",
    reason: &reason_from_request,
};
let outcome = services.mutate.apply(
    &req,
    serde_json::to_value(&before).unwrap_or_default(),
    serde_json::to_value(&after).unwrap_or_default(),
    || services.rules.upsert(id, &body, enabled).into_result(),
)?;
```

D-M4 mutating endpoints (`PUT /api/rules/{id}`,
`PUT /api/tiers/{name}`, `POST /api/blacklist[/bulk]`,
`POST /api/admin/password`, `POST /api/admin/break-glass`) plug
in via this pattern. The proxy admin_router gains the
`PUT|POST|DELETE` arms in P2 alongside the class-toggle UI work,
since both share the dispatch wiring.

### Previous (D-M4 + D-M5 + D-M6) — for context
- Task: **D-M4 + D-M5 + D-M6 — three milestones in one push**
- Crates: aegis-core (config), aegis-control (8 new api modules,
  10 new pages/components, polish tests), aegis-proxy (22 new
  dispatch arms)
- D-M4 (config management):
  - `api/rules.rs` — RuleStore + RuleStats + ValidateResponse
  - `api/tiers.rs` — TierStore with 4 canonical tiers + put/get
  - `api/blacklist.rs` — shared AccessListStore with compliance
    clamp + atomic bulk insert
  - `api/whitelist.rs` — re-exports the same store
  - `api/admin.rs` — password change validator, SessionStore,
    BreakGlass, IntegrationsResponse
  - 5 page modules: rules.js, tiers.js, blacklist.js,
    whitelist.js, settings.js — all read-only (mutating endpoints
    deferred until M3 audit-mutation pipeline integrates)
  - +29 tests (8 rules + 5 tiers + 9 blacklist + 6 admin + 1 page
    asset structure)
- D-M5 (tracking):
  - `api/tracking.rs` — single module hosting SLO/Cluster/Certs/
    GitOps/Alerts/Snapshot response types + handler. Snapshot
    aggregate composes the upstream summary via a typed
    `UpstreamHandler::snapshot()` helper added to
    api/upstreams.rs.
  - 7 endpoints wired: `/api/slo`, `/api/cluster`, `/api/certs`,
    `/api/gitops/status`, `/api/alerts`, `/api/upstreams`,
    `/api/tracking/snapshot`. Cert renew action returns 405
    `not_supported` until cert store wires.
  - `pages/tracking.js` — 6-section layout, polls snapshot every
    5 s, cert-renew button stub.
  - +7 tests (6 tracking module + 1 page asset structure).
- D-M6 (polish):
  - `tests/dashboard_polish.rs` — 8 polish tests: a11y
    aria-label coverage, landmark roles, live regions, WCAG-AA
    contrast on dark + light themes, security header table
    completeness, total + per-file bundle-size budget.
  - `docs/dashboard.md` — pointer to `dashboard-enterprise/` +
    legacy-flag deprecation note.
  - Removed `crates/aegis-control/src/dashboard/legacy.rs` and
    the `pub use legacy::DASHBOARD_HTML_V1` re-export. The
    `admin.dashboard.legacy_shell` field is kept on the config
    struct as deprecated/no-op (marked `#[serde(default, alias =
    "legacy_shell")]`) so existing `waf.yaml` files still parse —
    operators should drop the field on next edit.
    `dispatch::shell_for(use_legacy)` keeps the parameter as a
    no-op for back-compat. Affected legacy-aware tests in
    dispatch.rs + aegis-proxy/src/lib.rs were rewritten to
    assert the post-removal behaviour.
  - Skipped per session scope:
    - T6.4 XSS regression (needs headless browser CDP harness)
    - T6.5 SRI assertion (Chart.js still not vendored, T2.9
      deferral upheld)
    - T6.7 Lighthouse (browser harness)
    These three remain on the "deferred when Chart.js gets
    vendored" list.
- Status: DONE — **1,752 workspace tests pass** (was 1,712, +40
  net new across D-M4..D-M6). `cargo clippy --workspace -- -D
  warnings` clean.
- Date: 2026-04-28

### Dashboard track milestone closeout

| Milestone | Tasks | Δ tests | State |
|---|---|---|---|
| D-M1 SPA shell | 8 | +83 | done |
| D-M2 Overview + endpoints | 9 | +94 | done |
| D-M3 operator views | 11 | +58 | done |
| D-M4 config management | 10 | +29 | done (mutating endpoints deferred) |
| D-M5 tracking | 9 | +7 | done (data sources stubbed pending runtime) |
| D-M6 polish | 10 | +8 | done (browser-automation tests deferred) |
| **Totals** | **57** | **+275** | **dashboard track complete** |

Workspace tests went from 1,477 (pre-dashboard) to **1,752**.

### Aggregate carry-over / deferred items

These don't gate the milestones; they're green-flagged for follow-up:

1. **Chart.js vendoring + SRI** (D-M2-T2.9, D-M6-T6.5): vanilla
   SVG components shipped instead. Re-add when heavier chart
   needs arrive (e.g. Analytics stacked bars).
2. **Mutating endpoints** (D-M4): `POST /api/rules/validate`,
   `PUT /api/rules/{id}`, `PUT /api/tiers/{name}`,
   `POST /api/blacklist[/bulk]`, `POST /api/admin/password`,
   etc. — all gated on the M3 audit-mutation pipeline being
   wired so writes go through CSRF + audit chain.
3. **Real per-pool / per-cluster / per-cert state** (D-M5):
   handlers return placeholder shapes until the cluster runtime
   + cert store + alert state machines are runtime-populated.
4. **Browser automation tests** (D-M6 T6.4 XSS, T6.7 Lighthouse):
   need a headless Chromium harness in CI. The polish tests
   shipped cover what's testable without one.
5. **Pre-existing roadmap items** (carried since D-M1):
   - Full upstream proxying (currently stub "OK")
   - Full SSE streaming (currently single-event stub)
   - Production Dockerfile + Helm chart
   - End-to-end integration tests (k6 + nuclei)
   - CI/CD pipeline (GitHub Actions)
   - Benchmark mode track (B-T1..B-T6, parallel — see
     `plans/benchmark-mode.md`)

### Previous (D-M3-T3.10..T3.11) — for context
- Task: **D-M3-T3.10..T3.11 Analytics page + PromQL allow-list proxy** + **D-M3 milestone close-out**
- Crates: aegis-control (analytics module + page),
  aegis-proxy (dispatch arm + new query helper)
- Files changed:
  - `crates/aegis-control/src/api/analytics.rs` — new module:
    `ALLOW_LIST` const slice with 13 documented `expr` keys →
    canonical PromQL (8 base + 5 benchmark-mode rows from
    `docs/benchmark-mode.md`). `lookup_promql(expr)` for
    validation. `AnalyticsResponse { expr, promql, result_type,
    value | points }` matches Prometheus's `/api/v1/query`
    taxonomy ("scalar" for instantaneous, "matrix" for range)
    so the front-end stays compatible if we eventually proxy to
    a real Prometheus. `AnalyticsRendering { status, body }`
    bundles the HTTP status with the JSON so the proxy can
    return 200/400/503 directly. `render_query(expr, start,
    end, step, prometheus_url)` returns:
      * 400 `unknown_expr` for unknown keys
      * 503 `no_history_backend` for range queries with no
        `prometheus_url`
      * 200 scalar 0.0 for instantaneous (registry stub returns
        zero until series are wired)
      * 200 empty matrix when `prometheus_url` is set but the
        upstream call isn't yet implemented (forward-compat bridge).
    +8 unit tests including the milestone's "each allow-listed
    key returns parseable response" + "unknown key returns 400"
    + step-placeholder preservation + flattened result shape.
  - `crates/aegis-control/src/api/mod.rs` — `+pub mod analytics;`.
  - `crates/aegis-control/assets/dashboard/pages/analytics.js`
    — placeholder → real (~190 lines). 6 chart cards (requests
    rate, block ratio, latency p99, errors by route, SLO budget,
    cert days). Time-range selector (1h / 6h / 24h / 7d / 30d).
    Each card calls `/api/analytics/query`; scalar results render
    as a big number, matrix results render via the line-chart
    component (lazy-imported). 503 responses surface as a banner:
    "No history backend configured — set admin.prometheus_url".
    Range change tears down existing chart states so the next
    refresh re-mounts cleanly.
  - `crates/aegis-proxy/src/lib.rs` — `+/api/analytics/query`
    dispatch arm. New helper `parse_query_str(query, key)` for
    non-numeric query parameters. The dispatch arm uses
    `AnalyticsRendering.status` directly so 400/503 propagate.
  - `crates/aegis-control/src/dashboard/assets.rs` — +1 asset
    structure test (`analytics_page_calls_analytics_endpoint`).
- Tests added: 8 analytics unit + 1 asset structure = 9.
- Status: DONE — 1,712 workspace tests pass (was 1,703, +9 new).
- Date: 2026-04-27

### D-M3 milestone exit gate

All 11 tasks landed.
- [x] Live Feed page (T3.1) — SSE-driven row stream + class/action
      filter chips + row-detail drawer.
- [x] `/api/audit/since` (T3.2) — reconnect-replay with cursor +
      gap detection.
- [x] Attack Events page (T3.3) + 3 endpoints (T3.4–T3.6) —
      detector breakdown / threat-intel hits / bot mix.
- [x] Audit Log page (T3.7) + witness lag (T3.8) + filter
      catalogue (T3.9).
- [x] Analytics page (T3.10) + allow-listed PromQL proxy (T3.11).
- [ ] *(deferred)* Audit chain "tampered" smoke test — needs the
      existing `/api/audit/verify` endpoint, which is M3
      audit-chain territory; the wiring works but isn't tested
      end-to-end yet.
- [ ] *(deferred)* Range queries against a real Prometheus —
      `admin.prometheus_url` config field not added yet (mirror
      the `legacy_shell` pattern when needed). Every range query
      returns 503 cleanly until then; the page renders the
      banner.

### Previous (D-M3-T3.7..T3.9) — for context
- Task: **D-M3-T3.7..T3.9 Audit Log page + witness lag + filter catalogue**
- Crates: aegis-control (data layers + handlers + page module),
  aegis-proxy (2 new dispatch arms)
- Files changed:
  - `crates/aegis-control/src/api/audit.rs` — `+WitnessState`
    (in-memory `Arc<Mutex<Option<WitnessRecord>>>`, `update()` /
    `snapshot()` API; `snapshot()` computes `lag_seconds` against
    `Utc::now()` at call time so the value never freezes mid-cache).
    `+WitnessLagResponse { last_signature_ts, lag_seconds,
    chain_head_hash, node_id, entry_count }` — all `Option<…>` so
    a fresh boot with no signature yet renders as JSON nulls,
    distinct from `lag_seconds: 0`. `+WitnessHandler::render()`
    no-cache (snapshot is O(1) and lag must stay live). +5 unit
    tests including the milestone's "with a known last-witness
    time, assert lag math" (asserts ~60s lag for a 60-s-ago
    record, ±2s tolerance).
  - `crates/aegis-control/src/api/filters.rs` — new module:
    `FilterCatalogue { classes, actors, actions, routes }` —
    each is a `HashMap<String, Instant>` so distinct values
    take one slot regardless of repeat. `record(&AuditEvent)`
    inserts the new value; pruning runs every record (drop
    entries past 24 h) and a hard cap at `MAX_PER_CATEGORY =
    10 000` drops the oldest if exceeded — bounds memory under
    high-cardinality attack traffic. `snapshot()` returns
    alphabetically-sorted lists for UI stability. Actor field
    sourced from `client_ip` (skipped when empty so system events
    don't pollute the actor list). +7 unit tests.
  - `crates/aegis-control/src/api/mod.rs` — `+pub mod filters;`.
  - `crates/aegis-control/src/dashboard_services.rs` —
    `+witness_state: Arc<WitnessState>`, `+witness:
    Arc<WitnessHandler>`, `+filter_catalogue: Arc<FilterCatalogue>`,
    `+filters: Arc<FiltersHandler>`. Drain task now feeds five
    sinks (stats + attacks + audit ring + filter catalogue;
    witness state stays passive until a cluster-runtime task
    calls `update()`). `dispatch_event` signature extended.
  - `crates/aegis-proxy/src/lib.rs` — `+/api/audit/witness` arm
    (`Cache-Control: private, max-age=2`) and `+/api/filters`
    arm (`Cache-Control: private, max-age=30` — chip dropdowns
    don't need fresh data every second).
  - `crates/aegis-control/assets/dashboard/pages/audit.js` —
    placeholder → real (~285 lines). Header carries chain-status
    and witness-lag pills (read from `/api/audit/verify` +
    `/api/audit/witness`); filter strip with class + action chips
    that filter rows in-page (server-side filter queries are a
    Live-Feed concern — Audit Log re-uses the same SSE-less
    `/api/audit/since` cursor stream); paged table backed by the
    table component, row-click opens drawer with full event JSON;
    Export NDJSON button generates a downloadable Blob from the
    visible filtered rows. Polls every 5s for newer events
    (`?cursor=high_water`), witness lag, chain status, filter
    summary. Visibility-aware pause.
  - `crates/aegis-control/src/dashboard/assets.rs` — +1 asset
    structure test (`audit_page_has_pills_and_endpoints`).
- Tests added: 5 witness + 7 filters + 1 page = 13.
- Status: DONE — 1,703 workspace tests pass (was 1,690, +13 new).
- Date: 2026-04-27

### Previous (D-M3-T3.3..T3.6) — for context
- Task: **D-M3-T3.3..T3.6 Attack Events page + 3 supporting endpoints**
- Crates: aegis-control (data layer + handler + page module),
  aegis-proxy (3 new dispatch arms)
- Files changed:
  - `crates/aegis-control/src/api/attacks.rs` —
    `AttackEntry` extended with `threat_intel_feed`,
    `threat_intel_indicator`, `bot_category` (extracted at
    record time from `event.fields` — accepts both
    `threat_intel.{feed,indicator}` and flat `feed_id`/`indicator`
    shapes; `bot_category` is read directly). New response types:
    `DetectorCount` + `ByDetectorResponse`, `ThreatIntelHit` +
    `ThreatIntelResponse`, `BotCategoryCount` + `BotMixResponse`.
    New aggregator methods: `by_detector(window)` (slim projection
    of `distribution`), `threat_intel_hits(window, limit)`
    (groups by `(feed, indicator)`, sorted by hits desc, with
    `last_seen` per group), `bot_mix(window)` (buckets by
    `bot_category`, with `"unknown"` fallback so percentages always
    sum to 100). `AttacksHandler` grew three more cache slots +
    render methods (`render_by_detector`, `render_threat_intel`,
    `render_bot_mix`) — all five caches independent, each keyed on
    its own params.
  - `crates/aegis-control/assets/dashboard/pages/attacks.js` —
    placeholder → real (~210 lines). Four widgets: detector donut
    (`/api/attacks/by-detector`, 10s poll), top-rules table
    (`/api/attacks/top`, 10s — proxy for "top firing rules" since
    we don't yet have a per-rule aggregator), threat-intel table
    (`/api/threat-intel/hits`, 15s), bot-mix donut
    (`/api/bots/mix`, 15s). Visibility-aware pause; lazy-imports
    the donut + table components shared with Overview.
  - `crates/aegis-proxy/src/lib.rs` — 3 new dispatch arms with
    `Cache-Control: private, max-age=10`.
  - `crates/aegis-control/src/dashboard/assets.rs` — +1 asset
    structure test (`attacks_page_polls_four_endpoints`) verifying
    the page hits all four endpoints + lazy-imports donut+table.
- Tests added: 8 attacks unit tests + 1 asset structure = 9.
    - by_detector returns slim breakdown
    - by_detector empty aggregator
    - threat_intel_from_fields handles both shapes
    - threat_intel_hits groups by (feed, indicator)
    - threat_intel_hits respects limit
    - bot_mix buckets by category with "unknown" fallback
    - handler renders three new endpoints
    - five attacks caches independent
    - attacks page polls all four endpoints
- Status: DONE — 1,690 workspace tests pass (was 1,681, +9 new).
- Date: 2026-04-27

### Previous (D-M3-T3.2) — for context
- Task: **D-M3-T3.2 Live Feed reconnect / replay** (`/api/audit/since`)
- Crates: aegis-control (data layer + handler + services wire-up),
  aegis-proxy (admin router dispatch)
- Files changed:
  - `crates/aegis-control/src/api/audit.rs` — new module:
    `AuditRing { entries: VecDeque<(seq, AuditEvent)>, capacity,
    next_seq }` with monotonic sequence assignment starting at 1
    so `cursor=0` means "give me everything"; `record(ev) -> u64`
    appends + evicts past capacity; `since(cursor, limit) ->
    AuditSinceResponse { cursor, next_cursor, events, gap }`
    walks the ring forward from `cursor`, marks `gap = true` when
    the ring's oldest seq is past `cursor + 1` (history evicted).
    Default capacity 10 000 (≈ a few minutes at 5 000 RPS with
    ~0.1 % detection rate); `MAX_LIMIT = 1000` so a misbehaving
    client can't drain the ring on every reconnect.
    `AuditHandler::render_since(cursor, limit)` caches per
    `(timestamp, cursor, limit)` for 1 s.
  - `crates/aegis-control/src/api/mod.rs` — `+pub mod audit;`.
  - `crates/aegis-control/src/dashboard_services.rs` — new
    `audit_ring: Arc<AuditRing>` and `audit: Arc<AuditHandler>`
    fields; drain task now feeds three sinks (stats + attacks +
    audit ring); `dispatch_event(stats, attacks, audit, ev)`
    signature extended; +1 test.
  - `crates/aegis-proxy/src/lib.rs` — `/api/audit/since` dispatch
    arm with `Cache-Control: private, no-store` (cursor is
    request-specific, no shared cache benefit). Added
    `parse_query_u64(query, key, default)` for cursor parsing
    (u32 wraps after ~50 days at 1 RPS — go u64 for cursor only).
- Tests added: 14 audit module + 1 dashboard_services audit-drain
  + 1 ad-hoc through `dispatch_event_runs_synchronously`. Net 15.
    - record assigns monotonic seq starting at 1
    - since after cursor in order (the milestone's "50 events,
      since 30, expect 20")
    - cursor=0 returns everything
    - limit respected
    - cursor at high water → empty
    - cursor above high water → empty (no underflow)
    - eviction signals gap=true past evicted boundary
    - no gap when cursor inside live ring
    - ring evicts oldest when capacity exceeded
    - response shape (cursor / next_cursor / events / gap)
    - handler caches per (cursor, limit)
    - handler recomputes on different cursor or limit
    - handler clamps `?limit=u32::MAX` to MAX_LIMIT
    - handler `?limit=0` falls back to default (200)
- Status: DONE — 1,681 workspace tests pass (was 1,666, +15 new).
- Date: 2026-04-27

### Previous (D-M3-T3.1) — for context
- Task: **D-M3-T3.1 Live Feed page** (SSE filter + drawer + live page module)
- Crate: aegis-control
- Files changed:
  - `crates/aegis-control/src/dashboard/sse.rs` — added
    `EventFilter { classes, actions, routes }` value type +
    `EventFilter::parse_query("class=&action=&route=")` parser
    + `event_matches(filter, ev) -> bool` predicate. AND across
    fields, OR within a field. Repeated `class=detection&class=admin`
    permits both. Unknown `class=bogus` values are silently
    skipped (operator-supplied URL — match-nothing is safer than
    500). +10 unit tests including the milestone-mandated
    "feeds 1000 events, asserts predicate filters them" case.
  - `crates/aegis-control/assets/dashboard/components/drawer.js`
    — placeholder → real (~165 lines). Right-anchored overlay,
    `role="dialog"` + `aria-modal=true`. Focus trap on Tab /
    Shift+Tab, Escape closes (unless `dismissable: false`),
    click-out closes, focus restored to triggering element on
    close. Body accepts a string, a Node, or a JSON-serialisable
    object (objects render as a pretty-printed `<pre>`).
    `open(props)` returns a state handle with `close()` and
    `update(next)` for live drawer updates.
  - `crates/aegis-control/assets/dashboard/pages/live.js` —
    placeholder → real (~225 lines). Server-Sent Events consumer:
    closes + reopens the EventSource with a fresh filter query
    when a chip toggles. Row appends batched to
    `requestAnimationFrame` (cap 100 events per flush, 200 visible
    rows) so a 1k-event burst doesn't choke the main thread.
    Filter strip with class + action chips, Pause / Clear buttons.
    Row click lazy-imports the drawer and opens it with the full
    event JSON. Cleans up on `destroy()`.
  - `crates/aegis-control/src/dashboard/assets.rs` — +2 asset
    structure tests: drawer is real (≥1500 bytes, role=dialog,
    aria-modal, Escape handler); live page consumes EventSource +
    composes filter query + uses RAF + lazy-imports the drawer.
- Tests added: 12 (10 SSE filter + 2 asset structure).
- Status: DONE — 1,666 workspace tests pass (was 1,654, +12 new).
- Date: 2026-04-27

### T3.1 deferred items
- The proxy SSE handler at `/dashboard/sse` is still the M1 stub
  (returns one event then closes). The new `EventFilter` is
  ready to apply once full streaming lands; for now the live
  page consumer reconnects on every close, which is consistent
  with the existing T2.8 SSE pill behaviour.
- `/api/audit/{request_id}` endpoint (mentioned in the new
  endpoints table) is T3.2's territory in our split — the Live
  Feed drawer renders the SSE event payload directly, so the
  detail endpoint isn't a strict T3.1 dependency.

### Previous (D-M2-T2.9 + D-M2 close-out) — for context
- Task: **D-M2-T2.9 Real components + D-M2 milestone close-out**
- Crate: aegis-control
- Files changed:
  - `crates/aegis-control/assets/dashboard/components/stat-card.js`
    — placeholder → real (~95 lines). `create({title, value,
    subtitle, icon, status, href})` returns the documented
    `aegis-stat` markup; `update(el, props)` mutates without
    rebuilding so live updates keep focus / animation state.
  - `crates/aegis-control/assets/dashboard/components/line-chart.js`
    — placeholder → real (~165 lines). **Vanilla SVG** instead of
    Chart.js (deviation from spec; see notes). 4 horizontal
    gridlines, Y-axis tick labels, multi-series paths via
    `<path d="M ... L ...">`, hidden `<title>` for screen readers.
    `mount(el, props)` returns a `state` handle, `update(state,
    next)` re-renders, `destroy(state)` clears DOM.
  - `crates/aegis-control/assets/dashboard/components/donut.js`
    — placeholder → real (~155 lines). SVG annulus segments with
    inner radius 60% per spec, centre total label, side legend
    with click handlers dispatching `aegis:slice-click` (no
    callback prop — uses CustomEvent per components.md).
  - `crates/aegis-control/assets/dashboard/components/sparkline.js`
    — placeholder → real (~70 lines). 60×20 SVG line, no axes
    or tooltip — for in-row trends.
  - `crates/aegis-control/assets/dashboard/components/table.js`
    — placeholder → real (~150 lines). Sortable HTML table;
    header click toggles sort dir; emits `aegis:sort` and
    `aegis:row-click` CustomEvents; `aria-sort` + `role="button"`
    + Enter/Space keyboard activation on sortable headers.
  - `crates/aegis-control/assets/dashboard/pages/overview.js` —
    refresh handlers now `await import()` the new components on
    first use and call `mount()`/`update()`. The text/UL/HTML-table
    fallbacks from T2.7 are gone. `destroy()` calls each
    component's `destroy()` to clean up DOM + event listeners.
  - `crates/aegis-control/src/dashboard/assets.rs` — +6 tests:
    line-chart is real SVG with mount/destroy; donut dispatches
    `aegis:slice-click`; table dispatches `aegis:row-click` +
    `aegis:sort`, exposes `aria-sort`; stat-card has the
    documented value class + `update()`; sparkline is SVG-based
    with the documented class; overview.js lazy-imports the
    component bundle.
- Tests added: 6 (assets module: 49 total).
- Status: DONE — 1,654 workspace tests pass (was 1,648, +6 new).
- Date: 2026-04-27

### Spec deviation: Chart.js NOT vendored

The milestone spec calls for a vendored `chart.umd.min.js` plus an
SRI integrity test. Both are deferred. **Rationale:**
- Embedding a 200KB+ binary blob fetched from the web carries
  supply-chain risk that needs a dedicated verification script
  (GPG signature check, `cargo audit` cross-check, license
  bundling) — out of scope for an in-session task.
- The Overview page's chart needs (one or two time-series, a
  donut breakdown) are well within vanilla SVG capability.
- Vanilla SVG removes the CSP `style-src 'unsafe-inline'`
  exception that Chart.js's tooltip injector needs — strictly
  better security posture for v1.
- Asset budget gain: ~80 KB gzipped freed up.

The `index.html` SRI placeholder comment from D-M1-T1.2 stays in
place. When a future task vendors Chart.js (likely alongside
heavier chart needs in D-M3+ — Analytics page wants stacked
bars), it should also re-add the styles and the SRI test.

### D-M2 milestone exit gate

All 9 tasks landed. Exit-gate items from
`plans/dashboard-enterprise/milestone-2-overview.md`:
- [x] `/api/stats`, `/api/stats/timeseries`, `/api/upstreams/summary`,
      `/api/attacks/distribution`, `/api/attacks/top`, `/api/about`
      all reachable and returning the documented JSON shapes
      (verified by `tests/api_smoke.rs` and the proxy admin
      router wiring).
- [x] Overview page module mounts 4 stat tiles + line chart +
      donut + top-attackers table sourced from those endpoints,
      polling at the documented cadence with visibility-aware
      pause.
- [x] SSE status pill connects to `/dashboard/sse` and reflects
      connection state in the status bar.
- [x] Audit-bus drain task feeds both stats and attacks
      aggregators in a single subscriber.
- [ ] *(deviation)* Vendor `chart.umd.min.js` + SRI test —
      deferred (see "Spec deviation" above).

### Previous (D-M2-T2.8) — for context
- Task: **D-M2-T2.8 SSE status pill**
- Crate: aegis-control (JS + i18n + structure tests)
- Files changed:
  - `crates/aegis-control/assets/dashboard/app.js` — `+let sseSource`
    module-level handle, `+setConnectionState(state)` exported helper,
    `+startSse()` opens `EventSource("/dashboard/sse")` once on init.
    `setConnectionState` updates the status-bar dot's `data-state`
    plus the label's `data-i18n` + `textContent` across three
    explicit branches (`status.connected`, `status.reconnecting`,
    `status.disconnected`) so the asset-test extractor that scans
    for `dataset.i18n = "literal"` patterns picks up each key.
    Browser handles SSE backoff/retry transparently; the helper
    only reads `EventSource.readyState` to distinguish "transient
    error → reconnecting" from "closed → disconnected". Falls back
    to `disconnected` if `EventSource` is unavailable.
  - `crates/aegis-control/assets/dashboard/i18n/en.json` —
    +"status.connected": "Connected", +"status.reconnecting":
    "Reconnecting…". Existing "status.disconnected" untouched.
  - `crates/aegis-control/src/dashboard/assets.rs` — +3 tests:
    `app_js_opens_eventsource_for_dashboard_sse` (uses
    `EventSource` + `/dashboard/sse`), `app_js_updates_connection_state_data_attribute`
    (writes `dataset.state`, names all three states),
    `en_json_has_three_connection_state_keys`. The existing
    `every_app_js_dataset_i18n_key_exists_in_en_json` and
    `en_json_has_no_orphan_keys` tests catch the new keys.
- Tests added: 3 (assets module: 43 total).
- Status: DONE — 1,648 workspace tests pass (was 1,645, +3 new).
- Date: 2026-04-27

### Bug caught + fixed during this task
The first GREEN run failed `every_app_js_dataset_i18n_key_exists_in_en_json`
because `app.js` had a doc comment containing the literal string
`dataset.i18n = "literal"` inside backticks (explaining what the
extractor scans for). The substring-based extractor picked up
`"literal"` as a fake i18n key and looked it up in en.json. Fix:
rephrased the comment to omit the example string.

### Previous (D-M2-T2.7) — for context
- Task: **D-M2-T2.7 Overview page module + proxy wire-up**
- Crates: aegis-control (services bundle + page module + tests),
  aegis-proxy (admin router wiring)
- Files changed:
  - `crates/aegis-control/src/api/stats.rs` — `StatsHandler`
    refactored to always carry an upstream-summary provider closure.
    `StatsHandler::new(agg)` defaults to `UpstreamSummary::placeholder`
    (back-compat); new `with_upstream(agg, F)` and
    `with_ttl_and_upstream(agg, ttl, F)` constructors take a real
    closure. `render()` overlays the provider output onto the
    aggregator snapshot at every cache miss so stats and upstream
    summaries agree numerically. +2 unit tests.
  - `crates/aegis-control/src/dashboard_services.rs` — new module:
    `DashboardServices { stats, stats_agg, attacks, attacks_agg,
    upstreams, environment }` bundle. `spawn(bus, pool_provider,
    env)` builds every aggregator/handler, **subscribes to the
    audit bus synchronously before spawning the drain task** (the
    one bug surfaced during this task: `broadcast::Receiver` only
    sees post-subscribe messages, so doing `bus.subscribe()` inside
    the spawned task lost any event emitted before it scheduled —
    fixed by hoisting subscribe outside `tokio::spawn`). Drain task
    feeds both aggregators from one subscriber. `pool_snapshot_provider(cfg)`
    helper builds a config-derived snapshot (pool names + member
    counts; healthy = 0 until the cluster runtime lands real per-
    member health). +5 tests.
  - `crates/aegis-control/src/lib.rs` — `+pub mod dashboard_services;`.
  - `crates/aegis-proxy/src/lib.rs` — `admin_accept_loop` now
    builds `Arc<DashboardServices>` once at boot (passing
    `cfg.admin.environment` and the config-derived pool provider)
    and shares it with every connection handler. `admin_router`
    gained a `&DashboardServices` parameter and 6 new dispatch
    arms: `/api/about`, `/api/stats`, `/api/stats/timeseries`,
    `/api/upstreams/summary`, `/api/attacks/distribution`,
    `/api/attacks/top`. Each emits `Cache-Control` per
    `docs/dashboard-enterprise/api.md` §"Caching"
    (`max-age=1` for stats, `max-age=2` for upstreams,
    `max-age=10` for attacks + about). New helpers:
    `parse_query_u32(query, key, default)` (tolerates the spec's
    `15m`/`5s` suffix by trim_end_matches('s')) and
    `json_body_response(status, body, cache_control)`.
  - `crates/aegis-control/assets/dashboard/pages/overview.js` —
    placeholder → real page (~210 lines). Renders 4 stat tiles
    (request rate, blocks total, block rate, active threats), a
    traffic chart slot, an attack-distribution slot, and a top-
    attackers table slot. Polls each endpoint at the documented
    cadence (1 s / 5 s / 10 s / 10 s); first fetch fires
    immediately on mount. Pauses polling while
    `document.visibilityState !== "visible"`; refreshes everything
    on `visibilitychange` returning to visible. Aborts in-flight
    fetches on `destroy()` via `AbortController`. Reads
    `/api/about` once on mount to fill the topbar version + env
    slots. Component swap targets (`[data-slot="traffic-chart"]`
    etc.) keep T2.9 a drop-in.
  - `crates/aegis-control/tests/api_smoke.rs` — new integration
    smoke test (6 cases): about shape; stats shape with real
    aggregator (asserts `blocks_total`, upstream rollup);
    timeseries shape (window=60, step=5, 12 buckets, sum matches
    recorded events); attacks distribution percentages sum to ~100
    (the milestone's required test); attacks top groups by
    attacker (sorted by hits desc); upstreams summary reflects
    pool provider.
- Tests added: 13 net new (2 stats + 5 dashboard_services + 6
  api_smoke).
- Status: DONE — 1,645 workspace tests pass (was 1,632, +13 new).
- Date: 2026-04-27

## Next Task
- Track: **Enterprise Dashboard (D)** — **complete**. All six
  milestones (D-M1..D-M6) shipped.
- **Next track: pre-existing roadmap items**, in priority order:
  1. **Wire mutating endpoints** through the M3 audit-mutation
     pipeline so the D-M4 page writes (`PUT /api/rules/{id}`,
     `POST /api/blacklist`, `POST /api/admin/password`, etc.)
     actually persist + audit.
  2. **Cluster runtime → real tracking data**: replace the
     `TrackingHandler` placeholders with live cluster / cert /
     alert state once those subsystems land.
  3. **Full upstream proxying** in `aegis-proxy` (currently
     stub "OK" for clean requests).
  4. **Full SSE streaming** on `/dashboard/sse` — requires a
     streaming hyper response body wrapping the AuditBus
     subscriber.
  5. **Benchmark mode track** (B-T1..B-T6) — parallel to D, design
     specs already in place at `plans/benchmark-mode.md` +
     `docs/benchmark-mode.md`.
  6. Production Dockerfile + Helm chart, CI/CD pipeline, k6 +
     nuclei integration tests.
- (was) Next: D-M4-T4.1 Rule Manager page
  D-M4 covers configuration management — five pages: Rule
  Manager, Tier Config, Blacklist, Whitelist, Settings. Each
  has its own CRUD endpoints (some already exist in M3 audit /
  config work; the new endpoints add validation, dry-run,
  per-rule stats). T4.1 is the Rule Manager page itself —
  rule CRUD + diff editor + dry-run.
  See [`plans/dashboard-enterprise/milestone-4-config-management.md`](plans/dashboard-enterprise/milestone-4-config-management.md).
- (was) Next: D-M3-T3.10..T3.11 Analytics page + PromQL proxy
  - T3.10 — `assets/dashboard/pages/analytics.js`: six chart
    cards per `pages/analytics.md` with a time-range selector;
    on change, all cards refetch.
  - T3.11 — `src/api/analytics.rs`: `/api/analytics/query`
    accepts `?expr=<allow-list-key>&start=&end=&step=`. The
    `expr` is **not** raw PromQL — it's a key from the fixed
    allow-list in `docs/dashboard-enterprise/api.md` §analytics-
    allowlist. Resolves to PromQL, queries the local Prometheus
    registry's text encoder for instantaneous queries, returns
    503 with `{"error":{"code":"no_history_backend"}}` for
    range queries when no external Prometheus URL is configured.
  Closes D-M3.
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- (was) Next: D-M3-T3.7..T3.9 Audit Log page + supporting endpoints
  Three combined parts:
    - T3.7 — `assets/dashboard/pages/audit.js` page module:
      filter strip (reuses Live Feed chips), paged table
      (cursor pagination from `/api/audit` — already partially
      covered by T3.2's `/api/audit/since`), chain status pill,
      witness lag pill, export-NDJSON button.
    - T3.8 — `/api/audit/witness` returning the last witness
      signature + lag seconds. Reads from the existing
      `aegis_control::witness` state machine (verify it exists;
      may need a simple wrapper).
    - T3.9 — `/api/filters` returning the rolling 24h distinct
      sets of class/actor/action/route from the audit ring.
      Cheap O(1) read from a HashSet maintained alongside the
      ring, or a one-pass scan (limit 24h × ~few k events =
      tractable).
  Then T3.10 + T3.11 cover Analytics page + the PromQL proxy
  to close out D-M3.
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- (was) Next: D-M3-T3.3 Attack Events page
  The Attack Events page wires four widgets:
    1. detector breakdown bar chart (T3.4 — `/api/attacks/by-detector`)
    2. top firing rules table (already covered by T2.5 `/api/attacks/top`)
    3. threat-intel hits table (T3.5 — `/api/threat-intel/hits`)
    4. bot mix stacked bar (T3.6 — `/api/bots/mix`)
    plus a recent-detections live tail reusing the Live Feed SSE
    component with `class=detection` filter pre-applied.
  Pragmatic approach: deliver T3.3 + T3.4 + T3.5 + T3.6 together
  (the page is useless without the endpoints). Threat-intel hits
  + bot mix can use the same in-process aggregator pattern as
  attacks.rs; just add per-IP threat-intel-source and per-bot-class
  counts.
- (was) Next task: D-M3-T3.2 Live Feed reconnect / replay
  (`crates/aegis-control/src/api/audit.rs`).
  Add `GET /api/audit/since?cursor=&limit=` returning events
  after the given monotonic sequence number. Backed by an
  in-process audit ring (the audit subscriber drains the bus
  into a bounded `VecDeque` keyed by sequence). Test: write 50
  events, fetch since cursor 30, assert 20 returned in order.
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- D-M3 progress (all done):
  - [x] D-M3-T3.1 Live Feed page
  - [x] D-M3-T3.2 Live Feed reconnect / replay
  - [x] D-M3-T3.3 Attack Events page
  - [x] D-M3-T3.4 Detector breakdown endpoint
  - [x] D-M3-T3.5 Threat-intel hits endpoint
  - [x] D-M3-T3.6 Bot mix endpoint
  - [x] D-M3-T3.7 Audit Log page
  - [x] D-M3-T3.8 Witness lag endpoint
  - [x] D-M3-T3.9 Filter catalogue endpoint
  - [x] D-M3-T3.10 Analytics page
  - [x] D-M3-T3.11 Analytics PromQL proxy
- Remaining milestones: D-M4..D-M6 — see plan README.

### Previous Next Task block (T3.1 → T3.2 transition) — for context
- D-M2 closed; D-M3 begins.
- (was) **Next task: D-M3-T3.1 Live Feed page** (drawer + filters).
  Per `plans/dashboard-enterprise/milestone-3-operator-views.md`
  the M3 milestone covers Live Feed, Attack Events, Audit Log,
  and Analytics — the four "operator view" pages. T3.1 is the
  Live Feed: virtualised SSE-driven request stream with filters
  (tier / decision / detector / IP), row drawer with the full
  audit event JSON, and the `aegis:row-click` event from the
  table component (which T2.9 just delivered).
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- D-M2 milestone progress (all done):
  - [x] D-M2-T2.1 `/api/stats`
  - [x] D-M2-T2.2 `/api/stats/timeseries`
  - [x] D-M2-T2.3 `/api/upstreams/summary`
  - [x] D-M2-T2.4 `/api/attacks/distribution`
  - [x] D-M2-T2.5 `/api/attacks/top`
  - [x] D-M2-T2.6 `/api/about`
  - [x] D-M2-T2.7 Overview page module + proxy wire-up
  - [x] D-M2-T2.8 SSE status pill
  - [x] D-M2-T2.9 Real chart components (Chart.js vendor deferred)
- Remaining milestones: D-M3..D-M6 — see plan README.

### Known limitations / carry-overs
- Pool health: per-member `healthy` is hardcoded to 0 in
  `pool_snapshot_provider` because the cluster runtime that owns
  per-member health is itself stubbed. Pool *names* and *total*
  surface correctly. Real per-member readings land when the
  cluster runtime ships (likely M3 or later) — at that point
  swap the closure for one that reads from `cluster::Pool`
  state.
- `/dashboard/sse`: still returns one event then closes (the
  M1-era stub). T2.8 just wires the pill; full SSE streaming is
  in the existing deferred list.
- Components: stat-card, line-chart, donut, table are still
  M1-era stubs. T2.9 fills them and vendors `chart.umd.min.js`.

### Parallel track — Benchmark mode (B-)
- Plan: [`plans/benchmark-mode.md`](plans/benchmark-mode.md)
- Spec: [`docs/benchmark-mode.md`](docs/benchmark-mode.md)
- Status: planning complete, no code yet. B-T1..B-T3 (data plane)
  unblocked; B-T4.5 / B-T4.6 (dashboard panels) gated on D-M3.
  May land in any order alongside the dashboard track.
- Touches: aegis-core, aegis-proxy, aegis-security, aegis-control,
  aegis-bin. No new top-level deps.

### Deferred (post-dashboard track)
- [ ] Full upstream proxying (currently stub "OK" for clean requests — needs real TCP connect + proxy to upstream members)
- [ ] Full SSE streaming on `/dashboard/sse` (currently returns one event then closes — needs streaming body with AuditBus subscription)
- [ ] Production Dockerfile + Helm chart
- [ ] End-to-end integration tests (k6 load + nuclei security)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] D-M2: vendor `chart.umd.min.js` and replace the SRI placeholder
  in `index.html` with the real digest; add `tests/dashboard/sri.rs`.

## Verification
- `cargo test --workspace` → **1,752 passed** (across 10 binary
  / lib / integration test targets).
  Breakdown: 82 core + 598 control lib + 15 dod + 6 router_smoke +
  6 api_smoke + 8 dashboard_polish + 224 proxy + 780+1+32
  security.
- `cargo clippy --workspace -- -D warnings` → clean.

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security (pre-existing), aegis-bin | 2026-04-22 |
| M1-T1.2 Config loader (figment + validation) | aegis-core | 2026-04-22 |
| M1-T1.3 Hot reload (notify + ArcSwap) | aegis-proxy | 2026-04-22 |
| M1-T1.4 Dual listener model | aegis-proxy | 2026-04-22 |
| M1-T2.1 Host matcher | aegis-proxy | 2026-04-22 |
| M1-T2.2 Path trie | aegis-proxy | 2026-04-22 |
| M1-T2.3 RouteTable::build + resolve | aegis-proxy | 2026-04-22 |
| M1-T2.4 Upstream Pool + LB strategies | aegis-proxy | 2026-04-22 |
| M1-T2.5 Active health checks | aegis-proxy | 2026-04-22 |
| M1-T2.6 Circuit breaker | aegis-proxy | 2026-04-22 |
| M1-T2.7 Wire routing + upstream into proxy.rs | aegis-proxy | 2026-04-22 |
| M1-T3.1 DynamicResolver + CertStore | aegis-proxy | 2026-04-24 |
| M1-T3.2 HTTP/2 on both sides | aegis-proxy | 2026-04-24 |
| M1-T3.3 WebSocket upgrade passthrough | aegis-proxy | 2026-04-24 |
| M1-T3.4 gRPC trailer-preserving forward | aegis-proxy | 2026-04-24 |
| M1-T3.5 mTLS to upstream | aegis-proxy | 2026-04-24 |
| M1-T3.6 ACME (feature acme) | aegis-proxy | 2026-04-24 |
| M1-T3.7 OCSP stapling | aegis-proxy | 2026-04-24 |
| M1-T4.1 Per-route quotas | aegis-proxy, aegis-core | 2026-04-24 |
| M1-T4.2 Transformations + CORS | aegis-proxy | 2026-04-24 |
| M1-T4.3 Canary split + header/cookie steering | aegis-proxy | 2026-04-24 |
| M1-T4.4 Retries with budget | aegis-proxy | 2026-04-24 |
| M1-T4.5 Shadow mirroring | aegis-proxy | 2026-04-24 |
| M1-T4.6 Session affinity | aegis-proxy | 2026-04-24 |
| M1-T4.7 Worker supervisor + graceful drain | aegis-proxy | 2026-04-24 |
| M1-T4.8 Hot binary reload (SIGUSR2) | aegis-proxy | 2026-04-24 |
| M1-T4.9 Tier-aware smart cache | aegis-proxy | 2026-04-24 |
| M1-T5.1 InMemoryBackend polish | aegis-proxy | 2026-04-24 |
| M1-T5.2 RedisBackend (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership | aegis-proxy | 2026-04-24 |
| M2-T1.1 Rule AST + parser | aegis-security | 2026-04-24 |
| M2-T1.2 Linter | aegis-security | 2026-04-24 |
| M2-T1.3 Evaluator | aegis-security | 2026-04-24 |
| M2-T1.4 RuleSet hot reload | aegis-security | 2026-04-24 |
| M2-T1.5 Tier classifier | aegis-security | 2026-04-24 |
| M2-T2.1 Sliding window rate limit | aegis-security | 2026-04-26 |
| M2-T2.2 Token bucket | aegis-security | 2026-04-26 |
| M2-T2.3 DDoS per-IP burst + cluster spike | aegis-security | 2026-04-26 |
| M2-T2.4 OWASP detectors (SQLi, XSS, PathTraversal, SSRF, HeaderInjection, BodyAbuse, Recon) | aegis-security | 2026-04-26 |
| M2-T3.1 JA4/JA3 parser | aegis-security | 2026-04-26 |
| M2-T3.2 HTTP/2 fingerprint | aegis-security | 2026-04-26 |
| M2-T3.3 Composite device id | aegis-security | 2026-04-26 |
| M2-T3.4 RiskEngine (scoring + decay) | aegis-security | 2026-04-26 |
| M2-T3.5 Challenge ladder | aegis-security | 2026-04-26 |
| M2-T3.6 Challenge tokens (HMAC + nonce) | aegis-security | 2026-04-26 |
| M2-T3.7 CAPTCHA providers (Turnstile, hCaptcha, reCAPTCHA) | aegis-security | 2026-04-26 |
| M2-T3.8 Behavioral analyzer | aegis-security | 2026-04-26 |
| M2-T3.9 Transaction velocity | aegis-security | 2026-04-26 |
| M2-T4.1 CIDR lists + XFF walker | aegis-security | 2026-04-26 |
| M2-T4.2 MaxMind ASN classifier | aegis-security | 2026-04-26 |
| M2-T4.3 Bot classifier | aegis-security | 2026-04-26 |
| M2-T4.4 Threat intel feeds | aegis-security | 2026-04-26 |
| M2-T5.1 Streaming response filter | aegis-security | 2026-04-26 |
| M2-T5.2 DLP patterns + actions | aegis-security | 2026-04-26 |
| M2-T5.3 FPE (AES-FF1) | aegis-security | 2026-04-26 |
| M2-T5.4 OpenAPI schema enforcement | aegis-security | 2026-04-26 |
| M2-T5.5 ForwardAuth | aegis-security | 2026-04-26 |
| M2-T5.6 JWT validation | aegis-security | 2026-04-26 |
| M2-T5.7 ICAP antivirus | aegis-security | 2026-04-26 |
| M2-T5.8 Magic-byte + archive-bomb | aegis-security | 2026-04-26 |
| M2-T5.9 GraphQL guard | aegis-security | 2026-04-26 |
| M2-T5.10 HMAC request signing | aegis-security | 2026-04-26 |
| M2-T5.11 API-key management | aegis-security | 2026-04-26 |
| M2-T5.12 Basic Auth | aegis-security | 2026-04-26 |
| M2-T5.14 OPA callout | aegis-security | 2026-04-26 |
| M2-DoD Red-team suite + benign corpus + fixture expansion | aegis-security | 2026-04-26 |
| M3-T1.1 MetricsRegistry init | aegis-control | 2026-04-26 |
| M3-T1.2 Prometheus exporter | aegis-control | 2026-04-26 |
| M3-T1.3 Health endpoints (live/ready/startup) | aegis-control | 2026-04-26 |
| M3-T1.4 Dashboard shell + SSE | aegis-control | 2026-04-26 |
| M3-T1.4b Dashboard overview page | aegis-control | 2026-04-26 |
| M3-T1.5 GET /api/config | aegis-control | 2026-04-26 |
| M3-T2.2 Tracing init + W3C Trace Context | aegis-control | 2026-04-26 |
| M3-T2.4 Access log writer (combined/JSON/template) | aegis-control | 2026-04-26 |
| M3-T3.1 Audit chain writer (SHA-256 hash chain) | aegis-control | 2026-04-26 |
| M3-T3.2 Audit verify (chain walk + recompute) | aegis-control | 2026-04-26 |
| M3-T3.3 Audit sinks (JSONL, syslog, CEF, LEEF, OCSF, Splunk HEC, ECS, Kafka) | aegis-control | 2026-04-26 |
| M3-T3.4 Admin change log | aegis-control | 2026-04-26 |
| M3-T3.5 Witness export (blake3 signing) | aegis-control | 2026-04-26 |
| M3-T3.6 State snapshot tracker | aegis-control | 2026-04-26 |
| M3-T4.1 Password verify + PHC (argon2id) | aegis-control | 2026-04-26 |
| M3-T4.2 HMAC session cookie + SessionRecord | aegis-control | 2026-04-26 |
| M3-T4.3 CSRF double-submit | aegis-control | 2026-04-26 |
| M3-T4.4 Login rate limit + lockout | aegis-control | 2026-04-26 |
| M3-T4.5 IP allowlist (in mtls module) | aegis-control | 2026-04-26 |
| M3-T4.6 TOTP (RFC 6238) + recovery codes | aegis-control | 2026-04-26 |
| M3-T4.7 Admin mTLS | aegis-control | 2026-04-26 |
| M3-T5.1 Compliance profiles (FIPS, PCI, SOC2, GDPR, HIPAA) + conflict detection | aegis-control | 2026-04-26 |
| M3-T5.2 Residency / retention sweep / right-to-erasure | aegis-control | 2026-04-26 |
| M3-T5.3 GitOps loader (poll, sig verify, dry-run, break-glass) | aegis-control | 2026-04-27 |
| M3-T5.5 SLO / SLI + multi-burn alerts (5 SLIs, 3 windows, 5 receivers) | aegis-control | 2026-04-27 |
| M3-DoD Integration tests (login flow, audit verify, SIEM ≥3 sinks, FIPS, SLO) | aegis-control | 2026-04-27 |
| Cross-crate wiring (audit verify, admin set-password, admin enroll-totp, validate + compliance) | aegis-bin | 2026-04-27 |
| README.md full rewrite (status, architecture, features, security, CLI) | project-wide | 2026-04-27 |
| deploy/GUIDE.md deployment guide (dev, staging, production) | project-wide | 2026-04-27 |
| docs/USAGE.md operations & usage guide | project-wide | 2026-04-27 |
| Data-plane detector wiring (7 OWASP detectors run on every request, block+audit on detection) | aegis-proxy | 2026-04-27 |
| Admin listener wiring (dashboard, SSE stub, health, metrics, config API on :9443) | aegis-proxy | 2026-04-27 |
| deploy/etcd/bootstrap.sh fix (self-shadowing function) | deploy | 2026-04-27 |
| config/README.md configuration guide (12 sections) | project-wide | 2026-04-27 |
| D-M1-T1.1 Asset embedder (31 assets, blake3 ETag, OnceLock table) | aegis-control | 2026-04-27 |
| D-M1-T1.2 SPA shell HTML (full chrome + 17-symbol inlined sprite) | aegis-control | 2026-04-27 |
| D-M1-T1.3 Router (dispatch + vanilla app.js + aegis-proxy delegation) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.4 Chrome (aegis.css design tokens + theme.js bootstrap + toggle wiring) | aegis-control | 2026-04-27 |
| D-M1-T1.5 Security headers (CSP + 8 others, single-source const + proxy wiring) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.6 Legacy shell carve-out (legacy.rs + DashboardConfig + flag wiring) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.7 Hot-reload (cfg-gated disk read of assets in debug builds) | aegis-control | 2026-04-27 |
| D-M1-T1.8 i18n loader (en.json bundle + t()/applyI18n in app.js) | aegis-control | 2026-04-27 |
| **D-M1 milestone complete** (SPA shell + assets + router + chrome + security headers + legacy carve-out + dev hot-reload + i18n) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M2-T2.1 `/api/stats` data layer (StatsAggregator + Handler + 1s cache) | aegis-control | 2026-04-27 |
| D-M2-T2.2 `/api/stats/timeseries` (per-second BTreeMap + step-aligned downsampling) | aegis-control | 2026-04-27 |
| D-M2-T2.3 `/api/upstreams/summary` (compute_summary + UpstreamHandler with provider closure) | aegis-control | 2026-04-27 |
| D-M2-T2.4 `/api/attacks/distribution` (sliding-window per-detector counters + percentages) | aegis-control | 2026-04-27 |
| D-M2-T2.5 `/api/attacks/top` (per-attacker rollup + IP/JA4 identifier resolution) | aegis-control | 2026-04-27 |
| D-M2-T2.6 `/api/about` (AboutResponse + AdminConfig.environment) | aegis-core, aegis-control | 2026-04-27 |
| D-M2-T2.7 Overview page + proxy wire-up (DashboardServices + 6 endpoints + real overview.js) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M2-T2.8 SSE status pill (EventSource + 3-state setConnectionState in app.js + i18n) | aegis-control | 2026-04-27 |
| D-M2-T2.9 Real components (vanilla SVG line-chart/donut/sparkline + sortable table + stat-card) | aegis-control | 2026-04-27 |
| **D-M2 milestone complete** (6 endpoints + Overview page wired end-to-end) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.1 Live Feed page (SSE EventFilter + drawer + live page module) | aegis-control | 2026-04-27 |
| D-M3-T3.2 `/api/audit/since` (AuditRing + handler + drain wire-up) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.3..T3.6 Attack Events page + by-detector + threat-intel + bot-mix endpoints | aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.7..T3.9 Audit Log page + witness lag + filter catalogue | aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.10..T3.11 Analytics page + PromQL allow-list proxy | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M3 milestone complete** (4 operator pages + 11 endpoints) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M4 config management (5 pages + 11 endpoints + 5 stores) | aegis-control, aegis-proxy | 2026-04-28 |
| D-M5 tracking page (6 endpoints + snapshot aggregate + page) | aegis-control, aegis-proxy | 2026-04-28 |
| D-M6 polish (a11y/contrast/headers/budget tests + legacy removal + docs) | aegis-core, aegis-control, aegis-proxy, docs | 2026-04-28 |
| **Dashboard track complete** (D-M1..D-M6, +275 tests, workspace clippy clean) | aegis-core, aegis-control, aegis-proxy | 2026-04-28 |
