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
- **Workspace tests:** **173 in `aegis-core`** (+10 SC-T1
  BackendHealth/LatencyP/CircuitState tests) + **862 in
  `aegis-control`** (+7 unit + 2 integration SC-T1 tests) +
  **459 in `aegis-proxy` lib** (+2 in_memory health, +5
  client_trust, +5 tls_policy mTLS handshake, +16 identity
  extraction, +2 route auth_required, +1 e2e MTLS-T4 gate,
  +4 MTLS-T5 client-auth-reload tests; +9 more under
  `--features redis` for the Redis backend health helpers;
  **496 with `--features etcd`**) + **888 in
  `aegis-security`** + **41 in `aegis-bin`** (default
  features).
  **Dashboard bundle 182,090 B** (178 KB).
  Workspace total ~2,434 default-feature.
  **`aegis-proxy/src/lib.rs`: 5569 → 5484 (PRE-T1) → 4900
  (PRE-T2) → 4762 (PRE-T4) → 4287 (PRE-T5) → 2650
  (PRE-T6) → 559 (PRE-T7+T8)** lines,
  **cumulative −5010 (−90%)**. `lib.rs` is now a thin
  facade: module declarations + `pub use run::{run,
  ConfigReloadSource};` + a 200-line `#[cfg(test)] mod
  tests` covering the cross-cutting integration tests
  (mock upstream, accept loops, force-https, dashboard
  shell). Submodules: `responses.rs` 231,
  `data_plane.rs` 616, `admin_login.rs` 151,
  `admin_sse.rs` 385 (pre-existing), `admin_get.rs` 519,
  `admin_mutate.rs` 1714 (over guideline; flagged for
  per-resource split), `admin_dispatch.rs` 452,
  `accept.rs` 808 (single line over guideline; cohesive
  per-listener loops), `run.rs` 920 (boot orchestration —
  large because `pub fn run` is naturally that long;
  documented at the top). 8 of 9 new submodules under
  900 lines.
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
- **Latest activity:** **HACK-T5 TLS transport (deferred
  follow-up) closed 2026-05-02.** Closes the last
  explicitly-deferred item from the HACK-T track. Audit
  events can now traverse untrusted networks
  (cloud → on-prem SIEM, multi-region → central log lake)
  without exposing the audit stream.
  - **Schema**: `SyslogTransport` gains a `Tls` variant.
    `AuditSinkConfig::Syslog` gains `ca_bundle:
    Option<PathBuf>` (None → webpki system roots, Some →
    private CA PEM) and `server_name: Option<String>`
    (None → host part of `address`).
  - **Sink**: new `TransportState::Tls { stream, connector,
    server_name }` variant. Connect path runs
    `TcpStream::connect` then `tokio_rustls::TlsConnector::connect`;
    the `TlsConnector` is built once and reused across
    reconnects. Send writes newline-framed RFC 5424 / CEF
    payloads to the negotiated stream; failure drops the
    stream and triggers lazy reconnect on the next event
    (same contract as plain TCP). `webpki-roots` provides
    the default trust; private PKI configures `ca_bundle:`.
  - **`build_tls_connector`** + `derive_server_name` +
    `host_from_address` + `tls_connect` — pure helpers,
    each unit-tested.
  - **Cargo**: aegis-control gains `rustls = { features =
    ["ring"] }`, `tokio-rustls`, `webpki-roots` (workspace
    versions). Adds the `ring` crypto provider once per
    process via a `OnceLock`.
  - **Tests** (+8): host_from_address strips port, IPv6
    brackets preserved, derive_server_name explicit field
    wins, falls back to address host, build_tls_connector
    with webpki roots, build_tls_connector rejects missing
    ca_bundle path with operator-readable error,
    **`tls_send_round_trips_to_self_signed_loopback_listener`**
    (issues self-signed CA + leaf via rcgen, runs a real
    `tokio_rustls::TlsAcceptor`, configures the sink with
    the CA pem written to a tempdir, sends one event,
    verifies the receiver got the CEF-framed line),
    tls_handshake_failure does not panic.
  - **Backwards-compatible**: existing UDP / TCP YAML
    keeps working unchanged. The new fields all default to
    None.
  - aegis-control 889 → **897** lib tests; production
    build clean.

- **Earlier activity:** **HACK-T5 (Tier-C bonus: Syslog/CEF
  audit forwarder) closed 2026-05-02.** **Hackathon-
  readiness track is now complete** — all five slices
  (HACK-T1..T5) shipped; one feature claimed in each of
  Tier A / B / C per v2.3 §2.4 diminishing-returns rule.
  - **Module rewrite**: `aegis-control/src/audit/sinks/syslog.rs`
    (~440 LOC + 11 unit tests) was a stub; now actually
    sends to a remote endpoint. `SyslogSink::connect(cfg)`
    async constructor binds a UDP socket OR opens a TCP
    stream; `send(&self, ev)` per-event method; lazy
    reconnect on TCP send failure (drops the stream and
    rebuilds on next call). Failures are logged + dropped
    from this sink only — JSONL persistence is unaffected.
  - **Schema extension**: `AuditSinkConfig::Syslog` gained
    `transport` (Udp / Tcp) + `format` (Rfc5424 / Cef) +
    `facility` + `app_name` fields. Defaults preserve the
    minimal `address`-only YAML for backwards
    compatibility.
  - **RFC 5424 framing**: `<PRI>1 TS HOST APP PROCID
    MSGID STRUCTURED MSG` with the AuditEvent JSON in
    the MSG slot. PRI computed as `facility * 8 +
    severity`; severity per audit class (Detection=4,
    Admin/Access=6, System=5).
  - **CEF framing**: `CEF:0|Aegis|aegis-waf|0.1.0|<class>|<action>|<sev>|<ext>`
    with `act=`, `src=`, `request_id=`, `mode=`, `cs1=`
    (rule_id), `cn1=` (risk_score). Pipe / equals /
    backslash / newline are escaped per spec.
  - **Boot wiring**: `aegis-proxy::accept::admin_accept_loop`
    spawns one `run_forward_task` per
    `AuditSinkConfig::Syslog` entry alongside the existing
    JSONL persist task. Each forwarder task subscribes to
    the audit broadcast bus independently — backpressure
    is per-sink (lagged events log warn but never block
    the data plane).
  - **Live verified (run-17)**: WAF booted with
    `audit.sinks: [{ jsonl, syslog: { address, transport:
    udp, format: rfc5424 } }]`; benign request streamed
    `<86>` (Access class) RFC 5424 message to a Python
    UDP receiver; SQLi probe streamed `<84>` (Detection
    class) message with `detectors: ["sqli"]`,
    `risk_score: 40`, `action: block`. Receiver log in
    `tests/results/run-17-2026-05-02-hackt5/syslog-receiver.log`.
  - **Tests** (+6 net in aegis-control: 11 new syslog tests,
    minus 5 stub-tests that no longer apply): RFC 5424
    PRI / app_name / event-JSON / Admin-class severity;
    CEF canonical header / extension fields / rule_id +
    risk_score / pipe-equals-escape / per-class severity;
    UDP loopback round-trip (binds receiver, sends event,
    asserts framed line); TCP loopback round-trip with
    CEF format (newline-terminated); TCP reconnect-after-
    initial-failure does not panic.
  - aegis-control 883 → **889** lib tests (+6 net);
    workspace clean; production build clean.

  **HACK-T track summary**:
  - HACK-T1 ✅ retire dashboard mock data (Round 1
    elimination de-risk)
  - HACK-T2 ✅ v2.3 contract regression CI gate
    (40/40 PASS, Round 2 guard)
  - HACK-T3 ✅ Tier-A: rule simulator
  - HACK-T4 ✅ Tier-B: config history timeline
  - HACK-T5 ✅ Tier-C: Syslog/CEF audit forwarder

  Total **20-26 h** plan budget delivered as ~24 h
  actual across the five slices. v2.3 contract green
  end-to-end; hackathon Round 1 / 2 / 3 risks all
  addressed.

- **Earlier activity:** **HACK-T4 (Tier-B bonus: config
  history timeline) closed 2026-05-01.** Operators can
  now browse every audit-mutated configuration change via
  a timeline card on the Settings page — answers
  "who changed what when?" without grepping the JSONL
  audit sink.
  - **New endpoint:** `GET /api/config/versions?limit=50`
    in `aegis-control/src/api/config_versions.rs` (~310
    LOC + 11 unit tests). Filters the existing
    `AuditRing` to `class = Admin` events, returns
    newest-first with `seq` (monotonic version), `ts`,
    `action`, `reason`, `actor` (extracted from
    `fields.user` or `fields.actor`, falls back to
    `system`), `source` (explicit `fields.source` →
    heuristic: `path` field → `file`, else `dashboard`),
    `request_id` (for cross-linking to Audit Log), and
    the full `fields` payload (so the dashboard can show
    before/after diffs each handler stamps). `bounded:
    true` flag mirrors `/api/audit/since` so operators
    know to consult the JSONL sink for full history when
    the in-memory ring evicted older entries.
  - **Dispatch:** new arm in `admin_get.rs` next to
    `/api/audit/witness` (cached `private, max-age=2`).
  - **Dashboard hook:** `useConfigVersionsApi(limit)`
    polling at 5 s.
  - **Dashboard UI:** new `ConfigVersionsCard` component
    rendered on `#/settings` between the runtime hint
    banner and Shadow Mode card. TIER B pill, refresh
    button, table with version / time / action / reason
    / actor / source columns. Click a row to expand and
    see the full `fields` JSON (with mutation handlers'
    `before`/`after` diff payloads) plus a "View in
    Audit Log →" deep-link with the request_id.
    Empty-state copy when no mutations recorded yet.
  - **Live verified (run-16)**: drove two `PUT /api/mode`
    toggles → `/api/config/versions` returns both
    events newest-first with full diff:
    `{ before: { mode: "log_only" }, after: { mode: "enforce" } }`.
    Browser screenshot at
    `tests/results/run-16-2026-05-01-hackt4/screenshots/config-history-expanded.png`
    shows the row-expanded JSON view with the request_id
    + Audit-Log cross-link.
  - **Rollback deliberately deferred** to a follow-up
    (per the plan): each mutation type has its own
    inverse-apply path (re-applying old detector mask vs
    old blacklist vs old upstream config), and the
    audit-event payload doesn't always carry the full
    pre-state. The browse-able timeline is the visible
    Tier-B operator value per v2.3 §2.4; rollback would
    be a separate slice with per-handler undo logic.
  - aegis-control 872 → **883** lib tests (+11
    config_versions); bundle 201 KB (within budget);
    production build clean.

- **Earlier activity:** **HACK-T3 (Tier-A bonus: rule
  simulator) closed 2026-05-01.** Operators can now replay
  a hypothetical request through the live detector chain
  via `POST /api/rules/simulate` — no traffic, no risk
  increment, no rate-limit consumption, no audit emit.
  - **New module:** `aegis-control/src/api/simulator.rs`
    (~370 LOC + 10 unit tests). Pure
    `simulate(req, detectors, mask) -> SimulateResponse`
    function — deterministic, no side effects. Builds a
    `RequestView` from JSON, runs
    `aegis_security::detectors::run_all_filtered_observed`
    (same call site the data plane uses), returns
    `decision_action` / `rule_id` / `risk_score` /
    `detectors_fired` / `signals` (class + detail) /
    `tier` / `muted_detectors` (so operators see why a
    SQLi probe didn't fire when the SQLi class is
    disabled by the mask).
  - **URL-encoding helper**: `percent_encode_path` lets
    operators paste pre-decoded paths from the audit log
    (e.g. `/api/users?id=1' OR '1'='1`) without
    `http::Uri::parse` rejecting unencoded quotes /
    spaces. Detectors URL-decode internally so the
    simulator's verdict matches the live data-plane
    behaviour byte-for-byte.
  - **Wiring**: `DashboardServices.detectors:
    Option<Arc<Vec<Box<dyn Detector>>>>` (None for test
    bundles → simulator returns 503).
    `aegis-proxy::run` lifts the detector list above
    `admin_accept_loop` and passes a clone to both data-
    and admin-plane loops; the admin loop stamps it on
    `services.detectors`.
    `admin_dispatch::handle_simulate` is the async
    handler — caps body at 64 KiB (anti-DoS), parses JSON,
    invokes the pure helper, returns the JSON response.
  - **Dashboard UI**: new `RuleSimulator` component at
    the top of `#/rules` with a TIER A pill, method
    dropdown, path input, body input, Simulate button.
    Verdict pill (BLOCK / ALLOW / CHALLENGE in tone
    colours), rule_id + risk + tier badges, fired-detector
    chips, muted-detector chips, signals table (class +
    detail). Pre-fills with a SQLi probe so operators see
    a working example on first load.
  - **Live verified (run-15)**: SQLi probe → BLOCK + sqli
    rule_id + risk 40; XSS-in-body → BLOCK + xss; benign
    → ALLOW. Browser screenshot of the populated verdict
    panel in `tests/results/run-15-2026-05-01-hackt2-t3/screenshots/rule-simulator-verdict.png`.
  - **Bonus cleanup**: `PageRuleManager` was still
    falling back to `window.RULES` static fixture when
    the live API returned an empty list (a HACK-T1 miss).
    Fixed — now renders an honest "0 total" subtitle +
    "No rules match." empty state.
  - aegis-control 862 → **872** lib tests; bundle 197 KB
    (within 256 KB budget); production build clean.

- **Earlier activity:** **HACK-T2 (v2.3 contract regression
  check) closed 2026-05-01.** New
  `tests/contract/v2.3_compliance.sh` runs **40 numbered
  checks** mapped directly to sections of the v2.3
  interop-contract doc. CI fails on first violation with a
  `FAIL: [NNN] v2.3 §X.Y — <description>` line so the
  offending clause surfaces immediately in CI logs.
  - **Coverage**:
    §2.1 control-endpoint dispatch ·
    §2.2 `X-Benchmark-Secret` auth (missing/wrong → 403) ·
    §2.3 capabilities response shape (`ok`, `features`,
    `active.default_mode`, `active.overrides`) ·
    §2.4 atomic `reset_state` + audit-log preservation ·
    §2.5 `set_profile` semantics with response echo ·
    §2.6 `flush_cache` not-5xx ·
    §5.1 every required `X-WAF-*` header on allowed
    responses with exact value-set matches ·
    §5.3 every required header on blocked responses too ·
    §6 audit-log JSONL minimal schema (every mandatory
    field with valid types + value sets) ·
    §6 IP semantics — `audit.ip` is TCP peer, NOT XFF
    (drives a request with a forged XFF and asserts the
    log carries the loopback peer instead) ·
    §6 `X-WAF-Request-Id` ↔ `audit.request_id` correlation ·
    §3.1 high-confidence injection blocked or challenged ·
    §8 startup contract (binary exists + `/healthz/ready`).
  - **Boot harness**: reuses `tests/interop/_common.sh` —
    `start_waf` / `trap_cleanup` / `count_audit_lines` /
    `header_value` plumbing already there since DR-T*.
  - **Wired into CI**: `tests/README.md` § 9 promotes it to
    a dedicated stage 4 (the existing k6 scenarios become
    stage 5; nightly scanners stage 6) so contract drift is
    caught before perf testing burns runner time.
  - **Negative test**: running the script with a wrong
    `SECRET=` env exits 1 with `FAIL: [001] v2.3 §2.1 —
    GET /__waf_control/capabilities returns 200` —
    confirming the gate catches drift, not just success.
  - **Live (positive sweep)**: 40/40 PASS against the
    current binary. Full workspace tests still green;
    production build clean.

- **Earlier activity:** **HACK-T1 (retire dashboard mock
  data) closed 2026-05-01.** First slice of the hackathon-
  readiness track. Removes the Round-1 elimination risk
  identified in the v2.3 docs §2.2 — "Dashboard uses mock
  data, local state, or simulated responses that make the
  UI state inconsistent with the real WAF-PROXY state".
  - **Zero `Math.random` calls** remain in `pages.jsx`
    (was 7: PageAttackEvents detector bars, rule-stats
    sparkline, PageAnalytics req-over-time / block-ratio /
    p50 / p95 / p99). Only comment references documenting
    the retirement remain.
  - **PageAttackEvents** rewritten against live data:
    detector breakdown ← `/api/attacks/by-detector`; bot
    classification mix ← `/api/bots/mix`; threat-intel
    hits ← `/api/threat-intel/hits`. The `synthetic data`
    pill is gone. Empty-state copy renders honestly when
    the window has no events.
  - **PageAnalytics** rewritten: requests over time +
    block ratio ← `/api/stats/timeseries`; SLO budget ←
    `/api/slo`; cert freshness ← `/api/certs`. Latency
    p50/p95/p99 + error-rate-by-route show explanatory
    "ships via Prometheus / per-route aggregator follow-up"
    messages instead of fabricated values.
  - **All static-fixture fallbacks** (`CERTS`, `RULES`,
    `TIERS`, `BLACKLIST`, `WHITELIST`, `UPSTREAMS`,
    `CLUSTER`, `ALERTS`) flipped to empty arrays in
    `data.jsx::useApi` calls. Live API responses are now
    the only data source — no fixture seeds the dashboard.
  - **Three new hooks** in `data.jsx`:
    `useAttacksByDetectorApi`, `useBotMixApi`,
    `useThreatIntelApi`.
  - **Live verified (run-14)**: `data_plane_availability`
    SLI (83.33% / 99.90% target) renders from the live
    SLO engine; cert section shows "0 certificates · No
    certificates configured" honest empty state for the
    dev config; detector breakdown shows the actual two
    detector hits from 3 attack probes. Screenshots in
    `tests/results/run-14-2026-05-01-hackt1/screenshots/`.
  - Bundle: **192,381 B (188 KB)** — well within the 256
    KB budget. Workspace tests all pass; release build
    rebuilt to re-embed the new bundle.

- **Earlier activity:** **MTLS-T5 (CA-bundle hot-reload)
  closed 2026-05-01.** Operators can now rotate the
  inbound-mTLS CA bundle by editing `waf.yaml` —
  `cfg.tls.client_auth.ca_bundle` is re-parsed and the
  live `ClientTrustStore` is atomic-swapped on every
  successful reload, alongside the existing TLS cert-store
  reload (P5).
  - **New helper:**
    `apply_cfg_change_to_client_auth(new_cfg, trust_store)`
    in `aegis-proxy/src/config_source/reload.rs`. Returns
    one of `NoStore` / `Applied { cert_count, mode }` /
    `SkippedDisabled` / `MissingCaBundle` / `Failed { reason }`.
    **Skip-not-clear semantics**: if new cfg has
    `client_auth: None` or `mode: disabled`, the live
    trust stays — clearing it would crash every Required-
    mode handshake. Operators disabling client-auth at
    runtime need a restart.
  - **Watcher integration**: `supervisor::watch_loop`
    gains a `client_trust:
    Option<ClientTrustStore>` parameter (8 spawn-watcher
    test call sites updated). After the existing
    `tls_reloaded` event, the watcher invokes the new
    helper and emits `mtls_reloaded` (with cert_count +
    mode in fields) on Applied or `mtls_reload_failed`
    (with reason) on MissingCaBundle / Failed. Both events
    land on `AuditClass::Admin` so the audit chain
    captures the rotation.
  - **`run.rs` lift**: the TLS bootstrap now returns the
    parsed `ClientTrustStore` alongside the acceptor +
    resolver (3-tuple), so the config watcher receives a
    handle to swap into. Boot path threads
    `client_trust.clone()` into `spawn_config_watcher`.
  - **Tests** (+4 in `config_source::reload`): no-store
    short-circuit when caller passes `None`;
    skipped-disabled when `mode: disabled` in new cfg
    (live store unchanged); applied-swaps-to-new-CA on
    valid reload; failed-keeps-live-store when new
    `ca_bundle` path doesn't exist. Each test uses an
    rcgen-generated CA written to a tempdir then re-read
    by the helper — exercises the full PEM round-trip.
  - aegis-proxy 492 → **496 etcd**; full workspace
    ~2,447 default-feature tests pass; production build
    clean.

  **What's left in the MTLS track:**
  - **MTLS-T7..T11** — Console mutation surfaces (SAN
    allowlist, mode toggle, break-glass, CA bundle
    upload, per-route `auth_required` editor).
  - **Sub-slices deferred from T4**: `/admin/login`
    mTLS bypass; `AuditEvent.actor` field;
    identity-rate-limit fan-out.

- **Earlier activity:** **MTLS-T4 (route-scoped policy gate)
  closed 2026-05-01.** Routes can now declare
  `auth_required: ["mtls"]` (or `["spiffe"]`, or both) to
  reject anonymous clients with a 403 + `mtls_required`
  rule_id before any upstream is touched. Default empty
  list keeps existing routes open — backwards-compatible.
  - **Schema:** `RouteConfig.auth_required: Vec<String>`
    (`#[serde(default)]`) added to
    `aegis-core::config::RouteConfig`. Doc comment spells
    out the allow-list semantics + the `["mtls", "spiffe"]`
    common case.
  - **Resolver wiring:** `RouteCtx.auth_required` added to
    `aegis-core::context::RouteCtx`; `CompiledRoute`
    threads it from YAML through to `RouteCtx::to_ctx()`.
    Three pre-existing test-construction sites in
    `aegis-security/{noop,pipeline,rules/eval}.rs` and one
    in `aegis-core::context` test mod updated with
    `auth_required: Vec::new()`.
  - **Gate logic:** `forward_allow_to_upstream` now takes
    `&ClientIdentity`. After `route_table.resolve` returns
    a non-empty `auth_required`, the handler checks
    `identity.kind()` against the list. Mismatch returns
    403 (text/plain body, `rule_id = mtls_required`,
    contract action `block`) BEFORE the circuit breaker /
    upstream pick / forward — so authn rejection is cheap
    and never touches the upstream. Logs a `tracing::debug`
    line with route_id + required + actual_kind +
    principal so audits can trace the rejection.
  - **Plumbing:** `&ClientIdentity` threads from
    `accept_loop`'s per-connection `conn_identity` into
    `handle_data_request` → `handle_data_request_inner` →
    `forward_allow_to_upstream`. Plain-HTTP connections
    pass `&ClientIdentity::Anonymous`; mTLS connections
    pass the extracted identity from MTLS-T3.
  - **Tests** (+3): two route-table tests in
    `route::tests` (default empty open behaviour;
    YAML round-trip with `["mtls", "spiffe"]`) and one
    end-to-end test in `lib::tests` —
    `anonymous_request_to_mtls_required_route_returns_403`
    drives `accept_loop` against a mock upstream with a
    plain TCP client, confirms the 403 lands BEFORE the
    upstream is touched (mock would have returned 200).
    aegis-proxy 489 → **492 etcd**; full workspace
    ~2,443 default-feature tests pass; production build
    clean.

  **What's deferred from the broader MTLS-T4 scope** (per
  `plans/mtls.md`):
  - `/admin/login` mTLS bypass (cert with valid SAN skips
    password) — separate slice; needs `aegis-control::admin_auth::mtls`.
  - `actor: ActorIdentity { kind, principal }` field on
    `AuditEvent` — needs schema-version bump in the audit
    chain; better to land alongside MTLS-T11 SAN-allowlist
    audit so both fields ship together.
  - Identity-rate-limit fan-out — wires into `IpRateLimiter`'s
    keyer; needs an additive trait surface in
    `aegis-security`. Defer until there's a concrete identity-
    rate-limit policy to test against.

- **Earlier activity:** **MTLS-T3 (identity extraction)
  closed 2026-05-01.** Every accepted TLS connection now
  populates `ClientIdentity` from the verified leaf cert
  and feeds the per-identity sliding-window tracker — so
  the `/api/mtls/connections` dashboard surface (T6,
  shipped earlier) lights up with real data once an
  operator wires `cfg.tls.client_auth`.
  - **New module:** `aegis-proxy/src/listener/identity.rs`
    (~430 lines incl. tests) — `extract_identity_from_peer_certs`
    parses the leaf via `x509-parser`, fingerprints the DER
    with SHA-256 (lowercase hex), and walks SANs in priority
    order: SPIFFE URI (`spiffe://td/path`) → `Spiffe`
    variant; otherwise first non-SPIFFE URI / DNS / email
    SAN → `Mtls`; CN fallback when no SAN extension; bogus
    DER falls back to `Anonymous` (verifier accepted the
    chain — log + continue).
  - **`accept.rs` rewrite:** TLS handshake now runs
    *before* the per-connection `service_fn` is built so
    the captured identity is stable for every request on
    the connection. New `ServedIo { Tls | Plain }` enum
    threads the IO through to the hyper serve step. Plain
    HTTP connections stay `Anonymous` (no cert offered).
  - **Per-request wiring:** when (a) the data-plane has an
    `IdentityTracker` wired and (b) the connection
    presented a non-Anonymous identity, every request
    calls `tracker.record_request(principal, kind,
    decision_label)` after the audit emit. Decision label
    is the contract action (`allow` / `block` / etc.) so
    the dashboard's per-identity decision breakdown gets
    real data.
  - **`run.rs` lift:** the `IdentityTracker` is now created
    in `run.rs` (instead of inside `admin_accept_loop`)
    and passed to BOTH `accept_loop` (data plane) and
    `admin_accept_loop` (admin / dashboard). CA-bundle
    summary loading stays in `admin_accept_loop`.
  - **Cargo:** `sha2.workspace = true` added to
    `aegis-proxy` so the fingerprint helper has a
    SHA-256 implementation that matches the wire format
    operator UIs expect (most certificate fingerprint
    surfaces show SHA-256, not BLAKE3).
  - **Tests** (+16 in aegis-proxy lib): SAN parser matrix
    (DNS / email / URI / SPIFFE-URI / multi-SAN with
    SPIFFE wins / DNS-wins-over-email / non-SPIFFE URI
    keeps the Mtls variant), CN fallback when SAN
    extension absent, fingerprint stability across calls,
    fingerprint differs across distinct certs, `chain_ok`
    propagates, malformed leaf falls back to Anonymous,
    SPIFFE trust-domain parser (with-path / no-path /
    nested-path), Anonymous when no peer certs / empty
    list. aegis-proxy 473 → **489 tests with `--features
    etcd`**; full workspace ~2,440 default-feature; production
    build clean.

  **Remaining MTLS-T track items:**
  - **MTLS-T4** — policy integration (per-route
    `auth_required: bool` gate; identity-rate-limit
    fan-out; audit-event SAN field).
  - **MTLS-T5** — hot-reload (cfg watcher swaps the
    trust store + rebuilds the verifier).
  - **MTLS-T7..T11** — Console mutation surfaces
    (SAN allowlist / mode toggle / break-glass / CA
    bundle upload / per-route editor).

- **Earlier activity:** **MTLS-T2 (rustls inbound client-auth
  wiring) closed 2026-05-01.** The data-plane TLS listener
  now actually requests + verifies client certs when
  `cfg.tls.client_auth` is configured with
  `apply_to: [data]` (or `[admin, data]`). Three modes:
  `disabled` (no-op, existing path), `optional` (verifier
  built with `.allow_unauthenticated()` — handshake admits
  both with-cert and without-cert), `required` (verifier
  fails the handshake when no cert is presented or the
  cert chains to an untrusted CA).
  - **New module:** `aegis-proxy/src/listener/client_trust.rs`
    (~180 lines) — `ClientTrustStore` newtype around
    `Arc<ArcSwap<rustls::RootCertStore>>` with
    `load_from_pem_file` / `load_from_pem_bytes` / `current`
    / `swap` (the swap path lights up on MTLS-T5). Cheap
    `Clone`; the verifier observes the latest swap target
    via `current()` snapshot. Errors surface as
    `WafError::Config` with the offending path.
  - **New `tls_policy::build_hardened_server_config_with_client_auth`**
    — branches on `ClientAuthMode`: Disabled delegates to
    the existing no-client-auth shape, Optional builds a
    `WebPkiClientVerifier::builder(roots).allow_unauthenticated()`,
    Required builds the same without `.allow_unauthenticated()`.
    ALPN list (`h2` + `http/1.1`) preserved across all three
    branches so HP-T1's data-plane HTTP/2 path keeps working.
  - **`run.rs` boot path:** when `cfg.tls.client_auth` is
    set with `apply_to` including `Data` and a non-Disabled
    mode, parses the configured `ca_bundle` PEM into a
    `ClientTrustStore` and feeds the new builder. CA-bundle
    parse failures fail the boot (operator opted in;
    silently downgrading would be a security regression).
    Logs `tracing::info!("mtls inbound client auth enabled")`
    with mode + apply_to + bundle path so audits can
    confirm the rollout. Existing no-client-auth path is
    unchanged when `client_auth` is absent.
  - **Tests** (+10 in aegis-proxy lib):
    - `client_trust` (5): PEM parse round-trip on a real
      rcgen-generated CA, empty input rejected, garbage
      input rejected, error surfaces the offending path,
      swap doesn't mutate the previously-snapshotted store.
    - `tls_policy` (5): Disabled mode builds a config with
      ALPN preserved; full handshakes against a real
      `tokio_rustls::TlsAcceptor` cover Required-with-valid
      (succeeds), Required-without (fails before HTTP),
      Optional-without (succeeds — anonymous), Required-with-
      untrusted-CA (fails on issuer mismatch). Each
      handshake test installs the rustls ring crypto
      provider via a shared `ensure_crypto_provider`
      OnceLock helper.
  - Workspace: aegis-proxy 463 → **473** with `--features
    etcd`; total ~2,412 default-feature tests passing.
    Production build (`aegis-bin --features production`)
    clean.

  **What's still TODO in the mTLS track:**
  - **MTLS-T3** — identity extraction (parse leaf SAN +
    fingerprint, populate `ClientIdentity`).
  - **MTLS-T4** — policy integration (per-route
    `auth_required`, identity-rate-limit fan-out).
  - **MTLS-T5** — hot-reload (cfg watcher swaps the
    trust store + rebuilds the verifier).
  - **MTLS-T7..T11** — Console mutation surfaces.

- **Earlier activity:** **SC-T3 (Settings hint banner) +
  SC-T5 (doc consolidation) closed 2026-05-01.** Wraps the
  scaling-config track to the operator-visible surface
  except for the optional SC-T4 (tokio_unstable metrics).
  - **SC-T3:** One-liner banner above the Settings list
    when `useRuntimeApi()` returns a `runtime:` block —
    "Runtime sizing (workers, blocking threads, CPU
    affinity) is restart-only. **See the Scaling page →**"
    (links to `#/scaling`). Conditional on the API
    actually answering so the dashboard's loading state
    doesn't show a misleading hint. i18n keys
    `settings.runtimeHint` + `settings.runtimeHintLink`.
    Verified live — screenshot at
    `tests/results/run-13-2026-05-01-sct1-sct2/screenshots/settings-sct3-banner.png`.
  - **SC-T5:** New
    `docs/architecture/scaling-model.md` (3-section
    overview cross-linking the layer-specific docs:
    Layer 1 in-node workers → `runtime-tuning.md`,
    Layer 2 cluster → `ha-clustering.md`, Layer 3
    backend → in-tree state impls). Adds an "Operator
    visibility — the Scaling page" section spelling out
    poll cadence per card. Cross-links added to
    `docs/operations/runtime-tuning.md` (Verifying step 3
    rewritten to point at the Scaling page) and
    `docs/operations/ha-clustering.md` (new "Operator
    visibility" paragraph after the topology diagram).
    `docs/control-plane/enterprise/api.md` gains a new
    "Scaling page (SC-T2)" §endpoint listing for
    `/api/runtime` + `/api/cluster` + `/api/state` +
    `/admin/drain`.
  - Bundle: **192,690 B (188 KB)** — within budget.
  - All workspace tests pass.

- **Earlier activity:** **SC-T2 (Console "Scaling" page)
  closed 2026-05-01.** New `#/scaling` route under the
  Tracking nav group renders three stacked cards
  consuming SC-T1's `/api/state` plus the existing
  `/api/runtime` (L1) + `/api/cluster` (L2) endpoints —
  one focused page replacing the operator's reach-into-
  redis-cli + grep-config-yaml workflow.
  - **L1 card** (`ScalingL1Card`) shows workers (with
    logical-CPU context), mode badge (auto/fixed),
    blocking-pool size + stack, CPU affinity state
    (active / requested-inactive / off). Footer note
    documents that L1 is restart-only.
  - **L2 card** (`ScalingL2Card`) shows the peers table
    (node, healthy/down pill, last-heartbeat age,
    leader/replica role) with our-node row highlighted.
    **Drain this node** button is two-step gated
    (idle → "Confirm — drain {X}?" → final POST). Posts
    to the existing audit-mutated `/admin/drain`
    endpoint with CSRF cookie+header. Result pill
    (drained / failed HTTP {status}) rendered after.
  - **L3 card** (`ScalingL3Card`) consumes the new
    `useStateApi` hook (5 s poll matching Redis cache
    TTL): Connection live/down pill, Circuit
    closed/half_open/open pill (with last-open
    timestamp), Keys count (DBSIZE), Replica lag
    (warn pill ≥ 1 s), p50/p95/p99 latency chips
    auto-formatted (µs / ms / s).
  - Bundle: **192,132 B (188 KB)** — within the 256 KB
    budget.
  - **i18n:** 36 new `scaling.*` keys in `i18n.json`.
  - **MeteredStateBackend `health()` forwarder** —
    spotted live: the wrapper applied at boot was
    masking the real backend identifier as `"unknown"`
    because it didn't override `health()`. Added a
    forward to `inner.health()` so the dashboard sees
    the actual backend (`in_memory` / `redis` /
    `reconciling`).
  - **Live verification (run-13)**: `/api/state` returns
    `{"backend":"in_memory","connected":true,"key_count":0,
    "circuit":{"state":"closed"}, …}`; Scaling page
    screenshot in `tests/results/run-13-2026-05-01-sct1-sct2/screenshots/scaling.png`
    shows all three cards rendering with real data.

- **Earlier activity:** **SC-T1 (Layer-3 backend health
  endpoint) closed 2026-05-01.** New `/api/state` endpoint
  returns the configured `StateBackend`'s reachability +
  telemetry (latency p50/p95/p99 in microseconds, key count,
  worst-case replica lag, server version, circuit-breaker
  state) so the dashboard's Scaling page can render the L3
  card without operators dropping into `redis-cli`.
  - **Trait surface.** `aegis-core::state::StateBackend`
    gains a default `health()` method returning
    `BackendHealth::unknown()` — backwards-compatible. New
    public types: `BackendHealth`, `LatencyP` (with
    `from_samples()` nearest-rank percentile constructor),
    `CircuitState { Closed, HalfOpen, Open { last_open_at_unix_ms } }`.
  - **Backends.** `InMemoryBackend::health` reports
    `connected: true`, live `key_count` from `DashMap::len`,
    no latency/replica/version (in-memory doesn't measure).
    `RedisBackend::health` runs `PING` + `INFO server` +
    `INFO replication` + `DBSIZE` (5 s server-side cache;
    matches dashboard cadence; busy primaries don't pay
    every tick), with a 256-sample rolling latency ring
    populated by the existing `with_timeout` wrapper —
    every op contributes a sample, so the percentiles
    reflect real traffic, not a synthetic ping. Circuit
    state derives from "did PING succeed?" + a recent-error
    timer (errors stamp `last_error_at`; a successful op
    inside the cache-TTL window shows `HalfOpen`; failed
    PING shows `Open` with the unix-ms timestamp).
    `ReconcilingBackend::health` proxies its primary's
    snapshot but rebrands `backend` to `"reconciling"` and
    forces `HalfOpen` while a partition is active.
  - **API + dispatch.** New module
    `aegis-control/src/api/state.rs` defines `StateView`,
    `LatencyView`, `CircuitView` (externally-tagged JSON
    on `state`). Wired through `DashboardServices.state_backend:
    Option<Arc<dyn StateBackend>>` (None for test bundles
    falls back to `BackendHealth::unknown()`). Dispatched
    in `aegis-proxy::admin_dispatch::handle_admin_request`
    (async — the sync `admin_router` can't `.await`
    `health()`); `aegis-proxy::run` wires the metered
    backend into `services.state_backend` alongside the
    existing identity-tracker hand-off.
  - **OpenAPI.** `docs/control-plane/api.openapi.yaml`
    gains `/api/state` path + `StateResponse` /
    `StateLatency` / `StateCircuit` schemas.
  - **Tests.** +10 in `aegis-core` (percentile semantics:
    nearest-rank, single-sample collapse, uniform samples,
    sorted/unsorted ranks, tail-percentile outlier capture,
    empty-slice guard, `BackendHealth::unknown` defaults,
    `CircuitState::Open { … }` tag carry, default trait
    `health()` round-trip); +9 in `aegis-proxy` redis
    backend (`LatencyRing` overwrite, `parse_info_field`
    skips comments, `compute_replica_lag_ms` worst-case
    pick, no-replicas → None, replica role → None,
    unreachable server → Open circuit, cache TTL identity);
    +2 in `aegis-proxy` in_memory backend (connected:true /
    key_count tracks inserts); +7 unit + 2 integration
    tests in `aegis-control` (StateView render preserves /
    propagates / disconnected / serialises / open-with-ts /
    half_open snake_case / unknown-safe; api_smoke
    unwired-returns-unknown / wired-returns-backend-health
    via stub `StateBackend`). All workspace tests green.

- **Earlier activity:** **PRE-T7 + PRE-T8 (extract
  `accept.rs` + `admin_dispatch.rs` + `run.rs`, verify)
  closed 2026-05-01.** Final structural slice of the proxy
  refactor. `lib.rs` shrunk from **2650 → 559 lines**
  (−2091 this slice; **cumulative −5010, −90%** from the
  5569 baseline). Three new submodules:
  - `accept.rs` (808 lines) — `admin_accept_loop` +
    `accept_loop` (the per-listener `tokio::TcpListener`
    accept loops). Marked `pub(crate)`; single call sites
    in `run.rs`.
  - `admin_dispatch.rs` (452 lines) — `handle_admin_request`
    (admin/dashboard router) + `handle_interop_control`
    (`/__waf_control/*`) + `stamp_interop_response` (`X-WAF-*`
    headers + minimal-audit append) + `handle_force_https_request`
    (ACME-01 + 301 redirect) + the private cert-inventory
    parser. The "what runs per request on the admin port"
    surface, separated from "how the listener accepts
    connections".
  - `run.rs` (920 lines) — `pub fn run` boot orchestrator
    + `ConfigReloadSource` enum + `force_https_loop` +
    `build_interop_runtime`. Re-exported from `lib.rs`
    so the public API surface is byte-identical for
    `aegis-bin`.

  **`lib.rs` is now a thin facade**: 6 lines of module
  use, 17 module declarations, 1 `pub use`, and a 200-line
  test module that covers the cross-cutting integration
  tests (still owns the mock-upstream `spawn_mock_upstream`
  helper because it's used by tests of `accept_loop` /
  `force_https_loop` / `dashboard_*_response`).

  **PRE-T8 verification.** All 461 `aegis-proxy --features
  etcd` tests pass; `cargo build -p aegis-proxy --features
  etcd` clean; `cargo clippy -p aegis-proxy --features
  etcd --tests` produces zero new warnings (pre-existing
  warnings in `proto/grpc.rs`, `upstream/lb.rs`,
  `upstream/tls.rs`, `traffic.rs`, `supervisor.rs`,
  `admin_sse.rs` are unrelated to the refactor and were
  already there before PRE-T1). Workspace total still
  ~2,434 default-feature tests passing.

  Proxy refactor track **complete** — `lib.rs` is now a
  facade, every long-running task lives in a coherent
  submodule, and all 461 proxy tests pass. Next track:
  **MTLS-T2** (rustls inbound wiring) per `plans/mtls.md`.
  - **PRE-T5 (2026-05-01)** — Extracted `admin_get.rs`
    (519 lines): `admin_router` + 3 query parsers. lib.rs
    −475.
  - **PRE-T3 (no-op) + PRE-T4 (2026-05-01)** — PRE-T3 no-op
    (`admin_sse.rs` already extracted B4-T4 era). PRE-T4
    extracted `admin_login.rs` (151 lines) + lifted
    `extract_named_cookie` to `responses.rs`. lib.rs −138.
  - **PRE-T2 (2026-05-01)** — Extracted `data_plane.rs`
    (616 lines): `handle_data_request` + inner +
    `forward_allow_to_upstream` + `blocked_response`.
    lib.rs −584.
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

**Task:** **Followups bundle: HACK-T4 rollback action +
MTLS-T7 Console SAN allowlist.** Two cohesive Console
mutation surfaces wrapping up Tier-B Config history with a
one-click undo and the deferred MTLS-T7 SAN allowlist
management with hot-reloadable allowlist + UI.

### What landed (Part A — HACK-T4 rollback action)

- New `aegis-control/src/api/rollback.rs` (~280 LOC + 8 tests):
  `rollback_for_seq(audit_ring, seq, mode_store) ->
  Result<RollbackOutcome, RollbackError>` — looks up the audit
  event by seq, asserts class=Admin and action ∈
  `ROLLBACKABLE_ACTIONS` (v1: `["mode_set"]`), reads
  `event.fields.diff.before.mode`, calls
  `mode_store.set_all(target_mode)`, returns
  `{ rolled_back_to_seq, action, before, after }`.
- `RollbackError` variants: `NotFound(u64)` / `NotAdminClass`
  / `NotRollbackable(action)` / `MissingBefore` /
  `ApplyFailed(reason)` — each carries a short operator-
  readable `Display`.
- `aegis-proxy::admin_dispatch::handle_rollback` async handler
  for `POST /api/config/versions/{seq}/rollback`. Calls
  `rollback_for_seq`, then re-emits the rollback as a new
  Admin audit event with `action: "{orig}_rollback"`,
  `fields: { rollback_to_seq, diff: { before, after }, ... }`
  so the chain captures the rollback direction (not the
  original change direction). Errors map: NotFound → 404; the
  rest → 422 with operator-readable body.
- Dashboard: `data.jsx` adds `configRollback(seq)` + the
  `ROLLBACKABLE_ACTIONS` const (mirrors the Rust list);
  `pages.jsx::ConfigVersionsCard` gains a Rollback button on
  rollback-able rows with two-step confirm modal showing the
  `before` state preview.
- **Live verified (run-18):** drove `PUT /api/mode log_only`,
  then `POST /api/config/versions/1/rollback` returned
  `{"ok":true,"action":"mode_set","before":{"mode":"enforce"},
  "after":{"mode":"log_only"},"rolled_back_to_seq":1}`;
  `/api/mode` confirmed back to `enforce`; audit chain showed
  seq #2 with `action: "mode_set_rollback"` and
  `rollback_to_seq: 1`.

### What landed (Part B — MTLS-T7 Console SAN allowlist)

- New `AllowedSansStore` in `aegis-control/src/api/mtls.rs`
  with `Arc<ArcSwap<Vec<String>>>` + `current() / store(new) /
  remove(san) -> bool / admits(san) -> bool /
  matched_pattern(san) -> Option<String>` and the pure
  `san_matches(pattern, san)` helper implementing RFC 6125
  §6.4.3 wildcard semantics (`*.example.com` matches a single
  label only, NOT `example.com` and NOT `a.b.example.com`).
- `aegis-proxy/src/listener/identity.rs::extract_identity_with_allowlist`
  takes an `Option<&AllowedSansStore>` and downgrades any
  cert whose SANs don't match the (non-empty) allowlist to
  `ClientIdentity::Anonymous`. Empty allowlist = admit
  anything (back-compat). Original
  `extract_identity_from_peer_certs` now delegates to the new
  function with `None`.
- `DashboardServices.allowed_sans:
  Option<AllowedSansStore>` field; `accept.rs` seeds it from
  `cfg.tls.client_auth.allowed_sans` (empty fallback) so the
  three Console handlers below have a live store regardless
  of cfg shape.
- Three new audit-mutated handlers in
  `aegis-proxy/src/admin_mutate.rs`:
  - `handle_mtls_sans_put` — `PUT /api/mtls/sans` with
    `{ allowed: [...] }` body. Validates each entry (non-
    empty, no whitespace, single wildcard restricted to the
    leftmost label, no nested `*`); deduplicates.
    Action: `mtls_sans_set`.
  - `handle_mtls_sans_delete` — `DELETE
    /api/mtls/sans/{san}`. Returns 422 `validation` when SAN
    not present. Action: `mtls_sans_removed`.
  - `handle_mtls_sans_test` — `POST /api/mtls/sans/{san}/test`.
    Read-only synthetic admit check returning
    `{ admitted, matched }` — operators can verify wildcard
    behaviour without making a real mTLS handshake. No
    audit emit (read-side).
- Read endpoint `GET /api/mtls/sans` (in `admin_get.rs`)
  returns `{ allowed: [...] }`.
- Dashboard: `data.jsx` adds `useMtlsSansApi`, `mtlsSansPut`,
  `mtlsSansDelete`, `mtlsSansTest`. New `MtlsSansCard`
  component on Settings page (between `ConfigVersionsCard`
  and Shadow Mode card) with: list of patterns + per-row
  "Copy to test" / "Remove" buttons, "Add SAN" inline input,
  inline "Test admit" widget showing matched pattern as a pill.
- **Live verified (run-mtls-sans, 2026-05-02):**
  - `GET /api/mtls/sans` empty → `PUT` 3 entries
    (`svc.example.com`, `*.api.example.com`,
    `spiffe://example.org/svc`) → `GET` confirms.
  - Test endpoint matrix: exact match works; wildcard
    single-label match works (`thing.api.example.com` →
    `*.api.example.com`); wildcard multi-label correctly
    rejected (`deep.thing.api.example.com` not admitted);
    unknown SAN rejected.
  - `DELETE svc.example.com` succeeds; `DELETE missing.example.com`
    returns 400 validation.
  - Audit chain captured `mtls_sans_set` (seq #1) and
    `mtls_sans_removed` (seq #2) with full before/after diff.

### Test counts

- aegis-control: **15/15** mtls.rs tests pass (6 new
  `AllowedSansStore` tests).
- aegis-proxy: **23/23** identity tests pass (7 new
  allowlist tests).
- New rollback module: **8/8** tests pass.
- Workspace sweep: **all green**, 0 failures.
- Production build: clean (`cargo build --release -p
  aegis-bin`).

### Files touched

- new: `crates/aegis-control/src/api/rollback.rs` (~280 LOC,
  8 tests)
- new: `plans/followups-rollback-and-sans.md` (status now ✅
  DONE)
- modified: `crates/aegis-control/src/api/mtls.rs` (+
  AllowedSansStore + 6 tests)
- modified: `crates/aegis-control/src/api/mod.rs` (export
  `rollback`)
- modified: `crates/aegis-control/src/dashboard_services.rs`
  (+ `allowed_sans` field)
- modified: `crates/aegis-proxy/src/listener/identity.rs`
  (+ `extract_identity_with_allowlist` + 7 tests)
- modified: `crates/aegis-proxy/src/admin_mutate.rs` (+ 3
  handlers, ~210 LOC)
- modified: `crates/aegis-proxy/src/admin_get.rs` (+ GET
  arm)
- modified: `crates/aegis-proxy/src/admin_dispatch.rs` (+ 4
  dispatch arms, + handle_rollback)
- modified: `crates/aegis-proxy/src/accept.rs` (seed
  `services.allowed_sans` from cfg)
- modified:
  `crates/aegis-control/assets/dashboard/src/data.jsx`
  (+ rollback + SAN helpers)
- modified:
  `crates/aegis-control/assets/dashboard/src/pages.jsx`
  (+ MtlsSansCard, + Rollback button)
- bundle rebuilt (~210 KB).

### Deferred (carry-overs)

- Per-handler inverse-apply for additional rollback targets
  (rule_upserted, detector mask, blacklist/whitelist add/
  remove, threshold changes). v1 is `mode_set` only.
- Persisting the SAN allowlist back to disk: today edits
  live in ArcSwap and survive until restart; persistence
  via cfg-source writeback is a follow-up (matches the
  upstream-pools and alert-receivers pattern that already
  carries the same gap).
- Rotating the AllowedSansStore from cfg-watcher is
  intentionally NOT done; once an operator edits via UI,
  the watcher should NOT clobber. Deferred policy decision.

---

### Earlier — PRE-T6 (extract `admin_mutate.rs`)

Sixth slice of the proxy refactor + **README rewrite**. Pure
structural extraction, **zero behaviour change**.

### What landed

**18 audit-mutated handlers + 5 supporting helpers** moved
from `aegis-proxy/src/lib.rs` into a new `admin_mutate.rs`
submodule (1714 lines).

| Handler | Path |
|---|---|
| `handle_mode_put` | `PUT /api/mode` |
| `handle_upstreams_config_put` | `PUT /api/upstreams/config` |
| `handle_pool_upsert` | `PUT /api/upstreams/pool/{id}` |
| `handle_pool_delete` | `DELETE /api/upstreams/pool/{id}` |
| `handle_alert_receivers_put` | `PUT /api/alert-receivers` |
| `handle_alert_receiver_delete` | `DELETE /api/alert-receivers/{name}` |
| `handle_alert_receiver_test` | `POST /api/alert-receivers/{name}/test` |
| `handle_alert_ack` | `POST /api/alerts/{id}/ack` |
| `handle_logging_put` | `PUT /api/logging` |
| `handle_loadmode_put` | `PUT /api/loadmode` |
| `handle_rules_post` | `POST /api/rules` |
| `handle_rules_put` | `PUT /api/rules/{id}` |
| `handle_rules_delete` | `DELETE /api/rules/{id}` |
| `handle_rules_toggle` | `POST /api/rules/{id}/toggle` |
| `handle_risk_thresholds_put` | `PUT /api/risk/thresholds` |
| `handle_risk_reset` | `PUT /api/risk/{ip}/reset` |
| `handle_detectors_put` | `PUT /api/detectors` |
| `handle_admin_drain` | `POST /admin/drain` |

Plus shared helpers: `mutation_preamble` (+ `MutationPreamble`
struct), `redact_receivers_for_audit`, `upstreams_audit_view`,
`default_true`, `mask_state_to_json`. All `pub(crate) async fn`
for the 18 entry points (sed batch-rewrite); helpers private.

### File sizes (cumulative across PRE-T1..T6)

| File | Lines |
|---|---|
| `aegis-proxy/src/lib.rs` | **5569 → 2650** lines (cumulative **−2919, −52%**) |
| `responses.rs` | 231 |
| `data_plane.rs` | 616 |
| `admin_login.rs` | 151 |
| `admin_sse.rs` | 385 (pre-existing) |
| `admin_get.rs` | 519 |
| `admin_mutate.rs` (new) | **1714** |

`admin_mutate.rs` is over the 800-line guideline. Functionally
cohesive (every fn is a mutation handler with the same
audit-chain shape) so further per-resource splitting is a
judgment call documented in the module's own doc-comment as a
follow-up. 6 of 7 submodules under 800 lines.

### Bonus — README rewrite

Operator-requested. Full rewrite of `README.md` to reflect
everything we've built since the previous version (which was
written before the mTLS / hot-reload / etcd / OTel / Grafana
/ refactor work). New sections:

- **Status** with run-12 verification results (perf + security
  + admin console).
- **Hot-reload story** — table of the 5 hot-reload surfaces +
  audit events + boot-only-by-design exclusions.
- **Config sources** — file vs etcd boot-time selection.
- **Observability** — endpoints + Grafana + OTel/Jaeger.
- **Repository Layout** — updated to show the new
  `aegis-proxy/src/{responses,data_plane,admin_login,admin_get,admin_mutate,admin_sse}.rs`
  + `config_source/` + the new plan files
  (`mtls.md`, `proxy-refactor.md`).
- **Crate Responsibilities** — refreshed to mention the new
  submodules + ArcSwap-backed hot-reloadable surfaces.

### Verification

- `cargo build -p aegis-bin --features production` → clean.
- `cargo clippy -p aegis-proxy --features etcd --lib --
  -D warnings` → clean.
- `cargo test -p aegis-proxy --lib` → **424 / 0 / 0**
  default / **461** with `--features etcd`. **3/3 stable
  parallel runs.**
- All other crates unchanged: aegis-control 855,
  aegis-core 163, aegis-bin 41, aegis-security 888.

### What's next

**Track promotion (2026-05-01):**
[`plans/hackathon-readiness.md`](./plans/hackathon-readiness.md)
is now the **Active** track per
[`plans/README.md`](./plans/README.md). It targets the v2.3
hackathon contract — the two real gaps are (a) Round-1
mock-data risk on `#/attacks` + `#/analytics` and (b) Round-3
Tier A/B/C bonus features. The v2.3 §2 control plane,
required `X-WAF-*` headers, JSONL audit log, and
`reset_state` atomicity are all green per run-12 (32/32
OpenAPI shape + 8/8 round-1 acceptance).

- **HACK-T1** ✅ shipped today — Round-1 elimination risk
  closed. Live verification in
  `tests/results/run-14-2026-05-01-hackt1/`.
- **HACK-T2** ✅ shipped today — 40/40 v2.3 contract
  checks pass; CI gate added at stage 4.
- **HACK-T3** ✅ shipped today — `POST /api/rules/simulate`
  + Rule Manager "Simulate" card live. Tier A bonus.
- **HACK-T4** ✅ shipped today — `GET /api/config/versions`
  + Settings-page Config history card live. Tier B bonus
  (timeline browse; rollback deferred to follow-up).
- **HACK-T5** ✅ shipped today — `audit::sinks::syslog`
  forwarder: UDP/TCP transports + RFC 5424/CEF formats;
  one task per `AuditSinkConfig::Syslog` entry. **HACK-T
  track complete.**
- **HACK-T4 follow-up rollback action** ✅ shipped 2026-05-02
  — `POST /api/config/versions/{seq}/rollback` for `mode_set`
  (v1); UI Rollback button on `ConfigVersionsCard` with two-
  step confirm. See `plans/followups-rollback-and-sans.md`.
  Per-handler inverse-apply for additional rollback targets
  (rule_upserted, detector mask, blacklist, etc.) is queued
  as future polish.
- **MTLS-T7 (SAN allowlist)** ✅ shipped 2026-05-02 — live
  `AllowedSansStore` + GET/PUT/DELETE/test API + dashboard
  card on Settings page. Identity extraction now downgrades
  non-matching SANs to Anonymous. Wildcard semantics per RFC
  6125 §6.4.3 (single label only).

**Queued (paused) tracks:**
- **MTLS-T8..T11** — remaining Console mutation surfaces
  (break-glass, CA upload, per-route editor). The mode
  toggle is already shipped via CI-T6; T7 SAN allowlist is
  shipped above.
- **Phase B B6-T2** (Helm) + **B6-T3** (CI). T4 (HSM) +
  T5 (fd-pass) deferred.
- **SC-T4** — `tokio_unstable` runtime metrics → Prometheus
  (optional polish).
- **MTLS-T4 deferred sub-slices** (`/admin/login` mTLS
  bypass; identity-rate-limit fan-out).
- Per-resource split of `admin_mutate.rs` (1714 lines).

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
| 2026-05-02 | **Followups: HACK-T4 rollback action + MTLS-T7 Console SAN allowlist** | Two cohesive Console mutation surfaces: (a) rollback dispatcher (`aegis-control/src/api/rollback.rs`, ~280 LOC + 8 tests) + `POST /api/config/versions/{seq}/rollback` handler that re-applies captured `before` state for `mode_set` (v1) and emits `<orig>_rollback` audit event; UI Rollback button on `ConfigVersionsCard` with two-step confirm. (b) `AllowedSansStore` (ArcSwap-backed; RFC 6125 §6.4.3 single-label wildcard) + `extract_identity_with_allowlist` that downgrades non-matching SANs to Anonymous + 4 new endpoints (`GET/PUT /api/mtls/sans`, `DELETE /api/mtls/sans/{san}`, `POST /api/mtls/sans/{san}/test`); UI `MtlsSansCard` on Settings page with add/remove/test workflow. **Live verified:** rollback round-trip drove mode toggle then rolled back with audit chain confirming `mode_set_rollback` at seq #2; SAN allowlist GET-empty → PUT 3 → test admit matrix (exact / wildcard single-label match / wildcard multi-label rejected / unknown rejected) → DELETE one → audit captured `mtls_sans_set` + `mtls_sans_removed` with full before/after diff. **Tests** (+21 net): 8 rollback dispatcher + 6 AllowedSansStore + 7 identity-allowlist; workspace sweep all green; production build clean (~210 KB bundle). Closes both deferred follow-ups from HACK-T4 + MTLS-T7. |
| 2026-05-02 | **HACK-T5 TLS transport (deferred follow-up)** Audit forwarder over TLS | Closes the last explicit deferral from the HACK-T track. `SyslogTransport` gains `Tls`; `AuditSinkConfig::Syslog` gains `ca_bundle: Option<PathBuf>` (None = webpki system roots) + `server_name: Option<String>` (None = host part of address). New `TransportState::Tls { stream, connector, server_name }` variant uses `tokio_rustls::TlsConnector` to wrap the TCP stream after handshake; reconnect on send failure rebuilds the TLS session with the same connector + SNI. `build_tls_connector` + `derive_server_name` + `host_from_address` + `tls_connect` pure helpers each unit-tested. aegis-control Cargo adds `rustls = { features = ["ring"] }`, `tokio-rustls`, `webpki-roots` (workspace versions). **Tests** (+8): IPv6 + port-strip in `host_from_address`, explicit `server_name` wins, fallback to address host, webpki-roots connector build, missing-ca_bundle error surfaces path, **TLS round-trip** (rcgen self-signed CA + leaf, real `tokio_rustls::TlsAcceptor` server, sink configured with the CA pem in a tempdir, sends event, verifies receiver got the CEF-framed line), TLS handshake failure does not panic. Existing UDP/TCP YAML keeps working unchanged. aegis-control 889 → **897** lib tests; production build clean. |
| 2026-05-02 | **HACK-T5 (Tier-C bonus: Syslog/CEF audit forwarder)** Closes the hackathon-readiness track | Module rewrite of `aegis-control/src/audit/sinks/syslog.rs` (~440 LOC + 11 unit tests) — was a stub, now actually sends. New `SyslogSink::connect(cfg)` async constructor binds a UDP socket OR opens TCP; `send` per-event with lazy TCP reconnect. Schema extension on `AuditSinkConfig::Syslog`: `transport` (Udp/Tcp) + `format` (Rfc5424/Cef) + `facility` + `app_name` (defaults preserve old `address`-only YAML). RFC 5424 framing computes PRI from facility × 8 + severity (Detection=4, Admin/Access=6, System=5). CEF framing: `CEF:0\|Aegis\|aegis-waf\|0.1.0\|<class>\|<action>\|<sev>\|<ext>` with `act=` / `src=` / `request_id=` / `mode=` / `cs1=rule_id` / `cn1=risk_score`; pipe/equals/backslash/newline escaped per spec. Boot wiring: `accept::admin_accept_loop` spawns one `run_forward_task` per Syslog entry alongside existing JSONL persist task — failures log + drop from this sink only. **Live verified (run-17)**: WAF booted with both jsonl + syslog sinks; benign request streamed `<86>` RFC 5424 message to a UDP receiver; SQLi probe streamed `<84>` (Detection severity) with full event JSON; receiver log in `tests/results/run-17-2026-05-02-hackt5/`. **Tests** (+6 net): RFC 5424 PRI / app_name / event-JSON / Admin severity; CEF canonical header / extensions / pipe-equals-escape / per-class severity; UDP loopback round-trip; TCP loopback round-trip with CEF; TCP reconnect-no-panic. aegis-control 883 → **889** lib tests; production build clean. **HACK-T track complete** — all five slices (T1..T5) shipped; one feature each in Tier A/B/C per v2.3 §2.4 diminishing-returns rule. |
| 2026-05-01 | **HACK-T4 (Tier-B bonus: config history timeline)** | New `GET /api/config/versions?limit=50` filters the audit ring to `class = Admin` events, returns newest-first with seq / ts / action / reason / actor / source / request_id / fields. New `aegis-control/src/api/config_versions.rs` (~310 LOC + 11 unit tests covering: empty ring, detection-class excluded, newest-first ordering, limit cap, actor extraction with `system` fallback, source heuristic when field absent, explicit source field wins, limit-zero treated as one, JSON validity, fields-payload preservation, interleaved Detection/Admin filtering). Dashboard hook `useConfigVersionsApi` + `ConfigVersionsCard` component on Settings page (between runtime hint banner and Shadow Mode card) with TIER B pill, table view, and click-to-expand row showing the full `fields` JSON (mutation handlers' before/after diffs) plus a "View in Audit Log →" cross-link with the request_id. Live verified (run-16): drove two `PUT /api/mode` toggles → endpoint returns both events newest-first with full `{ before, after }` diff; browser screenshot at `tests/results/run-16-2026-05-01-hackt4/screenshots/config-history-expanded.png`. **Rollback deferred** to follow-up (per-handler undo logic; the timeline browse is the visible Tier-B value per v2.3 §2.4). aegis-control 872 → **883** lib tests; bundle 201 KB; production build clean. HACK-T5 (Tier-C Syslog forwarder) next. |
| 2026-05-01 | **HACK-T3 (Tier-A bonus: rule simulator)** | New `POST /api/rules/simulate` runs a synthetic request through the live detector chain (`default_detectors()` + live `SharedDetectorMask`) with **zero** side effects. New `aegis-control/src/api/simulator.rs` (~370 LOC + 10 unit tests): pure `simulate(req, detectors, mask) -> SimulateResponse` returning decision_action / rule_id / risk_score / detectors_fired / signals (class+detail) / tier / muted_detectors. `percent_encode_path` lets operators paste pre-decoded paths from the audit log without `http::Uri::parse` rejecting unencoded quotes. `DashboardServices.detectors: Option<Arc<Vec<Box<dyn Detector>>>>` lifted in `run.rs` and stamped by `admin_accept_loop` so simulator + data plane share the same detector instance — verdicts can't drift. `admin_dispatch::handle_simulate` async handler caps body at 64 KiB (anti-DoS). **Dashboard**: new `RuleSimulator` card on Rule Manager with TIER A pill, method/path/body inputs, Simulate button — clicking renders verdict pill (BLOCK/ALLOW/CHALLENGE) + rule_id + risk + tier + fired/muted chips + signals table. **Bonus**: also retired `window.RULES` static fallback in PageRuleManager (HACK-T1 miss). Live verified (run-15): SQLi → BLOCK+sqli+risk 40; XSS-in-body → BLOCK+xss; browser screenshot of populated verdict panel in `tests/results/run-15-2026-05-01-hackt2-t3/`. aegis-control 862 → **872** lib tests; bundle 197 KB; production build clean. HACK-T4 (Tier-B versioning) next. |
| 2026-05-01 | **HACK-T2 (v2.3 contract regression CI gate)** | New `tests/contract/v2.3_compliance.sh` runs 40 numbered checks mapped directly to v2.3 §X.Y citations. Coverage: §2.1 control-endpoint dispatch, §2.2 `X-Benchmark-Secret` auth (missing/wrong → 403), §2.3 capabilities shape, §2.4 atomic `reset_state` + audit preservation, §2.5 `set_profile` echo, §2.6 `flush_cache` not-5xx, §5.1 + §5.3 every required `X-WAF-*` header on allow + block responses with exact value-set matches, §6 audit-log JSONL schema with valid types + TCP-peer IP semantics + request_id correlation, §3.1 injection blocked/challenged, §8 startup contract. **Negative test**: wrong `SECRET=` exits 1 with `FAIL: [001] v2.3 §2.1` line proving the gate catches drift. **Wired into CI**: `tests/README.md` §9 stage 4. Reuses `tests/interop/_common.sh` boot/header plumbing. 40/40 PASS against current binary; full workspace + production build still green. HACK-T3 (Tier-A rule simulator) next. |
| 2026-05-01 | **HACK-T1 (retire dashboard mock data)** First slice of hackathon-readiness track | Removes Round-1 elimination risk per v2.3 §2.2 ("UI must not use mock/local-state data"). Zero `Math.random` calls remain in `pages.jsx` (was 7). **PageAttackEvents** wired to live `/api/attacks/by-detector` + `/api/bots/mix` + `/api/threat-intel/hits` (3 new hooks added to `data.jsx`); the synthetic-data pill is gone; honest empty states render when the window has no events. **PageAnalytics** wired to `/api/stats/timeseries` (req-over-time + block-ratio), `/api/slo` (live SLI rows), `/api/certs` (cert freshness); latency-percentile + per-route widgets show explanatory "ships via Prometheus / aggregator follow-up" messages instead of fake numbers. **All static-fixture fallbacks** (CERTS / RULES / TIERS / BLACKLIST / WHITELIST / UPSTREAMS / CLUSTER / ALERTS) swapped for empty arrays — the live API is the only data source. Live verification (run-14): `data_plane_availability` SLI 83.33%/99.90% target renders from live engine; "0 certificates · No certificates configured" honest empty state for dev config; detector breakdown shows actual counts from 3 attack probes. Screenshots in `tests/results/run-14-2026-05-01-hackt1/`. Bundle 192 KB. Workspace tests all pass; binary rebuilt to re-embed bundle. HACK-T2 (v2.3 contract regression check) next. |
| 2026-05-01 | **MTLS-T5 (CA-bundle hot-reload)** Operators rotate trust anchors by editing waf.yaml | New `apply_cfg_change_to_client_auth(new_cfg, trust_store)` helper in `config_source/reload.rs` returns `NoStore` / `Applied { cert_count, mode }` / `SkippedDisabled` / `MissingCaBundle` / `Failed { reason }`. **Skip-not-clear**: live trust stays when new cfg disables client_auth (clearing would crash Required-mode handshakes). `supervisor::watch_loop` gains a `client_trust:` parameter, calls the helper after the existing `tls_reloaded` step, emits `mtls_reloaded` (with cert_count + mode in fields) on Applied or `mtls_reload_failed` (with reason) on MissingCaBundle / Failed — both `AuditClass::Admin`. `run.rs` TLS bootstrap now returns the parsed `ClientTrustStore` alongside acceptor + resolver (3-tuple) and threads it into `spawn_config_watcher`. **Tests** (+4 in `config_source::reload`): no-store short-circuit when caller passes None; skipped-disabled when `mode: disabled` (live unchanged); applied-swaps-to-new-CA on valid reload; failed-keeps-live-store when path doesn't exist. Each test uses an rcgen-generated CA written to tempdir then re-read by the helper. 8 spawn_config_watcher test call sites updated for the new param. aegis-proxy 492 → **496 etcd**; production build clean. MTLS-T7 (Console SAN allowlist) next. |
| 2026-05-01 | **MTLS-T4 (route-scoped policy gate)** Routes can declare `auth_required` to reject anonymous clients with 403 | New `RouteConfig.auth_required: Vec<String>` (empty default = open). `RouteCtx.auth_required` threads through `CompiledRoute` from YAML to the resolver. `forward_allow_to_upstream` now takes `&ClientIdentity` and gates the request before circuit-breaker + upstream pick: mismatch → 403 with `mtls_required` rule_id (contract action `block`); a `tracing::debug` line records route_id + required + actual_kind + principal. `handle_data_request` + `_inner` both gain the `&ClientIdentity` parameter; accept_loop passes its per-connection `conn_identity`. Three pre-existing test-construction sites (`aegis-security/{noop,pipeline,rules/eval}` + `aegis-core::context` test) updated with `auth_required: Vec::new()`. **Tests** (+3): two route-table unit tests (default open; YAML round-trip with mtls+spiffe) + one end-to-end `anonymous_request_to_mtls_required_route_returns_403` driving `accept_loop` against a mock upstream confirms the 403 lands BEFORE the upstream is touched. **Deferred** (split slices): /admin/login mTLS bypass; AuditEvent `actor` field (bundle with MTLS-T11 schema bump); identity-rate-limit fan-out (no concrete policy yet). aegis-proxy 489 → **492 etcd**; production build clean. MTLS-T5 (hot-reload) next. |
| 2026-05-01 | **MTLS-T3 (identity extraction)** Every TLS connection now populates `ClientIdentity` + feeds the per-identity tracker | New `aegis-proxy/src/listener/identity.rs` (~430 lines incl. tests) — `extract_identity_from_peer_certs` parses the leaf via x509-parser, fingerprints the DER with SHA-256, and walks SANs in priority order: SPIFFE URI → `Spiffe`; otherwise non-SPIFFE URI / DNS / email SAN → `Mtls`; CN fallback when SAN extension absent; bogus DER → Anonymous (verifier accepted; log + continue). **`accept.rs` rewrite**: TLS handshake runs *before* the `service_fn` so the captured identity is stable for every request on the connection (new `ServedIo { Tls | Plain }` enum). Per-request: when both `IdentityTracker` is wired and identity is non-Anonymous, calls `tracker.record_request(principal, kind, decision_label)` after the audit emit — so `/api/mtls/connections` (T6) lights up with real data. **`run.rs` lift**: `IdentityTracker` created once in `run.rs` and passed to BOTH `accept_loop` (data plane) and `admin_accept_loop` (admin); CA-bundle summary load stays in admin_accept_loop. **Cargo**: `sha2.workspace = true` added to aegis-proxy. **Tests** (+16 in aegis-proxy lib): SAN parser matrix (DNS / email / URI / SPIFFE / multi-SAN with SPIFFE-wins / DNS-wins-over-email / non-SPIFFE URI keeps Mtls), CN fallback, fingerprint stability + uniqueness, `chain_ok` round-trip, malformed leaf → Anonymous, SPIFFE trust-domain parser cases, Anonymous when no peer certs / empty list. aegis-proxy 473 → **489 etcd**; production build clean. MTLS-T4 (policy integration) next. |
| 2026-05-01 | **MTLS-T2 (rustls inbound client-auth wiring)** Listener actually requests + verifies client certs | Three modes via `cfg.tls.client_auth.mode`: `disabled` (no-op), `optional` (`WebPkiClientVerifier::builder(roots).allow_unauthenticated()` — anonymous + verified both pass), `required` (handshake fails on missing or untrusted-CA cert before HTTP). New `aegis-proxy/src/listener/client_trust.rs` (~180 lines): `ClientTrustStore` newtype around `Arc<ArcSwap<RootCertStore>>` with PEM file/bytes loaders + `current()` / `swap()` (swap path lights up on MTLS-T5). New `tls_policy::build_hardened_server_config_with_client_auth` branches on the three modes; ALPN list (`h2` + `http/1.1`) preserved across all branches so HP-T1's HTTP/2 path keeps working. `run.rs` boot path parses `ca_bundle` PEM into a `ClientTrustStore` and feeds the new builder when `apply_to` includes `Data` and mode != Disabled; CA-bundle parse failures fail the boot (operator opted in; silent downgrade would be a security regression). `tracing::info!` logs mode + apply_to + bundle path so audits can confirm the rollout. **Tests** (+10 aegis-proxy lib): client_trust 5 (PEM round-trip on rcgen CA, empty/garbage rejected, error surfaces path, swap doesn't mutate snapshot); tls_policy 5 (Disabled config build; full handshake against `tokio_rustls::TlsAcceptor` for Required-with-valid → succeeds, Required-without → fails, Optional-without → succeeds, Required-with-untrusted-CA → fails). Shared `ensure_crypto_provider` OnceLock helper installs the rustls ring provider in test scope. aegis-proxy 463 → **473 etcd** tests; production build clean. MTLS-T3 (identity extraction) next. |
| 2026-05-01 | **SC-T3 (Settings hint banner) + SC-T5 (doc consolidation)** Closes the scaling-config track to the operator surface | **SC-T3:** One-liner banner above Settings (`PageSettings`) when `useRuntimeApi()` returns a runtime block — "Runtime sizing (workers, blocking threads, CPU affinity) is restart-only. **See the Scaling page →**" with a `#/scaling` deep-link. Conditional on the API actually answering so the loading state doesn't show a misleading hint. i18n keys `settings.runtimeHint` + `settings.runtimeHintLink`. Screenshot at `tests/results/run-13-2026-05-01-sct1-sct2/screenshots/settings-sct3-banner.png`. **SC-T5:** New `docs/architecture/scaling-model.md` (3-section overview: L1 in-node workers, L2 cross-node cluster, L3 shared state) cross-linking the layer-specific docs (`runtime-tuning.md`, `ha-clustering.md`, in-tree state impls), with an "Operator visibility — the Scaling page" §spelling out card behaviours + poll cadences and a "What's *not* in the model" §listing deliberate exclusions (hot-resize tokio, per-route worker pinning, auto-scaler, cluster mutation API, Redis Cluster slot-hashing). Cross-links added to `docs/operations/runtime-tuning.md` (Verifying step 3 rewritten) + `docs/operations/ha-clustering.md` (new "Operator visibility" paragraph). `docs/control-plane/enterprise/api.md` gains a "Scaling page (SC-T2)" endpoint listing for `/api/runtime` + `/api/cluster` + `/api/state` + `/admin/drain`. Bundle: 192,690 B (188 KB), within budget. All workspace tests green. |
| 2026-05-01 | **SC-T2 (Console "Scaling" page)** Three-layer scaling visibility surfaced to operators | New `#/scaling` route under the Tracking nav group renders three stacked cards consuming SC-T1's `/api/state` plus the existing `/api/runtime` (L1) + `/api/cluster` (L2). **L1 card**: workers (with logical-CPU context), mode auto/fixed, blocking pool + stack, CPU affinity state, restart-only footer note. **L2 card**: peers table with our-node highlight, two-step gated **Drain this node** button posting to existing audit-mutated `/admin/drain`, result pill on response. **L3 card**: Connection / Circuit / Keys / Replica-lag stats + p50/p95/p99 latency chips (auto µs/ms/s formatted), 5 s poll cadence matching Redis cache TTL. **i18n**: 36 new `scaling.*` keys. **MeteredStateBackend health() forwarder** spotted live during browser verification: wrapper was masking the real backend identifier as `"unknown"` because it didn't override `health()`; added a 1-line forward to `inner.health()` so the dashboard sees the actual backend (`in_memory` / `redis` / `reconciling`). **Live verification (run-13)**: `/api/state` returns `{"backend":"in_memory","connected":true,…}` HTTP 200 against `config/dev.yaml`; Scaling page screenshot in `tests/results/run-13-2026-05-01-sct1-sct2/screenshots/scaling.png` shows all three cards with real data. Bundle 188 KB (within 256 KB budget). All workspace tests green. |
| 2026-05-01 | **SC-T1 (`/api/state` Layer-3 backend health)** First slice of the scaling-config track | New `/api/state` GET endpoint surfaces the configured `StateBackend`'s reachability, latency p50/p95/p99 (microseconds), key count, worst-case replica lag, server version, and circuit-breaker state. **Trait surface:** `aegis-core::state::StateBackend` gains a default `health()` returning `BackendHealth::unknown()` — backwards-compatible. New public types: `BackendHealth`, `LatencyP::from_samples` (nearest-rank percentile constructor), `CircuitState { Closed, HalfOpen, Open { last_open_at_unix_ms } }`. **Backends:** `InMemoryBackend::health` reports connected:true + live `DashMap::len`. `RedisBackend::health` runs `PING` + `INFO server` + `INFO replication` + `DBSIZE` (5s server-side cache; 256-sample rolling latency ring fed by every `with_timeout` op so percentiles reflect real traffic, not synthetic pings; circuit derives from PING success + a recent-error timer). `ReconcilingBackend::health` proxies primary, rebrands `backend` to "reconciling", forces HalfOpen during partitions. **Wiring:** `aegis-control/src/api/state.rs` defines the JSON `StateView` (externally-tagged circuit on `state`); `DashboardServices.state_backend: Option<Arc<dyn StateBackend>>` (None falls back to unknown for test bundles); dispatched async in `aegis-proxy::admin_dispatch::handle_admin_request` (sync `admin_router` can't `.await`); `aegis-proxy::run` hands the metered backend through `admin_accept_loop`. **OpenAPI:** new `/api/state` path + `StateResponse` / `StateLatency` / `StateCircuit` schemas in `docs/control-plane/api.openapi.yaml`. **Tests:** +10 aegis-core (percentile semantics, default trait health), +9 aegis-proxy redis backend (LatencyRing, parse_info_field, compute_replica_lag_ms, unreachable→Open, cache TTL), +2 aegis-proxy in_memory, +7 aegis-control unit + 2 integration (api_smoke). All workspace tests green. SC-T2 (Console "Scaling" page consuming this) next. |
| 2026-05-01 | **PRE-T7 + PRE-T8 (extract `accept.rs` + `admin_dispatch.rs` + `run.rs`, verify)** Final proxy-refactor slice | Pure structural extraction, zero behaviour change. Three new submodules: **`accept.rs`** (808 lines — `admin_accept_loop` + `accept_loop` per-listener accept loops), **`admin_dispatch.rs`** (452 lines — `handle_admin_request` + `handle_interop_control` + `stamp_interop_response` + `handle_force_https_request` + private `read_cert_inventory`), **`run.rs`** (920 lines — `pub fn run` boot orchestrator + `ConfigReloadSource` enum + `force_https_loop` + `build_interop_runtime`). `lib.rs` re-exports `pub use run::{run, ConfigReloadSource};` so the public API surface is byte-identical for `aegis-bin`. **`lib.rs` 2650 → 559** (−2091 this slice; **cumulative −5010 / −90%** from 5569 baseline). lib.rs is now a thin facade — module declarations + `pub use` + the cross-cutting integration test module. **PRE-T8 verify**: 461 `aegis-proxy --features etcd` tests pass; full workspace ~2,434 default-feature tests pass; clippy on the refactored files clean (warnings in unrelated files are pre-existing). Proxy refactor track **complete**. Next: MTLS-T2 (rustls inbound wiring) per `plans/mtls.md`. |
| 2026-05-01 | **PRE-T6 (extract `admin_mutate.rs`) + README rewrite** Biggest chunk yet | 18 audit-mutated PUT/POST/DELETE handlers + 5 shared helpers moved into new `admin_mutate.rs` (1714 lines — over 800 guideline; flagged for follow-up per-resource split). lib.rs imports gain `use admin_mutate::{...18 handlers...}`. **`lib.rs` 4287 → 2650** (−1637 this slice; **cumulative −2919 / −52%** from 5569 baseline). 6 of 7 submodules under 800. **README.md fully rewritten** — status with run-12 results, hot-reload story (5 surfaces + audit events), config sources (file vs etcd), observability (Prometheus + OTel + Grafana + Jaeger), refreshed repo layout + crate responsibilities. 424 default / 461 etcd unchanged. 3/3 stable. PRE-T7 (run.rs, ~700 lines) next. |
| 2026-05-01 | **PRE-T5 (extract `admin_get.rs`)** The big chunk — every GET dispatch arm | Pure structural extraction, zero behaviour change. `admin_router` (~430 lines, every `/healthz/*` + `/metrics` + every `/api/*` GET arm — health, stats, audit, rules, upstreams, risk, mode, loadmode, runtime, detectors, blacklist, whitelist, alerts, slo, certs, cluster, gitops, **mtls (MTLS-T6)**, filters, integrations, admin sessions, cold-tier, logging, analytics, threat-intel, bots, audit/witness, tracking, upstreams/config) + 3 query parsers moved into new `admin_get.rs` (519 lines). Single call site in `admin_listener::service_fn` rebound. 5 dashboard-response unit tests import from `crate::responses::` (same fixup pattern as PRE-T4). **`lib.rs` 4762 → 4287** (−475 this slice; **cumulative −1282 / −23%**). All 6 submodules under 800-line guideline. 424 / 461 unchanged. 3/3 stable. PRE-T6 (mutation handlers, ~1500 lines) next. |
| 2026-05-01 | **PRE-T3 (no-op) + PRE-T4 (extract `admin_login.rs`)** Two slices in one turn | PRE-T3 no-op (`admin_sse.rs` was already extracted in B4-T4 era, 385 lines). PRE-T4: 4 login/logout fns + `extract_named_cookie` shared helper moved out of `lib.rs`. New `admin_login.rs` (151 lines) + `extract_named_cookie` lifted into `responses.rs` (213 → 231). **`lib.rs` 4900 → 4762** (−138 this slice; cumulative **−807** from 5569 baseline across PRE-T1+T2+T4). All 5 submodules under 800-line guideline. lib.rs `tests` import-fixup; 424 default / 461 etcd unchanged. 3/3 stable parallel runs. PRE-T5 (admin_get_handlers, ~1200 lines) next. |
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
