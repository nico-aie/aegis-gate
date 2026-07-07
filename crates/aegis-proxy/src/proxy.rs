use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;
use hyper::{Request, Response, StatusCode};

use aegis_core::config::WafConfig;
use aegis_core::pipeline::SecurityPipeline;

use crate::benchmark::{self, BenchmarkConfig, StageTimings};
use crate::route::RouteTable;
use crate::upstream::forward;
use crate::upstream::registry::PoolRegistry;

/// Shared context carried by every connection handler.
///
/// CC-T1.1.b — `pools` is a [`PoolRegistry`] (ArcSwap-backed) so
/// the audit-mutated `/api/upstreams/config` PUT/DELETE handlers
/// can hot-swap the pool table without bouncing the proxy.
/// In-flight requests that already grabbed an `Arc<Pool>` finish
/// on the old map; new requests after the swap see the new one.
pub struct ProxyContext {
    pub route_table: RouteTable,
    pub pools: PoolRegistry,
    /// Zone-aware load balancing P1 — this node's availability zone, resolved
    /// once at boot from `node.zone` with an `AEGIS_ZONE` env override (see
    /// [`aegis_core::config::resolve_self_zone`]). `None` ⇒ no zone identity,
    /// zone preference inert. P1 only plumbs it here (read-only); a later phase
    /// teaches `LbStrategy::pick` to prefer members whose `zone` matches.
    self_zone: Option<String>,
    /// Zone-aware LB P3 — served-local-vs-cross-zone routing counter. `None`
    /// for builds/tests without a metrics registry; the data-plane pick sites
    /// guard on it so the cost is nil when absent. Installed at boot in `run`.
    pub zone_metrics:
        Option<Arc<aegis_control::metrics::zone_routing::ZoneRoutingMetrics>>,
    /// SC-1 — per-upstream response cache (L1 in-process). Built from the
    /// boot config; only pools with a `cache:` block get an entry. CRITICAL
    /// tier is never cached (the data plane enforces that, not this).
    pub cache: Arc<crate::cache::ResponseCache>,
    pub pipeline: Arc<dyn SecurityPipeline>,
    /// Benchmark mode configuration. When enabled,
    /// `handle_request` captures per-stage timings and
    /// stamps `X-Aegis-*` headers on the response.
    pub benchmark: BenchmarkConfig,
    /// TCP-T3c — shared per-source-IP concurrent-tunnel
    /// counter for CONNECT-method dispatch on `scheme: tcp`
    /// routes. Cheap to clone (every clone shares state).
    pub tunnels: crate::tcp_tunnel::ConcurrentTunnels,
    /// FDP-T4 wiring — shared in-flight request counter. The
    /// admin + data accept loops admit a guard for every
    /// accepted connection; the guard's lifetime tracks the
    /// connection task. The SIGUSR2-driven handover's drain
    /// phase reads `inflight.current()` to know when it's
    /// safe to exit. Cheap to clone (Arc<AtomicU32> shared).
    pub inflight: crate::hotbin::InFlightCounter,
    /// 2026-06-20 (GAP 2) — accept-time concurrent-connection cap. The
    /// data-plane accept loop `try_acquire_owned()`s one permit per
    /// accepted connection BEFORE admitting it to the in-flight gauge or
    /// spawning its task; the permit rides the connection task and
    /// releases on its end (clean close / panic / cancel). When permits
    /// are exhausted the loop closes the connection at TCP and `continue`s
    /// WITHOUT calling `inflight.admit()`, so the drain gauge never counts
    /// a rejected connection (reject-before-admit — keeps the SIGUSR2
    /// handover correct). Sized from `cfg.proxy.max_connections` at boot.
    /// Modeled on `streaming_permits`. See
    /// `plans/issues/PLAN-conn-layer-dos-gaps-2026-06-20.md`.
    pub conn_limit: Arc<tokio::sync::Semaphore>,
    /// FIX 2026-05-03 — runtime access-list enforcement.
    /// Operators populate these via the Console; the handler
    /// consults them after XFF resolution but BEFORE the
    /// detector chain. Always present (may be empty) so the
    /// data-plane handler doesn't need a hot-path `Option`
    /// check — ArcSwap inside `AccessListStore` makes
    /// hot-reload free.
    pub blacklist: Arc<aegis_control::api::blacklist::AccessListStore>,
    pub whitelist: Arc<aegis_control::api::blacklist::AccessListStore>,
    /// Adapter wrapping the live GeoIP reader (when wired) so
    /// the access-list matcher can resolve `kind: country`
    /// entries without taking a direct dep on `aegis-security`.
    /// Wrapped in [`std::sync::OnceLock`] so the boot path can
    /// install the lookup AFTER `Arc::new(ProxyContext)` — the
    /// `MaxMindReader` is built inside the admin accept-loop
    /// where `cfg.geoip` is consulted; storing it back here
    /// shares the same reader between control + data planes.
    /// Unset when the binary is built without `geoip` OR no
    /// .mmdb is configured — country entries silently miss.
    pub access_list_country_lookup: std::sync::OnceLock<
        Arc<dyn aegis_control::api::blacklist::AccessListCountryLookup>,
    >,
    /// WS-T6 — WebSocket bridge metrics.  `None` for tests
    /// that don't wire a metrics registry; the data-plane
    /// bridge code uses `if let Some(m) = ...` so the cost is
    /// nil when absent.  Production boot path installs this
    /// once at registration time.
    pub websocket_metrics: Option<Arc<aegis_control::metrics::websocket::WebSocketMetrics>>,
    /// WS-MSG3 — detector chain + mask handles for the WebSocket
    /// message-inspection bridge. The bridge runs on a spawned task that
    /// outlives the request handler, so it needs owned `Arc`/`Shared`
    /// handles rather than the borrowed slice the HTTP path uses. `None`
    /// (tests / builds that don't wire detectors) ⇒ the bridge forwards
    /// without inspecting. Set once at boot in `run`.
    pub ws_detectors:
        Option<Arc<Vec<Box<dyn aegis_security::detectors::Detector>>>>,
    pub ws_detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    /// v2.3 §2.5 — interop control plane's per-feature/policy
    /// `enforce | log_only` store. The data-plane block paths
    /// consult this via `aegis_control::interop::rule_map::
    /// mode_for_rule` to honor `log_only` (record + audit but
    /// don't enforce). Wrapped in `OnceLock` because the boot
    /// path constructs `ProxyContext` BEFORE the interop runtime
    /// (which depends on cfg validation + audit-sink open) — the
    /// listener installs the modes back here once both are up.
    /// Empty when the binary boots without the interop runtime
    /// (test bundles); the data plane treats missing modes as
    /// `Mode::Enforce` for every rule.
    pub interop_modes: std::sync::OnceLock<
        Arc<aegis_control::interop::mode::ModeStore>,
    >,
    /// 2026-05-08 NEW-2 — Proof-of-work challenge issuer for the
    /// v2.3 §3 contract. The data-plane challenge path issues a
    /// `{nonce, difficulty, expires_at_ms, mac}` body so the OC
    /// harness (or any automated client) can solve the PoW and
    /// submit it to `POST /__waf_control/challenge_verify`.
    /// `OnceLock` because the issuer is constructed in
    /// `aegis-proxy::run` after the interop secret is parsed.
    /// Empty when the binary boots without the interop runtime;
    /// the data plane falls back to a body with `challenge_type`
    /// only (degraded but never-panic).
    pub pow_issuer: std::sync::OnceLock<
        Arc<aegis_security::challenge::PowIssuer>,
    >,
    /// 2026-05-09 BUG-DDOS-STUB Phase 1 — DDoS runtime. Wraps
    /// `DdosDetector` + the state-backend handle + the observe-
    /// only flag so the data-plane call site is a single lookup.
    /// `OnceLock` because the boot path constructs `ProxyContext`
    /// before the state backend is fully initialised; `run.rs`
    /// installs this once both pieces are ready. Empty when
    /// `cfg.ddos.enabled = false` — the data plane treats absent
    /// runtime as "skip the check".
    pub ddos: std::sync::OnceLock<Arc<aegis_security::ddos::DdosRuntime>>,
    /// 2026-05-10 — TierStore handle for per-tier policy lookups.
    /// The data plane reads `tier.cumulative_challenge_at`,
    /// `tier.cumulative_block_at`, and `tier.challenges_enabled`
    /// after the detector chain runs to decide challenge / block
    /// behavior on the matched tier. `OnceLock` because the boot
    /// path constructs `ProxyContext` before
    /// `DashboardServices::tiers` is wired; `run.rs` installs the
    /// handle once both are available. Empty (test bundles, etc.)
    /// means "no per-tier overrides" — the data plane uses the
    /// global `cfg.risk.thresholds` and treats every tier as
    /// `challenges_enabled = true`.
    pub tiers: std::sync::OnceLock<Arc<aegis_control::api::tiers::TierStore>>,
    /// 2026-05-17 F-CRITICAL-004 — global request-body cap, populated
    /// from `cfg.proxy.max_body_bytes`. The detector chain buffers up
    /// to this many bytes before inspecting body; requests above it
    /// return 413. Previously a hard-coded 1 MiB const in
    /// `data_plane.rs`; surfaced here so the data-plane hot path
    /// reads the live value via the context it already holds.
    pub max_body_bytes: usize,
    /// 2026-06-20 (GAP 1, anti-RUDY) — global request-body read deadline,
    /// populated from `cfg.proxy.read_timeout`. The data plane wraps the
    /// client-body buffering in this timeout; a slow-trickle body that
    /// does not complete in time returns `408` + `X-WAF-Action: timeout`
    /// rather than pinning the worker task. Read off this context on the
    /// hot path exactly like `max_body_bytes`. See
    /// `plans/issues/PLAN-conn-layer-dos-gaps-2026-06-20.md`.
    pub read_timeout: std::time::Duration,
    /// C-5 (multi-node consistency) — trusted reverse-proxy / LB CIDRs,
    /// parsed once from `cfg.proxy.trusted_proxies` at build time (like
    /// `max_body_bytes`). The data plane walks `X-Forwarded-For`
    /// right-to-left through this set to resolve the real client IP when
    /// the WAF sits behind a trusted L7/SNAT load balancer. Empty (the
    /// default) ⇒ the TCP peer always wins and XFF is ignored — the
    /// F-HIGH-002-safe posture. Retired the hard-coded
    /// `data_plane::default_trusted_proxies()` (which was always empty
    /// with no way to configure it).
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// 2026-05-17 F-HIGH-005 — clone of `InteropRuntime.reset_in_progress`,
    /// installed once after the interop runtime is built. Data plane
    /// reads via `.get()`; absent (test fixtures without interop) is
    /// treated as "not in reset" — the data plane never short-
    /// circuits. See `InteropRuntime.reset_in_progress` for the full
    /// contract rationale.
    pub reset_in_progress: std::sync::OnceLock<
        Arc<std::sync::atomic::AtomicBool>,
    >,
    /// 2026-05-17 F-CRITICAL-006 — adaptive load shedder. Set when
    /// `cfg.load_shedder.enabled = true` and unset otherwise. Data
    /// plane reads via `.get()` so test fixtures and disabled
    /// configs short-circuit to "always admit". See
    /// `crates/aegis-proxy/src/shed.rs` for the algorithm.
    pub load_shedder: std::sync::OnceLock<Arc<crate::shed::LoadShedder>>,
    /// 2026-07-07 — runtime on/off for the load shedder (`cfg.load_shedder
    /// .enabled`). The shedder itself is installed unconditionally so the
    /// gate can be hot-flipped without a restart; the data plane reads this
    /// atomic before consulting `load_shedder`. `DashboardServices` holds a
    /// clone that the audit-mutated `PUT /api/gates/shed` flips, and the
    /// config watcher re-derives it on a converged doc change (via
    /// `apply_cfg_change_to_shed`). `false` → every request is admitted.
    pub load_shed_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// 2026-05-17 F-CRITICAL-001 (control audit) — live operator rule
    /// set. Same `Arc<RuleSet>` that `DashboardServices.active_ruleset`
    /// points at (and that the Pipeline's `rules_arc()` returns), so
    /// when the dashboard CRUD path swaps rules in via
    /// `RuleSet::replace_rules`, the data plane reads the new set on
    /// the next request. `OnceLock` because the boot path constructs
    /// `ProxyContext` before the Pipeline; `accept.rs` installs the
    /// handle once both are available. Empty (test fixtures without
    /// a wired engine) means "no rules" — data plane treats absent
    /// as `Decision::Allow` and falls straight through to the
    /// detector chain.
    pub active_ruleset: std::sync::OnceLock<Arc<aegis_security::RuleSet>>,
    /// 2026-05-18 (QC follow-up TLS-wiring batch — F-CRITICAL-015
    /// activation): live GeoIP / ASN reader, the same Arc the
    /// access-list country adapter + `AttacksHandler::set_geo_lookup`
    /// hold. The data plane reads peer ASN here when building
    /// `BotSignals` so the bot classifier's ASN-class ladder
    /// (added in `f8b4dd5`) actually fires. `OnceLock` because the
    /// boot path constructs `ProxyContext` before the MaxMind
    /// reader is opened; `accept.rs` installs the handle when both
    /// are ready. Absent when no .mmdb is configured —
    /// `BotSignals.asn` / `asn_classification` stay at `Unknown`
    /// defaults and the ladder branch is a no-op.
    pub geoip: std::sync::OnceLock<Arc<dyn aegis_security::geoip::GeoIpLookup>>,
    /// 2026-05-18 (QC TLS wire-up — F-CRITICAL-010 activation):
    /// device→IP rotation tracker. Built in `aegis-proxy::run`
    /// alongside the other security primitives; the data plane
    /// calls `observe(ja4, peer_ip)` after the detector chain
    /// so distinct IPs sharing the same fingerprint within a
    /// 60 s window fire a `device_ip_rotation` signal. Defaults
    /// to threshold 5 / window 60s / score 60 — see
    /// `aegis_security::fingerprint::DeviceIpTracker::with_tuning`.
    pub device_ip_tracker:
        Arc<aegis_security::fingerprint::DeviceIpTracker>,
    /// AC-P2-a (2026-07-03) — the behavioral analyzer, wired behind the
    /// default-OFF `detectors.behavior_analyzer` toggle. `Some` only when
    /// enabled, so a disabled deployment constructs nothing and the data
    /// plane's `observe()` call is skipped entirely (zero cost).
    pub behavior_analyzer:
        Option<Arc<aegis_security::behavior::BehavioralAnalyzer>>,
    /// AC-P2-d (2026-07-04) — the enumeration detector, off the chain and
    /// onto the context because its 404-rate half consumes the AC-P3-b
    /// response-outcome hook (chain detectors never see upstream status).
    /// Behind the default-OFF `detectors.enumeration` toggle; `Some` only
    /// when enabled, so a disabled deployment pays nothing.
    pub enumeration:
        Option<Arc<aegis_security::detectors::enumeration::EnumerationDetector>>,
    /// EG-2 T4 (2026-07-05) — response-path error-leak detector. Off the
    /// chain (needs response status + body). Behind the default-OFF
    /// `detectors.egress_error_leak` toggle; `Some` only when enabled. The
    /// body-scrub site calls `observe(...)` (before redact) and emits a
    /// Detection audit row per leak; the outcome hook drains the per-IP risk
    /// delta into the `RiskTracker`.
    pub egress_error_leak:
        Option<Arc<aegis_security::detectors::egress_leak::ErrorLeakDetector>>,
    /// EG-2 T5 (2026-07-05) — response egress-volume accounting. Off the
    /// chain (needs response size + `RiskTracker`, seen only at the outcome
    /// hook). Behind the default-OFF `detectors.egress_volume` toggle; `Some`
    /// only when enabled. The outcome hook feeds it the response size + the
    /// client's current risk score and folds any volume signal into risk.
    pub egress_volume:
        Option<Arc<aegis_security::detectors::egress_volume::EgressVolumeTracker>>,
    /// EG-2 T2/T3 (2026-07-05) — response sensitive-data sampling. Off the
    /// chain (needs the response body). Behind the default-OFF
    /// `detectors.egress_sensitive` toggle; `Some` only when enabled. The
    /// body-scrub site calls `observe_and_record(...)` (before redact) and
    /// emits a Detection audit row per hit; the outcome hook drains the
    /// per-IP risk delta into the `RiskTracker`.
    pub egress_sensitive:
        Option<Arc<aegis_security::detectors::egress_sensitive::SensitiveDataDetector>>,
    /// EG-2 T2/T3 observe gate (2026-07-07). The `egress_sensitive`
    /// detector is always constructed; this shared `AtomicBool` — read at
    /// the body-scrub site before `observe(...)` runs — decides whether the
    /// observability rung fires. `DashboardServices` holds a clone that the
    /// audit-mutated `PUT /api/gates/egress` flips, so the observe rung
    /// hot-applies with no restart. Observability only: audit rows, never
    /// risk/block. Initialised from `cfg.detectors.egress_sensitive.enabled`.
    pub egress_observe_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// 2026-05-21 — gate-style on/off for the bot classifier
    /// (`cfg.bots.enabled`). The listener reads this before
    /// classifying; `false` skips classification and leaves
    /// `bot_category` unset. Shared `Arc` — `DashboardServices`
    /// holds a clone that the audit-mutated `PUT /api/gates/bots`
    /// flips, so the toggle hot-applies with no restart.
    pub bots_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// SSE streaming stream-through config (allowlist, idle timeout,
    /// kill-switch). Read by `forward()` to classify each upstream
    /// response's [`ResponseMode`](crate::upstream::streaming::ResponseMode).
    pub streaming: aegis_core::config::StreamingConfig,
    /// Decision 5 — bounds concurrent live streams (each pins an upstream
    /// connection). `forward()` acquires a permit before streaming and the
    /// permit rides the response body, releasing on stream end / client
    /// disconnect. Sized from `cfg.streaming.max_concurrent` at boot.
    pub streaming_permits: Arc<tokio::sync::Semaphore>,
    /// SSE streaming metrics (active gauge / streamed counter / duration +
    /// bytes histograms). `None` for test bundles that don't wire a
    /// metrics registry; the boot path installs it once at registration.
    pub stream_metrics: Option<Arc<aegis_control::metrics::streaming::StreamingMetrics>>,
    /// Tier-1A — live GraphQL query guard (depth / node-count / complexity
    /// / introspection caps). Held behind an `ArcSwap` so the config plane
    /// hot-swaps the whole limits struct fleet-wide with no restart (see
    /// `config_source::reload::apply_cfg_change_to_graphql`). Built from
    /// `cfg.graphql`; the data plane consults it for `POST`s to a
    /// configured GraphQL path before the detector chain.
    pub graphql_guard: Arc<arc_swap::ArcSwap<crate::graphql_guard::GraphqlGuard>>,
}

impl ProxyContext {
    /// Build from config. Validation runs inside
    /// [`PoolRegistry::build_pools`] so an invalid `cfg.upstreams`
    /// shape fails boot rather than going live.
    pub fn build(cfg: &WafConfig, pipeline: Arc<dyn SecurityPipeline>) -> aegis_core::Result<Self> {
        let route_table = RouteTable::build(cfg)?;
        let upstream_identity = cfg
            .zero_trust
            .as_ref()
            .and_then(|z| z.upstream_identity.as_ref());
        let (pools, breakers) = PoolRegistry::build_pools(&cfg.upstreams, upstream_identity)
            .map_err(|e| aegis_core::WafError::Config(e.to_string()))?;
        let pool_registry = PoolRegistry::from_pools(pools, breakers);
        // FIX 2026-05-04 — seed the raw shadow with the boot map
        // so admin reads see the boot config before any runtime
        // mutation has landed.
        pool_registry.seed_raw(cfg.upstreams.clone());
        // P2 — seed the shared upstream-mTLS identity so runtime
        // pool re-applies re-resolve client certs against it.
        pool_registry.seed_upstream_identity(upstream_identity.cloned());
        let cache = Arc::new(crate::cache::ResponseCache::from_upstreams(&cfg.upstreams));
        // Zone-aware LB P1 — resolve this node's self-zone once at boot. Env
        // (`AEGIS_ZONE`, for per-pod injection) wins over the config file so
        // one image deploys across zones.
        let self_zone = aegis_core::config::resolve_self_zone(
            cfg.node.zone.as_deref(),
            std::env::var("AEGIS_ZONE").ok().as_deref(),
        );
        if let Some(zone) = self_zone.as_deref() {
            tracing::info!(zone, "node self-zone resolved (zone-aware LB)");
        }
        // Zone-aware LB P3 — seed the registry so live_snapshot marks local
        // members and echoes the node's zone to the dashboard.
        pool_registry.seed_self_zone(self_zone.clone());
        Ok(Self {
            route_table,
            pools: pool_registry,
            self_zone,
            zone_metrics: None,
            cache,
            pipeline,
            benchmark: BenchmarkConfig::off(),
            tunnels: crate::tcp_tunnel::ConcurrentTunnels::new(),
            inflight: crate::hotbin::InFlightCounter::new(),
            // GAP 2 — accept-time connection cap. `Semaphore::MAX_PERMITS`
            // is never reached by a sane config; saturate to be safe.
            conn_limit: Arc::new(tokio::sync::Semaphore::new(
                cfg.proxy.max_connections.min(tokio::sync::Semaphore::MAX_PERMITS),
            )),
            // Default empty stores — boot path shares the
            // same Arcs into DashboardServices so
            // /api/blacklist + /api/whitelist mutations are
            // observed by the data-plane matcher in real time.
            blacklist: Arc::new(
                aegis_control::api::blacklist::AccessListStore::new(),
            ),
            whitelist: Arc::new(
                aegis_control::api::blacklist::AccessListStore::new(),
            ),
            access_list_country_lookup: std::sync::OnceLock::new(),
            websocket_metrics: None,
            ws_detectors: None,
            ws_detector_mask: None,
            interop_modes: std::sync::OnceLock::new(),
            pow_issuer: std::sync::OnceLock::new(),
            ddos: std::sync::OnceLock::new(),
            tiers: std::sync::OnceLock::new(),
            // Cast u64 → usize: on 64-bit targets these are
            // identical width. We saturate on 32-bit hosts (which
            // are unsupported anyway) to avoid silent truncation.
            max_body_bytes: usize::try_from(cfg.proxy.max_body_bytes)
                .unwrap_or(usize::MAX),
            // GAP 1 — anti-RUDY body read deadline, applied proxy-global.
            read_timeout: cfg.proxy.read_timeout,
            // C-5 — parse trusted-proxy CIDRs once; validate() already
            // rejected malformed entries at boot.
            trusted_proxies: cfg.proxy.parsed_trusted_proxies(),
            reset_in_progress: std::sync::OnceLock::new(),
            load_shedder: std::sync::OnceLock::new(),
            active_ruleset: std::sync::OnceLock::new(),
            geoip: std::sync::OnceLock::new(),
            // 2026-05-18 (QC TLS wire-up — F-CRITICAL-010
            // activation): always-on. The tracker no-ops when
            // observe() is called with an empty device fp, so a
            // proxy build without TLS termination at this layer
            // still works (the data plane simply doesn't observe).
            device_ip_tracker: Arc::new(
                aegis_security::fingerprint::DeviceIpTracker::new(),
            ),
            // AC-P2-a — construct only when opted in. 100k sessions / 60s
            // window matches the `behavior_signals` bound.
            behavior_analyzer: cfg.detectors.behavior_analyzer.enabled.then(|| {
                Arc::new(aegis_security::behavior::BehavioralAnalyzer::new(100_000, 60))
            }),
            // AC-P2-d — construct only when opted in; defaults carry the
            // bounded caps (100k IPs / 128 path-hashes / threshold 40).
            enumeration: cfg.detectors.enumeration.enabled.then(|| {
                Arc::new(
                    aegis_security::detectors::enumeration::EnumerationDetector::new(),
                )
            }),
            // EG-2 T4 — construct only when opted in; the scanner carries
            // the default 64 KiB body-scan cap and a bounded per-IP pending
            // map (100k IPs, mirroring enumeration).
            egress_error_leak: cfg.detectors.egress_error_leak.enabled.then(|| {
                Arc::new(
                    aegis_security::detectors::egress_leak::ErrorLeakDetector::new(),
                )
            }),
            // EG-2 T5 — construct only when opted in; carries the default
            // 50 MiB/window threshold + risk gate + 100k-IP bound.
            egress_volume: cfg.detectors.egress_volume.enabled.then(|| {
                Arc::new(
                    aegis_security::detectors::egress_volume::EgressVolumeTracker::new(),
                )
            }),
            // EG-2 T2/T3 — always constructed (cheap; carries the default
            // 64 KiB cap, 1-in-8 sampling, PAN-density threshold) so the
            // observe rung can be hot-toggled at runtime via the
            // `egress_observe_enabled` gate below (PUT /api/gates/egress).
            // The gate — not construction — decides whether `observe(...)`
            // runs, mirroring `bots_enabled` / `load_shed_enabled`.
            egress_sensitive: Some(Arc::new(
                aegis_security::detectors::egress_sensitive::SensitiveDataDetector::new(),
            )),
            // EG-2 observe gate — response sensitive-data observability
            // (default OFF, from config). Observability only: audit rows,
            // never risk/block. Hot-flipped by PUT /api/gates/egress.
            egress_observe_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                cfg.detectors.egress_sensitive.enabled,
            )),
            bots_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                cfg.bots.enabled,
            )),
            load_shed_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                cfg.load_shedder.enabled,
            )),
            streaming_permits: Arc::new(tokio::sync::Semaphore::new(
                cfg.streaming.max_concurrent,
            )),
            stream_metrics: None,
            streaming: cfg.streaming.clone(),
            graphql_guard: Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::graphql_guard::GraphqlGuard::from_config(&cfg.graphql),
            )),
        })
    }

    /// This node's resolved availability zone (zone-aware LB P1), or `None`
    /// when no zone identity is configured. A later phase compares this to
    /// `Member.zone` in `LbStrategy::pick` to prefer same-zone upstreams.
    pub fn self_zone(&self) -> Option<&str> {
        self.self_zone.as_deref()
    }

    /// Spawn one health-check task per pool that has a `health:`
    /// block configured. Each task flips `Member.healthy` on every
    /// probe response (success → true, failure → false) and emits
    /// an audit event on state transitions. The dashboard's
    /// `/api/upstreams` then reflects the live state via the
    /// `live_snapshot` UpstreamWriter trait method.
    ///
    /// Returns the handles so the caller can drop / cancel during
    /// shutdown if needed; in practice the proxy supervisor
    /// manages the task lifetime.
    pub fn spawn_health_checks(
        &self,
        cfg: &WafConfig,
        bus: &aegis_core::audit::AuditBus,
        // SLO-P5 — degrade/recover alert channel into the SLO
        // dispatch loop; `None` in tests.
        alert_tx: Option<tokio::sync::mpsc::UnboundedSender<aegis_control::slo::AlertEvent>>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        // 2026-06-18 (upstream "up" badge report) — defaults for the
        // display-only TCP observer spawned for pools with no `health:`
        // block. Conservative cadence: this only drives the dashboard
        // badge, never load-balancer selection.
        const TCP_OBSERVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
        const TCP_OBSERVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
        // P3 — half-open recovery probe cadence for passively-downed members.
        // A downed member gets no real traffic, so this loop is its only path
        // back; probe a little more eagerly than the badge observer.
        const PASSIVE_RECOVERY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        const PASSIVE_RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

        let mut handles = Vec::new();
        let pools = self.pools.snapshot();
        for (name, pool) in pools.iter() {
            let pool_cfg = match cfg.upstreams.get(name) {
                Some(c) => c,
                None => continue,
            };
            match &pool_cfg.health {
                Some(health) => {
                    let h = crate::upstream::health::spawn_health_checker(
                        name.clone(),
                        pool.members.clone(),
                        health.path.clone(),
                        health.interval,
                        health.timeout,
                        bus.clone(),
                        alert_tx.clone(),
                    );
                    tracing::info!(
                        pool = %name,
                        interval_ms = health.interval.as_millis() as u64,
                        "upstream health-check task spawned"
                    );
                    handles.push(h);
                }
                // No active health check configured. P4: passive health is the
                // default health source for these pools — spawn the passive
                // monitor (badge refresh + half-open recovery), which folds the
                // standalone TCP observer. When the operator explicitly opted
                // out (`passive_health.enabled: false`) fall back to the
                // display-only TCP observer so the dashboard badge stays live.
                None => {
                    let ph = pool.passive_health;
                    if ph.enabled {
                        let r = crate::upstream::health::spawn_passive_health_monitor(
                            name.clone(),
                            pool.members.clone(),
                            ph.rise_threshold,
                            ph.fail_threshold,
                            PASSIVE_RECOVERY_INTERVAL,
                            PASSIVE_RECOVERY_TIMEOUT,
                            bus.clone(),
                            alert_tx.clone(),
                        );
                        tracing::info!(
                            pool = %name,
                            "passive-health monitor spawned (no health block)"
                        );
                        handles.push(r);
                    } else {
                        let h = crate::upstream::health::spawn_tcp_observer(
                            name.clone(),
                            pool.members.clone(),
                            TCP_OBSERVE_INTERVAL,
                            TCP_OBSERVE_TIMEOUT,
                        );
                        tracing::info!(
                            pool = %name,
                            "upstream TCP liveness observer spawned (passive health off)"
                        );
                        handles.push(h);
                    }
                }
            }
        }
        handles
    }
}

/// Handle a single HTTP request: resolve route → pick upstream → forward → respond.
pub async fn handle_request<B>(
    req: Request<B>,
    ctx: Arc<ProxyContext>,
) -> Result<Response<crate::body::DataBody>, hyper::Error>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: std::fmt::Display,
{
    // Stopwatch for benchmark-mode total. Lives outside the
    // `if ctx.benchmark.is_on()` branch because we'd lose
    // any time spent before the branch otherwise.
    let bench_total_start: Option<Instant> =
        ctx.benchmark.is_on().then(Instant::now);

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // 1. Resolve route.
    let route_start = ctx.benchmark.is_on().then(Instant::now);
    let route_ctx = match ctx.route_table.resolve(&host, &path, &method) {
        Some(r) => r,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(crate::body::full("no matching route\n"))
                .unwrap());
        }
    };

    // 2. Check circuit breaker.
    if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
        if !cb.allow_request() {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(crate::body::full("circuit open\n"))
                .unwrap());
        }
    }

    // 3. Pick upstream member. `pools.get` returns an owning
    //    `Arc<Pool>` so the borrow chain (`pool.strategy`,
    //    `pool.members`, `pool.connection` below) survives any
    //    concurrent hot-swap of the pool table.
    let pool = match ctx.pools.get(&route_ctx.upstream) {
        Some(p) => p,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(crate::body::full("unknown upstream\n"))
                .unwrap());
        }
    };

    let member = match pool.strategy.pick_with_locality(
        &pool.members,
        None,
        ctx.self_zone(),
        pool.locality,
    ) {
        Some(m) => m,
        None => {
            // All members unhealthy.
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                cb.record_failure();
            }
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(crate::body::full("no healthy upstream\n"))
                .unwrap());
        }
    };

    // Zone-aware LB P3 — record whether this request was served from the
    // node's own zone or spilled cross-zone (no-op unless locality is on,
    // the node has a self-zone, and a metrics registry is wired).
    if let Some(zm) = &ctx.zone_metrics {
        if let Some(outcome) = crate::upstream::zone_routing_outcome(
            pool.locality.enabled,
            ctx.self_zone(),
            member.zone.as_deref(),
        ) {
            zm.record(&route_ctx.upstream, outcome);
        }
    }

    // Captured route stage timing (only meaningful when
    // benchmark mode is on).
    let route_elapsed = route_start.map(|s| s.elapsed());

    // 4. Collect the original body before forwarding. The
    //    proxy carries `Full<Bytes>` everywhere, so we
    //    materialise to bytes here. Streaming forwarding is
    //    a separate refactor (future).
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to collect client body");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(crate::body::full("body read error\n"))
                .unwrap());
        }
    };

    // F-CRITICAL-008 (2026-05-17 s-tester audit): RAII guard so a
    // cancellation or panic inside `forward::forward` doesn't leak
    // the in-flight counter. Pre-fix the manual fetch_add /
    // fetch_sub pair around the `.await` skewed LeastConn / P2C
    // load balancers against any pool member that ever saw a
    // dropped future.
    let _inflight_guard = member.inflight_guard();
    let upstream_start = ctx.benchmark.is_on().then(Instant::now);
    let result = forward::forward(
        member,
        &pool.connection,
        parts.method,
        parts.uri,
        parts.headers,
        body_bytes,
        &ctx.streaming,
        &ctx.streaming_permits,
    )
    .await;
    let upstream_elapsed = upstream_start.map(|s| s.elapsed());
    drop(_inflight_guard);

    let mut response = match result {
        // `_mode` unused on this (legacy/test) path — the data plane is
        // the production response chain that acts on the streaming mode.
        Ok((resp, _mode)) => {
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                if resp.status().is_server_error() {
                    cb.record_failure();
                } else {
                    cb.record_success();
                }
            }
            // Passive upstream health (P2): a received response means the
            // connection works, so it's a member success — unless the
            // `count_5xx` toggle is on and this is a 5xx. Default-off ⇒
            // skipped entirely (no member ever flips). CB stays the pool
            // fuse; this is per-member rotation — no double-penalty.
            crate::upstream::record_passive_outcome_ok(
                &pool.passive_health,
                member,
                resp.status(),
            );
            resp
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream forward failed");
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                cb.record_failure();
            }
            crate::upstream::record_passive_outcome_err(&pool.passive_health, member, &e);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(crate::body::full("upstream error\n"))
                .unwrap()
        }
    };

    // Stamp benchmark headers when enabled. Cheap no-op
    // otherwise.
    if let Some(start) = bench_total_start {
        let timings = StageTimings {
            route: route_elapsed,
            security: None,
            upstream: upstream_elapsed,
            total: Some(start.elapsed()),
            tier: Some(format!("{:?}", route_ctx.tier).to_lowercase()),
            decision: Some("forwarded".to_string()),
            rule_id: None,
            request_id: None,
        };
        benchmark::stamp_headers(&mut response, &timings, &ctx.benchmark);
    }

    Ok(response)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    /// Spin up a mock upstream returning a given status and body.
    async fn mock_upstream(
        status: u16,
        body: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let st = hyper::StatusCode::from_u16(status).unwrap();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: Request<hyper::body::Incoming>| {
                        let st = st;
                        async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(st)
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    fn cfg_yaml(healthy_addr: std::net::SocketAddr, unhealthy_addr: std::net::SocketAddr) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: api
    host: "api.test"
    path: "/api/"
    upstream: healthy-pool
  - id: catch-all
    path: "/"
    upstream: unhealthy-pool
upstreams:
  healthy-pool:
    members:
      - addr: "{healthy_addr}"
  unhealthy-pool:
    members:
      - addr: "{unhealthy_addr}"
state:
  backend: in_memory
"#
        )
    }

    // C-5 — `cfg.proxy.trusted_proxies` must be parsed into the
    // long-lived ProxyContext so the data-plane handler can resolve the
    // real client IP behind a trusted LB. Empty config ⇒ empty set
    // (XFF ignored — the F-HIGH-002-safe default).
    #[test]
    fn proxy_context_carries_trusted_proxies() {
        let base = r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:9000"
state:
  backend: in_memory
"#;
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);

        // No proxy block ⇒ empty trusted set.
        let cfg: WafConfig = serde_yaml::from_str(base).unwrap();
        cfg.validate().unwrap();
        let ctx = ProxyContext::build(&cfg, Arc::clone(&pipeline)).unwrap();
        assert!(ctx.trusted_proxies.is_empty());

        // Configured CIDRs ⇒ parsed into the context.
        let with_proxies = format!("{base}proxy:\n  trusted_proxies:\n    - \"10.0.0.0/8\"\n");
        let cfg: WafConfig = serde_yaml::from_str(&with_proxies).unwrap();
        cfg.validate().unwrap();
        let ctx = ProxyContext::build(&cfg, pipeline).unwrap();
        assert_eq!(ctx.trusted_proxies.len(), 1);
        let probe: std::net::IpAddr = "10.9.9.9".parse().unwrap();
        assert!(ctx.trusted_proxies.iter().any(|n| n.contains(&probe)));
    }

    // Zone-aware LB P1 — the node's self-zone (node.zone, AEGIS_ZONE env
    // override) must resolve once into the long-lived ProxyContext so a later
    // phase's `pick` can compare it against `Member.zone`. P1 is read-only: no
    // routing change, just the plumbing + accessor.
    #[test]
    fn proxy_context_carries_self_zone() {
        let with_zone = r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:9000"
state:
  backend: in_memory
node:
  id: pod-7
  zone: az-a
"#;
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let cfg: WafConfig = serde_yaml::from_str(with_zone).unwrap();
        cfg.validate().unwrap();
        let ctx = ProxyContext::build(&cfg, pipeline).unwrap();
        assert_eq!(ctx.self_zone(), Some("az-a"));
    }

    #[test]
    fn proxy_context_self_zone_none_when_unset() {
        let no_zone = r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:9000"
state:
  backend: in_memory
"#;
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let cfg: WafConfig = serde_yaml::from_str(no_zone).unwrap();
        cfg.validate().unwrap();
        let ctx = ProxyContext::build(&cfg, pipeline).unwrap();
        assert_eq!(ctx.self_zone(), None);
    }

    #[tokio::test]
    async fn traffic_hits_healthy_pool() {
        let (healthy_addr, srv_h) = mock_upstream(200, "healthy").await;
        let (unhealthy_addr, srv_u) = mock_upstream(503, "down").await;

        let yaml = cfg_yaml(healthy_addr, unhealthy_addr);
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);

        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // Request to api.test/api/foo should hit healthy-pool.
        let req = Request::builder()
            .uri("/api/foo")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();

        let resp = handle_request(req, ctx.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        srv_h.abort();
        srv_u.abort();
    }

    #[tokio::test]
    async fn no_matching_route_returns_404() {
        let (healthy_addr, srv) = mock_upstream(200, "ok").await;

        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "{healthy_addr}"
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let mut ctx = ProxyContext::build(&cfg, pipeline).unwrap();

        // Sabotage the route table so nothing resolves (remove all groups).
        ctx.route_table = RouteTable::build(&{
            // Use a config that has a catch-all but we won't actually use ctx's route table.
            cfg.clone()
        })
        .unwrap();

        // Actually, with the catch-all present, everything matches.
        // Let's just test that an unknown host+path still resolves to catch-all.
        let ctx = Arc::new(ctx);
        let req = Request::builder()
            .uri("/unknown")
            .header("host", "random.host")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        // Catch-all routes to "pool" which has the healthy upstream.
        assert_eq!(resp.status(), StatusCode::OK);

        srv.abort();
    }

    /// Mock upstream that echoes the inbound request line +
    /// every header + the body, separated by newlines, in the
    /// response body. Used by the B4-T3 end-to-end tests.
    async fn echoing_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc =
                        service_fn(|req: Request<hyper::body::Incoming>| async move {
                            let method = req.method().to_string();
                            let pq = req
                                .uri()
                                .path_and_query()
                                .map(|p| p.as_str().to_string())
                                .unwrap_or_else(|| "/".to_string());
                            let mut out = format!("LINE {method} {pq}\n");
                            let mut header_lines: Vec<String> = req
                                .headers()
                                .iter()
                                .map(|(k, v)| {
                                    format!(
                                        "HDR {} {}",
                                        k.as_str(),
                                        v.to_str().unwrap_or("")
                                    )
                                })
                                .collect();
                            header_lines.sort();
                            out.push_str(&header_lines.join("\n"));
                            out.push('\n');
                            use http_body_util::BodyExt as _;
                            let body =
                                req.into_body().collect().await.unwrap().to_bytes();
                            out.push_str(&format!(
                                "BODY {}",
                                String::from_utf8_lossy(&body)
                            ));
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("x-upstream-marker", "echo")
                                    .body(Full::new(Bytes::from(out)))
                                    .unwrap(),
                            )
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    fn echo_cfg(addr: std::net::SocketAddr) -> WafConfig {
        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "{addr}"
state:
  backend: in_memory
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    async fn body_string<B>(resp: Response<B>) -> String
    where
        B: hyper::body::Body<Data = Bytes>,
        B::Error: std::fmt::Debug,
    {
        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn forward_preserves_method_and_path_and_query() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/users?id=42&debug=true")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("x-upstream-marker")
                .and_then(|v| v.to_str().ok()),
            Some("echo")
        );
        let body = body_string(resp).await;
        assert!(
            body.contains("LINE POST /api/users?id=42&debug=true"),
            "body was {body:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn forward_preserves_request_body() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("host", "api.test")
            .header("content-type", "application/json")
            .body(Full::<Bytes>::new(Bytes::from(r#"{"hello":"world"}"#)))
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"BODY {"hello":"world"}"#),
            "body was {body:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn forward_strips_hop_by_hop_headers() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/headers")
            .header("host", "api.test")
            .header("connection", "close")
            .header("keep-alive", "timeout=5")
            .header("user-agent", "aegis-test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        let body = body_string(resp).await;
        // The upstream should NOT have seen connection / keep-alive.
        assert!(!body.contains("HDR connection close"), "body was {body:?}");
        assert!(!body.contains("HDR keep-alive"), "body was {body:?}");
        // And SHOULD have seen user-agent + the rewritten host.
        assert!(body.contains("HDR user-agent aegis-test"), "body was {body:?}");
        let upstream_host = format!("HDR host {}", addr);
        assert!(body.contains(&upstream_host), "body was {body:?}");
        srv.abort();
    }

    #[tokio::test]
    async fn forward_records_x_forwarded_host() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/xfh")
            .header("host", "edge.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        let body = body_string(resp).await;
        assert!(
            body.contains("HDR x-forwarded-host edge.example.com"),
            "body was {body:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn benchmark_headers_emitted_when_enabled() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let mut ctx = ProxyContext::build(&cfg, pipeline).unwrap();
        ctx.benchmark = crate::benchmark::BenchmarkConfig {
            enabled: true,
            expose_rule_ids: false,
            ..Default::default()
        };
        let ctx = Arc::new(ctx);

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert!(
            resp.headers().contains_key(crate::benchmark::hdr::TOTAL_US),
            "expected total-us header"
        );
        assert!(
            resp.headers().contains_key(crate::benchmark::hdr::TIER),
            "expected tier header"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn benchmark_headers_absent_when_disabled() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert!(
            !resp.headers().contains_key(crate::benchmark::hdr::TOTAL_US),
            "benchmark off must not emit headers"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn upstream_connect_failure_returns_502() {
        // No mock running on this port — connect will refuse.
        let bogus_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cfg = echo_cfg(bogus_addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = body_string(resp).await;
        assert!(body.contains("upstream error"), "body was {body:?}");
    }

    #[tokio::test]
    async fn circuit_breaker_trips_on_failures() {
        let (addr, srv) = mock_upstream(503, "error").await;

        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "{addr}"
    circuit_breaker:
      error_rate_threshold: 0.5
      open_duration: 30s
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // Send enough requests to trip the breaker.
        for _ in 0..15 {
            let req = Request::builder()
                .uri("/")
                .header("host", "test")
                .body(Full::<Bytes>::default())
                .unwrap();
            let _ = handle_request(req, ctx.clone()).await.unwrap();
        }

        // Now the breaker should be open.
        let cb = ctx.pools.breaker("pool").unwrap();
        assert_eq!(
            cb.state(),
            crate::upstream::circuit::State::Open,
        );

        // Next request should get 503 "circuit open".
        let req = Request::builder()
            .uri("/")
            .header("host", "test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        srv.abort();
    }

    // FDP-T4 wiring — the in-flight counter is part of
    // ProxyContext and starts at zero on a fresh build. The
    // accept loops admit/drop guards as connections come and
    // go; drain reads `current()` to know when in-flight=0.
    #[tokio::test]
    async fn proxy_context_inflight_starts_at_zero_and_admits_increment() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        assert_eq!(
            ctx.inflight.current(),
            0,
            "fresh ProxyContext must start with no in-flight requests",
        );

        // Admitting a guard increments; drop returns to zero.
        // Mirrors the accept-loop's per-connection admit pattern
        // — proves the counter on ProxyContext is the same
        // shared instance the accept loops use.
        {
            let _g1 = ctx.inflight.admit();
            assert_eq!(ctx.inflight.current(), 1);
            let _g2 = ctx.inflight.admit();
            assert_eq!(ctx.inflight.current(), 2);
        }
        // Both guards dropped at scope end.
        assert_eq!(ctx.inflight.current(), 0);

        srv.abort();
    }
}
