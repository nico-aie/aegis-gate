use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use aegis_core::state::StateBackend;
use aegis_core::tier::{FailureMode, Tier};

/// 2026-05-23 — at most one idle-key sweep per this interval, so the
/// in-process counting maps stay bounded without per-request cost.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005): per-tier override
/// of the global limit + window. Operator writes one of these
/// into `ddos.tier_overrides.<tier>` in YAML to tighten
/// (`critical: { per_ip_limit: 50, per_ip_window_s: 10 }`) or
/// loosen (`low: { per_ip_limit: 10000, per_ip_window_s: 10 }`)
/// the per-tier cap. Missing override falls back to the global
/// `per_ip_limit` / `per_ip_window_s` on `DdosConfig`.
#[derive(Clone, Debug)]
pub struct DdosTierLimit {
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
}

/// Per-IP DDoS configuration.
#[derive(Clone, Debug)]
pub struct DdosConfig {
    /// Master toggle. `false` means [`DdosDetector::check`] is never
    /// called — the request handler short-circuits before reaching
    /// the detector. Default `true`.
    pub enabled: bool,
    /// Observation mode. `true` runs the gate + writes audit events
    /// (`ddos_observed`) but does NOT short-circuit with HTTP 403.
    /// Default `false` — enforce by default, matching every other
    /// security primitive in the data plane. Operators with edge
    /// cases (CDN-fronted high-RPS-per-IP, internal-API trusted
    /// callers) opt into shadow mode by setting `observe_only: true`
    /// explicitly.
    pub observe_only: bool,
    /// Max requests per IP within the window.
    pub per_ip_limit: u64,
    /// Sliding window for per-IP counting.
    pub per_ip_window_s: u32,
    /// TTL for auto-block after breach.
    pub block_ttl_s: u64,
    /// Cluster-wide RPS multiplier to detect spikes.
    pub spike_multiplier: f64,
    /// Per-IP RPS cap during cluster spike mode. Tighter than
    /// `per_ip_limit` so a spike clamps every offender. Default 20.
    pub tightened_per_ip_rps: u64,
    /// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005): per-tier limit
    /// overrides. Schema landed in Phase G (`678baa2`); this is
    /// the runtime side that actually consumes it. Empty map (the
    /// default) means "use the global limit for every tier".
    pub tier_overrides: HashMap<Tier, DdosTierLimit>,
    /// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.8): per-tier
    /// failure mode. When the state-backend `incr_window` returns
    /// `Err(_)` (e.g. Redis unavailable, cluster split), each tier
    /// independently picks fail-close or fail-open:
    ///
    /// - `FailClose` → 503 immediately. Used for tiers that
    ///   would rather drop legitimate traffic than allow a flood
    ///   through unmetered. `Tier::Critical` is the natural
    ///   default here (login / OTP / deposit / withdrawal).
    /// - `FailOpen` → pass through with a warn log. Used for
    ///   tiers where dropping legit traffic is worse than the
    ///   flood risk (static asset paths, public health checks).
    ///
    /// Missing entry falls back to `Tier::default_failure_mode()`
    /// which is `FailClose` for `Critical` and `FailOpen` for
    /// everything else — matching the spec's "fail-close for
    /// CRITICAL, fail-open for MEDIUM / CATCH-ALL" guidance in
    /// §5.8.
    pub failure_mode: HashMap<Tier, FailureMode>,
}

impl DdosConfig {
    /// 2026-05-18 (QC Sprint 1.2): resolve the effective per-IP
    /// limit + window for `tier`. Falls back to the global values
    /// when no override is configured. `tier == None` (admin /
    /// untagged paths) also uses the global values.
    pub fn limit_for(&self, tier: Option<Tier>) -> (u64, u32) {
        match tier.and_then(|t| self.tier_overrides.get(&t)) {
            Some(l) => (l.per_ip_limit, l.per_ip_window_s),
            None => (self.per_ip_limit, self.per_ip_window_s),
        }
    }

    /// 2026-05-18 (QC Sprint 1.2): resolve the effective failure
    /// mode for `tier`. Falls back to `Tier::default_failure_mode()`
    /// when no operator override is configured.
    pub fn fail_mode_for(&self, tier: Option<Tier>) -> FailureMode {
        match tier {
            Some(t) => self
                .failure_mode
                .get(&t)
                .copied()
                .unwrap_or_else(|| t.default_failure_mode()),
            // Untagged path (admin / unknown). Treat as fail-open
            // — admin port is on a separate listener anyway.
            None => FailureMode::FailOpen,
        }
    }
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: false,
            per_ip_limit: 1000,
            per_ip_window_s: 10,
            block_ttl_s: 300,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
            tier_overrides: HashMap::new(),
            failure_mode: HashMap::new(),
        }
    }
}

impl From<aegis_core::config::DdosConfig> for DdosConfig {
    fn from(c: aegis_core::config::DdosConfig) -> Self {
        // 2026-05-18 (QC Sprint 1.2): pull the per-tier overrides
        // from the YAML config into the runtime struct. Schema for
        // `tier_overrides` already exists at aegis-core (Phase G
        // commit 678baa2) but the runtime didn't read it before
        // this commit.
        let tier_overrides: HashMap<Tier, DdosTierLimit> = c
            .tier_overrides
            .iter()
            .map(|(tier, override_cfg)| {
                let limit = DdosTierLimit {
                    per_ip_limit: override_cfg
                        .per_ip_limit
                        .unwrap_or(c.per_ip_limit),
                    per_ip_window_s: override_cfg
                        .per_ip_window_s
                        .unwrap_or(c.per_ip_window_s),
                };
                (*tier, limit)
            })
            .collect();
        Self {
            enabled: c.enabled,
            observe_only: c.observe_only,
            per_ip_limit: c.per_ip_limit,
            per_ip_window_s: c.per_ip_window_s,
            block_ttl_s: c.block_ttl_s,
            spike_multiplier: c.spike_multiplier,
            tightened_per_ip_rps: c.tightened_per_ip_rps,
            tier_overrides,
            // The fail-mode map at the WafConfig level is keyed
            // by Tier via the v2.3 `fail_mode_by_tier` schema
            // field. That lives on `WafConfig`, not `DdosConfig`,
            // so the runtime constructor in `aegis-proxy::run`
            // populates this field separately after building the
            // From. Empty map here = "use Tier::default_failure_mode()".
            failure_mode: HashMap::new(),
        }
    }
}

/// Spike-mode per-IP cap. When `spike_active`, return the tighter of the
/// normal per-window `per_ip_limit` and the spike cap derived from
/// `tightened_per_ip_rps` (an RPS → multiply by the window seconds to get a
/// per-window count). `.min` makes it tighten-only: a config where
/// `tightened × window` exceeds `per_ip_limit` is a safe no-op. When no
/// spike is active the normal limit is returned unchanged.
///
/// See `plans/issues/PLAN-ddos-spike-enforcement-2026-06-20.md` (P1).
fn spike_tightened_limit(
    cfg: &DdosConfig,
    per_ip_limit: u64,
    per_ip_window_s: u32,
    spike_active: bool,
) -> u64 {
    if !spike_active {
        return per_ip_limit;
    }
    let tightened = cfg
        .tightened_per_ip_rps
        .saturating_mul(u64::from(per_ip_window_s));
    per_ip_limit.min(tightened)
}

/// DDoS detector.
pub struct DdosDetector {
    /// Wrapped in `ArcSwap` so config hot-reload (file/etcd
    /// watcher OR audit-mutated `PUT /api/gates/ddos`) can update
    /// thresholds atomically without rebuilding the per-IP state.
    /// Matches the `IpRateLimiter` pattern.
    /// Hot-path cost: one `ArcSwap::load` per request (~5 ns).
    config: arc_swap::ArcSwap<DdosConfig>,
    /// Rolling RPS estimate (requests in current second).
    rolling_rps: AtomicU64,
    /// Average RPS baseline.
    baseline_rps: AtomicU64,
    /// Whether cluster spike mode is active.
    spike_active: AtomicU64,
    /// 2026-05-23 (perf) — in-process per-`(tier,ip)` sliding window.
    /// Replaces the per-request `StateBackend::incr_window` round-trip
    /// (the dominant WAF-overhead tail + a Redis-throughput cap at
    /// high RPS). Same proven pattern as `IpRateLimiter`. Tradeoff:
    /// counting is now PER-NODE, not cluster-wide — a flood spread
    /// thin across many nodes needs to breach each node's window. In
    /// practice an LB fans a single source IP to every node, so each
    /// node breaches independently, and the in-process per-IP
    /// rate-limiter already provides a second per-node cap.
    windows: DashMap<String, VecDeque<Instant>>,
    /// In-process auto-block cache (`ip -> expiry`). Replaces the
    /// per-request `StateBackend::is_auto_blocked` round-trip. On a
    /// fresh local breach the runtime ALSO writes the block to the
    /// backend asynchronously (fire-and-forget) so the cluster-wide
    /// block list + dashboard stay populated.
    local_blocks: DashMap<IpAddr, Instant>,
    /// Bounds the idle-key sweep to one run per `IDLE_SWEEP_INTERVAL`.
    last_sweep: Mutex<Instant>,
}

/// In-process decision from [`DdosDetector::check_local`]. Carries
/// enough for the runtime to decide enforcement + async propagation
/// without any backend round-trip on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDdosDecision {
    /// Under the per-IP window — forward.
    Allowed,
    /// IP is in the local auto-block cache from an earlier breach.
    AlreadyBlocked,
    /// This request tipped the IP over the limit. The runtime should
    /// propagate the block to the backend with this TTL.
    NewlyBlocked { ttl: Duration },
}

/// Result of DDoS check.
#[derive(Debug)]
pub struct DdosResult {
    pub blocked: bool,
    pub reason: Option<String>,
    pub spike_active: bool,
}

/// 2026-05-09 BUG-DDOS-STUB Phase 1 — runtime wrapper that bundles
/// the detector with its state-backend handle + observe-only flag.
/// This is the type the proxy data plane consults on every request.
///
/// The wrapper exists so the data-plane call site stays a single
/// `if let Some(ddos) = ...` lookup instead of needing three
/// separate fields on `ProxyContext` (detector + state backend +
/// observe-only flag) wired in lockstep.
pub struct DdosRuntime {
    detector: std::sync::Arc<DdosDetector>,
    state: std::sync::Arc<dyn aegis_core::state::StateBackend>,
}

/// Outcome of a single per-request DDoS check. Drives the data-
/// plane decision: emit audit/metrics always, 503 only when
/// [`Self::should_enforce`] returns `true`.
#[derive(Debug)]
pub struct DdosCheckOutcome {
    pub blocked: bool,
    pub reason: Option<String>,
    pub spike_active: bool,
    pub observe_only: bool,
}

impl DdosCheckOutcome {
    /// `true` when the data plane should short-circuit with 503.
    /// Always `false` in observe-only mode, even if `blocked` is
    /// `true` — observe mode emits audit + metric without
    /// changing request behaviour.
    pub fn should_enforce(&self) -> bool {
        self.blocked && !self.observe_only
    }
}

impl DdosRuntime {
    pub fn new(
        cfg: DdosConfig,
        state: std::sync::Arc<dyn aegis_core::state::StateBackend>,
    ) -> Self {
        Self {
            detector: std::sync::Arc::new(DdosDetector::new(cfg)),
            state,
        }
    }

    /// Run the per-IP check. Backend errors propagate so the
    /// caller can decide fail-open vs fail-close. Phase 1 wiring
    /// in `aegis-proxy/src/data_plane.rs` fail-opens on errors
    /// (observe-only never blocks anyway).
    ///
    /// **2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005):** this
    /// tier-agnostic shim is retained for callers that don't have
    /// a resolved tier yet. New call sites should use
    /// [`Self::check_with_tier`] so per-tier limits apply.
    pub async fn check(&self, peer_ip: IpAddr) -> aegis_core::Result<DdosCheckOutcome> {
        self.check_with_tier(peer_ip, None).await
    }

    /// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.2 #03):
    /// per-tier-aware check. `tier` is the route's resolved tier
    /// (Critical / High / Medium / Low) or `None` when called
    /// before route resolution. The detector reads the per-tier
    /// limit + window via `DdosConfig::limit_for(tier)` instead
    /// of the global values.
    /// 2026-05-23 (perf) — the per-request decision is now fully
    /// in-process: NO `StateBackend` round-trip on the hot path (was
    /// 2 — `is_auto_blocked` + `incr_window` — the dominant
    /// WAF-overhead tail and a Redis-throughput cap). On a fresh
    /// breach we propagate the auto-block to the backend
    /// asynchronously (fire-and-forget) so the cluster block list +
    /// dashboard stay populated without blocking the request. Returns
    /// `Result` for signature stability (the in-process path can't
    /// fail like a backend call); callers' fail-mode branches are now
    /// effectively unreachable.
    pub async fn check_with_tier(
        &self,
        peer_ip: IpAddr,
        tier: Option<Tier>,
    ) -> aegis_core::Result<DdosCheckOutcome> {
        let cfg = self.detector.config_snapshot();
        let observe_only = cfg.observe_only;
        if !cfg.enabled {
            return Ok(DdosCheckOutcome {
                blocked: false,
                reason: None,
                spike_active: false,
                observe_only,
            });
        }

        let decision = self.detector.check_local(peer_ip, tier, Instant::now());
        let spike_active = self.detector.is_spike_active();

        let (blocked, reason) = match decision {
            LocalDdosDecision::Allowed => (false, None),
            LocalDdosDecision::AlreadyBlocked => {
                (true, Some(format!("auto-blocked IP: {peer_ip}")))
            }
            LocalDdosDecision::NewlyBlocked { ttl } => {
                // Cluster propagation — durability + dashboard block
                // list. Fire-and-forget: never on the request's
                // critical path.
                let state = std::sync::Arc::clone(&self.state);
                tokio::spawn(async move {
                    if let Err(e) = state.auto_block(peer_ip, ttl).await {
                        tracing::warn!(
                            ip = %peer_ip,
                            error = %e,
                            "ddos: async auto_block propagation failed",
                        );
                    }
                });
                (
                    true,
                    Some(format!(
                        "IP {peer_ip} exceeded per-IP burst limit; blocked for {} s",
                        ttl.as_secs()
                    )),
                )
            }
        };

        Ok(DdosCheckOutcome {
            blocked,
            reason,
            spike_active,
            observe_only,
        })
    }

    /// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.8): resolve
    /// the failure mode for `tier`. Used by the data-plane caller
    /// to decide what to do when `check_with_tier` returns
    /// `Err(_)` — Critical-tier requests fail-close (503),
    /// everything else fails-open with a warn log.
    pub fn fail_mode_for(&self, tier: Option<Tier>) -> FailureMode {
        self.detector.config_snapshot().fail_mode_for(tier)
    }

    pub fn tick_rps(&self) {
        self.detector.tick_rps();
    }

    pub fn observe_only(&self) -> bool {
        self.detector.config_snapshot().observe_only
    }

    /// Snapshot the live config — drives the GET /api/gates/ddos
    /// payload and the audit-mutated PUT's "before" view.
    pub fn config_snapshot(&self) -> DdosConfig {
        self.detector.config_snapshot()
    }

    /// Hot-swap the config. Audit-mutated `PUT /api/gates/ddos`
    /// calls this through the `AuditedMutate` pipeline so every
    /// edit is captured in the audit chain. Per-IP StateBackend
    /// state is preserved — operators editing thresholds don't
    /// reset every flooding source IP.
    pub fn set_config(&self, cfg: DdosConfig) {
        self.detector.set_config(cfg);
    }

    pub fn current_rps(&self) -> u64 {
        self.detector.current_rps()
    }

    pub fn baseline_rps(&self) -> u64 {
        self.detector.baseline_rps()
    }

    pub fn is_spike_active(&self) -> bool {
        self.detector.is_spike_active()
    }

    /// 2026-05-20 — clear temporary spike-detection state on
    /// `/__waf_control/reset_state`. Forwards to
    /// [`DdosDetector::reset`]. Durable config is preserved.
    pub fn reset(&self) {
        self.detector.reset();
    }
}

impl DdosDetector {
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config: arc_swap::ArcSwap::from_pointee(config),
            rolling_rps: AtomicU64::new(0),
            baseline_rps: AtomicU64::new(100),
            spike_active: AtomicU64::new(0),
            windows: DashMap::new(),
            local_blocks: DashMap::new(),
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    /// 2026-05-23 (perf) — in-process per-IP check. No backend
    /// round-trip: reads the local auto-block cache, then the
    /// in-process sliding window. Caller must have already confirmed
    /// `cfg.enabled` (the runtime short-circuits on disabled). The
    /// `now` seam lets unit tests drive window-edge behaviour
    /// deterministically.
    pub fn check_local(
        &self,
        ip: IpAddr,
        tier: Option<Tier>,
        now: Instant,
    ) -> LocalDdosDecision {
        let cfg = self.config.load();

        // 1. Local auto-block cache. Copy the expiry out before
        // touching the map again so we don't hold a read guard across
        // a remove (DashMap would deadlock on the same shard).
        if let Some(expiry) = self.local_blocks.get(&ip).map(|e| *e.value()) {
            if now < expiry {
                return LocalDdosDecision::AlreadyBlocked;
            }
            self.local_blocks.remove(&ip);
        }

        // 2. In-process sliding window, keyed per (tier, ip) so a
        // tight Critical-tier quota doesn't auto-block an IP's Low
        // static-asset traffic — mirrors the old backend key.
        let (per_ip_limit, per_ip_window_s) = cfg.limit_for(tier);
        // Spike enforcement (plans/issues/PLAN-ddos-spike-enforcement):
        // when spike-mode is active, clamp the per-IP window count to the
        // tightened cap (`tightened_per_ip_rps` is an RPS, convert to a
        // per-window count). `.min` so it only ever tightens — a
        // misconfigured `tightened×window > per_ip_limit` is a safe no-op.
        let per_ip_limit = spike_tightened_limit(&cfg, per_ip_limit, per_ip_window_s, self.is_spike_active());
        let window = Duration::from_secs(u64::from(per_ip_window_s));
        let tier_str = tier.map(|t| t.as_str()).unwrap_or("none");
        let key = format!("{tier_str}:{ip}");
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let mut entry = self.windows.entry(key).or_default();
        while let Some(&t) = entry.front() {
            if t < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }

        if entry.len() as u64 >= per_ip_limit {
            // Breach. Don't push (measure would-have rate, like the
            // rate limiter) — record the block locally.
            drop(entry);
            let ttl = Duration::from_secs(cfg.block_ttl_s);
            self.local_blocks
                .insert(ip, now.checked_add(ttl).unwrap_or(now));
            self.maybe_sweep(now);
            return LocalDdosDecision::NewlyBlocked { ttl };
        }

        entry.push_back(now);
        drop(entry);
        self.rolling_rps.fetch_add(1, Ordering::Relaxed);
        self.maybe_sweep(now);
        LocalDdosDecision::Allowed
    }

    /// Bounded idle-key sweep — at most one run per
    /// `IDLE_SWEEP_INTERVAL` (one mutex try-lock amortised on the hot
    /// path). Drops window keys idle for > 2× their window and
    /// expired local auto-blocks.
    fn maybe_sweep(&self, now: Instant) {
        let mut guard = match self.last_sweep.try_lock() {
            Some(g) => g,
            None => return,
        };
        if now.saturating_duration_since(*guard) < IDLE_SWEEP_INTERVAL {
            return;
        }
        *guard = now;
        drop(guard);

        let stale_after =
            Duration::from_secs(u64::from(self.config.load().per_ip_window_s)) * 2;
        self.windows.retain(|_, deque| match deque.back() {
            Some(&latest) => now.saturating_duration_since(latest) < stale_after,
            None => false,
        });
        self.local_blocks.retain(|_, &mut expiry| expiry > now);
    }

    /// Number of IPs currently tracked in the sliding-window map —
    /// useful for metrics / introspection.
    pub fn tracked(&self) -> usize {
        self.windows.len()
    }

    /// 2026-05-09 — hot-swap the detector config. Keeps the
    /// per-IP StateBackend window state intact (operators editing
    /// thresholds via PUT /api/gates/ddos don't accidentally
    /// reset every flooding source IP back to zero counts). The
    /// new thresholds apply on the next `check()` call. Matches
    /// the `IpRateLimiter::set_config` shape.
    pub fn set_config(&self, config: DdosConfig) {
        self.config.store(std::sync::Arc::new(config));
    }

    /// Snapshot the live config (for read-back via the GET API).
    pub fn config_snapshot(&self) -> DdosConfig {
        (**self.config.load()).clone()
    }

    /// Check if an IP should be blocked.
    ///
    /// **2026-05-18 (QC Sprint 1.2):** retained for callers without
    /// a resolved tier — forwards to [`Self::check_with_tier`] with
    /// `None`, which falls back to the global limit.
    pub async fn check(
        &self,
        state: &dyn StateBackend,
        ip: IpAddr,
    ) -> aegis_core::Result<DdosResult> {
        self.check_with_tier(state, ip, None).await
    }

    /// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.2 #03):
    /// per-tier-aware check. The sliding-window key includes the
    /// tier so the per-tier override applies cleanly without
    /// retroactively re-keying existing buckets when the operator
    /// flips a tier override on/off.
    ///
    /// Behaviour:
    /// 1. Auto-block lookup is unchanged (per-IP, not per-tier).
    /// 2. Sliding-window key = `ddos:ip:<tier?>:<ip>`. Per-tier
    ///    overrides are read via `DdosConfig::limit_for(tier)`.
    /// 3. Auto-block on breach is unchanged (per-IP, with the
    ///    global block_ttl_s).
    pub async fn check_with_tier(
        &self,
        state: &dyn StateBackend,
        ip: IpAddr,
        tier: Option<Tier>,
    ) -> aegis_core::Result<DdosResult> {
        let cfg = self.config.load();
        // 2026-05-19 — hot-flippable enable/disable. The runtime is
        // always installed at boot (see aegis-proxy::run); whether
        // the gate actually enforces is decided here at decision
        // time so PUT /api/gates/ddos { enabled: false } takes
        // effect without a restart. Returning a clean (non-blocked,
        // no-spike) result keeps the downstream audit/telemetry
        // paths in their "happy" branch — no false ddos events.
        if !cfg.enabled {
            return Ok(DdosResult {
                blocked: false,
                reason: None,
                spike_active: false,
            });
        }
        // 1. Check if already auto-blocked. Per-IP — tier doesn't
        // change who's blocked, only how fast they got blocked.
        if state.is_auto_blocked(ip).await? {
            return Ok(DdosResult {
                blocked: true,
                reason: Some(format!("auto-blocked IP: {ip}")),
                spike_active: self.is_spike_active(),
            });
        }

        // 2. Sliding window per-IP-per-tier. Tier suffix in the
        // key segregates buckets so an IP burning through the
        // `Critical` tier's tight quota doesn't auto-block its
        // `Low` tier static-asset requests.
        let (per_ip_limit, per_ip_window_s) = cfg.limit_for(tier);
        // Parity with `check_local` — spike-tighten the per-IP cap so
        // enforcement is identical regardless of which backend is enabled.
        let per_ip_limit = spike_tightened_limit(&cfg, per_ip_limit, per_ip_window_s, self.is_spike_active());
        let tier_str = tier.map(|t| t.as_str()).unwrap_or("none");
        let key = format!("ddos:ip:{tier_str}:{ip}");
        let window = Duration::from_secs(u64::from(per_ip_window_s));
        let result = state.incr_window(&key, window, per_ip_limit).await?;

        if !result.allowed {
            // Auto-block. The TTL is global — once an IP is bad
            // enough to flood ANY tier, ban it across the board.
            let ttl = Duration::from_secs(cfg.block_ttl_s);
            state.auto_block(ip, ttl).await?;
            return Ok(DdosResult {
                blocked: true,
                reason: Some(format!(
                    "IP {ip} exceeded {per_ip_limit}/{per_ip_window_s} s \
                     on tier {tier_str}; blocked for {} s",
                    cfg.block_ttl_s
                )),
                spike_active: self.is_spike_active(),
            });
        }

        // 3. Bump rolling RPS.
        self.rolling_rps.fetch_add(1, Ordering::Relaxed);

        Ok(DdosResult {
            blocked: false,
            reason: None,
            spike_active: self.is_spike_active(),
        })
    }

    /// Update cluster spike detection.  Called periodically (e.g. every second).
    pub fn tick_rps(&self) {
        let cfg = self.config.load();
        // 2026-05-19 — when the gate is hot-disabled, freeze the
        // EWMA. We zero `rolling_rps` so the counter doesn't keep
        // accumulating across the disabled window, but leave
        // `baseline_rps` / `spike_active` untouched — the next
        // re-enable starts from the prior steady-state instead of
        // re-warming for ~30 ticks.
        if !cfg.enabled {
            self.rolling_rps.store(0, Ordering::Relaxed);
            self.spike_active.store(0, Ordering::Relaxed);
            return;
        }
        let current = self.rolling_rps.swap(0, Ordering::Relaxed);
        let baseline = self.baseline_rps.load(Ordering::Relaxed);

        // EWMA update: baseline = 0.9 * baseline + 0.1 * current
        let new_baseline = ((baseline as f64) * 0.9 + (current as f64) * 0.1) as u64;
        self.baseline_rps.store(new_baseline.max(1), Ordering::Relaxed);

        let threshold = (baseline as f64 * cfg.spike_multiplier) as u64;
        if current > threshold && baseline > 10 {
            self.spike_active.store(1, Ordering::Relaxed);
        } else {
            self.spike_active.store(0, Ordering::Relaxed);
        }
    }

    /// Whether cluster spike mode is currently active.
    pub fn is_spike_active(&self) -> bool {
        self.spike_active.load(Ordering::Relaxed) != 0
    }

    /// Current rolling RPS.
    pub fn current_rps(&self) -> u64 {
        self.rolling_rps.load(Ordering::Relaxed)
    }

    /// Baseline RPS.
    pub fn baseline_rps(&self) -> u64 {
        self.baseline_rps.load(Ordering::Relaxed)
    }

    /// 2026-05-20 — clear the temporary spike-detection state for
    /// `/__waf_control/reset_state` (committee item 6, "temporary
    /// enforcement state"). Resets `rolling_rps` + `spike_active`
    /// to zero and `baseline_rps` to the cold-start default so the
    /// next benchmark run re-warms from a clean slate. Config
    /// (thresholds, enabled flag) is left intact — it's durable.
    /// 2026-05-23 — also clears the in-process sliding-window +
    /// local auto-block maps (they moved off the StateBackend onto
    /// the detector), so a reset truly starts from a clean slate.
    pub fn reset(&self) {
        self.rolling_rps.store(0, Ordering::Relaxed);
        self.spike_active.store(0, Ordering::Relaxed);
        self.baseline_rps.store(100, Ordering::Relaxed);
        self.windows.clear();
        self.local_blocks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    struct MockState {
        windows: Mutex<HashMap<String, (u64, Instant)>>,
        blocked: Mutex<HashMap<String, ()>>,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                windows: Mutex::new(HashMap::new()),
                blocked: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for MockState {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, key: &str, window: Duration, limit: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            let mut map = self.windows.lock().unwrap();
            let now = Instant::now();
            let entry = map.entry(key.to_string()).or_insert((0, now));
            if now.duration_since(entry.1) > window {
                entry.0 = 0;
                entry.1 = now;
            }
            entry.0 += 1;
            let count = entry.0;
            let allowed = count <= limit;
            Ok(aegis_core::SlidingWindowResult {
                count,
                allowed,
                retry_after: if allowed { None } else { Some(window) },
            })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, ip: IpAddr, _t: Duration) -> aegis_core::Result<()> {
            self.blocked.lock().unwrap().insert(ip.to_string(), ());
            Ok(())
        }
        async fn is_auto_blocked(&self, ip: IpAddr) -> aegis_core::Result<bool> {
            Ok(self.blocked.lock().unwrap().contains_key(&ip.to_string()))
        }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
    }

    #[tokio::test]
    async fn normal_traffic_allowed() {
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(DdosConfig::default());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let r = detector.check(state.as_ref(), ip).await.unwrap();
        assert!(!r.blocked);
    }

    #[tokio::test]
    async fn exceed_per_ip_limit_blocks() {
        let cfg = DdosConfig {
            per_ip_limit: 5,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            ..Default::default()
        };
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(cfg);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        for _ in 0..5 {
            let r = detector.check(state.as_ref(), ip).await.unwrap();
            assert!(!r.blocked);
        }
        // 6th should block.
        let r = detector.check(state.as_ref(), ip).await.unwrap();
        assert!(r.blocked);
        assert!(r.reason.unwrap().contains("exceeded"));
    }

    #[tokio::test]
    async fn auto_blocked_ip_stays_blocked() {
        let cfg = DdosConfig {
            per_ip_limit: 2,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            ..Default::default()
        };
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(cfg);
        let ip: IpAddr = "10.0.0.3".parse().unwrap();

        // Exhaust limit.
        for _ in 0..3 {
            detector.check(state.as_ref(), ip).await.unwrap();
        }
        // Should be auto-blocked on next check.
        let r = detector.check(state.as_ref(), ip).await.unwrap();
        assert!(r.blocked);
        assert!(r.reason.unwrap().contains("auto-blocked"));
    }

    #[test]
    fn spike_detection() {
        let cfg = DdosConfig {
            spike_multiplier: 2.0,
            ..Default::default()
        };
        let detector = DdosDetector::new(cfg);
        // Set a baseline.
        detector.baseline_rps.store(100, Ordering::Relaxed);

        // Normal traffic — no spike.
        detector.rolling_rps.store(150, Ordering::Relaxed);
        detector.tick_rps();
        assert!(!detector.is_spike_active());

        // Spike traffic — 3x baseline.
        detector.baseline_rps.store(100, Ordering::Relaxed);
        detector.rolling_rps.store(300, Ordering::Relaxed);
        detector.tick_rps();
        assert!(detector.is_spike_active());
    }

    #[test]
    fn spike_clears_when_traffic_drops() {
        let cfg = DdosConfig {
            spike_multiplier: 2.0,
            ..Default::default()
        };
        let detector = DdosDetector::new(cfg);
        detector.baseline_rps.store(100, Ordering::Relaxed);

        // Trigger spike.
        detector.rolling_rps.store(300, Ordering::Relaxed);
        detector.tick_rps();
        assert!(detector.is_spike_active());

        // Normal traffic.
        detector.rolling_rps.store(50, Ordering::Relaxed);
        detector.tick_rps();
        assert!(!detector.is_spike_active());
    }

    // ── Spike enforcement (GAP: tightened_per_ip_rps was dead config) ──
    // plans/issues/PLAN-ddos-spike-enforcement-2026-06-20.md (P1)

    /// When spike-mode is active, the per-IP block threshold must drop to
    /// `tightened_per_ip_rps × per_ip_window_s` (tighten-only). Today the
    /// in-process gate ignores `tightened_per_ip_rps` entirely.
    #[test]
    fn spike_active_tightens_check_local_block_threshold() {
        let cfg = DdosConfig {
            per_ip_limit: 1000,        // normal: very loose
            per_ip_window_s: 10,
            tightened_per_ip_rps: 2,   // spike cap = 2 × 10s = 20 / window
            block_ttl_s: 60,
            ..Default::default()
        };
        let detector = DdosDetector::new(cfg);
        detector.spike_active.store(1, Ordering::Relaxed); // force spike

        let ip: IpAddr = "10.1.0.1".parse().unwrap();
        let now = Instant::now();
        // 20 requests in-window are allowed under the tightened cap …
        for i in 0..20 {
            assert_eq!(
                detector.check_local(ip, None, now),
                LocalDdosDecision::Allowed,
                "request {i} should be allowed under the tightened cap (20)"
            );
        }
        // … the 21st trips the tightened threshold (well under per_ip_limit).
        assert!(
            matches!(
                detector.check_local(ip, None, now),
                LocalDdosDecision::NewlyBlocked { .. }
            ),
            "21st request must block under the spike-tightened cap"
        );
    }

    /// Companion: with no spike, the same rate is allowed — tightening is
    /// spike-gated, never applied to steady-state traffic.
    #[test]
    fn no_spike_leaves_per_ip_limit_untightened() {
        let cfg = DdosConfig {
            per_ip_limit: 1000,
            per_ip_window_s: 10,
            tightened_per_ip_rps: 2, // would be 20/window IF spike were active
            block_ttl_s: 60,
            ..Default::default()
        };
        let detector = DdosDetector::new(cfg);
        // spike_active stays 0.
        let ip: IpAddr = "10.1.0.2".parse().unwrap();
        let now = Instant::now();
        for i in 0..21 {
            assert_eq!(
                detector.check_local(ip, None, now),
                LocalDdosDecision::Allowed,
                "request {i} must be allowed when no spike is active (cap is 1000)"
            );
        }
    }

    /// Parity: the Redis/StateBackend path (`check_with_tier`) must tighten
    /// identically so enforcement is backend-agnostic.
    #[tokio::test]
    async fn spike_active_tightens_redis_check_with_tier() {
        let cfg = DdosConfig {
            per_ip_limit: 1000,
            per_ip_window_s: 10,
            tightened_per_ip_rps: 2, // spike cap = 20 / window
            block_ttl_s: 60,
            ..Default::default()
        };
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(cfg);
        detector.spike_active.store(1, Ordering::Relaxed);
        let ip: IpAddr = "10.1.0.3".parse().unwrap();

        for i in 0..20 {
            let r = detector.check_with_tier(state.as_ref(), ip, None).await.unwrap();
            assert!(!r.blocked, "request {i} should be allowed under tightened cap");
        }
        let r = detector.check_with_tier(state.as_ref(), ip, None).await.unwrap();
        assert!(
            r.blocked,
            "21st request must block under the spike-tightened cap on the Redis path"
        );
    }

    /// Composition: spike tightening must NOT turn a shadow gate into an
    /// enforcing one. With `observe_only`, a tightened breach is recorded
    /// (`blocked`) but `enforced()` stays false.
    #[tokio::test]
    async fn observe_only_with_spike_still_only_observes() {
        let cfg = DdosConfig {
            per_ip_limit: 1000,
            per_ip_window_s: 10,
            tightened_per_ip_rps: 2,
            block_ttl_s: 60,
            observe_only: true,
            ..Default::default()
        };
        let state: Arc<dyn StateBackend> = Arc::new(MockState::new());
        let runtime = DdosRuntime::new(cfg, state);
        runtime.detector.spike_active.store(1, Ordering::Relaxed);
        let ip: IpAddr = "10.1.0.4".parse().unwrap();

        // Breach the tightened cap.
        let mut last = None;
        for _ in 0..25 {
            last = Some(runtime.check_with_tier(ip, None).await.unwrap());
        }
        let outcome = last.unwrap();
        assert!(outcome.blocked, "tightened breach must be recorded as blocked");
        assert!(
            !outcome.should_enforce(),
            "observe_only must keep should_enforce() false even under spike tightening"
        );
    }

    // 2026-05-20 — reset_state committee item 6. reset() must
    // clear the temporary enforcement atomics but leave config
    // (thresholds, enabled flag) intact.
    #[test]
    fn reset_clears_spike_state_but_preserves_config() {
        let cfg = DdosConfig {
            spike_multiplier: 2.0,
            per_ip_limit: 4242,
            ..Default::default()
        };
        let detector = DdosDetector::new(cfg);
        detector.baseline_rps.store(900, Ordering::Relaxed);
        detector.rolling_rps.store(5000, Ordering::Relaxed);
        detector.tick_rps();
        assert!(detector.is_spike_active(), "precondition: spike active");

        detector.reset();

        assert!(!detector.is_spike_active(), "spike_active should clear");
        assert_eq!(detector.current_rps(), 0, "rolling_rps should clear");
        assert_eq!(detector.baseline_rps(), 100, "baseline resets to cold-start");
        // Durable config untouched.
        assert_eq!(detector.config_snapshot().per_ip_limit, 4242);
        assert_eq!(detector.config_snapshot().spike_multiplier, 2.0);
    }

    #[test]
    fn ewma_baseline_update() {
        let detector = DdosDetector::new(DdosConfig::default());
        detector.baseline_rps.store(100, Ordering::Relaxed);
        detector.rolling_rps.store(200, Ordering::Relaxed);
        detector.tick_rps();
        // 0.9 * 100 + 0.1 * 200 = 110
        assert_eq!(detector.baseline_rps(), 110);
    }

    // 2026-05-09 BUG-DDOS-STUB Phase 1 — DdosRuntime wrapper tests.

    #[tokio::test]
    async fn runtime_observe_only_returns_blocked_but_should_not_enforce() {
        // Tight per-IP cap so the detector trips fast.
        let cfg = DdosConfig {
            enabled: true,
            observe_only: true,
            per_ip_limit: 3,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
        tier_overrides: HashMap::new(),
        failure_mode: HashMap::new(),
        };
        let state: Arc<dyn aegis_core::state::StateBackend> = Arc::new(MockState::new());
        let runtime = DdosRuntime::new(cfg, state);
        let ip: IpAddr = "10.0.0.42".parse().unwrap();

        // Exhaust the limit. After the cap is exceeded, blocked
        // turns true but observe-only must keep should_enforce()
        // returning false so the data plane never 503s.
        let mut tripped = false;
        for _ in 0..6 {
            let outcome = runtime.check(ip).await.unwrap();
            if outcome.blocked {
                tripped = true;
                assert!(
                    !outcome.should_enforce(),
                    "observe-only must never enforce, even when blocked",
                );
                assert!(outcome.observe_only);
            }
        }
        assert!(tripped, "expected the detector to trip under burst");
    }

    #[tokio::test]
    async fn runtime_enforce_mode_returns_should_enforce_when_blocked() {
        let cfg = DdosConfig {
            enabled: true,
            observe_only: false, // Phase 2 mode
            per_ip_limit: 2,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
        tier_overrides: HashMap::new(),
        failure_mode: HashMap::new(),
        };
        let state: Arc<dyn aegis_core::state::StateBackend> = Arc::new(MockState::new());
        let runtime = DdosRuntime::new(cfg, state);
        let ip: IpAddr = "10.0.0.43".parse().unwrap();

        let mut enforced = false;
        for _ in 0..5 {
            let outcome = runtime.check(ip).await.unwrap();
            if outcome.blocked {
                assert!(!outcome.observe_only);
                assert!(outcome.should_enforce(), "enforce mode + blocked → should_enforce");
                enforced = true;
            }
        }
        assert!(enforced);
    }

    #[tokio::test]
    async fn runtime_clean_traffic_under_limit_does_not_block() {
        let cfg = DdosConfig::default(); // generous defaults
        let state: Arc<dyn aegis_core::state::StateBackend> = Arc::new(MockState::new());
        let runtime = DdosRuntime::new(cfg, state);
        let ip: IpAddr = "10.0.0.44".parse().unwrap();

        for _ in 0..50 {
            let outcome = runtime.check(ip).await.unwrap();
            assert!(!outcome.blocked, "50 reqs is well under the 1000-req default cap");
            assert!(!outcome.should_enforce());
        }
    }

    #[test]
    fn runtime_from_core_config_round_trip() {
        // Verifies the From<aegis_core::config::DdosConfig> impl
        // doesn't drop fields silently.
        let core_cfg = aegis_core::config::DdosConfig {
            enabled: false,
            observe_only: false,
            per_ip_limit: 42,
            per_ip_window_s: 7,
            block_ttl_s: 9,
            spike_multiplier: 4.0,
            tightened_per_ip_rps: 11,
            tier_overrides: std::collections::HashMap::new(),
        };
        let sec_cfg: DdosConfig = core_cfg.clone().into();
        assert_eq!(sec_cfg.enabled, false);
        assert_eq!(sec_cfg.observe_only, false);
        assert_eq!(sec_cfg.per_ip_limit, 42);
        assert_eq!(sec_cfg.per_ip_window_s, 7);
        assert_eq!(sec_cfg.block_ttl_s, 9);
        assert!((sec_cfg.spike_multiplier - 4.0).abs() < 1e-9);
        assert_eq!(sec_cfg.tightened_per_ip_rps, 11);
    }

    // ---- 2026-05-18 QC Sprint 1.2 (F-CRITICAL-005) — per-tier ----

    /// `limit_for(Some(Critical))` reads the per-tier override
    /// when configured, falls back to the global limit otherwise.
    #[test]
    fn limit_for_returns_per_tier_override() {
        let mut cfg = DdosConfig::default();
        cfg.per_ip_limit = 1000;
        cfg.per_ip_window_s = 10;
        cfg.tier_overrides.insert(
            Tier::Critical,
            DdosTierLimit {
                per_ip_limit: 50,
                per_ip_window_s: 10,
            },
        );

        // Critical uses the override.
        assert_eq!(cfg.limit_for(Some(Tier::Critical)), (50, 10));
        // Low falls back to the global.
        assert_eq!(cfg.limit_for(Some(Tier::Low)), (1000, 10));
        // None also falls back.
        assert_eq!(cfg.limit_for(None), (1000, 10));
    }

    /// `fail_mode_for(Some(Critical))` defaults to FailClose
    /// (`Tier::default_failure_mode`) when no override; returns
    /// the override when configured.
    #[test]
    fn fail_mode_for_defaults_per_tier() {
        let cfg = DdosConfig::default();
        // No override → Tier defaults.
        assert_eq!(cfg.fail_mode_for(Some(Tier::Critical)), FailureMode::FailClose);
        assert_eq!(cfg.fail_mode_for(Some(Tier::High)), FailureMode::FailOpen);
        assert_eq!(cfg.fail_mode_for(Some(Tier::Medium)), FailureMode::FailOpen);
        assert_eq!(cfg.fail_mode_for(Some(Tier::Low)), FailureMode::FailOpen);
        // None → FailOpen (admin / untagged).
        assert_eq!(cfg.fail_mode_for(None), FailureMode::FailOpen);
    }

    #[test]
    fn fail_mode_for_honors_operator_override() {
        let mut cfg = DdosConfig::default();
        cfg.failure_mode.insert(Tier::High, FailureMode::FailClose);
        // High is now FailClose by operator.
        assert_eq!(cfg.fail_mode_for(Some(Tier::High)), FailureMode::FailClose);
        // Critical untouched, still FailClose (was default).
        assert_eq!(cfg.fail_mode_for(Some(Tier::Critical)), FailureMode::FailClose);
        // Low untouched, still FailOpen.
        assert_eq!(cfg.fail_mode_for(Some(Tier::Low)), FailureMode::FailOpen);
    }

    /// `check_with_tier` keys the sliding window by tier, so the
    /// Critical bucket exhausting doesn't take the Low bucket
    /// with it. Operator's "tight per-Critical, loose per-Low"
    /// posture works without retroactive bucket merging.
    #[tokio::test]
    async fn check_with_tier_uses_separate_buckets_per_tier() {
        let mut cfg = DdosConfig::default();
        cfg.per_ip_limit = 5;
        cfg.per_ip_window_s = 10;
        cfg.tier_overrides.insert(
            Tier::Critical,
            DdosTierLimit {
                per_ip_limit: 2,
                per_ip_window_s: 10,
            },
        );
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(cfg);
        let ip: IpAddr = "10.0.0.42".parse().unwrap();

        // Burn the Critical bucket (limit 2).
        for _ in 0..2 {
            let r = detector
                .check_with_tier(state.as_ref(), ip, Some(Tier::Critical))
                .await
                .unwrap();
            assert!(!r.blocked, "first 2 critical reqs allowed");
        }
        let r = detector
            .check_with_tier(state.as_ref(), ip, Some(Tier::Critical))
            .await
            .unwrap();
        // 3rd Critical request — over the per-tier limit. Blocked.
        assert!(r.blocked, "3rd critical req must block");

        // The Critical breach autoblocks the IP globally, so Low is
        // also blocked now (autoblock is per-IP, not per-tier).
        // That's intentional — once an IP is bad, it's bad everywhere.
        let r = detector
            .check_with_tier(state.as_ref(), ip, Some(Tier::Low))
            .await
            .unwrap();
        assert!(r.blocked, "auto-block applies cross-tier");
    }

    /// A fresh IP at Low tier can consume the global limit without
    /// being affected by a different IP's Critical-tier breach.
    #[tokio::test]
    async fn check_with_tier_isolates_distinct_ips() {
        let mut cfg = DdosConfig::default();
        cfg.per_ip_limit = 3;
        cfg.per_ip_window_s = 10;
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(cfg);

        let bad: IpAddr = "10.0.0.5".parse().unwrap();
        let good: IpAddr = "10.0.0.6".parse().unwrap();
        // Burn bad's quota.
        for _ in 0..3 {
            let _ = detector
                .check_with_tier(state.as_ref(), bad, Some(Tier::Critical))
                .await
                .unwrap();
        }
        let r = detector
            .check_with_tier(state.as_ref(), bad, Some(Tier::Critical))
            .await
            .unwrap();
        assert!(r.blocked);

        // Good IP is unaffected.
        let r = detector
            .check_with_tier(state.as_ref(), good, Some(Tier::Critical))
            .await
            .unwrap();
        assert!(!r.blocked);
    }

    /// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005): the `From`
    /// impl carries `tier_overrides` from `aegis_core::config::DdosConfig`
    /// (where the schema lives) into the runtime struct.
    #[test]
    fn from_core_config_carries_tier_overrides() {
        let mut core_cfg = aegis_core::config::DdosConfig {
            enabled: true,
            observe_only: false,
            per_ip_limit: 1000,
            per_ip_window_s: 10,
            block_ttl_s: 300,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
            tier_overrides: std::collections::HashMap::new(),
        };
        core_cfg.tier_overrides.insert(
            Tier::Critical,
            aegis_core::config::DdosTierConfig {
                per_ip_limit: Some(50),
                per_ip_window_s: Some(10),
                ..Default::default()
            },
        );

        let runtime_cfg: DdosConfig = core_cfg.into();
        let limit = runtime_cfg
            .tier_overrides
            .get(&Tier::Critical)
            .expect("critical override carried through");
        assert_eq!(limit.per_ip_limit, 50);
        assert_eq!(limit.per_ip_window_s, 10);
    }

    // ---- 2026-05-19 — hot-flippable cfg.enabled ----

    /// With `enabled = false`, even a hot bucket that *would*
    /// trip the per-IP cap returns `blocked = false`. Mirrors
    /// the dashboard PUT { enabled: false } operator flow.
    #[tokio::test]
    async fn check_with_tier_returns_unblocked_when_disabled() {
        let cfg = DdosConfig {
            enabled: false,
            // Tight limit — if the gate were enforcing, request #2
            // would block. The test proves the cap is bypassed.
            per_ip_limit: 1,
            per_ip_window_s: 10,
            ..Default::default()
        };
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(cfg);
        let ip: IpAddr = "10.0.0.50".parse().unwrap();
        for _ in 0..10 {
            let r = detector
                .check_with_tier(state.as_ref(), ip, Some(Tier::Critical))
                .await
                .unwrap();
            assert!(!r.blocked, "disabled gate must never block");
            assert!(!r.spike_active, "disabled gate must report no spike");
            assert!(r.reason.is_none());
        }
    }

    /// Disable → enable round-trip via `set_config`: requests pass
    /// while disabled, then start enforcing once enabled flips
    /// back. Per-IP window state survives the swap (operator
    /// tightening doesn't reset every flooding source IP).
    #[tokio::test]
    async fn set_config_hot_flip_enables_and_disables_in_place() {
        let base = DdosConfig {
            enabled: true,
            per_ip_limit: 2,
            per_ip_window_s: 60,
            ..Default::default()
        };
        let state = Arc::new(MockState::new());
        let detector = DdosDetector::new(base.clone());
        let ip: IpAddr = "10.0.0.51".parse().unwrap();

        // 1. Disable. Burst freely.
        detector.set_config(DdosConfig {
            enabled: false,
            ..base.clone()
        });
        for _ in 0..20 {
            let r = detector
                .check_with_tier(state.as_ref(), ip, Some(Tier::Low))
                .await
                .unwrap();
            assert!(!r.blocked, "burst under disabled gate must pass");
        }

        // 2. Re-enable. From a *fresh* IP so the test isolates the
        //    flip behaviour from the lingering MockState counter
        //    accumulated above. (The autoblock side-effect of the
        //    enabled-side cap is exercised by other tests.)
        detector.set_config(base.clone());
        let fresh: IpAddr = "10.0.0.52".parse().unwrap();
        let r1 = detector
            .check_with_tier(state.as_ref(), fresh, Some(Tier::Low))
            .await
            .unwrap();
        assert!(!r1.blocked, "first req under enabled gate allowed");
        let r2 = detector
            .check_with_tier(state.as_ref(), fresh, Some(Tier::Low))
            .await
            .unwrap();
        assert!(!r2.blocked, "second req still under cap");
        let r3 = detector
            .check_with_tier(state.as_ref(), fresh, Some(Tier::Low))
            .await
            .unwrap();
        assert!(r3.blocked, "third req exceeds the per_ip_limit=2 cap");
    }

    /// `tick_rps` freezes the EWMA while disabled: rolling counts
    /// drain, spike flag clears, but baseline doesn't decay so the
    /// next re-enable resumes from the prior steady state.
    #[test]
    fn tick_rps_freezes_ewma_when_disabled() {
        let detector = DdosDetector::new(DdosConfig {
            enabled: false,
            spike_multiplier: 2.0,
            ..Default::default()
        });
        detector.baseline_rps.store(500, Ordering::Relaxed);
        detector.rolling_rps.store(9_999, Ordering::Relaxed);
        detector.spike_active.store(1, Ordering::Relaxed);

        detector.tick_rps();

        assert_eq!(detector.baseline_rps(), 500, "baseline preserved across disabled tick");
        assert_eq!(detector.current_rps(), 0, "rolling drained");
        assert!(!detector.is_spike_active(), "spike cleared while disabled");
    }

    // ---- 2026-05-23 in-process counting (check_local) ----

    /// Deterministic window-edge + expiry test via the `now` seam:
    /// allowed under the limit, breach AT the limit, stays blocked
    /// until the TTL expires, then (once the window also rolls off)
    /// allowed again.
    #[test]
    fn check_local_blocks_at_limit_then_expires() {
        let cfg = DdosConfig {
            per_ip_limit: 3,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            ..Default::default()
        };
        let d = DdosDetector::new(cfg);
        let ip: IpAddr = "10.1.0.1".parse().unwrap();
        let t0 = Instant::now();

        // 3 allowed within the window.
        for i in 0..3 {
            assert_eq!(
                d.check_local(ip, None, t0 + Duration::from_millis(i * 10)),
                LocalDdosDecision::Allowed,
                "request {i} under limit must be allowed",
            );
        }
        // 4th tips over → newly blocked with the configured TTL.
        assert_eq!(
            d.check_local(ip, None, t0 + Duration::from_millis(40)),
            LocalDdosDecision::NewlyBlocked { ttl: Duration::from_secs(60) },
        );
        // Still inside the block TTL → already blocked.
        assert_eq!(
            d.check_local(ip, None, t0 + Duration::from_secs(30)),
            LocalDdosDecision::AlreadyBlocked,
        );
        // After the TTL AND the window have rolled off → allowed again.
        assert_eq!(
            d.check_local(ip, None, t0 + Duration::from_secs(120)),
            LocalDdosDecision::Allowed,
        );
    }

    /// Per-(tier,ip) isolation: an IP burning its Critical-tier quota
    /// must not auto-block its Low-tier traffic.
    #[test]
    fn check_local_buckets_per_tier() {
        let cfg = DdosConfig { per_ip_limit: 2, per_ip_window_s: 10, ..Default::default() };
        let d = DdosDetector::new(cfg);
        let ip: IpAddr = "10.1.0.2".parse().unwrap();
        let t = Instant::now();
        // Exhaust Critical.
        assert_eq!(d.check_local(ip, Some(Tier::Critical), t), LocalDdosDecision::Allowed);
        assert_eq!(d.check_local(ip, Some(Tier::Critical), t), LocalDdosDecision::Allowed);
        assert!(matches!(
            d.check_local(ip, Some(Tier::Critical), t),
            LocalDdosDecision::NewlyBlocked { .. } | LocalDdosDecision::AlreadyBlocked,
        ));
        // Low tier for the SAME ip is a separate window — still allowed.
        // (The IP is now in local_blocks, so it WILL be AlreadyBlocked;
        //  the block is per-IP by design. Use a fresh IP to prove the
        //  window key is per-tier.)
        let ip2: IpAddr = "10.1.0.3".parse().unwrap();
        assert_eq!(d.check_local(ip2, Some(Tier::Critical), t), LocalDdosDecision::Allowed);
        assert_eq!(d.check_local(ip2, Some(Tier::Low), t), LocalDdosDecision::Allowed,
            "Low-tier window is independent of the Critical-tier window");
    }

    /// Perf invariant — the runtime hot path makes ZERO StateBackend
    /// round-trips (the whole point of the 2026-05-23 change). A
    /// counting backend asserts `incr_window` + `is_auto_blocked` are
    /// never called; only `auto_block` may fire (async, on breach).
    #[tokio::test]
    async fn runtime_hot_path_makes_no_backend_roundtrip() {
        use std::sync::atomic::AtomicU64;
        struct CountingState {
            incr: AtomicU64,
            is_blocked: AtomicU64,
        }
        #[async_trait::async_trait]
        impl StateBackend for CountingState {
            async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
            async fn set(&self, _: &str, _: &[u8], _: Duration) -> aegis_core::Result<()> { Ok(()) }
            async fn del(&self, _: &str) -> aegis_core::Result<()> { Ok(()) }
            async fn incr_window(&self, _: &str, _: Duration, _: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
                self.incr.fetch_add(1, Ordering::Relaxed);
                Ok(aegis_core::SlidingWindowResult { count: 1, allowed: true, retry_after: None })
            }
            async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> { Ok(true) }
            async fn get_risk(&self, _: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
            async fn add_risk(&self, _: &aegis_core::RiskKey, _: i32, _: u32) -> aegis_core::Result<u32> { Ok(0) }
            async fn auto_block(&self, _: IpAddr, _: Duration) -> aegis_core::Result<()> { Ok(()) }
            async fn is_auto_blocked(&self, _: IpAddr) -> aegis_core::Result<bool> {
                self.is_blocked.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
            async fn put_nonce(&self, _: &str, _: Duration) -> aegis_core::Result<bool> { Ok(true) }
            async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> { Ok(true) }
        }
        let state = Arc::new(CountingState { incr: AtomicU64::new(0), is_blocked: AtomicU64::new(0) });
        let cfg = DdosConfig { per_ip_limit: 3, per_ip_window_s: 10, block_ttl_s: 60, ..Default::default() };
        let rt = DdosRuntime::new(cfg, state.clone());
        let ip: IpAddr = "10.1.0.9".parse().unwrap();
        // Drive past the limit (allowed ×3, breach, already-blocked).
        for _ in 0..6 {
            let _ = rt.check_with_tier(ip, Some(Tier::Low)).await.unwrap();
        }
        assert_eq!(state.incr.load(Ordering::Relaxed), 0, "incr_window must never be called on the hot path");
        assert_eq!(state.is_blocked.load(Ordering::Relaxed), 0, "is_auto_blocked must never be called on the hot path");
    }
}
