use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aegis_core::state::StateBackend;

/// Per-IP DDoS configuration.
#[derive(Clone, Debug)]
pub struct DdosConfig {
    /// Master toggle. `false` means [`DdosDetector::check`] is never
    /// called — the request handler short-circuits before reaching
    /// the detector. Default `true`.
    pub enabled: bool,
    /// 2026-05-09 BUG-DDOS-STUB Phase 1 — observation mode. `true`
    /// runs the detector + emits Prometheus counters + writes audit
    /// events but **never** flips a [`DdosResult::blocked`] signal
    /// into a 503. Default `true` until operators have validated
    /// the signal in their environment.
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
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: true,
            per_ip_limit: 1000,
            per_ip_window_s: 10,
            block_ttl_s: 300,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
        }
    }
}

impl From<aegis_core::config::DdosConfig> for DdosConfig {
    fn from(c: aegis_core::config::DdosConfig) -> Self {
        Self {
            enabled: c.enabled,
            observe_only: c.observe_only,
            per_ip_limit: c.per_ip_limit,
            per_ip_window_s: c.per_ip_window_s,
            block_ttl_s: c.block_ttl_s,
            spike_multiplier: c.spike_multiplier,
            tightened_per_ip_rps: c.tightened_per_ip_rps,
        }
    }
}

/// DDoS detector.
pub struct DdosDetector {
    config: DdosConfig,
    /// Rolling RPS estimate (requests in current second).
    rolling_rps: AtomicU64,
    /// Average RPS baseline.
    baseline_rps: AtomicU64,
    /// Whether cluster spike mode is active.
    spike_active: AtomicU64,
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
    observe_only: bool,
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
        let observe_only = cfg.observe_only;
        Self {
            detector: std::sync::Arc::new(DdosDetector::new(cfg)),
            state,
            observe_only,
        }
    }

    /// Run the per-IP check. Backend errors propagate so the
    /// caller can decide fail-open vs fail-close. Phase 1 wiring
    /// in `aegis-proxy/src/data_plane.rs` fail-opens on errors
    /// (observe-only never blocks anyway).
    pub async fn check(&self, peer_ip: IpAddr) -> aegis_core::Result<DdosCheckOutcome> {
        let result = self.detector.check(self.state.as_ref(), peer_ip).await?;
        Ok(DdosCheckOutcome {
            blocked: result.blocked,
            reason: result.reason,
            spike_active: result.spike_active,
            observe_only: self.observe_only,
        })
    }

    pub fn tick_rps(&self) {
        self.detector.tick_rps();
    }

    pub fn observe_only(&self) -> bool {
        self.observe_only
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
}

impl DdosDetector {
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config,
            rolling_rps: AtomicU64::new(0),
            baseline_rps: AtomicU64::new(100),
            spike_active: AtomicU64::new(0),
        }
    }

    /// Check if an IP should be blocked.
    pub async fn check(
        &self,
        state: &dyn StateBackend,
        ip: IpAddr,
    ) -> aegis_core::Result<DdosResult> {
        // 1. Check if already auto-blocked.
        if state.is_auto_blocked(ip).await? {
            return Ok(DdosResult {
                blocked: true,
                reason: Some(format!("auto-blocked IP: {ip}")),
                spike_active: self.is_spike_active(),
            });
        }

        // 2. Sliding window per-IP.
        let key = format!("ddos:ip:{ip}");
        let window = Duration::from_secs(u64::from(self.config.per_ip_window_s));
        let result = state
            .incr_window(&key, window, self.config.per_ip_limit)
            .await?;

        if !result.allowed {
            // Auto-block.
            let ttl = Duration::from_secs(self.config.block_ttl_s);
            state.auto_block(ip, ttl).await?;
            return Ok(DdosResult {
                blocked: true,
                reason: Some(format!(
                    "IP {ip} exceeded {}/{} s; blocked for {} s",
                    self.config.per_ip_limit, self.config.per_ip_window_s, self.config.block_ttl_s
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
        let current = self.rolling_rps.swap(0, Ordering::Relaxed);
        let baseline = self.baseline_rps.load(Ordering::Relaxed);

        // EWMA update: baseline = 0.9 * baseline + 0.1 * current
        let new_baseline = ((baseline as f64) * 0.9 + (current as f64) * 0.1) as u64;
        self.baseline_rps.store(new_baseline.max(1), Ordering::Relaxed);

        let threshold = (baseline as f64 * self.config.spike_multiplier) as u64;
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
}
