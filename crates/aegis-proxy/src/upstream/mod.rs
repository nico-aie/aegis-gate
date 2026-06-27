pub mod lb;
pub mod health;
pub mod circuit;
pub mod dns_refresh;
pub mod dns_resolve;
pub mod forward;
pub mod identity;
pub mod idle_timeout;
pub mod mtls_failures;
pub mod pinned_resolver;
pub mod probe;
pub mod registry;
pub mod rotation;
pub mod streaming;
pub mod tls;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use aegis_control::api::upstreams::MemberStatus;

/// `observed` tri-state encoding (display-only liveness — see `Member`).
const OBSERVED_UNKNOWN: u8 = 0;
const OBSERVED_UP: u8 = 1;
const OBSERVED_DOWN: u8 = 2;

/// Runtime representation of an upstream member.
#[derive(Debug)]
pub struct Member {
    pub addr: SocketAddr,
    pub weight: u32,
    pub zone: Option<String>,
    pub healthy: AtomicBool,
    pub inflight: AtomicU64,
    /// 2026-06-18 (upstream "up" badge report): display-only observed
    /// liveness, distinct from [`Self::healthy`]. `healthy` drives
    /// load-balancer member selection and is left optimistically `true`
    /// until an *active* HTTP health check flips it (unchanged routing).
    /// `observed` is what the dashboard renders: an active HTTP check OR a
    /// lightweight TCP probe (for pools without a `health:` block) writes
    /// the verified `Up`/`Down` here. It NEVER feeds the LB, so a probe
    /// result can never pull the last member out of rotation. Starts
    /// `Unknown` so the badge shows "unverified" rather than a false "up"
    /// before the first probe.
    observed: AtomicU8,
    /// Passive-health consecutive-failure streak (P2 of
    /// `plans/future/passive-upstream-health.md`). Incremented by
    /// [`Self::record_passive_failure`] on a connection-level forward
    /// failure and reset to 0 by [`Self::record_passive_success`]. Drives
    /// the LB `healthy` flip only once it reaches the pool's
    /// `fail_threshold` (hysteresis — a single error never evicts). `0`
    /// when passive health is disabled, since the call sites never touch it.
    consec_failures: AtomicU32,
    /// Passive-health consecutive-success streak — the mirror of
    /// [`Self::consec_failures`], used to restore a downed member after the
    /// pool's `rise_threshold` consecutive successes.
    consec_successes: AtomicU32,
    /// FIX 2026-05-03 — explicit Host-header override mirroring
    /// `MemberConfig.host_header`. When `Some(host)`,
    /// `forward()` sends `Host: <host>` upstream instead of
    /// rewriting it to `<addr>` — required for vhost-routed
    /// backends.
    pub host_override: Option<String>,
}

impl Member {
    pub fn new(addr: SocketAddr, weight: u32, zone: Option<String>) -> Self {
        Self {
            addr,
            weight,
            zone,
            healthy: AtomicBool::new(true),
            inflight: AtomicU64::new(0),
            observed: AtomicU8::new(OBSERVED_UNKNOWN),
            consec_failures: AtomicU32::new(0),
            consec_successes: AtomicU32::new(0),
            host_override: None,
        }
    }

    pub fn with_host_override(
        addr: SocketAddr,
        weight: u32,
        zone: Option<String>,
        host_override: Option<String>,
    ) -> Self {
        Self {
            addr,
            weight,
            zone,
            healthy: AtomicBool::new(true),
            inflight: AtomicU64::new(0),
            observed: AtomicU8::new(OBSERVED_UNKNOWN),
            consec_failures: AtomicU32::new(0),
            consec_successes: AtomicU32::new(0),
            host_override,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Record a verified probe result for display (does NOT affect
    /// [`Self::is_healthy`] / load-balancer selection).
    pub fn set_observed(&self, up: bool) {
        let v = if up { OBSERVED_UP } else { OBSERVED_DOWN };
        self.observed.store(v, Ordering::Relaxed);
    }

    /// Passive health — record a connection-level failure on the real
    /// request path (P2 of `plans/future/passive-upstream-health.md`).
    ///
    /// Resets the consecutive-success streak and grows the consecutive-
    /// failure streak. When the streak reaches `fail_threshold` *and* the
    /// member is currently healthy, flips it **down** for both the load
    /// balancer ([`Self::healthy`]) and the display badge
    /// ([`Self::observed`]). Returns `true` exactly on the transition, so
    /// the caller can log the eviction once.
    ///
    /// Hysteresis: with `fail_threshold >= 2` a single error never flips a
    /// member. The gate (whether passive health runs at all) lives at the
    /// call site (`Pool.passive_health.enabled`); this method is a no-op on
    /// routing until the threshold is crossed.
    pub fn record_passive_failure(&self, fail_threshold: u32) -> bool {
        self.consec_successes.store(0, Ordering::Relaxed);
        let streak = self.consec_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if streak >= fail_threshold && self.healthy.swap(false, Ordering::Relaxed) {
            // We held the last `true` → this call performed the transition.
            self.set_observed(false);
            return true;
        }
        false
    }

    /// Passive health — record a successful forward outcome (a response was
    /// received; the connection works). Resets the consecutive-failure
    /// streak and grows the consecutive-success streak. When the streak
    /// reaches `rise_threshold` *and* the member is currently down, restores
    /// it **up** for both the load balancer and the display badge. Returns
    /// `true` exactly on the transition.
    pub fn record_passive_success(&self, rise_threshold: u32) -> bool {
        self.consec_failures.store(0, Ordering::Relaxed);
        let streak = self.consec_successes.fetch_add(1, Ordering::Relaxed) + 1;
        if streak >= rise_threshold && !self.healthy.swap(true, Ordering::Relaxed) {
            // We held the last `false` → this call performed the restore.
            self.set_observed(true);
            return true;
        }
        false
    }

    /// Display-only observed liveness. `Unknown` until the first probe.
    pub fn observed_status(&self) -> MemberStatus {
        match self.observed.load(Ordering::Relaxed) {
            OBSERVED_UP => MemberStatus::Up,
            OBSERVED_DOWN => MemberStatus::Down,
            _ => MemberStatus::Unknown,
        }
    }

    /// RAII guard for the per-member `inflight` counter
    /// (F-CRITICAL-008, 2026-05-17 s-tester audit).
    ///
    /// Pre-fix the proxy + data-plane forward paths manually called
    /// `inflight.fetch_add(1)` before the upstream `.await` and
    /// `inflight.fetch_sub(1)` after. A cancellation or panic
    /// between those points leaked the counter, permanently biasing
    /// `LeastConn` / `P2C` load balancers against the affected pool
    /// member. `inflight_guard()` returns a guard whose `Drop` runs
    /// the decrement regardless of how the surrounding future exits
    /// (await cancellation, panic, early return).
    pub fn inflight_guard(self: &Arc<Self>) -> InflightGuard {
        self.inflight.fetch_add(1, Ordering::Relaxed);
        InflightGuard { member: Arc::clone(self) }
    }
}

/// RAII handle that decrements `Member.inflight` on drop. Issued by
/// [`Member::inflight_guard`]. See that fn's doc for the bug this
/// closed.
pub struct InflightGuard {
    member: Arc<Member>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.member.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Resolved, hot-path-cheap passive-health settings for a pool
/// (`plans/future/passive-upstream-health.md`). A `Copy` snapshot derived from
/// the pool's [`aegis_core::config::PassiveHealthConfig`] via [`Self::resolve`].
/// The bare [`Default`] is **disabled** (the forward-result call sites skip all
/// passive accounting); `resolve` applies the P4 default-on policy — passive
/// becomes the health source for pools without an active `health:` block.
#[derive(Debug, Clone, Copy)]
pub struct PassiveHealthRuntime {
    pub enabled: bool,
    pub fail_threshold: u32,
    pub rise_threshold: u32,
    pub count_5xx: bool,
}

impl Default for PassiveHealthRuntime {
    fn default() -> Self {
        Self {
            enabled: false,
            fail_threshold: 3,
            rise_threshold: 2,
            count_5xx: false,
        }
    }
}

impl PassiveHealthRuntime {
    /// Resolve a pool's effective passive-health settings (P4 default-on
    /// policy).
    ///
    /// - An explicit `passive_health` block always wins — `enabled` is taken
    ///   verbatim (so an operator can force it on alongside an active checker,
    ///   or opt back out).
    /// - **Absent** ⇒ passive health is the **default health source for pools
    ///   without an active `health:` block** (`enabled = !has_active_health`).
    ///   A pool with an active checker leaves it off — that checker is
    ///   authoritative.
    pub fn resolve(
        cfg: Option<&aegis_core::config::PassiveHealthConfig>,
        has_active_health: bool,
    ) -> Self {
        match cfg {
            Some(c) => Self {
                enabled: c.enabled,
                fail_threshold: c.fail_threshold,
                rise_threshold: c.rise_threshold,
                count_5xx: c.count_5xx,
            },
            None => Self {
                enabled: !has_active_health,
                ..Self::default()
            },
        }
    }
}

/// Apply the passive-health verdict for a forward that **returned a
/// response**. A received response means the connection works → a member
/// success, unless the `count_5xx` toggle is on and this is a 5xx. No-op
/// when passive health is disabled (today's behavior). Shared by the
/// legacy proxy path and the production data plane so the two never drift.
pub fn record_passive_outcome_ok(
    ph: &PassiveHealthRuntime,
    member: &Arc<Member>,
    status: hyper::StatusCode,
) {
    if !ph.enabled {
        return;
    }
    if ph.count_5xx && status.is_server_error() {
        member.record_passive_failure(ph.fail_threshold);
    } else {
        member.record_passive_success(ph.rise_threshold);
    }
}

/// Apply the passive-health verdict for a forward that **errored**. Only
/// connection-level failures (`ForwardError::is_member_failure`) evict a
/// member; ambiguous mid-stream errors are ignored so a client-cancelled or
/// long-streaming request can't miscount. No-op when disabled.
///
/// Recording happens only on a *completed* forward outcome — a cancelled
/// future never reaches the call sites (the inflight RAII guard handles the
/// counter), so cancellation can't be miscounted as a failure here either.
pub fn record_passive_outcome_err(
    ph: &PassiveHealthRuntime,
    member: &Arc<Member>,
    err: &forward::ForwardError,
) {
    if !ph.enabled {
        return;
    }
    if err.is_member_failure() {
        member.record_passive_failure(ph.fail_threshold);
    }
}

/// Resolved, hot-path-cheap locality (zone-aware LB) settings for a pool
/// (`plans/future/zone-aware-load-balancing.md` P2). A `Copy` snapshot of the
/// pool's [`aegis_core::config::LocalityConfig`]; the default is **disabled**,
/// which makes `LbStrategy::pick_with_locality` behave like plain `pick`
/// (zone-agnostic — today's behavior).
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalityRuntime {
    pub enabled: bool,
    /// Capacity gate (P4) — prefer the local zone only while its healthy
    /// fraction is ≥ this percentage; below it, spill cross-zone. `None` ⇒ v1
    /// presence gate (any healthy local member keeps traffic local).
    pub min_local_healthy_pct: Option<u8>,
}

impl LocalityRuntime {
    /// Resolve from a pool's optional config block. `None` ⇒ disabled.
    pub fn resolve(cfg: Option<&aegis_core::config::LocalityConfig>) -> Self {
        match cfg {
            Some(c) => Self {
                enabled: c.enabled,
                min_local_healthy_pct: c.min_local_healthy_pct,
            },
            None => Self::default(),
        }
    }
}

/// Classify which zone a picked member was served from, for the zone-aware LB
/// P3 routing metric (`waf_upstream_zone_routing_total`). Returns the metric
/// `outcome` label, or `None` when this wasn't a zone-aware decision (locality
/// disabled, or the node has no self-zone) so the counter isn't polluted with
/// traffic that never had a locality preference to honor.
pub fn zone_routing_outcome(
    locality_enabled: bool,
    self_zone: Option<&str>,
    member_zone: Option<&str>,
) -> Option<&'static str> {
    use aegis_control::metrics::zone_routing::{OUTCOME_CROSS_ZONE, OUTCOME_LOCAL};
    if !locality_enabled {
        return None;
    }
    let sz = self_zone?;
    Some(if member_zone == Some(sz) {
        OUTCOME_LOCAL
    } else {
        OUTCOME_CROSS_ZONE
    })
}

/// A pool of upstream members with a configured load-balancing strategy.
#[derive(Debug)]
pub struct Pool {
    pub name: String,
    pub members: Vec<Arc<Member>>,
    pub strategy: lb::LbStrategy,
    /// UP-T1 — per-pool connection-pool tuning. Threaded into
    /// [`forward::forward`] so each call uses the same pooled
    /// `Client` for that signature.
    pub connection: aegis_core::config::ConnectionPoolConfig,
    /// P2 — passive upstream health settings (default disabled). Read by
    /// the forward-result call sites to decide whether a connection-level
    /// failure / success rotates this member.
    pub passive_health: PassiveHealthRuntime,
    /// Zone-aware LB P2 — locality settings (default disabled). Read by
    /// `LbStrategy::pick_with_locality` at the pick call sites to prefer
    /// same-zone members.
    pub locality: LocalityRuntime,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> Arc<Member> {
        Arc::new(Member::new(
            "127.0.0.1:9999".parse().unwrap(),
            1,
            None,
        ))
    }

    #[test]
    fn inflight_guard_increments_on_create_and_decrements_on_drop() {
        let m = member();
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
        {
            let _g = m.inflight_guard();
            assert_eq!(m.inflight.load(Ordering::Relaxed), 1);
        }
        // Guard dropped → counter decremented.
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inflight_guard_decrements_on_unwind() {
        // Regression for F-CRITICAL-008: pre-fix, a panic inside
        // the forward.await dropped the future and leaked the
        // counter. The guard's Drop runs even on panic-unwind, so
        // a `catch_unwind` here lets us assert it.
        let m = member();
        let m_clone = Arc::clone(&m);
        let result = std::panic::catch_unwind(move || {
            let _g = m_clone.inflight_guard();
            assert_eq!(m_clone.inflight.load(Ordering::Relaxed), 1);
            panic!("simulated forward panic");
        });
        assert!(result.is_err());
        // Counter must be back to zero despite the panic.
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
    }

    // -----------------------------------------------------------------------
    // Passive upstream health (P2) — per-member consecutive failure/success
    // accounting with hysteresis. The passive verdict writes BOTH `healthy`
    // (load balancer) and `observed` (display badge) so routing and the
    // dashboard agree. Gating (default-off) lives at the call sites
    // (`Pool.passive_health.enabled`); these tests exercise the Member
    // primitives directly with thresholds passed in.
    // -----------------------------------------------------------------------

    fn lb_member(port: u16) -> Arc<Member> {
        Arc::new(Member::new(
            format!("127.0.0.1:{port}").parse().unwrap(),
            1,
            None,
        ))
    }

    // P4 — `PassiveHealthRuntime::resolve` default-on policy: passive health is
    // the health source for pools without an active `health:` block, off when
    // one exists, and an explicit config block always wins.

    fn passive_cfg(enabled: bool) -> aegis_core::config::PassiveHealthConfig {
        aegis_core::config::PassiveHealthConfig {
            enabled,
            fail_threshold: 3,
            rise_threshold: 2,
            count_5xx: false,
        }
    }

    #[test]
    fn passive_health_defaults_on_for_pool_without_active_health() {
        // No `passive_health` block + no active `health:` → passive is the
        // health source for this pool.
        let rt = PassiveHealthRuntime::resolve(None, false);
        assert!(rt.enabled);
        assert_eq!(rt.fail_threshold, 3);
        assert_eq!(rt.rise_threshold, 2);
    }

    #[test]
    fn passive_health_defaults_off_when_active_health_present() {
        // An active `health:` checker is authoritative — passive stays off
        // unless explicitly enabled.
        let rt = PassiveHealthRuntime::resolve(None, true);
        assert!(!rt.enabled);
    }

    #[test]
    fn explicit_passive_disable_is_honored_without_active_health() {
        // Operator opts back out → off even though there's no active checker.
        let rt = PassiveHealthRuntime::resolve(Some(&passive_cfg(false)), false);
        assert!(!rt.enabled);
    }

    #[test]
    fn explicit_passive_enable_is_honored_with_active_health() {
        // Operator forces passive on alongside an active checker → honored.
        let rt = PassiveHealthRuntime::resolve(Some(&passive_cfg(true)), true);
        assert!(rt.enabled);
    }

    // Zone-aware LB P3 — routing-outcome classifier for the served-local /
    // cross-zone metric.

    #[test]
    fn zone_routing_outcome_none_when_locality_disabled() {
        assert_eq!(zone_routing_outcome(false, Some("az-a"), Some("az-a")), None);
    }

    #[test]
    fn zone_routing_outcome_none_without_self_zone() {
        assert_eq!(zone_routing_outcome(true, None, Some("az-a")), None);
    }

    #[test]
    fn zone_routing_outcome_local_when_member_matches_node() {
        assert_eq!(
            zone_routing_outcome(true, Some("az-a"), Some("az-a")),
            Some("local")
        );
    }

    #[test]
    fn zone_routing_outcome_cross_zone_when_member_differs_or_unlabeled() {
        assert_eq!(
            zone_routing_outcome(true, Some("az-a"), Some("az-b")),
            Some("cross_zone")
        );
        assert_eq!(
            zone_routing_outcome(true, Some("az-a"), None),
            Some("cross_zone")
        );
    }

    #[test]
    fn passive_failure_marks_member_down_after_threshold() {
        let m = member();
        assert!(m.is_healthy());
        // fail_threshold = 3: the first two failures must NOT flip it.
        assert!(!m.record_passive_failure(3));
        assert!(m.is_healthy());
        assert!(!m.record_passive_failure(3));
        assert!(m.is_healthy());
        // The third consecutive failure trips it — returns `true` (flipped).
        assert!(m.record_passive_failure(3));
        assert!(!m.is_healthy());
        // Display badge agrees with routing.
        assert_eq!(m.observed_status(), MemberStatus::Down);
    }

    #[test]
    fn single_failure_never_flips_a_healthy_member() {
        let m = member();
        assert!(!m.record_passive_failure(3));
        assert!(m.is_healthy(), "one error must never evict a member");
        assert_eq!(m.observed_status(), MemberStatus::Unknown);
    }

    #[test]
    fn passive_success_marks_member_up_after_rise_threshold() {
        let m = member();
        // Drive it down first (fail_threshold = 2).
        m.record_passive_failure(2);
        m.record_passive_failure(2);
        assert!(!m.is_healthy());
        // rise_threshold = 2: the first success doesn't restore it yet.
        assert!(!m.record_passive_success(2));
        assert!(!m.is_healthy());
        // The second consecutive success restores it — returns `true`.
        assert!(m.record_passive_success(2));
        assert!(m.is_healthy());
        assert_eq!(m.observed_status(), MemberStatus::Up);
    }

    #[test]
    fn a_success_resets_the_failure_streak() {
        let m = member();
        // Two failures (fail_threshold = 3 — not yet down).
        m.record_passive_failure(3);
        m.record_passive_failure(3);
        assert!(m.is_healthy());
        // A success resets the consecutive-failure streak...
        m.record_passive_success(2);
        // ...so it again takes a FULL 3 consecutive failures to trip.
        assert!(!m.record_passive_failure(3));
        assert!(!m.record_passive_failure(3));
        assert!(m.is_healthy());
        assert!(m.record_passive_failure(3));
        assert!(!m.is_healthy());
    }

    #[test]
    fn passively_downed_member_is_skipped_by_lb_while_peers_up() {
        use super::lb::LbStrategy;
        use std::sync::atomic::AtomicUsize;
        let members = vec![lb_member(3000), lb_member(3001)];
        // Passively mark member 0 down (fail_threshold = 2).
        members[0].record_passive_failure(2);
        members[0].record_passive_failure(2);
        assert!(!members[0].is_healthy());

        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        for _ in 0..10 {
            let picked = strategy.pick(&members, None).unwrap();
            assert_eq!(
                picked.addr.port(),
                3001,
                "LB must route around a passively-downed member"
            );
        }
    }

    #[test]
    fn lb_still_routes_when_passive_health_downs_the_only_member() {
        use super::lb::LbStrategy;
        use std::sync::atomic::AtomicUsize;
        let members = vec![lb_member(3000)];
        members[0].record_passive_failure(1);
        assert!(!members[0].is_healthy());
        // Fail open (PREREQ-B): a non-empty pool never returns None, even
        // when passive health has downed every member — it still attempts a
        // forward (a real 502) rather than refusing to route (a 503).
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        assert!(strategy.pick(&members, None).is_some());
    }
}
