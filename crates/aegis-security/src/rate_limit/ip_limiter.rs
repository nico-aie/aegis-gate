//! Per-IP sliding-window rate limiter for the proxy hot path
//! (F-T2 of the post-k6 follow-up).
//!
//! # Why a separate limiter from `sliding::check`
//!
//! `super::sliding::check` works against the cluster
//! [`StateBackend`] so quotas survive node failures. The hot
//! path doesn't currently carry a `StateBackend`, and adding
//! one for a single-IP volumetric guard would be premature —
//! a flooding source IP needs to be blocked at the *local*
//! node anyway. A DashMap with a per-IP `VecDeque<Instant>`
//! is simple, lock-free per shard, and matches the existing
//! [`crate::risk::tracker::RiskTracker`] shape.
//!
//! [`StateBackend`]: aegis_core::state::StateBackend
//!
//! # Algorithm
//!
//! Sliding-window log: keep the timestamps of every accepted
//! request in the last `window`, prune older entries on each
//! `consume`, deny the request when the window count would
//! exceed `limit`.
//!
//! Per-IP map size is bounded by sweeping idle entries (no
//! request in `2 × window`) every `IDLE_SWEEP_INTERVAL`. That
//! prevents long-lived flooding sources from leaking memory
//! after they back off.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::Serialize;

const DEFAULT_LIMIT: u32 = 1_000;
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Rate-limit decision returned to the hot path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RateDecision {
    /// `true` if the request should pass through.
    pub allowed: bool,
    /// Number of requests counted in the current window
    /// (including this one).
    pub count: u32,
    /// Configured limit at decision time.
    pub limit: u32,
    /// Suggested `Retry-After` seconds if `!allowed`.
    pub retry_after_seconds: u32,
}

/// Configuration for the per-IP limiter. Mirrors the
/// `RateCap` shape used by the YAML schema so config →
/// runtime mapping is trivial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRateLimitConfig {
    pub limit: u32,
    pub window: Duration,
}

impl Default for IpRateLimitConfig {
    fn default() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            window: DEFAULT_WINDOW,
        }
    }
}

#[derive(Clone)]
pub struct IpRateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    /// Wrapped in `ArcSwap` so config hot-reload (file or etcd
    /// watcher) can update `limit` / `window` atomically without
    /// rebuilding the per-IP timestamp map. Existing timestamps
    /// stay live; the new limit applies on the next `consume_at`
    /// call. Hot-path cost: one `ArcSwap::load` per request
    /// (~5 ns) — strictly cheaper than the surrounding
    /// `DashMap::entry` lookup.
    cfg: ArcSwap<IpRateLimitConfig>,
    /// 2026-05-18 F-CRITICAL-002 (security audit, Phase E): the
    /// limiter map keys on `RiskKey` (composite) so two sessions
    /// on the same NAT'd IP get independent rate-limit buckets —
    /// same migration as `RiskTracker` did in commit 01c053c.
    /// IP-only methods (`consume(ip)`, `reset(ip)`) keep working
    /// by internally constructing `RiskKey::from_ip(ip)`. New
    /// `*_with_key` methods take the full composite.
    map: DashMap<aegis_core::risk::RiskKey, VecDeque<Instant>>,
    last_sweep: parking_lot::Mutex<Instant>,
}

impl IpRateLimiter {
    pub fn new(cfg: IpRateLimitConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                cfg: ArcSwap::from_pointee(cfg),
                map: DashMap::new(),
                last_sweep: parking_lot::Mutex::new(Instant::now()),
            }),
        }
    }

    /// Hot-swap the limiter config. Keeps the per-IP timestamp
    /// map intact — operators editing `cfg.rate_limit.buckets`
    /// don't accidentally reset every flood-source IP back to
    /// zero counts. The new limit applies on the next
    /// `consume_at` call; the new window changes which timestamps
    /// the eviction loop drops on the next sweep.
    pub fn set_config(&self, cfg: IpRateLimitConfig) {
        self.inner.cfg.store(Arc::new(cfg));
    }

    /// Snapshot the live config — drives the `GET /api/rate-limit`
    /// payload + the audit-mutated PUT's "before" view.
    pub fn config_snapshot(&self) -> IpRateLimitConfig {
        **self.inner.cfg.load()
    }

    /// Consume one slot for `ip`. Returns the post-state
    /// decision the hot path acts on.
    pub fn consume(&self, ip: IpAddr) -> RateDecision {
        self.consume_at(ip, Instant::now())
    }

    /// Test seam — drives the clock from the caller so unit
    /// tests can verify window-edge behaviour deterministically.
    pub fn consume_at(&self, ip: IpAddr, now: Instant) -> RateDecision {
        self.consume_at_with_key(
            aegis_core::risk::RiskKey::from_ip(ip),
            now,
        )
    }

    /// 2026-05-18 F-CRITICAL-002 (security audit, Phase E):
    /// composite-key variant of [`consume`]. Caller builds the
    /// full `RiskKey`; two sessions on the same NAT'd IP get
    /// independent buckets.
    pub fn consume_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
    ) -> RateDecision {
        self.consume_at_with_key(key, Instant::now())
    }

    /// Composite-key + explicit-clock variant.
    pub fn consume_at_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        now: Instant,
    ) -> RateDecision {
        let cfg = **self.inner.cfg.load();
        let mut entry = self.inner.map.entry(key).or_default();
        let cutoff = now.checked_sub(cfg.window).unwrap_or(now);

        // Drop timestamps older than the window. The deque is
        // maintained in increasing order so a front-pop loop
        // is O(k) where k = expired entries this call.
        while let Some(&t) = entry.front() {
            if t < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }

        let count_before = entry.len() as u32;
        if count_before >= cfg.limit {
            // Don't push when denied — the limiter measures
            // the "would-have" request rate, not "tried" rate.
            // This makes recovery deterministic: once N seconds
            // pass, the oldest entries roll out and traffic
            // resumes.
            let oldest = entry.front().copied().unwrap_or(now);
            let elapsed = now.saturating_duration_since(oldest);
            let retry = cfg.window.saturating_sub(elapsed);
            drop(entry);
            self.maybe_sweep(now);
            return RateDecision {
                allowed: false,
                count: count_before,
                limit: cfg.limit,
                retry_after_seconds: retry.as_secs().max(1) as u32,
            };
        }

        entry.push_back(now);
        let count_after = entry.len() as u32;
        drop(entry);
        self.maybe_sweep(now);
        RateDecision {
            allowed: true,
            count: count_after,
            limit: cfg.limit,
            retry_after_seconds: 0,
        }
    }

    /// Sweep IPs that have been idle for more than 2× the
    /// window. Bounded — at most one sweep per
    /// `IDLE_SWEEP_INTERVAL` to keep the hot-path overhead at
    /// "one mutex try-lock" amortised.
    fn maybe_sweep(&self, now: Instant) {
        let mut guard = match self.inner.last_sweep.try_lock() {
            Some(g) => g,
            None => return,
        };
        if now.saturating_duration_since(*guard) < IDLE_SWEEP_INTERVAL {
            return;
        }
        *guard = now;
        drop(guard);

        let stale_after = self.inner.cfg.load().window * 2;
        self.inner.map.retain(|_, deque| {
            match deque.back() {
                Some(&latest) => now.saturating_duration_since(latest) < stale_after,
                None => false,
            }
        });
    }

    pub fn config(&self) -> IpRateLimitConfig {
        **self.inner.cfg.load()
    }

    /// Number of IPs currently tracked. Useful for metrics.
    pub fn tracked(&self) -> usize {
        self.inner.map.len()
    }

    /// Reset all per-IP state. Used by `/api/risk/{ip}/reset`
    /// when an operator wants to clear strikes — clearing the
    /// rate-limit counters at the same time means the IP isn't
    /// stuck with old timestamps right after the reset.
    pub fn reset(&self, ip: IpAddr) {
        self.reset_with_key(&aegis_core::risk::RiskKey::from_ip(ip));
    }

    /// Composite-key variant of [`reset`]. Drops exactly one
    /// bucket without touching peers on the same IP.
    pub fn reset_with_key(&self, key: &aegis_core::risk::RiskKey) {
        self.inner.map.remove(key);
    }

    /// Drop every tracked IP. Used by the external control
    /// plane's `reset_state` so a phase transition starts from
    /// a clean limiter.
    pub fn reset_all(&self) {
        self.inner.map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limiter(limit: u32, window_secs: u64) -> IpRateLimiter {
        IpRateLimiter::new(IpRateLimitConfig {
            limit,
            window: Duration::from_secs(window_secs),
        })
    }

    #[test]
    fn under_limit_returns_allowed() {
        let l = limiter(5, 60);
        for i in 1..=5 {
            let d = l.consume(ip("10.0.0.1"));
            assert!(d.allowed);
            assert_eq!(d.count, i);
            assert_eq!(d.retry_after_seconds, 0);
        }
    }

    #[test]
    fn over_limit_denied_with_retry_after() {
        let l = limiter(3, 60);
        for _ in 0..3 {
            let d = l.consume(ip("10.0.0.1"));
            assert!(d.allowed);
        }
        let d = l.consume(ip("10.0.0.1"));
        assert!(!d.allowed);
        assert_eq!(d.count, 3);
        assert!(d.retry_after_seconds >= 1);
        assert!(d.retry_after_seconds <= 60);
    }

    #[test]
    fn denied_request_does_not_extend_window() {
        // Property: a denied request does NOT push a new
        // timestamp into the deque. Otherwise an attacker who
        // keeps hammering during a deny window would push the
        // oldest timestamp forward and never let the gate
        // reopen.
        let l = limiter(2, 1);
        let now = Instant::now();
        l.consume_at(ip("10.0.0.1"), now);
        l.consume_at(ip("10.0.0.1"), now);
        // 100 denied attempts inside the window
        for _ in 0..100 {
            let d = l.consume_at(
                ip("10.0.0.1"),
                now + Duration::from_millis(500),
            );
            assert!(!d.allowed);
        }
        // After the window expires, the gate reopens.
        let d = l.consume_at(
            ip("10.0.0.1"),
            now + Duration::from_secs(2),
        );
        assert!(d.allowed, "limiter must reopen after window elapses");
    }

    #[test]
    fn different_ips_independent() {
        let l = limiter(3, 60);
        for _ in 0..3 {
            l.consume(ip("10.0.0.1"));
        }
        // Same instant, different IP — must still be allowed.
        let d = l.consume(ip("10.0.0.2"));
        assert!(d.allowed);
    }

    #[test]
    fn window_recovers_for_single_ip() {
        let l = limiter(2, 1);
        let t0 = Instant::now();
        l.consume_at(ip("10.0.0.1"), t0);
        l.consume_at(ip("10.0.0.1"), t0);
        // Advance one full window.
        let t1 = t0 + Duration::from_secs(2);
        let d = l.consume_at(ip("10.0.0.1"), t1);
        assert!(d.allowed, "should reopen after window expires");
        assert_eq!(d.count, 1, "old entries pruned");
    }

    #[test]
    fn reset_clears_per_ip_state() {
        let l = limiter(1, 60);
        l.consume(ip("10.0.0.1"));
        let denied = l.consume(ip("10.0.0.1"));
        assert!(!denied.allowed);
        l.reset(ip("10.0.0.1"));
        let after = l.consume(ip("10.0.0.1"));
        assert!(after.allowed, "reset must clear the bucket");
    }

    #[test]
    fn tracked_count_grows_with_distinct_ips() {
        let l = limiter(100, 60);
        for i in 0..50u8 {
            l.consume(ip(&format!("10.0.0.{i}")));
        }
        assert_eq!(l.tracked(), 50);
    }

    #[test]
    fn config_is_observable() {
        let l = limiter(7, 30);
        assert_eq!(l.config().limit, 7);
        assert_eq!(l.config().window, Duration::from_secs(30));
    }

    #[test]
    fn boundary_at_exact_limit_is_still_allowed() {
        // Property: limit=N means the Nth request is allowed,
        // the (N+1)th is denied. Off-by-one regressions here
        // bite hard under DDoS.
        let l = limiter(5, 60);
        let mut last = None;
        for _ in 0..5 {
            last = Some(l.consume(ip("10.0.0.1")));
        }
        assert!(last.unwrap().allowed);
        let next = l.consume(ip("10.0.0.1"));
        assert!(!next.allowed);
    }

    #[test]
    fn set_config_swaps_limit_atomically() {
        // Boot with limit=3. Consume 3 → all allowed. set_config
        // raises limit to 10 → next 7 should also be allowed
        // (existing 3 timestamps still in the window count
        // toward the new limit).
        let l = limiter(3, 60);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(l.consume_at(ip("10.0.0.1"), now).allowed);
        }
        // 4th would be denied at limit=3.
        assert!(!l.consume_at(ip("10.0.0.1"), now).allowed);

        l.set_config(IpRateLimitConfig {
            limit: 10,
            window: Duration::from_secs(60),
        });

        // 4th-10th now allowed (count_before = 3, limit = 10).
        for i in 0..7 {
            let d = l.consume_at(ip("10.0.0.1"), now);
            assert!(d.allowed, "request {} after raise should pass", i + 4);
        }
        // 11th denied at the new limit.
        assert!(!l.consume_at(ip("10.0.0.1"), now).allowed);
    }

    #[test]
    fn set_config_preserves_per_ip_timestamp_state() {
        // Operator intent on hot-reload: editing
        // cfg.rate_limit.buckets shouldn't reset every flooding
        // source IP back to zero counts.
        let l = limiter(100, 60);
        let now = Instant::now();
        for _ in 0..50 {
            l.consume_at(ip("203.0.113.1"), now);
        }
        for _ in 0..30 {
            l.consume_at(ip("203.0.113.2"), now);
        }
        let tracked_before = l.tracked();
        assert_eq!(tracked_before, 2);

        // Hot-reload to a tighter limit. Per-IP state stays.
        l.set_config(IpRateLimitConfig {
            limit: 10,
            window: Duration::from_secs(60),
        });
        assert_eq!(l.tracked(), tracked_before);
        assert_eq!(l.config().limit, 10);
    }

    #[test]
    fn set_config_to_lower_limit_denies_already_over_quota_ips() {
        // IP at 50 consumed under limit=100. Drop limit to 30 →
        // next consume should be denied (count_before 50 >= 30).
        let l = limiter(100, 60);
        let now = Instant::now();
        for _ in 0..50 {
            l.consume_at(ip("10.0.0.99"), now);
        }
        l.set_config(IpRateLimitConfig {
            limit: 30,
            window: Duration::from_secs(60),
        });
        let d = l.consume_at(ip("10.0.0.99"), now);
        assert!(!d.allowed);
        assert_eq!(d.limit, 30);
    }

    #[test]
    fn high_concurrency_caps_at_limit() {
        // 200 concurrent calls, limit 100 — exactly 100 allowed,
        // exactly 100 denied. The DashMap entry guard
        // serialises the per-IP critical section even though
        // the outer call is wait-free across IPs.
        use std::thread;
        let l = limiter(100, 60);
        let mut handles = vec![];
        for _ in 0..200 {
            let l = l.clone();
            handles.push(thread::spawn(move || l.consume(ip("10.0.0.1"))));
        }
        let mut allowed = 0u32;
        let mut denied = 0u32;
        for h in handles {
            let d = h.join().unwrap();
            if d.allowed {
                allowed += 1;
            } else {
                denied += 1;
            }
        }
        assert_eq!(allowed, 100);
        assert_eq!(denied, 100);
    }

    // ---- 2026-05-18 F-CRITICAL-002 Phase E composite-key tests ----

    fn key(ip_str: &str, device_fp: Option<&str>, session: Option<&str>) -> aegis_core::risk::RiskKey {
        aegis_core::risk::RiskKey {
            ip: ip(ip_str),
            device_fp: device_fp.map(String::from),
            session: session.map(String::from),
        }
    }

    /// Composite-key isolation: two sessions on the same NAT'd IP
    /// get independent rate-limit buckets.
    #[test]
    fn composite_key_isolates_buckets_on_same_ip() {
        let l = limiter(2, 60); // limit 2 per window
        let alice = key("10.0.0.1", Some("fp-alice"), Some("sess-alice"));
        let bob = key("10.0.0.1", Some("fp-bob"), Some("sess-bob"));

        // Alice consumes 2 (the limit) — third request denied.
        assert!(l.consume_with_key(alice.clone()).allowed);
        assert!(l.consume_with_key(alice.clone()).allowed);
        assert!(!l.consume_with_key(alice.clone()).allowed);

        // Bob (same IP, different session) still has full quota.
        assert!(l.consume_with_key(bob.clone()).allowed);
        assert!(l.consume_with_key(bob.clone()).allowed);
        // Bob exhausts his quota independently.
        assert!(!l.consume_with_key(bob.clone()).allowed);
    }

    /// IP-only and composite calls populate DIFFERENT buckets.
    #[test]
    fn ip_only_and_composite_dont_share_buckets() {
        let l = limiter(2, 60);
        let p = ip("10.0.0.1");
        let composite = key("10.0.0.1", Some("fp-x"), Some("sess-x"));

        // Burn IP-only bucket.
        l.consume(p);
        l.consume(p);
        assert!(!l.consume(p).allowed);

        // Composite bucket is fresh — still allowed.
        assert!(l.consume_with_key(composite.clone()).allowed);
    }

    /// `reset_with_key` drops one composite bucket without
    /// touching peers on the same IP or the IP-only bucket.
    #[test]
    fn reset_with_key_drops_only_target_bucket() {
        let l = limiter(2, 60);
        let p = ip("10.0.0.5");
        let k1 = key("10.0.0.5", Some("fp1"), None);
        let k2 = key("10.0.0.5", Some("fp2"), None);
        l.consume(p);
        l.consume_with_key(k1.clone());
        l.consume_with_key(k2.clone());
        let before = l.tracked();
        assert!(before >= 3);

        l.reset_with_key(&k1);
        // tracked count drops by exactly 1.
        assert_eq!(l.tracked(), before - 1);
    }

    /// 2026-05-19 — sanity check for the data-plane swap. Two
    /// distinct composite keys with the same IP get independent
    /// token buckets, so attacker bob's flood doesn't 429 legit
    /// user alice through the same NAT.
    #[test]
    fn consume_with_key_isolates_two_sessions_on_same_ip() {
        let l = limiter(2, 60); // limit=2 per 60s window
        let alice = key("10.0.0.1", Some("fp-alice"), Some("sess-alice"));
        let bob   = key("10.0.0.1", Some("fp-bob"),   Some("sess-bob"));

        // Bob burns through his bucket.
        assert!(l.consume_with_key(bob.clone()).allowed);
        assert!(l.consume_with_key(bob.clone()).allowed);
        assert!(!l.consume_with_key(bob.clone()).allowed, "3rd req for bob is over the cap");

        // Alice on the same IP is unaffected.
        assert!(l.consume_with_key(alice.clone()).allowed);
        assert!(l.consume_with_key(alice.clone()).allowed);
        assert!(!l.consume_with_key(alice.clone()).allowed, "alice's own cap also enforced");
    }
}
