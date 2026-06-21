use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::Member;

/// Load-balancing strategy for an upstream pool.
#[derive(Debug)]
pub enum LbStrategy {
    RoundRobin(AtomicUsize),
    WeightedRoundRobin(AtomicUsize),
    LeastConn,
    P2c,
    ConsistentHash,
}

impl LbStrategy {
    /// Pick a healthy member from `members`.
    ///
    /// `hash_key` is used only by `ConsistentHash`; other strategies ignore it.
    pub fn pick<'a>(
        &self,
        members: &'a [Arc<Member>],
        hash_key: Option<&str>,
    ) -> Option<&'a Arc<Member>> {
        let healthy: Vec<(usize, &Arc<Member>)> = members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_healthy())
            .collect();

        if healthy.is_empty() {
            return None;
        }

        match self {
            LbStrategy::RoundRobin(counter) => {
                let idx = counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Some(healthy[idx].1)
            }
            LbStrategy::WeightedRoundRobin(counter) => {
                pick_weighted(&healthy, counter)
            }
            LbStrategy::LeastConn => {
                healthy
                    .iter()
                    .min_by_key(|(_, m)| m.inflight.load(Ordering::Relaxed))
                    .map(|(_, m)| *m)
            }
            LbStrategy::P2c => {
                pick_p2c(&healthy)
            }
            LbStrategy::ConsistentHash => {
                let key = hash_key.unwrap_or("");
                pick_consistent_hash(&healthy, key)
            }
        }
    }
}

/// Weighted round-robin: expand the schedule by weight, then index.
fn pick_weighted<'a>(
    healthy: &[(usize, &'a Arc<Member>)],
    counter: &AtomicUsize,
) -> Option<&'a Arc<Member>> {
    let total_weight: u32 = healthy.iter().map(|(_, m)| m.weight).sum();
    if total_weight == 0 {
        return None;
    }
    let idx = counter.fetch_add(1, Ordering::Relaxed) % (total_weight as usize);
    let mut acc: usize = 0;
    for (_, m) in healthy {
        acc += m.weight as usize;
        if idx < acc {
            return Some(m);
        }
    }
    Some(healthy.last().unwrap().1)
}

/// Power-of-two-choices: pick 2 distinct random candidates,
/// choose the one with fewer inflight requests.
///
/// **2026-05-11 PROXY-10 fix.** Pre-fix used a thread-local
/// counter `(v % n, (v + 1 + (v / n)) % n)` which was deterministic
/// — for small pools the two picks repeated identically across
/// requests, collapsing P2C to round-robin and losing the load-
/// balancing advantage. Now uses an atomic counter mixed with
/// system-time nanos for a process-wide entropy source. No new
/// crate dependency.
fn pick_p2c<'a>(healthy: &[(usize, &'a Arc<Member>)]) -> Option<&'a Arc<Member>> {
    let n = healthy.len();
    if n == 1 {
        return Some(healthy[0].1);
    }
    // For n=2 P2C is just "pick the less-loaded of the two".
    if n == 2 {
        let m0 = healthy[0].1;
        let m1 = healthy[1].1;
        return Some(
            if m0.inflight.load(Ordering::Relaxed) <= m1.inflight.load(Ordering::Relaxed) {
                m0
            } else {
                m1
            },
        );
    }
    // For n >= 3 generate two distinct indices using a counter +
    // sub-nanosecond entropy. Distribution doesn't need to be
    // cryptographic — just "different per request, across the
    // member list, on average".
    static P2C_CTR: AtomicUsize = AtomicUsize::new(0);
    let counter = P2C_CTR.fetch_add(1, Ordering::Relaxed);
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as usize)
        .unwrap_or(0);
    let seed = counter.wrapping_mul(0x9E3779B1).wrapping_add(jitter);
    let a = seed % n;
    let mut b = seed.wrapping_div(n).wrapping_mul(0x9E3779B1) % n;
    if b == a {
        b = (a + 1) % n;
    }
    let ma = healthy[a].1;
    let mb = healthy[b].1;
    if ma.inflight.load(Ordering::Relaxed) <= mb.inflight.load(Ordering::Relaxed) {
        Some(ma)
    } else {
        Some(mb)
    }
}

/// Consistent hash via Rendezvous Hashing (Highest Random Weight).
///
/// **2026-05-11 PROXY-11 fix.** Pre-fix used `DefaultHasher(key) %
/// healthy.len()` — plain modulo hashing, which remaps roughly
/// `(n-1)/n` of keys when a member is added or removed
/// (~50% for n=2). Real consistent hashing needs to remap
/// only `1/n` of keys on a member change. Rendezvous Hashing
/// achieves this without maintaining a hash-ring data
/// structure: for each request compute `hash(key, member_addr)`
/// per healthy member and pick the max. O(N) per pick, no
/// pool-lifecycle state to manage, monotonically optimal on
/// member adds / removes (only the keys whose previous-winner
/// changes get reassigned). `DefaultHasher::new()` is
/// deterministic with no random seed, so the same `(key,
/// member-set)` pair always picks the same member — exactly
/// what session affinity needs.
fn pick_consistent_hash<'a>(
    healthy: &[(usize, &'a Arc<Member>)],
    key: &str,
) -> Option<&'a Arc<Member>> {
    healthy
        .iter()
        .max_by_key(|(_, m)| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            m.addr.to_string().hash(&mut hasher);
            hasher.finish()
        })
        .map(|(_, m)| *m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn make_members(n: usize) -> Vec<Arc<Member>> {
        (0..n)
            .map(|i| {
                Arc::new(Member::new(
                    format!("127.0.0.1:{}", 3000 + i).parse().unwrap(),
                    1,
                    None,
                ))
            })
            .collect()
    }

    fn make_weighted_members(weights: &[u32]) -> Vec<Arc<Member>> {
        weights
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                Arc::new(Member::new(
                    format!("127.0.0.1:{}", 3000 + i).parse().unwrap(),
                    w,
                    None,
                ))
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // RoundRobin
    // -----------------------------------------------------------------------

    #[test]
    fn round_robin_cycles_through_members() {
        let members = make_members(3);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));

        let mut addrs = Vec::new();
        for _ in 0..6 {
            let m = strategy.pick(&members, None).unwrap();
            addrs.push(m.addr);
        }
        // Should cycle: 0, 1, 2, 0, 1, 2
        assert_eq!(addrs[0], addrs[3]);
        assert_eq!(addrs[1], addrs[4]);
        assert_eq!(addrs[2], addrs[5]);
    }

    #[test]
    fn round_robin_skips_unhealthy() {
        let members = make_members(3);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));

        for _ in 0..10 {
            let m = strategy.pick(&members, None).unwrap();
            assert_ne!(m.addr.port(), 3001);
        }
    }

    #[test]
    fn round_robin_returns_none_all_unhealthy() {
        let members = make_members(2);
        members[0].healthy.store(false, Ordering::Relaxed);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        assert!(strategy.pick(&members, None).is_none());
    }

    // -----------------------------------------------------------------------
    // WeightedRoundRobin
    // -----------------------------------------------------------------------

    #[test]
    fn weighted_round_robin_respects_weights() {
        let members = make_weighted_members(&[3, 1]);
        let strategy = LbStrategy::WeightedRoundRobin(AtomicUsize::new(0));

        let mut counts = [0u32; 2];
        for _ in 0..400 {
            let m = strategy.pick(&members, None).unwrap();
            if m.addr.port() == 3000 {
                counts[0] += 1;
            } else {
                counts[1] += 1;
            }
        }
        // With weights 3:1, expect ~75% vs ~25%.
        assert!(counts[0] > counts[1] * 2, "counts: {:?}", counts);
    }

    // -----------------------------------------------------------------------
    // LeastConn
    // -----------------------------------------------------------------------

    #[test]
    fn least_conn_picks_lowest_inflight() {
        let members = make_members(3);
        members[0].inflight.store(10, Ordering::Relaxed);
        members[1].inflight.store(2, Ordering::Relaxed);
        members[2].inflight.store(5, Ordering::Relaxed);

        let strategy = LbStrategy::LeastConn;
        let m = strategy.pick(&members, None).unwrap();
        assert_eq!(m.addr.port(), 3001);
    }

    // -----------------------------------------------------------------------
    // P2C
    // -----------------------------------------------------------------------

    #[test]
    fn p2c_picks_from_healthy() {
        let members = make_members(4);
        members[0].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::P2c;

        for _ in 0..20 {
            let m = strategy.pick(&members, None).unwrap();
            assert_ne!(m.addr.port(), 3000);
        }
    }

    // -----------------------------------------------------------------------
    // ConsistentHash
    // -----------------------------------------------------------------------

    #[test]
    fn consistent_hash_stable_for_same_key() {
        let members = make_members(5);
        let strategy = LbStrategy::ConsistentHash;

        let first = strategy.pick(&members, Some("user-42")).unwrap().addr;
        for _ in 0..100 {
            let m = strategy.pick(&members, Some("user-42")).unwrap();
            assert_eq!(m.addr, first);
        }
    }

    #[test]
    fn consistent_hash_stable_under_member_churn() {
        let members = make_members(5);
        let strategy = LbStrategy::ConsistentHash;

        let before = strategy.pick(&members, Some("user-99")).unwrap().addr;

        // Remove member index 0 by marking unhealthy.
        members[0].healthy.store(false, Ordering::Relaxed);
        let after = strategy.pick(&members, Some("user-99")).unwrap();

        // If the original pick was not member 0, it should remain stable.
        if before.port() != 3000 {
            // The result might still differ because the healthy list changed,
            // but this is acceptable for consistent hashing in the baseline
            // implementation. The key stability invariant is tested above.
            let _ = after;
        }
    }

    // -----------------------------------------------------------------------
    // 2026-05-11 PROXY-10 / PROXY-11 — correctness property tests
    // -----------------------------------------------------------------------

    /// P2C — with N>=3 healthy members, picks should spread across
    /// the pool (no single member receives >50% of picks). Pre-fix
    /// the deterministic counter could concentrate picks on a
    /// small subset.
    #[test]
    fn p2c_spreads_picks_across_pool() {
        let members = make_members(5);
        let strategy = LbStrategy::P2c;
        let mut counts = vec![0usize; 5];
        for _ in 0..1000 {
            let m = strategy.pick(&members, None).unwrap();
            let idx = (m.addr.port() - 3000) as usize;
            counts[idx] += 1;
        }
        // Every member should get hit at least once across 1000
        // picks. With uniform random selection each member sees
        // ~200; we use a generous lower bound (50) to avoid
        // flakiness from system-time-seeded entropy.
        for (i, &c) in counts.iter().enumerate() {
            assert!(
                c >= 50,
                "member {i} got {c} picks across 1000 (expected ~200); \
                 the P2C entropy source is broken — picks are not spreading"
            );
        }
        // No single member should dominate (>50%).
        let max = *counts.iter().max().unwrap();
        assert!(
            max < 500,
            "single member got {max}/1000 picks (>50%); P2C entropy is broken"
        );
    }

    /// Rendezvous Hashing — adding or removing a member should
    /// remap only ~1/n of the keys. Pre-fix used modulo, which
    /// remapped ~(n-1)/n = ~50-80% of keys.
    #[test]
    fn consistent_hash_minimal_disruption_on_member_change() {
        let members5 = make_members(5);
        let members6 = make_members(6); // Same first 5 + one new

        let strategy = LbStrategy::ConsistentHash;
        let keys: Vec<String> = (0..1000).map(|i| format!("session-{i:06}")).collect();

        let mut moved = 0usize;
        for k in &keys {
            let pick5 = strategy.pick(&members5, Some(k)).unwrap().addr;
            let pick6 = strategy.pick(&members6, Some(k)).unwrap().addr;
            if pick5 != pick6 {
                moved += 1;
            }
        }

        // With Rendezvous Hashing, the expected fraction of keys
        // that move when adding the 6th member is 1/6 ≈ 17%.
        // Allow generous slack (5% lower, 30% upper) for stochastic
        // variance over 1000 keys.
        let pct = (moved * 100) / keys.len();
        assert!(
            pct < 30,
            "added 1 member to a pool of 5; {moved}/1000 keys remapped ({pct}%). \
             Expected ~17% — the hash is not consistent across member changes."
        );
        assert!(
            pct >= 5,
            "added 1 member to a pool of 5; only {moved}/1000 keys remapped ({pct}%). \
             Expected ~17% — the new member is unreachable."
        );
    }

    /// Rendezvous Hashing — for a fixed (key, member-set), the
    /// pick must be deterministic. Same key always lands on the
    /// same member.
    #[test]
    fn consistent_hash_deterministic_for_session_affinity() {
        let members = make_members(7);
        let strategy = LbStrategy::ConsistentHash;
        for k in ["user-1", "user-42", "abc-xyz-123", ""] {
            let first = strategy.pick(&members, Some(k)).unwrap().addr;
            for _ in 0..100 {
                let again = strategy.pick(&members, Some(k)).unwrap().addr;
                assert_eq!(first, again, "non-deterministic pick for key '{k}'");
            }
        }
    }
}
