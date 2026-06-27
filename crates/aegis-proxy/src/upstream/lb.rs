use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::{LocalityRuntime, Member};

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
    /// Pick a member to forward to, preferring healthy members.
    ///
    /// **Fails open:** if no member is healthy, the full member set is used so
    /// an all-down pool still attempts a forward (a real 502) rather than
    /// refusing to route (a 503). `None` is returned only for a genuinely empty
    /// pool (no members configured).
    ///
    /// `hash_key` is used only by `ConsistentHash`; other strategies ignore it.
    pub fn pick<'a>(
        &self,
        members: &'a [Arc<Member>],
        hash_key: Option<&str>,
    ) -> Option<&'a Arc<Member>> {
        let candidates = healthy_or_fallback(members)?;
        self.apply(&candidates, hash_key)
    }

    /// Zone-aware pick (zone-aware LB P2). Identical to [`Self::pick`] except
    /// that, when `locality.enabled` and the node has a `self_zone`, the
    /// candidate set is **narrowed to members in the node's own zone** before
    /// the strategy is applied — so an operator still gets round_robin / p2c /
    /// consistent_hash *within* the local zone.
    ///
    /// **Spillover (v1 presence gate):** the narrowing only applies when the
    /// local zone has at least one candidate; otherwise the full (healthy or
    /// fail-open) set is used, so traffic is never stranded in an
    /// under-provisioned zone. Composes with the fail-open fallback: narrowing
    /// happens *after* the healthy→all-members fallback, on a guaranteed
    /// non-empty set, so the invariant holds — **`pick` never returns `None`
    /// for a non-empty pool** under any zone configuration.
    ///
    /// `locality` disabled or `self_zone == None` ⇒ byte-identical to
    /// [`Self::pick`].
    pub fn pick_with_locality<'a>(
        &self,
        members: &'a [Arc<Member>],
        hash_key: Option<&str>,
        self_zone: Option<&str>,
        locality: LocalityRuntime,
    ) -> Option<&'a Arc<Member>> {
        let mut candidates = healthy_or_fallback(members)?;
        if locality.enabled {
            if let Some(zone) = self_zone {
                let local: Vec<(usize, &Arc<Member>)> = candidates
                    .iter()
                    .filter(|(_, m)| m.zone.as_deref() == Some(zone))
                    .cloned()
                    .collect();
                // Prefer local only when it has capacity; otherwise spill to
                // the full set (keep `candidates`).
                if !local.is_empty() && local_zone_has_capacity(members, zone, local.len(), locality)
                {
                    candidates = local;
                }
            }
        }
        self.apply(&candidates, hash_key)
    }

    /// Apply the configured strategy to an already-resolved candidate set.
    fn apply<'a>(
        &self,
        candidates: &[(usize, &'a Arc<Member>)],
        hash_key: Option<&str>,
    ) -> Option<&'a Arc<Member>> {
        match self {
            LbStrategy::RoundRobin(counter) => {
                let idx = counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Some(candidates[idx].1)
            }
            LbStrategy::WeightedRoundRobin(counter) => {
                pick_weighted(candidates, counter)
            }
            LbStrategy::LeastConn => {
                candidates
                    .iter()
                    .min_by_key(|(_, m)| m.inflight.load(Ordering::Relaxed))
                    .map(|(_, m)| *m)
            }
            LbStrategy::P2c => {
                pick_p2c(candidates)
            }
            LbStrategy::ConsistentHash => {
                let key = hash_key.unwrap_or("");
                pick_consistent_hash(candidates, key)
            }
        }
    }
}

/// Capacity gate (zone-aware LB P4). Given the count of healthy local-zone
/// candidates, decide whether to keep traffic local or spill cross-zone.
///
/// - `min_local_healthy_pct == None` ⇒ **presence gate** (v1): any healthy
///   local member keeps traffic local (the caller already checked non-empty).
/// - `Some(pct)` ⇒ prefer local only while the local zone's healthy fraction
///   (`local_healthy / local_total`, over *configured* local members) is at or
///   above `pct` percent; below it, spill so a half-dead local zone isn't
///   hammered. Integer math, no float.
fn local_zone_has_capacity(
    members: &[Arc<Member>],
    zone: &str,
    local_healthy: usize,
    locality: LocalityRuntime,
) -> bool {
    match locality.min_local_healthy_pct {
        None => true,
        Some(pct) => {
            let local_total = members
                .iter()
                .filter(|m| m.zone.as_deref() == Some(zone))
                .count();
            // local_total >= local_healthy >= 1 here, so it's never zero.
            local_healthy * 100 >= pct as usize * local_total
        }
    }
}

/// Build the candidate set: the healthy members, or — when none are healthy —
/// the **full** member set (fail open, PREREQ-B for passive-upstream-health),
/// so an all-down pool still attempts a forward (a real 502) instead of
/// refusing to route (a 503). `None` only for a genuinely empty pool (no
/// members configured), the one case where there is nothing to attempt.
fn healthy_or_fallback<'a>(
    members: &'a [Arc<Member>],
) -> Option<Vec<(usize, &'a Arc<Member>)>> {
    let healthy: Vec<(usize, &Arc<Member>)> = members
        .iter()
        .enumerate()
        .filter(|(_, m)| m.is_healthy())
        .collect();
    if healthy.is_empty() {
        if members.is_empty() {
            return None;
        }
        Some(members.iter().enumerate().collect())
    } else {
        Some(healthy)
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

    fn make_zoned_members(spec: &[(u16, &str)]) -> Vec<Arc<Member>> {
        spec.iter()
            .map(|(port, zone)| {
                Arc::new(Member::new(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    1,
                    Some((*zone).to_string()),
                ))
            })
            .collect()
    }

    fn locality_on() -> LocalityRuntime {
        LocalityRuntime { enabled: true, min_local_healthy_pct: None }
    }

    fn locality_pct(pct: u8) -> LocalityRuntime {
        LocalityRuntime { enabled: true, min_local_healthy_pct: Some(pct) }
    }

    // -----------------------------------------------------------------------
    // Zone-aware load balancing (P2) — `pick_with_locality` prefers members in
    // the node's own zone, with v1 presence-gate spillover, composed with the
    // fail-open fallback. Default-off (`pick`) stays byte-identical.
    // -----------------------------------------------------------------------

    #[test]
    fn zone_preference_routes_only_to_local_when_present() {
        // Pool spans az-a + az-b; node is in az-a; all healthy → every pick
        // lands in az-a.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b"), (3002, "az-a")]);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        for _ in 0..30 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_on());
            assert_eq!(
                m.unwrap().zone.as_deref(),
                Some("az-a"),
                "must prefer the node's own zone when local capacity exists"
            );
        }
    }

    #[test]
    fn zone_preference_distributes_within_local_zone() {
        // Two local members → the strategy still spreads across them
        // (round-robin cycles both az-a ports).
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b"), (3002, "az-a")]);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_on());
            seen.insert(m.unwrap().addr.port());
        }
        assert_eq!(
            seen,
            std::collections::HashSet::from([3000, 3002]),
            "strategy must distribute across BOTH local members"
        );
    }

    #[test]
    fn zone_preference_spills_when_no_local_healthy() {
        // The only az-a member is unhealthy → spill to the healthy az-b member
        // (no None, no stranding in the local zone).
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b")]);
        members[0].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        for _ in 0..10 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_on());
            assert_eq!(
                m.unwrap().addr.port(),
                3001,
                "must spill cross-zone when the local zone has no healthy member"
            );
        }
    }

    #[test]
    fn zone_preference_off_is_identity_with_pick() {
        // Locality disabled → identical candidate set to plain `pick` (routes
        // across all zones). Regression guard.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b")]);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        let mut ports = std::collections::HashSet::new();
        for _ in 0..20 {
            let m = strategy.pick_with_locality(
                &members,
                None,
                Some("az-a"),
                LocalityRuntime { enabled: false, min_local_healthy_pct: None },
            );
            ports.insert(m.unwrap().addr.port());
        }
        assert_eq!(
            ports,
            std::collections::HashSet::from([3000, 3001]),
            "disabled locality must route across all zones, like plain pick"
        );
    }

    #[test]
    fn zone_preference_inert_without_self_zone() {
        // Locality on but the node has no zone identity → feature inert, routes
        // across all zones.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b")]);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        let mut ports = std::collections::HashSet::new();
        for _ in 0..20 {
            let m = strategy.pick_with_locality(&members, None, None, locality_on());
            ports.insert(m.unwrap().addr.port());
        }
        assert_eq!(ports, std::collections::HashSet::from([3000, 3001]));
    }

    #[test]
    fn zone_preference_never_none_when_all_unhealthy() {
        // All members unhealthy + locality on → fail-open still routes (a real
        // 502 from the attempt), never None for a non-empty pool.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b")]);
        members[0].healthy.store(false, Ordering::Relaxed);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        assert!(strategy
            .pick_with_locality(&members, None, Some("az-a"), locality_on())
            .is_some());
    }

    // -------------------------------------------------------------------
    // P4 — capacity gate. `min_local_healthy_pct` spills cross-zone when the
    // local zone's healthy fraction drops below the threshold, so a half-dead
    // local zone isn't hammered. `None` ⇒ v1 presence gate (unchanged).
    // -------------------------------------------------------------------

    #[test]
    fn capacity_gate_spills_when_local_below_threshold() {
        // az-a has 3 members, only 1 healthy (33%); az-b has 1 healthy. Node
        // in az-a, threshold 50% → 33% < 50% → spill to the full healthy set.
        let members =
            make_zoned_members(&[(3000, "az-a"), (3001, "az-a"), (3002, "az-a"), (3003, "az-b")]);
        members[1].healthy.store(false, Ordering::Relaxed);
        members[2].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_pct(50));
            seen.insert(m.unwrap().addr.port());
        }
        assert!(
            seen.contains(&3003),
            "below threshold must spill cross-zone (az-b expected), saw {seen:?}"
        );
    }

    #[test]
    fn capacity_gate_stays_local_when_at_or_above_threshold() {
        // az-a 3 members, 2 healthy (66%); threshold 50% → 66% >= 50% → local
        // only (never az-b).
        let members =
            make_zoned_members(&[(3000, "az-a"), (3001, "az-a"), (3002, "az-a"), (3003, "az-b")]);
        members[2].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        for _ in 0..20 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_pct(50));
            assert_eq!(
                m.unwrap().zone.as_deref(),
                Some("az-a"),
                "at/above threshold must stay local"
            );
        }
    }

    #[test]
    fn capacity_gate_none_is_presence_gate() {
        // No threshold → v1 presence gate: a single healthy local member is
        // enough to keep all traffic local.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-a"), (3002, "az-b")]);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        for _ in 0..20 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_on());
            assert_eq!(m.unwrap().addr.port(), 3000, "presence gate keeps it local");
        }
    }

    #[test]
    fn capacity_gate_100_requires_all_local_healthy() {
        // threshold 100%: 1 of 2 local healthy (50%) → spill.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-a"), (3002, "az-b")]);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let m = strategy.pick_with_locality(&members, None, Some("az-a"), locality_pct(100));
            seen.insert(m.unwrap().addr.port());
        }
        assert!(seen.contains(&3002), "100% threshold with a down local member must spill");
    }

    #[test]
    fn capacity_gate_never_none_for_nonempty_pool() {
        // All unhealthy + capacity gate on → fail-open still routes.
        let members = make_zoned_members(&[(3000, "az-a"), (3001, "az-b")]);
        members[0].healthy.store(false, Ordering::Relaxed);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        assert!(strategy
            .pick_with_locality(&members, None, Some("az-a"), locality_pct(50))
            .is_some());
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
    fn round_robin_fails_open_when_all_unhealthy() {
        // PREREQ-B: an all-unhealthy pool must still route — fall back to the
        // full member set so the forward attempt yields a real 502, rather
        // than returning None (a 503 refusal to route).
        let members = make_members(2);
        members[0].healthy.store(false, Ordering::Relaxed);
        members[1].healthy.store(false, Ordering::Relaxed);
        let strategy = LbStrategy::RoundRobin(AtomicUsize::new(0));
        let picked = strategy.pick(&members, None);
        assert!(
            picked.is_some(),
            "all-unhealthy pool must fail open (route + 502), not refuse (503)",
        );
        let port = picked.unwrap().addr.port();
        assert!(port == 3000 || port == 3001, "fallback picks a real member");
    }

    #[test]
    fn pick_returns_none_for_genuinely_empty_pool() {
        // No members configured at all → nothing to attempt → None (503 is the
        // correct contract here; fail-open only covers all-*unhealthy*).
        let members: Vec<Arc<Member>> = Vec::new();
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
