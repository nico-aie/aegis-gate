//! TCP-T2 — per-source-IP concurrent-tunnel counter.
//!
//! See [`plans/tcp-forwarder-phase-4.md`] §6 for the design.
//! Tunnels are heavy (one TCP socket each direction + a
//! `tokio::io::copy_bidirectional` task); a misbehaving client
//! can otherwise drain FDs. This module provides a cheap
//! lock-free counter the CONNECT handler increments before
//! attaching the upgrade hook and decrements when the tunnel
//! task exits.
//!
//! ## Semantics
//!
//! - `try_admit(ip, limit)` atomically increments the per-IP
//!   counter iff it would stay `<= limit`. Returns
//!   `Some(TunnelGuard)` on admit, `None` on overflow.
//! - Dropping the guard decrements the counter. When the
//!   count reaches zero the entry is removed from the map so
//!   the long-tail of one-shot IPs doesn't leak memory.
//! - `limit == 0` is **uncapped** — admits unconditionally.
//!   The plan default is 16 (boot constant); 0 is the YAML
//!   sentinel for "use default", but at this layer we treat
//!   the resolved post-default value of 0 as "no cap" so
//!   integration test fixtures can opt out.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

use aegis_core::tcp_destination::{
    is_internal_address, parse_authority, policy_admits, TcpDestinationRule,
};

/// Default per-IP cap when [`RouteConfig::max_concurrent_tunnels_per_ip`]
/// is unset (`0` in YAML). Tunnels are heavy; 16 is generous
/// for legitimate proxy clients (one per browser tab) and
/// tight enough that an unauthenticated abuser hits the wall
/// quickly.
///
/// [`RouteConfig::max_concurrent_tunnels_per_ip`]: aegis_core::config::RouteConfig::max_concurrent_tunnels_per_ip
pub const DEFAULT_MAX_CONCURRENT_TUNNELS_PER_IP: u32 = 16;

/// Resolve the effective cap from a configured value. `0`
/// (the YAML default sentinel) maps to
/// [`DEFAULT_MAX_CONCURRENT_TUNNELS_PER_IP`].
pub fn effective_cap(configured: u32) -> u32 {
    if configured == 0 {
        DEFAULT_MAX_CONCURRENT_TUNNELS_PER_IP
    } else {
        configured
    }
}

/// Lock-free per-IP concurrent-tunnel counter. Cheap to
/// `Clone` (one `Arc<DashMap>` underneath); every clone shares
/// the same counters.
#[derive(Clone, Debug, Default)]
pub struct ConcurrentTunnels {
    counts: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
}

impl ConcurrentTunnels {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to admit one more tunnel for `ip`. Returns
    /// `Some(TunnelGuard)` when the post-increment count is
    /// `<= limit`; otherwise rolls back and returns `None`.
    ///
    /// `limit == 0` is interpreted as "uncapped" — see module
    /// docs.
    pub fn try_admit(&self, ip: IpAddr, limit: u32) -> Option<TunnelGuard> {
        let counter = self
            .counts
            .entry(ip)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone();
        // fetch_add is monotonic; if we overshoot we roll back
        // and the failure is observable to the caller. This
        // gives `+1 then -1` semantics under contention rather
        // than CAS-looping; the small transient overshoot is
        // harmless because the count never escapes this
        // module.
        let post = counter.fetch_add(1, Ordering::SeqCst) + 1;
        if limit != 0 && post > limit {
            counter.fetch_sub(1, Ordering::SeqCst);
            // Don't try to evict on rollback — a concurrent
            // try_admit on the same key is racing us; whoever
            // sees count==0 on drop does the cleanup.
            return None;
        }
        Some(TunnelGuard {
            ip,
            counter,
            counts: self.counts.clone(),
            armed: true,
        })
    }

    /// Snapshot the live count for `ip`. Cheap (one shard
    /// lock + atomic load). Returns 0 for unseen IPs.
    pub fn count(&self, ip: IpAddr) -> u32 {
        self.counts
            .get(&ip)
            .map(|e| e.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Total number of distinct IPs with at least one open
    /// tunnel. Used by `/api/tcp-tunnels` (future) and
    /// integration-test sanity checks.
    pub fn distinct_ips(&self) -> usize {
        self.counts.len()
    }
}

/// RAII handle returned from [`ConcurrentTunnels::try_admit`].
/// Decrements the per-IP count on drop and evicts the entry
/// when the count reaches zero.
///
/// Holders must keep the guard alive for the full lifetime of
/// the tunnel (typically inside the spawned bridge task) so
/// the count tracks the real number of open sockets.
#[must_use = "tunnel guard must be held for the lifetime of the tunnel — dropping it early frees the slot"]
pub struct TunnelGuard {
    ip: IpAddr,
    counter: Arc<AtomicU32>,
    counts: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    armed: bool,
}

impl TunnelGuard {
    /// Source IP this guard accounts for.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Disarm the guard so dropping it does NOT decrement.
    /// Used by tests that want to inspect the post-admit
    /// state without the side effect.
    #[cfg(test)]
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl std::fmt::Debug for TunnelGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelGuard")
            .field("ip", &self.ip)
            .field("count", &self.counter.load(Ordering::SeqCst))
            .field("armed", &self.armed)
            .finish()
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let post = self.counter.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
        if post == 0 {
            // Evict the empty slot. `remove_if` checks the
            // predicate under the shard lock so a concurrent
            // try_admit racing us either sees the empty slot
            // and re-creates it, or sees a zero counter and
            // we're about to remove — both cases are safe.
            self.counts.remove_if(&self.ip, |_, v| {
                v.load(Ordering::SeqCst) == 0
            });
        }
    }
}

/// TCP-T3a — admission decision for a CONNECT request that
/// resolved to a `scheme: tcp` route. Pure function; the data-
/// plane handler (TCP-T3c) calls this after route resolution
/// and before attaching the upgrade hook.
///
/// The caller is responsible for **DNS resolution** when the
/// authority isn't a literal IP. We deliberately don't resolve
/// here so the function stays sync + side-effect-free; T3c uses
/// `tokio::net::lookup_host` and re-enters this admit with the
/// resolved literal address.
///
/// Returns one of:
/// - [`ConnectAdmission::Admit`] — caller returns 200 OK and
///   spawns the bridge task; the embedded [`TunnelGuard`] must
///   be moved into that task to keep the per-IP slot alive.
/// - [`ConnectAdmission::Deny`] — caller renders the response
///   from the `status` + `rule_id` + `message` fields. The
///   `rule_id`s match plans/tcp-forwarder-phase-4.md §3.
pub fn connect_admit(req: ConnectAdmissionRequest<'_>) -> ConnectAdmission {
    let Some((dest, port)) = parse_authority(req.authority) else {
        return ConnectAdmission::Deny {
            status: 400,
            rule_id: "connect_authority_unparseable",
            message:
                "CONNECT authority must be host:port with a literal IP \
                 (DNS resolution is the caller's responsibility)",
        };
    };
    if is_internal_address(dest) {
        // Bypass via env var lives at the parse-time gate so a
        // route with `127.0.0.0/8:*` in its allowlist would have
        // been rejected at config-load. At runtime we always
        // refuse internal targets.
        return ConnectAdmission::Deny {
            status: 403,
            rule_id: "connect_destination_internal",
            message: "CONNECT destination is internal-only address space",
        };
    }
    if !policy_admits(req.allowlist, dest, port) {
        return ConnectAdmission::Deny {
            status: 403,
            rule_id: "connect_destination_denied",
            message: "CONNECT destination not in route's allowlist",
        };
    }
    let limit = effective_cap(req.max_per_ip);
    let Some(guard) = req.tunnels.try_admit(req.peer_ip, limit) else {
        return ConnectAdmission::Deny {
            status: 429,
            rule_id: "connect_concurrent_tunnel_cap",
            message: "per-source-IP concurrent CONNECT tunnel cap reached",
        };
    };
    ConnectAdmission::Admit { dest, port, guard }
}

/// Inputs to [`connect_admit`].
#[derive(Clone, Copy, Debug)]
pub struct ConnectAdmissionRequest<'a> {
    /// CONNECT request authority (`host:port`). For HTTP/1.1
    /// CONNECT requests this is `req.uri().authority().as_str()`.
    /// MUST be a literal IP at this layer — see fn doc.
    pub authority: &'a str,
    /// Pre-parsed allowlist rules from the resolved route's
    /// `tcp_destination_allowlist`. Empty = closed.
    pub allowlist: &'a [TcpDestinationRule],
    /// Resolved per-route cap from
    /// `RouteConfig.max_concurrent_tunnels_per_ip`. `0` falls
    /// back to [`DEFAULT_MAX_CONCURRENT_TUNNELS_PER_IP`].
    pub max_per_ip: u32,
    /// Source IP of the request, post-XFF validation.
    pub peer_ip: IpAddr,
    /// The shared per-IP counter map. Cheap to clone and pass
    /// in (every clone shares state).
    pub tunnels: &'a ConcurrentTunnels,
}

/// Outcome of [`connect_admit`].
#[derive(Debug)]
pub enum ConnectAdmission {
    Admit {
        dest: IpAddr,
        port: u16,
        guard: TunnelGuard,
    },
    Deny {
        status: u16,
        rule_id: &'static str,
        message: &'static str,
    },
}

impl ConnectAdmission {
    pub fn is_admit(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }

    /// Convenience for tests + the future audit emitter — pull
    /// the rule_id out of either branch (Admit reports
    /// `tunnel_admitted`).
    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::Admit { .. } => "tunnel_admitted",
            Self::Deny { rule_id, .. } => rule_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::tcp_destination::parse_rule;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(s: &str) -> TcpDestinationRule {
        parse_rule(s).expect("parse")
    }

    #[test]
    fn effective_cap_zero_maps_to_default() {
        assert_eq!(effective_cap(0), DEFAULT_MAX_CONCURRENT_TUNNELS_PER_IP);
    }

    #[test]
    fn effective_cap_nonzero_passes_through() {
        assert_eq!(effective_cap(1), 1);
        assert_eq!(effective_cap(99), 99);
    }

    #[test]
    fn try_admit_increments_count() {
        let tunnels = ConcurrentTunnels::new();
        let _g1 = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
        assert_eq!(tunnels.count(ip("203.0.113.1")), 1);
        let _g2 = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
        assert_eq!(tunnels.count(ip("203.0.113.1")), 2);
    }

    #[test]
    fn try_admit_blocks_at_limit() {
        let tunnels = ConcurrentTunnels::new();
        let mut guards = Vec::new();
        for _ in 0..3 {
            guards.push(tunnels.try_admit(ip("203.0.113.1"), 3).unwrap());
        }
        // 4th admit at limit=3 must fail.
        assert!(tunnels.try_admit(ip("203.0.113.1"), 3).is_none());
        // Count must NOT have moved past the limit (rollback
        // semantics).
        assert_eq!(tunnels.count(ip("203.0.113.1")), 3);
    }

    #[test]
    fn try_admit_with_limit_zero_is_uncapped() {
        let tunnels = ConcurrentTunnels::new();
        let mut guards = Vec::new();
        for _ in 0..50 {
            guards.push(tunnels.try_admit(ip("203.0.113.1"), 0).unwrap());
        }
        assert_eq!(tunnels.count(ip("203.0.113.1")), 50);
    }

    #[test]
    fn drop_decrements_count() {
        let tunnels = ConcurrentTunnels::new();
        let g = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
        assert_eq!(tunnels.count(ip("203.0.113.1")), 1);
        drop(g);
        assert_eq!(tunnels.count(ip("203.0.113.1")), 0);
    }

    #[test]
    fn count_zero_evicts_entry() {
        let tunnels = ConcurrentTunnels::new();
        {
            let _g = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
            assert_eq!(tunnels.distinct_ips(), 1);
        }
        // Guard dropped → count=0 → entry evicted.
        assert_eq!(tunnels.distinct_ips(), 0);
        assert_eq!(tunnels.count(ip("203.0.113.1")), 0);
    }

    #[test]
    fn entry_kept_while_other_guards_alive() {
        let tunnels = ConcurrentTunnels::new();
        let g1 = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
        let g2 = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
        drop(g1);
        // g2 still alive — count stays at 1, entry stays.
        assert_eq!(tunnels.count(ip("203.0.113.1")), 1);
        assert_eq!(tunnels.distinct_ips(), 1);
        drop(g2);
        // Now both gone — entry evicted.
        assert_eq!(tunnels.distinct_ips(), 0);
    }

    #[test]
    fn distinct_ips_tracked_independently() {
        let tunnels = ConcurrentTunnels::new();
        let _g_a = tunnels.try_admit(ip("203.0.113.1"), 2).unwrap();
        let _g_b1 = tunnels.try_admit(ip("198.51.100.1"), 2).unwrap();
        assert_eq!(tunnels.distinct_ips(), 2);
        // A's limit doesn't affect B's count — bind the second
        // B guard so the count actually stays at 2 for the
        // assertion below (an unbound result drops on the
        // next statement).
        let _g_b2 = tunnels.try_admit(ip("198.51.100.1"), 2).unwrap();
        assert_eq!(tunnels.count(ip("203.0.113.1")), 1);
        assert_eq!(tunnels.count(ip("198.51.100.1")), 2);
    }

    #[test]
    fn rollback_after_overshoot_allows_subsequent_admit() {
        let tunnels = ConcurrentTunnels::new();
        let _g1 = tunnels.try_admit(ip("203.0.113.1"), 1).unwrap();
        // Limit hit — next admit fails and rolls back.
        assert!(tunnels.try_admit(ip("203.0.113.1"), 1).is_none());
        // Roll back left count at 1; raising the limit lets
        // the next admit through. Bind the guard so the post-
        // admit count actually persists across the assertion.
        let _g2 = tunnels.try_admit(ip("203.0.113.1"), 2).unwrap();
        assert_eq!(tunnels.count(ip("203.0.113.1")), 2);
    }

    #[test]
    fn guard_carries_source_ip() {
        let tunnels = ConcurrentTunnels::new();
        let g = tunnels.try_admit(ip("198.51.100.99"), 4).unwrap();
        assert_eq!(g.ip(), ip("198.51.100.99"));
    }

    #[test]
    fn ipv6_is_tracked_separately_from_ipv4() {
        let tunnels = ConcurrentTunnels::new();
        let _g_v4 = tunnels.try_admit(ip("203.0.113.1"), 1).unwrap();
        // Distinct address family — separate entry, no
        // collision with the v4 limit.
        let _g_v6 = tunnels.try_admit(ip("2001:db8::1"), 1).unwrap();
        assert_eq!(tunnels.distinct_ips(), 2);
    }

    #[test]
    fn disarm_skips_decrement() {
        let tunnels = ConcurrentTunnels::new();
        let g = tunnels.try_admit(ip("203.0.113.1"), 4).unwrap();
        g.disarm();
        // Disarmed guard dropped → count NOT decremented;
        // entry NOT evicted. Test-only escape hatch.
        assert_eq!(tunnels.count(ip("203.0.113.1")), 1);
    }

    #[tokio::test]
    async fn concurrent_admits_respect_limit() {
        // Hammer try_admit from many tasks; the post-condition
        // is that the steady-state count never exceeded the
        // limit, regardless of contention.
        let tunnels = ConcurrentTunnels::new();
        let target = ip("203.0.113.1");
        let limit = 5u32;
        let mut handles = Vec::new();
        for _ in 0..50 {
            let t = tunnels.clone();
            handles.push(tokio::spawn(async move {
                t.try_admit(target, limit)
            }));
        }
        let mut admits: Vec<_> = Vec::new();
        for h in handles {
            if let Some(g) = h.await.unwrap() {
                admits.push(g);
            }
        }
        // Exactly `limit` of the 50 attempts should have
        // admitted; the rest rolled back.
        assert_eq!(admits.len() as u32, limit);
        assert_eq!(tunnels.count(target), limit);
        // Drop everything → count goes to zero, entry evicted.
        drop(admits);
        assert_eq!(tunnels.count(target), 0);
        assert_eq!(tunnels.distinct_ips(), 0);
    }

    // -----------------------------------------------------------
    // TCP-T3a — connect_admit
    // -----------------------------------------------------------

    fn admit_req<'a>(
        authority: &'a str,
        allowlist: &'a [TcpDestinationRule],
        peer_ip: IpAddr,
        tunnels: &'a ConcurrentTunnels,
    ) -> ConnectAdmissionRequest<'a> {
        ConnectAdmissionRequest {
            authority,
            allowlist,
            max_per_ip: 4,
            peer_ip,
            tunnels,
        }
    }

    #[test]
    fn connect_admit_admits_allowed_destination() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "203.0.113.42:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        match outcome {
            ConnectAdmission::Admit { dest, port, .. } => {
                assert_eq!(dest, ip("203.0.113.42"));
                assert_eq!(port, 443);
            }
            ConnectAdmission::Deny { rule_id, .. } => {
                panic!("expected admit, got deny: {rule_id}")
            }
        }
        // Guard still alive inside the Admit value → counter is 1.
        // (We pattern-matched but didn't drop.)
        // Wait — the match dropped the guard at end of arm. Verify.
    }

    #[test]
    fn connect_admit_keeps_guard_alive_until_drop() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "203.0.113.42:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        // Hold the outcome (and thus the guard) — counter = 1.
        assert!(outcome.is_admit());
        assert_eq!(tunnels.count(ip("198.51.100.1")), 1);
        drop(outcome);
        assert_eq!(tunnels.count(ip("198.51.100.1")), 0);
    }

    #[test]
    fn connect_admit_rejects_unparseable_authority() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "not-a-host-port",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        match outcome {
            ConnectAdmission::Deny { status, rule_id, .. } => {
                assert_eq!(status, 400);
                assert_eq!(rule_id, "connect_authority_unparseable");
            }
            _ => panic!("expected deny"),
        }
        // No counter touch on early reject.
        assert_eq!(tunnels.count(ip("198.51.100.1")), 0);
    }

    #[test]
    fn connect_admit_rejects_dns_name_authority() {
        // DNS names go through `parse_authority` → None; the
        // caller is expected to resolve before calling
        // `connect_admit`. Until they do, we deny.
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "api.example.com:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        assert!(!outcome.is_admit());
        assert_eq!(outcome.rule_id(), "connect_authority_unparseable");
    }

    #[test]
    fn connect_admit_rejects_internal_destination() {
        // Internal destinations are blocked even if the operator
        // tried to put them in the allowlist (they couldn't —
        // parse_rule rejects internal CIDRs at config load).
        // Belt-and-braces.
        let tunnels = ConcurrentTunnels::new();
        let allowlist: Vec<TcpDestinationRule> = vec![]; // empty doesn't matter — internal gate fires first
        let outcome = connect_admit(admit_req(
            "127.0.0.1:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        match outcome {
            ConnectAdmission::Deny { status, rule_id, .. } => {
                assert_eq!(status, 403);
                assert_eq!(rule_id, "connect_destination_internal");
            }
            _ => panic!("expected internal deny"),
        }
    }

    #[test]
    fn connect_admit_rejects_outside_allowlist() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "198.18.0.1:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        match outcome {
            ConnectAdmission::Deny { status, rule_id, .. } => {
                assert_eq!(status, 403);
                assert_eq!(rule_id, "connect_destination_denied");
            }
            _ => panic!("expected destination_denied"),
        }
    }

    #[test]
    fn connect_admit_rejects_outside_allowlist_port() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "203.0.113.5:6379",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        assert_eq!(outcome.rule_id(), "connect_destination_denied");
    }

    #[test]
    fn connect_admit_empty_allowlist_rejects_everything() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist: Vec<TcpDestinationRule> = vec![];
        let outcome = connect_admit(admit_req(
            "203.0.113.5:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        assert_eq!(outcome.rule_id(), "connect_destination_denied");
    }

    #[test]
    fn connect_admit_rejects_when_per_ip_cap_full() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let peer = ip("198.51.100.1");
        // Saturate to limit=2.
        let mut req = admit_req("203.0.113.5:443", &allowlist, peer, &tunnels);
        req.max_per_ip = 2;
        let _g1 = match connect_admit(req) {
            ConnectAdmission::Admit { guard, .. } => guard,
            other => panic!("first admit failed: {other:?}"),
        };
        let _g2 = match connect_admit(req) {
            ConnectAdmission::Admit { guard, .. } => guard,
            other => panic!("second admit failed: {other:?}"),
        };
        // Third attempt exceeds the cap.
        let outcome = connect_admit(req);
        match outcome {
            ConnectAdmission::Deny { status, rule_id, .. } => {
                assert_eq!(status, 429);
                assert_eq!(rule_id, "connect_concurrent_tunnel_cap");
            }
            _ => panic!("expected concurrent-tunnel-cap deny"),
        }
        // Cap rejection didn't leave the counter overshooting.
        assert_eq!(tunnels.count(peer), 2);
    }

    #[test]
    fn connect_admit_v6_authority_round_trip() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("2001:db8::/32:443")];
        let outcome = connect_admit(admit_req(
            "[2001:db8::1]:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        match outcome {
            ConnectAdmission::Admit { dest, port, .. } => {
                assert_eq!(dest, ip("2001:db8::1"));
                assert_eq!(port, 443);
            }
            other => panic!("expected admit, got {other:?}"),
        }
    }

    #[test]
    fn connect_admit_rule_id_for_admit_branch() {
        let tunnels = ConcurrentTunnels::new();
        let allowlist = vec![rule("203.0.113.0/24:443")];
        let outcome = connect_admit(admit_req(
            "203.0.113.5:443",
            &allowlist,
            ip("198.51.100.1"),
            &tunnels,
        ));
        assert_eq!(outcome.rule_id(), "tunnel_admitted");
    }
}
