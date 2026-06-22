//! Background DNS refresh for `MemberAddrSpec::Hostname` members.
//!
//! **PR-DNS-2 (2026-05-11) — Phase 2.** Builds on Phase 1's
//! `dns_resolve` (boot + dashboard-PUT one-shot resolver). For
//! every pool that has at least one hostname member, this module
//! spawns a background task that re-resolves the hostnames at
//! their DNS TTL, builds a fresh `PoolConfig`, and calls
//! `PoolRegistry::apply` whenever the resolved IP set changes.
//! Operators get cloud-LB / K8s Service / Consul rotation without
//! a config reload.
//!
//! ## Per-pool task shape
//!
//! - One task per pool that has hostname members at boot.
//! - The task keeps:
//!   - `static_members` — operator-pinned IP members; preserved
//!     verbatim across refreshes.
//!   - `hostnames` — the operator-authored hostname specs +
//!     per-hostname `last_known_ips` cache so a resolver outage
//!     doesn't drop members mid-rotation.
//!   - `base` — the rest of `PoolConfig` (`lb`, `health`,
//!     `circuit_breaker`, `connection`) so the registry swap
//!     keeps every non-membership setting intact.
//! - Sleep cadence: `min(record TTL, refresh_seconds override,
//!   DEFAULT_REFRESH)` clamped to `[MIN_REFRESH, MAX_REFRESH]`.
//!
//! ## Soft failure
//!
//! Resolve failures don't drop members. The per-hostname
//! `last_known_ips` cache survives until the next successful
//! resolution. The task logs `tracing::warn!` and retries on the
//! next tick — same pattern as nginx's `resolver` directive.
//!
//! ## Audit event
//!
//! `pool_dns_resolved` fires on the audit bus when an actual IP
//! diff lands. The `before` / `after` JSON carries the IP sets so
//! operators can correlate "the LB rotated" with downstream
//! latency changes in Live Feed.
//!
//! ## Scope guard
//!
//! Phase 2 spawns refresh tasks at boot only. Dashboard PUTs that
//! add a new hostname to a pool **don't** spawn a new refresh
//! task today — the new hostname gets Phase 1's one-shot
//! resolution at PUT time and stays static until the next process
//! restart. Phase 2.5 / Phase 3 will lift this restriction.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_core::audit::{AuditClass, AuditEvent, AuditBus};
use aegis_core::config::{MemberAddrSpec, MemberConfig, PoolConfig};
use hickory_resolver::TokioResolver;

use crate::upstream::registry::PoolRegistry;

/// Lowest interval we'll honour — defends against an authoritative
/// returning TTL=1 storm. Operators wanting tighter cadence can
/// set `refresh_seconds` explicitly down to this floor.
pub const MIN_REFRESH: Duration = Duration::from_secs(10);
/// Upper bound regardless of TTL — keeps a polling task firing
/// often enough that operators see DNS rotations within an
/// SLA-relevant window even when authoritatives lie about long
/// TTLs.
pub const MAX_REFRESH: Duration = Duration::from_secs(3600);
/// Fallback when the resolver returns no TTL and the operator
/// hasn't set `refresh_seconds`. 60 s mirrors nginx's `resolver
/// valid=60s` default.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(60);

/// One hostname-shaped member from the operator's config. The
/// refresh task holds the original spec (not the expanded IP
/// members) so it knows what to re-resolve.
#[derive(Clone, Debug)]
pub struct HostnameSpec {
    pub host: String,
    pub port: u16,
    pub refresh_seconds: Option<u32>,
    pub weight: u32,
    pub zone: Option<String>,
    /// Explicit `host_header` the operator set on this member.
    /// `None` means "default to the hostname for SNI"; an
    /// explicit value overrides the default.
    pub explicit_host_header: Option<String>,
}

/// All the inputs a refresh task needs for one pool.
#[derive(Clone, Debug)]
pub struct DnsRefreshSpec {
    /// Static IP-typed members. Preserved verbatim across every
    /// refresh.
    pub static_members: Vec<MemberConfig>,
    /// Hostnames to re-resolve on every tick.
    pub hostnames: Vec<HostnameSpec>,
    /// Skeleton `PoolConfig` — `members` is overwritten on each
    /// refresh; every other field carries through.
    pub base: PoolConfig,
}

impl DnsRefreshSpec {
    pub fn has_hostnames(&self) -> bool {
        !self.hostnames.is_empty()
    }
}

/// Pull the refresh spec out of an operator-authored `PoolConfig`
/// before Phase 1's resolver expands it. The static-member
/// `MemberConfig`s pass through unchanged; hostname members get
/// stripped + summarised in `hostnames`.
pub fn extract_spec(pool_cfg: &PoolConfig) -> DnsRefreshSpec {
    let mut static_members = Vec::new();
    let mut hostnames = Vec::new();
    for m in &pool_cfg.members {
        match &m.addr {
            MemberAddrSpec::Ip(_) => static_members.push(m.clone()),
            MemberAddrSpec::Hostname { host, port, refresh_seconds } => {
                hostnames.push(HostnameSpec {
                    host: host.clone(),
                    port: *port,
                    refresh_seconds: *refresh_seconds,
                    weight: m.weight,
                    zone: m.zone.clone(),
                    explicit_host_header: m.host_header.clone(),
                });
            }
        }
    }
    DnsRefreshSpec {
        static_members,
        hostnames,
        base: pool_cfg.clone(),
    }
}

/// Resolve one hostname into `Vec<IpAddr>` + TTL deadline.
///
/// Returns `Ok((ips, ttl_deadline))` on success, or `Err(reason)`
/// on resolver failure. The caller decides how to soft-fail —
/// keeping the previous IP set is the production path.
async fn resolve_once(
    resolver: &TokioResolver,
    host: &str,
) -> Result<(Vec<IpAddr>, Instant), String> {
    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| e.to_string())?;
    let ips: Vec<IpAddr> = lookup.iter().collect();
    let valid_until = lookup.valid_until();
    Ok((ips, valid_until))
}

/// Decide how long to sleep before the next refresh tick. Honours
/// the smallest of (record TTL, operator-overridden
/// `refresh_seconds`, `DEFAULT_REFRESH`), clamped to
/// `[MIN_REFRESH, MAX_REFRESH]`.
fn next_sleep(min_ttl_until: Option<Instant>, override_seconds: Option<u32>) -> Duration {
    let now = Instant::now();
    // Start with the record TTL when we have one; otherwise the
    // nginx-style 60s fallback. Then narrow by the operator-set
    // override if any. Final clamp keeps the resolver from
    // hammering on a TTL=1s storm and from sleeping past a
    // production-acceptable rotation window.
    let ttl_dur = min_ttl_until
        .map(|t| t.saturating_duration_since(now))
        .unwrap_or(DEFAULT_REFRESH);
    let candidate = match override_seconds {
        Some(s) => ttl_dur.min(Duration::from_secs(s.into())),
        None => ttl_dur,
    };
    candidate.clamp(MIN_REFRESH, MAX_REFRESH)
}

/// Build the full `MemberConfig` list for the pool — static
/// members first (in original order), then DNS-resolved members
/// grouped per hostname (in operator-authored order).
///
/// `last_known_ips` is indexed by `hostnames` position; entries
/// for failed resolutions carry their previous IPs so a transient
/// resolver outage doesn't shrink the pool.
pub fn build_members(
    static_members: &[MemberConfig],
    hostnames: &[HostnameSpec],
    last_known_ips: &[Vec<IpAddr>],
) -> Vec<MemberConfig> {
    let mut out = Vec::with_capacity(
        static_members.len() + last_known_ips.iter().map(Vec::len).sum::<usize>(),
    );
    out.extend_from_slice(static_members);
    for (spec, ips) in hostnames.iter().zip(last_known_ips.iter()) {
        let default_host_header = spec
            .explicit_host_header
            .clone()
            .or_else(|| Some(spec.host.clone()));
        for ip in ips {
            out.push(MemberConfig {
                addr: MemberAddrSpec::Ip(SocketAddr::new(*ip, spec.port)),
                weight: spec.weight,
                zone: spec.zone.clone(),
                host_header: default_host_header.clone(),
            });
        }
    }
    out
}

/// Spawn the per-pool refresh task. `applied_ip_set_seed` is the
/// set of DNS-resolved IPs already live in the registry for this
/// pool (from Phase 1's boot expansion); the first refresh tick
/// will compare against this seed and skip the apply + audit
/// event when the resolution matches what's already running.
pub fn spawn_pool_refresh(
    pool_name: String,
    spec: DnsRefreshSpec,
    registry: Arc<PoolRegistry>,
    resolver: Arc<TokioResolver>,
    bus: AuditBus,
    applied_ip_set_seed: HashSet<IpAddr>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // `last_known_ips[i]` mirrors `spec.hostnames[i]`. Empty
        // at start — the first tick fills it in. The
        // `last_applied_ip_set` is seeded so the first tick skips
        // a redundant apply + audit when the resolution matches
        // the current registry state.
        let mut last_known_ips: Vec<Vec<IpAddr>> = vec![Vec::new(); spec.hostnames.len()];
        let mut last_applied_ip_set: HashSet<IpAddr> = applied_ip_set_seed;

        // Surface the task lifetime so operators see in the log
        // that the refresh loop started for this pool.
        tracing::info!(
            pool = %pool_name,
            hostnames = ?spec.hostnames.iter().map(|h| h.host.as_str()).collect::<Vec<_>>(),
            "dns_refresh: starting per-pool refresh loop",
        );

        loop {
            let mut next_known_ips: Vec<Vec<IpAddr>> = last_known_ips.clone();
            let mut min_ttl_until: Option<Instant> = None;
            let mut min_override_seconds: Option<u32> = None;

            for (idx, hostspec) in spec.hostnames.iter().enumerate() {
                match resolve_once(&resolver, &hostspec.host).await {
                    Ok((ips, valid_until)) => {
                        next_known_ips[idx] = ips;
                        min_ttl_until = Some(min_ttl_until.map_or(valid_until, |t| t.min(valid_until)));
                    }
                    Err(reason) => {
                        // Soft-failure — keep the previous IP set
                        // for this hostname, retry on the next
                        // tick. The pool's circuit breaker + health
                        // probes catch stale IPs that the
                        // upstream actually dropped.
                        tracing::warn!(
                            pool = %pool_name,
                            host = %hostspec.host,
                            error = %reason,
                            "dns_refresh: resolve failed, keeping last-known IPs",
                        );
                    }
                }
                if let Some(s) = hostspec.refresh_seconds {
                    min_override_seconds = Some(min_override_seconds.map_or(s, |x| x.min(s)));
                }
            }

            // Diff against the previously-applied set; only push
            // through to the registry on an actual change.
            let new_ip_set: HashSet<IpAddr> = next_known_ips
                .iter()
                .flat_map(|v| v.iter().copied())
                .collect();

            if new_ip_set != last_applied_ip_set {
                let new_members = build_members(
                    &spec.static_members,
                    &spec.hostnames,
                    &next_known_ips,
                );
                let mut full_map = registry.current_pools();
                let pool_cfg = PoolConfig {
                    members: new_members,
                    lb: spec.base.lb.clone(),
                    health: spec.base.health.clone(),
                    circuit_breaker: spec.base.circuit_breaker.clone(),
                    connection: spec.base.connection.clone(),
                    // Preserve the per-upstream cache policy across DNS refresh.
                    cache: spec.base.cache.clone(),
                    // Preserve upstream-mTLS policy; `registry.apply`
                    // re-resolves it against the shared fleet identity.
                    upstream_mtls: spec.base.upstream_mtls.clone(),
                };
                full_map.insert(pool_name.clone(), pool_cfg);
                match registry.apply(&full_map) {
                    Ok(()) => {
                        emit_dns_resolved(
                            &bus,
                            &pool_name,
                            &last_applied_ip_set,
                            &new_ip_set,
                        );
                        last_applied_ip_set = new_ip_set;
                        last_known_ips = next_known_ips;
                    }
                    Err(e) => {
                        tracing::warn!(
                            pool = %pool_name,
                            error = %e,
                            "dns_refresh: registry.apply failed; will retry next tick",
                        );
                    }
                }
            } else {
                // No IP diff — keep `last_known_ips` in sync so
                // that subsequent ticks build off the latest
                // resolution successes (even if the union didn't
                // change).
                last_known_ips = next_known_ips;
            }

            let sleep_dur = next_sleep(min_ttl_until, min_override_seconds);
            tracing::debug!(
                pool = %pool_name,
                sleep_secs = sleep_dur.as_secs(),
                "dns_refresh: next refresh tick scheduled",
            );
            tokio::time::sleep(sleep_dur).await;
        }
    })
}

fn emit_dns_resolved(
    bus: &AuditBus,
    pool_name: &str,
    before: &HashSet<IpAddr>,
    after: &HashSet<IpAddr>,
) {
    let before_sorted: Vec<String> = {
        let mut v: Vec<String> = before.iter().map(|ip| ip.to_string()).collect();
        v.sort();
        v
    };
    let after_sorted: Vec<String> = {
        let mut v: Vec<String> = after.iter().map(|ip| ip.to_string()).collect();
        v.sort();
        v
    };
    let added: Vec<String> = after
        .difference(before)
        .map(|ip| ip.to_string())
        .collect();
    let removed: Vec<String> = before
        .difference(after)
        .map(|ip| ip.to_string())
        .collect();
    bus.emit(AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: String::new(),
        class: AuditClass::System,
        tenant_id: None,
        tier: None,
        action: "pool_dns_resolved".into(),
        reason: format!(
            "dns refresh changed resolved IP set for pool `{pool_name}` (+{} / -{})",
            added.len(),
            removed.len(),
        ),
        client_ip: String::new(),
        route_id: None,
        rule_id: None,
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({
            "pool": pool_name,
            "before": before_sorted,
            "after": after_sorted,
            "added": added,
            "removed": removed,
        }),
    });
}

/// Walk `upstreams` and return the subset of pools that have at
/// least one hostname member, paired with their refresh specs.
/// `aegis_proxy::run` uses this to know which pools warrant a
/// refresh task.
pub fn extract_specs(
    upstreams: &HashMap<String, PoolConfig>,
) -> Vec<(String, DnsRefreshSpec)> {
    upstreams
        .iter()
        .filter_map(|(name, cfg)| {
            let spec = extract_spec(cfg);
            if spec.has_hostnames() {
                Some((name.clone(), spec))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_member(s: &str) -> MemberConfig {
        MemberConfig {
            addr: MemberAddrSpec::Ip(s.parse().unwrap()),
            weight: 1,
            zone: None,
            host_header: None,
        }
    }

    fn host_member(host: &str, port: u16, weight: u32) -> MemberConfig {
        MemberConfig {
            addr: MemberAddrSpec::Hostname {
                host: host.into(),
                port,
                refresh_seconds: None,
            },
            weight,
            zone: None,
            host_header: None,
        }
    }

    fn base_pool(members: Vec<MemberConfig>) -> PoolConfig {
        PoolConfig {
            members,
            lb: aegis_core::config::LbStrategy::RoundRobin,
            health: None,
            circuit_breaker: None,
            connection: aegis_core::config::ConnectionPoolConfig::default(),
            cache: None,
            upstream_mtls: None,
        }
    }

    #[test]
    fn extract_spec_splits_static_and_hostnames() {
        let pool = base_pool(vec![
            ip_member("10.0.0.1:8080"),
            host_member("api.example.com", 443, 3),
            ip_member("10.0.0.2:8080"),
        ]);
        let spec = extract_spec(&pool);
        assert_eq!(spec.static_members.len(), 2, "two IP members preserved");
        assert_eq!(spec.hostnames.len(), 1);
        assert_eq!(spec.hostnames[0].host, "api.example.com");
        assert_eq!(spec.hostnames[0].port, 443);
        assert_eq!(spec.hostnames[0].weight, 3);
        assert!(spec.has_hostnames());
    }

    #[test]
    fn extract_spec_no_hostnames_when_all_ip() {
        let pool = base_pool(vec![ip_member("10.0.0.1:8080")]);
        let spec = extract_spec(&pool);
        assert!(!spec.has_hostnames());
        assert_eq!(spec.static_members.len(), 1);
    }

    #[test]
    fn build_members_combines_static_first() {
        let static_members = vec![ip_member("10.0.0.1:8080")];
        let hostnames = vec![HostnameSpec {
            host: "api.example.com".into(),
            port: 443,
            refresh_seconds: None,
            weight: 2,
            zone: Some("us-east".into()),
            explicit_host_header: None,
        }];
        let last_known: Vec<Vec<IpAddr>> = vec![vec![
            "52.84.150.17".parse().unwrap(),
            "52.84.150.42".parse().unwrap(),
        ]];

        let members = build_members(&static_members, &hostnames, &last_known);
        assert_eq!(members.len(), 3, "1 static + 2 dns");
        // Static first.
        assert!(matches!(members[0].addr, MemberAddrSpec::Ip(_)));
        assert!(members[0].host_header.is_none(), "static member host_header unchanged");
        // DNS members carry hostname-derived host_header for SNI.
        assert_eq!(members[1].host_header.as_deref(), Some("api.example.com"));
        assert_eq!(members[1].weight, 2);
        assert_eq!(members[1].zone.as_deref(), Some("us-east"));
        // DNS members all share the same port.
        match members[1].addr {
            MemberAddrSpec::Ip(sa) => assert_eq!(sa.port(), 443),
            _ => panic!("expected Ip"),
        }
    }

    #[test]
    fn build_members_honours_explicit_host_header() {
        let hostnames = vec![HostnameSpec {
            host: "internal.example.com".into(),
            port: 443,
            refresh_seconds: None,
            weight: 1,
            zone: None,
            explicit_host_header: Some("public.example.com".into()),
        }];
        let last_known: Vec<Vec<IpAddr>> = vec![vec!["10.0.0.10".parse().unwrap()]];
        let members = build_members(&[], &hostnames, &last_known);
        assert_eq!(
            members[0].host_header.as_deref(),
            Some("public.example.com"),
            "explicit host_header must win over hostname-default",
        );
    }

    #[test]
    fn next_sleep_honours_ttl_when_smaller() {
        // TTL says ~30s, no override → return ~30s (clamped to MIN floor).
        let in_30s = Instant::now() + Duration::from_secs(30);
        let dur = next_sleep(Some(in_30s), None);
        // Within a small jitter window of 30s.
        assert!(dur >= Duration::from_secs(25) && dur <= Duration::from_secs(30));
    }

    #[test]
    fn next_sleep_clamps_short_ttl_to_min() {
        // TTL says ~1s → clamped up to MIN_REFRESH (10s).
        let in_1s = Instant::now() + Duration::from_secs(1);
        let dur = next_sleep(Some(in_1s), None);
        assert_eq!(dur, MIN_REFRESH);
    }

    #[test]
    fn next_sleep_clamps_long_ttl_to_max() {
        // TTL says ~10h → clamped down to MAX_REFRESH (1h).
        let in_10h = Instant::now() + Duration::from_secs(36000);
        let dur = next_sleep(Some(in_10h), None);
        assert_eq!(dur, MAX_REFRESH);
    }

    #[test]
    fn next_sleep_uses_override_when_smaller_than_ttl() {
        // TTL says 60s, override says 20s → 20s wins.
        let in_60s = Instant::now() + Duration::from_secs(60);
        let dur = next_sleep(Some(in_60s), Some(20));
        // Within jitter of 20s.
        assert!(dur >= Duration::from_secs(15) && dur <= Duration::from_secs(20));
    }

    #[test]
    fn next_sleep_falls_back_to_default_without_ttl() {
        // No TTL, no override → DEFAULT_REFRESH (clamped to range).
        let dur = next_sleep(None, None);
        assert_eq!(dur, DEFAULT_REFRESH);
    }

    #[test]
    fn extract_specs_filters_to_dns_pools() {
        let mut upstreams: HashMap<String, PoolConfig> = HashMap::new();
        upstreams.insert(
            "ip-only".into(),
            base_pool(vec![ip_member("10.0.0.1:8080")]),
        );
        upstreams.insert(
            "with-dns".into(),
            base_pool(vec![
                ip_member("10.0.0.2:8080"),
                host_member("api.example.com", 443, 1),
            ]),
        );
        let specs = extract_specs(&upstreams);
        assert_eq!(specs.len(), 1, "only the pool with a hostname is returned");
        assert_eq!(specs[0].0, "with-dns");
    }

    // ---- reconcile core (BUG-dns-refresh-not-spawned-for-live-added-hostnames) ----

    fn dns_pool(hosts: &[(&str, u16)]) -> PoolConfig {
        let members = hosts
            .iter()
            .map(|(h, p)| host_member(h, *p, 1))
            .collect();
        base_pool(members)
    }

    #[test]
    fn fingerprint_stable_for_identical_specs() {
        let a = extract_spec(&dns_pool(&[("api.example.com", 443)]));
        let b = extract_spec(&dns_pool(&[("api.example.com", 443)]));
        assert_eq!(
            spec_fingerprint(&a),
            spec_fingerprint(&b),
            "same hostname set must fingerprint identically (no churn)",
        );
    }

    #[test]
    fn fingerprint_changes_when_hostname_added() {
        let one = extract_spec(&dns_pool(&[("api.example.com", 443)]));
        let two = extract_spec(&dns_pool(&[
            ("api.example.com", 443),
            ("api2.example.com", 443),
        ]));
        assert_ne!(
            spec_fingerprint(&one),
            spec_fingerprint(&two),
            "adding a hostname member must change the fingerprint so the task respawns",
        );
    }

    #[test]
    fn fingerprint_changes_when_refresh_seconds_changes() {
        let mut a = extract_spec(&dns_pool(&[("api.example.com", 443)]));
        let b_spec = {
            let mut s = a.clone();
            s.hostnames[0].refresh_seconds = Some(30);
            s
        };
        a.hostnames[0].refresh_seconds = None;
        assert_ne!(
            spec_fingerprint(&a),
            spec_fingerprint(&b_spec),
            "changing refresh_seconds must change the fingerprint",
        );
    }

    /// The case-3 repro at the unit level: a hostname pool that the
    /// manager isn't tracking yet (e.g. added live via the dashboard
    /// after boot) must be planned for a fresh refresh task.
    #[test]
    fn plan_spawns_live_added_hostname_pool() {
        let tracked: HashMap<String, u64> = HashMap::new();
        let fp = spec_fingerprint(&extract_spec(&dns_pool(&[("api.example.com", 443)])));
        let desired = vec![("new-pool".to_string(), fp)];

        let plan = plan_reconcile(&tracked, &desired);

        assert_eq!(plan.spawn, vec!["new-pool".to_string()]);
        assert!(plan.respawn.is_empty());
        assert!(plan.stop.is_empty());
        assert!(plan.keep.is_empty());
    }

    #[test]
    fn plan_keeps_unchanged_pool() {
        let fp = 0xABCD;
        let mut tracked = HashMap::new();
        tracked.insert("p".to_string(), fp);
        let desired = vec![("p".to_string(), fp)];

        let plan = plan_reconcile(&tracked, &desired);

        assert_eq!(plan.keep, vec!["p".to_string()]);
        assert!(plan.spawn.is_empty());
        assert!(plan.respawn.is_empty());
        assert!(plan.stop.is_empty());
    }

    #[test]
    fn plan_respawns_changed_pool() {
        let mut tracked = HashMap::new();
        tracked.insert("p".to_string(), 1u64);
        let desired = vec![("p".to_string(), 2u64)];

        let plan = plan_reconcile(&tracked, &desired);

        assert_eq!(plan.respawn, vec!["p".to_string()]);
        assert!(plan.spawn.is_empty());
        assert!(plan.keep.is_empty());
        assert!(plan.stop.is_empty());
    }

    #[test]
    fn plan_stops_removed_pool() {
        let mut tracked = HashMap::new();
        tracked.insert("gone".to_string(), 7u64);
        let desired: Vec<(String, u64)> = Vec::new();

        let plan = plan_reconcile(&tracked, &desired);

        assert_eq!(plan.stop, vec!["gone".to_string()]);
        assert!(plan.spawn.is_empty());
        assert!(plan.respawn.is_empty());
        assert!(plan.keep.is_empty());
    }

    #[test]
    fn plan_mixed_spawn_keep_respawn_stop_is_sorted() {
        let mut tracked = HashMap::new();
        tracked.insert("keep".to_string(), 10u64);
        tracked.insert("change".to_string(), 10u64);
        tracked.insert("remove".to_string(), 10u64);
        let desired = vec![
            ("keep".to_string(), 10u64),
            ("change".to_string(), 99u64),
            ("add".to_string(), 5u64),
        ];

        let plan = plan_reconcile(&tracked, &desired);

        assert_eq!(plan.spawn, vec!["add".to_string()]);
        assert_eq!(plan.keep, vec!["keep".to_string()]);
        assert_eq!(plan.respawn, vec!["change".to_string()]);
        assert_eq!(plan.stop, vec!["remove".to_string()]);
    }
}
