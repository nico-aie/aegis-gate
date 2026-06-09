//! Boot-time DNS resolver for `MemberAddrSpec::Hostname` members.
//!
//! **PR-DNS-1 (2026-05-11) — Phase 1.** Operators can now address
//! backends by hostname (`api.example.com:443`) rather than being
//! forced to pin a `SocketAddr`. This module walks every pool's
//! members, resolves each hostname via `tokio::net::lookup_host`,
//! and rewrites the config so every member becomes an
//! `MemberAddrSpec::Ip`. Multi-A records expand into N synthetic
//! members so the pool's load-balancing strategies distribute
//! across all resolved IPs — same shape as Envoy's STRICT_DNS.
//!
//! **Scope.** Boot + hot-reload only. Background DNS refresh is
//! Phase 2 (separate PR, adds `hickory-resolver` as a dep). Phase 1
//! relies on `tokio::net::lookup_host` (a thin async wrapper around
//! the system resolver), so no new dependency is pulled.
//!
//! **SNI default.** When a member's `host_header` is unset and the
//! configured addr is a hostname, the expanded `MemberConfig`s
//! inherit the hostname as `host_header`. This means HTTPS upstreams
//! addressed by hostname get correct SNI + cert-SAN matching for
//! free — operators no longer have to repeat the hostname in
//! `host_header` to satisfy TLS.
//!
//! **Failure mode.** A single hostname that fails to resolve fails
//! the whole boot. This is loud but safe: operators see a clear
//! error at startup instead of a pool that silently starts empty.
//! Phase 2 will soften this to "start with the pool empty, retry
//! in the background".

use std::collections::HashMap;
use std::net::SocketAddr;

use aegis_core::config::{MemberAddrSpec, MemberConfig, PoolConfig};

/// How `expand_hostname_members` reacts to a hostname that fails
/// to resolve.
///
/// **Strict (default)** — first failure aborts. Used by the
/// dashboard PUT path so operators catch typos at config-set time.
///
/// **SoftSkip** — log warn + drop the failing hostname's members
/// from the pool, keep going. Used by the Phase 2 boot path
/// because the per-pool refresh task
/// (`crate::upstream::dns_refresh::spawn_pool_refresh`) will
/// retry the resolution every TTL tick — soft-failing at boot
/// lets the proxy come up even when DNS is temporarily down.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResolveFailurePolicy {
    #[default]
    Strict,
    SoftSkip,
}

/// One failure encountered while expanding hostnames in a config.
#[derive(Debug, thiserror::Error)]
pub enum DnsResolveError {
    /// `lookup_host(host:port)` returned an error (NXDOMAIN, timeout,
    /// resolver unreachable). The wrapped string is the OS-level
    /// error message; the field names match `tokio::net`'s shape.
    #[error("dns: failed to resolve `{host}:{port}` in pool `{pool}`: {reason}")]
    LookupFailed {
        pool: String,
        host: String,
        port: u16,
        reason: String,
    },
    /// `lookup_host` returned successfully but the iterator was
    /// empty. Should be rare in practice (most resolvers return
    /// NXDOMAIN as `LookupFailed`); guarded so the caller can fail
    /// loudly instead of building an empty pool.
    #[error("dns: `{host}:{port}` in pool `{pool}` resolved to zero addresses")]
    NoAddresses { pool: String, host: String, port: u16 },
}

/// Walk `upstreams` and replace every `MemberAddrSpec::Hostname`
/// entry with one or more `MemberAddrSpec::Ip` entries — one per
/// resolved A/AAAA record. Members that are already IP-shaped pass
/// through untouched. The returned map preserves pool names + the
/// per-pool ordering; the expansion happens in-place inside each
/// pool's `members` vector.
///
/// **Hot-path note.** This is an `async` function because
/// `tokio::net::lookup_host` is async; we run all hostnames in
/// parallel via `futures::future::try_join_all` so a pool with N
/// hostnames pays one RTT total, not N. Typical resolver RTT is
/// 1-10 ms over a local stub; cold lookups can be 100ms+. Run this
/// at boot, not per-request.
pub async fn expand_hostname_members(
    upstreams: HashMap<String, PoolConfig>,
) -> Result<HashMap<String, PoolConfig>, DnsResolveError> {
    expand_hostname_members_with_policy(upstreams, ResolveFailurePolicy::Strict).await
}

/// Same as [`expand_hostname_members`] but with an explicit
/// failure policy. PR-DNS-2 wires `SoftSkip` into the boot path so
/// transient resolver outages don't abort startup; dashboard PUTs
/// keep using `Strict` so typos surface immediately.
pub async fn expand_hostname_members_with_policy(
    upstreams: HashMap<String, PoolConfig>,
    policy: ResolveFailurePolicy,
) -> Result<HashMap<String, PoolConfig>, DnsResolveError> {
    use futures::future::join_all;

    let mut out: HashMap<String, PoolConfig> = HashMap::with_capacity(upstreams.len());

    for (pool_name, mut pool_cfg) in upstreams {
        // Resolve in parallel, then stitch back together so the
        // operator's authored ordering survives the expansion.
        let resolutions = join_all(pool_cfg.members.iter().map(|mc| {
            let pool_name = pool_name.clone();
            let mc = mc.clone();
            async move { resolve_one(&pool_name, mc).await }
        }))
        .await;

        let mut expanded: Vec<MemberConfig> = Vec::with_capacity(pool_cfg.members.len());
        for r in resolutions {
            match r {
                Ok(batch) => expanded.extend(batch),
                Err(e) => match policy {
                    ResolveFailurePolicy::Strict => return Err(e),
                    ResolveFailurePolicy::SoftSkip => {
                        tracing::warn!(
                            error = %e,
                            "dns: skipping unresolved hostname member at boot (soft-failure); refresh task will retry",
                        );
                    }
                },
            }
        }
        pool_cfg.members = expanded;
        out.insert(pool_name, pool_cfg);
    }

    Ok(out)
}

/// Resolve a single `MemberConfig`. `Ip`-shaped members pass
/// through; `Hostname`-shaped members fan out into N clones (one
/// per resolved IP). `host_header` defaults to the hostname when
/// the operator didn't pin one, so SNI lines up without operators
/// having to set both fields.
async fn resolve_one(
    pool: &str,
    mc: MemberConfig,
) -> Result<Vec<MemberConfig>, DnsResolveError> {
    let (host, port, refresh_seconds) = match &mc.addr {
        MemberAddrSpec::Ip(_) => return Ok(vec![mc]),
        MemberAddrSpec::Hostname { host, port, refresh_seconds } => {
            (host.clone(), *port, *refresh_seconds)
        }
    };
    let _ = refresh_seconds; // Phase 2 honours this; Phase 1 ignores.

    let target = format!("{host}:{port}");
    let addrs = tokio::net::lookup_host(target.as_str())
        .await
        .map_err(|e| DnsResolveError::LookupFailed {
            pool: pool.to_string(),
            host: host.clone(),
            port,
            reason: e.to_string(),
        })?
        .collect::<Vec<SocketAddr>>();

    if addrs.is_empty() {
        return Err(DnsResolveError::NoAddresses {
            pool: pool.to_string(),
            host,
            port,
        });
    }

    tracing::info!(
        pool = pool,
        host = host.as_str(),
        port,
        resolved_count = addrs.len(),
        "dns: resolved hostname upstream",
    );

    // PR-DNS-1 SNI default — when no `host_header` override was
    // configured, use the hostname so HTTPS upstreams get correct
    // SNI + cert validation without the operator having to set
    // both fields. Explicit `host_header` still wins (operators
    // pointing the WAF at a vhost that lives behind a different
    // SNI name).
    let host_header_default = match mc.host_header.as_deref() {
        Some(_) => mc.host_header.clone(),
        None => Some(host.clone()),
    };

    Ok(addrs
        .into_iter()
        .map(|sa| MemberConfig {
            addr: MemberAddrSpec::Ip(sa),
            weight: mc.weight,
            zone: mc.zone.clone(),
            host_header: host_header_default.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_member(host: &str, port: u16) -> MemberConfig {
        MemberConfig {
            addr: MemberAddrSpec::Hostname {
                host: host.into(),
                port,
                refresh_seconds: None,
            },
            weight: 1,
            zone: None,
            host_header: None,
        }
    }

    fn ip_member(s: &str) -> MemberConfig {
        MemberConfig {
            addr: MemberAddrSpec::Ip(s.parse().unwrap()),
            weight: 1,
            zone: None,
            host_header: None,
        }
    }

    /// Bare pool with the given members, default LB / no health /
    /// no breaker / default connection pool — keeps the test
    /// surface small. PoolConfig doesn't derive Default so we
    /// stamp the same shape here.
    fn pool_with(members: Vec<MemberConfig>) -> PoolConfig {
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

    #[tokio::test]
    async fn ip_members_pass_through_untouched() {
        let mut pools: HashMap<String, PoolConfig> = HashMap::new();
        pools.insert(
            "api".into(),
            pool_with(vec![ip_member("10.0.0.1:8080"), ip_member("10.0.0.2:8080")]),
        );
        let out = expand_hostname_members(pools).await.unwrap();
        let pool = out.get("api").unwrap();
        assert_eq!(pool.members.len(), 2);
        assert!(matches!(pool.members[0].addr, MemberAddrSpec::Ip(_)));
        assert!(matches!(pool.members[1].addr, MemberAddrSpec::Ip(_)));
    }

    #[tokio::test]
    async fn localhost_resolves_and_expands() {
        // `localhost` is the one hostname every test environment
        // resolves the same way (loopback). We don't make
        // assumptions about whether v4 or v6 comes back first, only
        // that at least one entry exists.
        let mut pools: HashMap<String, PoolConfig> = HashMap::new();
        pools.insert(
            "api".into(),
            pool_with(vec![host_member("localhost", 8080)]),
        );
        let out = expand_hostname_members(pools).await.unwrap();
        let pool = out.get("api").unwrap();
        assert!(
            !pool.members.is_empty(),
            "localhost should resolve to at least one address",
        );
        for m in &pool.members {
            match &m.addr {
                MemberAddrSpec::Ip(sa) => {
                    assert_eq!(sa.port(), 8080, "port preserved across resolution");
                    assert!(sa.ip().is_loopback(), "localhost should resolve to a loopback addr");
                }
                MemberAddrSpec::Hostname { .. } => panic!("expansion left a hostname behind"),
            }
        }
    }

    #[tokio::test]
    async fn sni_defaults_to_hostname_when_host_header_unset() {
        let mut pools: HashMap<String, PoolConfig> = HashMap::new();
        pools.insert(
            "api".into(),
            pool_with(vec![host_member("localhost", 8443)]),
        );
        let out = expand_hostname_members(pools).await.unwrap();
        let pool = out.get("api").unwrap();
        for m in &pool.members {
            assert_eq!(
                m.host_header.as_deref(),
                Some("localhost"),
                "host_header should default to the hostname when unset",
            );
        }
    }

    #[tokio::test]
    async fn explicit_host_header_wins_over_default() {
        let mut pools: HashMap<String, PoolConfig> = HashMap::new();
        let mut m = host_member("localhost", 8443);
        m.host_header = Some("override.example.com".into());
        pools.insert(
            "api".into(),
            pool_with(vec![m]),
        );
        let out = expand_hostname_members(pools).await.unwrap();
        let pool = out.get("api").unwrap();
        for m in &pool.members {
            assert_eq!(
                m.host_header.as_deref(),
                Some("override.example.com"),
                "explicit host_header must win over the hostname default",
            );
        }
    }

    #[tokio::test]
    async fn unresolvable_hostname_fails_loudly() {
        // RFC 6761 reserves `invalid.` — every resolver returns
        // NXDOMAIN for anything under it.
        let mut pools: HashMap<String, PoolConfig> = HashMap::new();
        pools.insert(
            "api".into(),
            pool_with(vec![host_member("nope.invalid", 443)]),
        );
        let err = expand_hostname_members(pools).await.unwrap_err();
        match err {
            DnsResolveError::LookupFailed { pool, host, port, .. } => {
                assert_eq!(pool, "api");
                assert_eq!(host, "nope.invalid");
                assert_eq!(port, 443);
            }
            other => panic!("expected LookupFailed, got {other:?}"),
        }
    }
}
