//! 2026-05-03 PM — Pinned-DNS resolver for upstream HTTPS SNI
//! pinning.
//!
//! ## Why
//!
//! `MemberConfig.host_header` rewrites the upstream `Host:`
//! header so vhost-routed backends see the right virtual host.
//! For HTTPS upstreams the cert + SNI also need to match that
//! hostname, but `addr: SocketAddr` requires an IP literal — we
//! can't put `example.com:443` in the config.
//!
//! Putting `host_header: "example.com"` AND `addr: "203.0.113.1:443"`
//! is the natural shape, but hyper-rustls's [`HttpsConnector`]
//! pulls SNI from the URL host.  Two solutions:
//!
//! 1. URL = `https://203.0.113.1:443/path` → SNI = `203.0.113.1`
//!    → cert validation fails against any hostname-named cert.
//! 2. URL = `https://example.com:443/path` → SNI = `example.com`
//!    → cert validates correctly, BUT the underlying
//!    `HttpConnector` resolves `example.com` via the system DNS
//!    resolver — defeating the IP pinning.
//!
//! This module owns option 2's missing piece — a
//! [`PinnedResolver`] that maps any pinned hostname back to a
//! known [`SocketAddr`] before hitting the system resolver.  The
//! global pin table is built at boot from
//! `cfg.upstreams.<pool>.members[*].host_header` and consulted
//! on every resolve.  Unpinned hostnames fall through to
//! [`GaiResolver`] so non-pinned destinations (ACME challenges,
//! webhooks, anything else) keep working.
//!
//! ## Hot-path cost
//!
//! One [`HashMap::get`] under a [`parking_lot::RwLock`] read
//! guard per resolve.  The pin table is mutated only at boot
//! (or on a cfg hot-reload of `upstreams`); every subsequent
//! resolve hits the read path which is ~ns.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use std::sync::RwLock;
use tower_service::Service;

/// Iterator type returned by [`PinnedResolver`].  Boxed because
/// the resolver returns either a single-element vec (pinned hit)
/// or the GaiResolver's iterator (fallback).
pub type ResolvedAddrs = Box<dyn Iterator<Item = SocketAddr> + Send>;

/// Cloneable resolver that consults a shared pin table before
/// delegating to the system [`GaiResolver`].  Cheap clone — both
/// the pin table and the inner resolver are `Arc`-shared.
#[derive(Clone)]
pub struct PinnedResolver {
    pins: Arc<RwLock<HashMap<String, SocketAddr>>>,
    fallback: GaiResolver,
}

impl PinnedResolver {
    fn new() -> Self {
        Self {
            pins: Arc::new(RwLock::new(HashMap::new())),
            fallback: GaiResolver::new(),
        }
    }

    /// Pin `host` to `addr`.  Idempotent — re-registering the
    /// same hostname overwrites the previous addr.  Called once
    /// per member at boot from
    /// [`crate::upstream::registry::PoolRegistry::build_pools`].
    pub fn register(&self, host: impl Into<String>, addr: SocketAddr) {
        self.pins.write().expect("PinnedResolver pin write lock poisoned").insert(host.into(), addr);
    }

    /// Drop a pin.  Used by hot-reload paths that rebuild the
    /// pool table.
    #[allow(dead_code)]
    pub fn deregister(&self, host: &str) {
        self.pins.write().expect("PinnedResolver pin write lock poisoned").remove(host);
    }

    /// Snapshot the pin count.  Test-only.
    #[cfg(test)]
    pub fn pin_count(&self) -> usize {
        self.pins.read().expect("PinnedResolver pin read lock poisoned").len()
    }
}

impl Service<Name> for PinnedResolver {
    type Response = ResolvedAddrs;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_string();
        // Pin lookup is the fast path — single read-lock + map
        // get.  Holding the guard across the await would be a
        // bug; clone the addr out and drop the guard before the
        // boxed future returns.
        if let Some(addr) = self.pins.read().expect("PinnedResolver pin read lock poisoned").get(&host).copied() {
            tracing::trace!(
                host = %host,
                addr = %addr,
                "pinned dns: hit",
            );
            return Box::pin(async move {
                let v: Vec<SocketAddr> = vec![addr];
                Ok(Box::new(v.into_iter()) as ResolvedAddrs)
            });
        }
        // Fallback: delegate to GaiResolver.  Boxed up to unify
        // the iterator type with the pinned branch.
        let mut fallback = self.fallback.clone();
        Box::pin(async move {
            let res = fallback.call(name).await;
            match res {
                Ok(addrs) => {
                    let collected: Vec<SocketAddr> = addrs.collect();
                    Ok(Box::new(collected.into_iter()) as ResolvedAddrs)
                }
                Err(e) => Err(std::io::Error::other(e.to_string())),
            }
        })
    }
}

/// Process-global resolver instance.  All [`HttpConnector`]s
/// the proxy builds share this single resolver so a pin
/// registered by one pool's boot path is visible to any other
/// pool's outbound requests.
pub fn global() -> &'static PinnedResolver {
    static G: OnceLock<PinnedResolver> = OnceLock::new();
    G.get_or_init(PinnedResolver::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn name(s: &str) -> Name {
        s.parse().expect("valid Name")
    }

    #[tokio::test]
    async fn pinned_host_returns_pinned_addr() {
        let r = PinnedResolver::new();
        let pinned: SocketAddr = (Ipv4Addr::new(203, 0, 113, 7), 443).into();
        r.register("example.test", pinned);
        let mut svc = r.clone();
        let addrs = svc.call(name("example.test")).await.unwrap();
        let collected: Vec<SocketAddr> = addrs.collect();
        assert_eq!(collected, vec![pinned]);
    }

    #[tokio::test]
    async fn unpinned_host_delegates_to_gai() {
        let r = PinnedResolver::new();
        // Localhost is on every machine's resolver. Use a
        // bounded timeout in case the platform's gai is slow.
        let mut svc = r.clone();
        let addrs = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            svc.call(name("localhost")),
        )
        .await
        .expect("gai resolve timed out")
        .unwrap();
        let collected: Vec<SocketAddr> = addrs.collect();
        assert!(
            collected.iter().any(|a| a.ip().is_loopback()),
            "expected loopback in localhost resolution; got {:?}",
            collected,
        );
    }

    #[tokio::test]
    async fn deregister_removes_pin() {
        let r = PinnedResolver::new();
        let pinned: SocketAddr = (Ipv4Addr::new(203, 0, 113, 7), 443).into();
        r.register("example.test", pinned);
        assert_eq!(r.pin_count(), 1);
        r.deregister("example.test");
        assert_eq!(r.pin_count(), 0);
    }

    #[test]
    fn cloning_shares_pin_table() {
        let r1 = PinnedResolver::new();
        let r2 = r1.clone();
        let pinned: SocketAddr = (Ipv4Addr::new(192, 0, 2, 1), 80).into();
        r1.register("a.test", pinned);
        assert_eq!(r2.pin_count(), 1, "clones must share the pin table");
    }

    #[test]
    fn global_returns_same_instance() {
        let g1 = global();
        let g2 = global();
        // Same Arc'd table.
        let addr: SocketAddr = (Ipv4Addr::new(127, 0, 0, 99), 80).into();
        g1.register("global-pin.test", addr);
        let cnt = g2.pin_count();
        assert!(cnt >= 1);
        g1.deregister("global-pin.test");
    }
}
