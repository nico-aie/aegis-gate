//! Shared on-reload helpers used by both the file-watcher
//! (`supervisor::watch_loop`) and the etcd-watcher
//! (`etcd_source::watch_loop`).
//!
//! A "config reload" lands a new [`WafConfig`] into the data
//! plane. Two side effects must happen atomically with the swap:
//!
//! 1. **Detector-mask base re-derivation.** `cfg.detectors`'s
//!    enable flags drive the *initial* mask state. A hot-reload
//!    that flipped `cfg.detectors.sqli.enabled: false` would be
//!    silently ignored without re-deriving the base. Per-tier
//!    overrides set by `PUT /api/detectors` are intentionally
//!    preserved — they're explicit operator intent, separate
//!    from cfg defaults.
//!
//! 2. **Compliance clamp.** Re-deriving the base from cfg might
//!    have just disabled a class that `cfg.compliance.modes`
//!    pins to ON (PCI / HIPAA / SOC2 / GDPR / FIPS). The clamp
//!    forces those classes back on; the helper returns the
//!    `forced` list so callers can emit a
//!    `compliance_clamp_applied` audit event.
//!
//! Both effects fire on every successful reload, regardless of
//! source — file, etcd, future raft. Putting the logic here
//! keeps the supervisor + etcd watchers in lockstep on the
//! correctness contract.

use std::sync::Arc;

use aegis_core::config::WafConfig;
use aegis_security::detectors::{DetectorMask, SharedDetectorMask};
use aegis_security::rate_limit::{IpRateLimitConfig, IpRateLimiter};

use crate::listener::client_trust::ClientTrustStore;
use crate::listener::tls::{CertStore, DynamicResolver};
use crate::proxy::ProxyContext;

/// Outcome of [`apply_cfg_change_to_mask`]. Mirrors
/// `detectors_persist::ApplyOutcome` but is local to this module
/// so callers don't drag in the persistence types when they
/// only care about the reload path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// Mask re-derived from `new_cfg.detectors`. No compliance
    /// clamp was needed.
    Applied,
    /// Mask re-derived AND clamped — `forced` lists the classes
    /// the clamp had to flip back on (`"sqli"` for base,
    /// `"override[medium]:sqli"` for per-tier).
    AppliedWithCompliance { forced: Vec<String> },
    /// Caller passed `mask: None` — no work to do. Returned so
    /// callers can log a single info event uniformly.
    NoMask,
}

/// Re-derive the detector mask base from `new_cfg.detectors` and
/// run the compliance clamp against the result. Per-tier
/// overrides are preserved.
///
/// The mask's `store(new_base)` only replaces the base; per-tier
/// overrides set via `PUT /api/detectors` survive the reload.
/// The compliance clamp then re-runs on both base and overrides
/// so a freshly-disabled compliance-pinned class gets forced
/// back on no matter where it lives.
pub fn apply_cfg_change_to_mask(
    new_cfg: &WafConfig,
    mask: Option<&SharedDetectorMask>,
) -> ReloadOutcome {
    let Some(mask) = mask else {
        return ReloadOutcome::NoMask;
    };

    let new_base = DetectorMask::from_config(&new_cfg.detectors);
    mask.store(new_base);

    let modes = new_cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();
    if modes.is_empty() {
        return ReloadOutcome::Applied;
    }

    use aegis_control::api::detectors_persist::{
        apply_live_mask_with_compliance, ApplyOutcome,
    };
    match apply_live_mask_with_compliance(mask, &modes) {
        ApplyOutcome::Applied => ReloadOutcome::Applied,
        ApplyOutcome::AppliedWithCompliance { forced } => {
            ReloadOutcome::AppliedWithCompliance { forced }
        }
    }
}

/// Outcome of [`apply_cfg_change_to_routes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteReloadOutcome {
    /// Caller passed `ctx: None` — no work to do.
    NoCtx,
    /// New route table built and atomic-swapped into the live
    /// `ProxyContext`. In-flight requests that already loaded a
    /// snapshot finish on the old table.
    Applied,
    /// Route table validation failed (e.g. missing catch-all,
    /// invalid host pattern). The live table is unchanged.
    Failed { reason: String },
}

/// Outcome of [`apply_cfg_change_to_tls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsReloadOutcome {
    /// Caller passed `resolver: None` — the proxy boot path
    /// didn't have any TLS certs configured, so there's nothing
    /// to swap into. Callers can still attempt to enable TLS
    /// after restart.
    NoResolver,
    /// New cert store built from `new_cfg.tls.certificates` and
    /// atomic-swapped into the resolver. `cert_count` reflects
    /// the number of `(cert, key, hosts)` triples loaded.
    Applied { cert_count: usize },
    /// `cfg.tls` is `None` or `cfg.tls.certificates` is empty in
    /// the new cfg. Keeping the previous cert store live is
    /// safer than swapping to nothing — listeners with
    /// `tls: true` would handshake-fail otherwise. Operators
    /// disabling TLS need a restart.
    SkippedEmpty,
    /// Cert load / key parse / chain validation failed. The
    /// previous cert store stays live; operators see
    /// `tls_reload_failed` in the audit chain. The most common
    /// causes: missing cert files, mismatched cert/key, or a
    /// PEM with no private key.
    Failed { reason: String },
}

/// Re-derive a [`CertStore`] from `new_cfg.tls.certificates`
/// and atomic-swap it into the live `DynamicResolver`. Triggered
/// by both file + etcd watchers on every successful reload.
///
/// **Empty / missing TLS cfg** is treated as "skip" rather than
/// "remove" — clearing the cert store would crash every
/// `tls: true` listener's next handshake. Operators who want to
/// disable TLS at runtime need to restart.
///
/// **Disk read errors** (missing cert path, unreadable key) and
/// **chain validation errors** (empty PEM, bad signature
/// algorithm) keep the previous store live. The
/// [`TlsReloadOutcome::Failed`] variant carries the reason so
/// the dashboard can surface it.
pub fn apply_cfg_change_to_tls(
    new_cfg: &WafConfig,
    resolver: Option<&Arc<DynamicResolver>>,
) -> TlsReloadOutcome {
    let Some(resolver) = resolver else {
        return TlsReloadOutcome::NoResolver;
    };
    let Some(tls_cfg) = new_cfg.tls.as_ref() else {
        return TlsReloadOutcome::SkippedEmpty;
    };
    if tls_cfg.certificates.is_empty() {
        return TlsReloadOutcome::SkippedEmpty;
    }

    let entries: Vec<(_, _, &[String])> = tls_cfg
        .certificates
        .iter()
        .map(|c| {
            let hosts: &[String] = &c.hosts;
            (
                c.cert_path.clone(),
                std::path::PathBuf::from(&c.key_ref),
                hosts,
            )
        })
        .collect();
    let cert_count = entries.len();

    match CertStore::load(&entries) {
        Ok(store) => {
            resolver.swap(store);
            TlsReloadOutcome::Applied { cert_count }
        }
        Err(e) => TlsReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

/// Outcome of [`apply_cfg_change_to_rate_limit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitReloadOutcome {
    /// Caller passed `limiter: None` — no work to do.
    NoLimiter,
    /// New `IpRateLimitConfig` derived from `new_cfg.rate_limit`
    /// and stored. Old per-IP timestamp state is preserved.
    Applied { limit: u32, window_secs: u64 },
    /// New cfg matched the live cfg byte-for-byte; the
    /// `ArcSwap` store was skipped to keep hot reads
    /// uncontended on the no-op path.
    Unchanged,
}

/// Derive an [`IpRateLimitConfig`] from
/// `new_cfg.rate_limit.buckets` and hot-swap it into the live
/// limiter. Same selection rule as the boot path: the FIRST
/// bucket with `scope: Global` + `key: Ip` wins; if none is
/// configured we fall back to the library default. The per-IP
/// timestamp map stays intact across the swap — operators
/// editing the bucket don't accidentally reset every
/// flooding-source IP back to zero counts.
pub fn apply_cfg_change_to_rate_limit(
    new_cfg: &WafConfig,
    limiter: Option<&Arc<IpRateLimiter>>,
) -> RateLimitReloadOutcome {
    let Some(limiter) = limiter else {
        return RateLimitReloadOutcome::NoLimiter;
    };

    let new_rl_cfg = derive_ip_rate_cfg(new_cfg);
    if limiter.config() == new_rl_cfg {
        return RateLimitReloadOutcome::Unchanged;
    }
    limiter.set_config(new_rl_cfg);
    RateLimitReloadOutcome::Applied {
        limit: new_rl_cfg.limit,
        window_secs: new_rl_cfg.window.as_secs(),
    }
}

/// Pure: derive the IP rate-limit config the boot path uses
/// from a `WafConfig`. Shared between `aegis-proxy::run` (boot)
/// and the watchers (hot-reload) so the selection rule stays
/// in one place.
pub fn derive_ip_rate_cfg(cfg: &WafConfig) -> IpRateLimitConfig {
    cfg.rate_limit
        .buckets
        .iter()
        .find(|b| {
            matches!(b.scope, aegis_core::config::RlScope::Global)
                && matches!(b.key, aegis_core::config::RlKey::Ip)
        })
        .map(|b| IpRateLimitConfig {
            limit: b.limit.min(u32::MAX as u64) as u32,
            window: b.window,
        })
        .unwrap_or_default()
}

/// Rebuild the live `ProxyContext.route_table` from
/// `new_cfg.routes` and atomic-swap it. Validation runs first
/// (`RouteTable::build`) so an invalid new cfg leaves the live
/// table intact.
///
/// Note: `ctx.pools` (the upstream pool registry) is *not*
/// rebuilt here. Pools have their own audit-mutated PUT path
/// (CC-T1.1.b) which provides the same hot-swap semantics —
/// applying both from a single cfg-reload would race the
/// audit-mutated state against itself. Operators who edit
/// `cfg.upstreams` and want it live should either restart or
/// PUT through the dashboard.
pub fn apply_cfg_change_to_routes(
    new_cfg: &WafConfig,
    ctx: Option<&Arc<ProxyContext>>,
) -> RouteReloadOutcome {
    let Some(ctx) = ctx else {
        return RouteReloadOutcome::NoCtx;
    };
    match ctx.route_table.apply(new_cfg) {
        Ok(()) => RouteReloadOutcome::Applied,
        Err(e) => RouteReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

/// Outcome of [`apply_cfg_change_to_client_auth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthReloadOutcome {
    /// Caller passed `trust_store: None` — proxy boot didn't
    /// configure inbound mTLS, so there's nothing to swap into.
    /// Operators who flip from "no client_auth" to client_auth
    /// at runtime need to restart (the verifier is wired into
    /// the rustls config at boot, and we don't rebuild that
    /// here).
    NoStore,
    /// New CA bundle parsed and atomic-swapped into the live
    /// store. `cert_count` is the number of trust anchors in
    /// the new bundle (operators see this in the
    /// `mtls_reloaded` audit event).
    Applied {
        cert_count: usize,
        mode: aegis_core::config::ClientAuthMode,
    },
    /// `cfg.tls.client_auth` is `None` or its mode is
    /// `Disabled` in the new cfg. Skip-not-clear: keeping the
    /// previous trust store live is safer than swapping to
    /// nothing — `Required`-mode listeners would reject every
    /// handshake otherwise. Operators disabling client-auth
    /// at runtime need a restart.
    SkippedDisabled,
    /// New cfg has no `ca_bundle` path even though
    /// `mode != Disabled`. Validation should have caught this
    /// at the `WafConfig::validate` step; we still defend in
    /// depth and surface a `Failed` so the audit log records
    /// the bad reload attempt.
    MissingCaBundle,
    /// PEM parse / chain validation of the new bundle failed.
    /// The previous trust store stays live; operators see
    /// `mtls_reload_failed` in the audit chain. Common
    /// causes: missing file, no `BEGIN CERTIFICATE` blocks,
    /// or an unsupported CA encoding.
    Failed { reason: String },
}

/// MTLS-T5 — re-parse the configured CA bundle and atomic-
/// swap it into the live [`ClientTrustStore`]. Triggered by
/// both file + etcd watchers after `tls_reloaded`.
///
/// **Empty / disabled cfg** is treated as "skip" rather than
/// "remove" — clearing the trust store would crash every
/// `Required`-mode handshake. Operators disabling client-
/// auth at runtime need a restart.
///
/// **Disk read errors** + **PEM parse failures** keep the
/// previous store live and return [`ClientAuthReloadOutcome::Failed`]
/// so the watcher can emit `mtls_reload_failed` for audit.
pub fn apply_cfg_change_to_client_auth(
    new_cfg: &WafConfig,
    trust_store: Option<&ClientTrustStore>,
) -> ClientAuthReloadOutcome {
    let Some(trust_store) = trust_store else {
        return ClientAuthReloadOutcome::NoStore;
    };
    let Some(tls_cfg) = new_cfg.tls.as_ref() else {
        return ClientAuthReloadOutcome::SkippedDisabled;
    };
    let Some(ca_cfg) = tls_cfg.client_auth.as_ref() else {
        return ClientAuthReloadOutcome::SkippedDisabled;
    };
    if ca_cfg.mode == aegis_core::config::ClientAuthMode::Disabled {
        return ClientAuthReloadOutcome::SkippedDisabled;
    }

    let Some(bundle_path) = ca_cfg.ca_bundle.as_ref() else {
        return ClientAuthReloadOutcome::MissingCaBundle;
    };

    match ClientTrustStore::load_from_pem_file(bundle_path) {
        Ok(parsed) => {
            // Move the parsed RootCertStore into the live
            // handle. We can't expose `Arc<RootCertStore>`
            // directly through `swap`, so re-clone the trust
            // anchors into a fresh owned store and swap that.
            let cur = parsed.current();
            let mut owned = rustls::RootCertStore::empty();
            for ta in cur.roots.iter() {
                owned.roots.push(ta.clone());
            }
            let cert_count = owned.len();
            trust_store.swap(owned);
            ClientAuthReloadOutcome::Applied {
                cert_count,
                mode: ca_cfg.mode,
            }
        }
        Err(e) => ClientAuthReloadOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::ComplianceMode;
    use aegis_security::detectors::DetectorClass;

    fn yaml_with_sqli(enabled: bool, modes: &[&str]) -> String {
        let modes_yaml = if modes.is_empty() {
            String::new()
        } else {
            format!("compliance:\n  modes: [{}]\n", modes.join(", "))
        };
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
detectors:
  sqli:
    enabled: {enabled}
{modes_yaml}"#
        )
    }

    fn parse(yaml: &str) -> WafConfig {
        aegis_core::load_config_str(yaml).unwrap()
    }

    #[test]
    fn no_mask_returns_no_mask_outcome() {
        let cfg = parse(&yaml_with_sqli(true, &[]));
        let outcome = apply_cfg_change_to_mask(&cfg, None);
        assert_eq!(outcome, ReloadOutcome::NoMask);
    }

    #[test]
    fn applied_when_no_compliance_modes_and_no_violations() {
        let cfg = parse(&yaml_with_sqli(true, &[]));
        let mask = SharedDetectorMask::default();
        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn rederives_base_from_new_cfg() {
        // Boot mask had sqli ON; new cfg flips it OFF. With no
        // compliance modes, the mask should reflect the new cfg.
        let cfg = parse(&yaml_with_sqli(false, &[]));
        let mask = SharedDetectorMask::default();
        // Pre-seed mask with sqli ON to simulate boot.
        mask.store(DetectorMask::all_enabled());

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(!mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn pci_does_not_force_classes_on_while_lock_is_deferred() {
        // 2026-05-10 — compliance lock is deferred. New cfg disables
        // sqli with PCI mode declared; the clamp is a no-op so the
        // mask reload applies sqli=false verbatim.
        let cfg = parse(&yaml_with_sqli(false, &["pci"]));
        assert_eq!(
            cfg.compliance.as_ref().unwrap().modes,
            vec![ComplianceMode::Pci],
        );
        let mask = SharedDetectorMask::default();
        mask.store(DetectorMask::all_enabled());

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(
            !mask.load().is_enabled(DetectorClass::Sqli),
            "lock is deferred — sqli stays off as the YAML requested"
        );
    }

    #[test]
    fn preserves_per_tier_overrides_on_reload() {
        use aegis_core::tier::Tier;
        let cfg = parse(&yaml_with_sqli(true, &[]));
        let mask = SharedDetectorMask::default();
        // Operator set a per-tier override before reload.
        let custom_override = DetectorMask::all_enabled()
            .with(DetectorClass::Recon, false);
        mask.store_state(
            mask.load_state().with_override(Tier::Medium, Some(custom_override)),
        );

        let outcome = apply_cfg_change_to_mask(&cfg, Some(&mask));
        assert_eq!(outcome, ReloadOutcome::Applied);
        let live = mask.load_state();
        let kept = live.override_for(Tier::Medium).expect("override preserved");
        assert!(!kept.is_enabled(DetectorClass::Recon), "override survived reload");
    }

    // ---- apply_cfg_change_to_routes ----

    fn yaml_with_route(id: &str, path: &str) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: {id}
    path: "{path}"
    upstream: pool
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
  default:
    members:
      - addr: "127.0.0.1:3001"
state:
  backend: in_memory
"#
        )
    }

    fn boot_ctx(yaml: &str) -> Arc<ProxyContext> {
        let cfg = parse(yaml);
        Arc::new(
            ProxyContext::build(
                &cfg,
                Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        )
    }

    #[test]
    fn route_reload_no_ctx_returns_no_ctx_outcome() {
        let cfg = parse(&yaml_with_route("v1", "/api/v1"));
        let outcome = apply_cfg_change_to_routes(&cfg, None);
        assert_eq!(outcome, RouteReloadOutcome::NoCtx);
    }

    #[test]
    fn route_reload_swaps_route_table_atomically() {
        let ctx = boot_ctx(&yaml_with_route("v1", "/api/v1"));
        // Boot snapshot resolves /api/v1 → v1.
        let r = ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v1");

        // Hot-reload to a v2 route table.
        let new_cfg = parse(&yaml_with_route("v2", "/api/v2"));
        let outcome = apply_cfg_change_to_routes(&new_cfg, Some(&ctx));
        assert_eq!(outcome, RouteReloadOutcome::Applied);

        // /api/v1 now falls through to catch-all.
        let r = ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "catch-all");

        // /api/v2 resolves to v2.
        let r = ctx
            .route_table
            .resolve("any", "/api/v2", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v2");
    }

    // ---- apply_cfg_change_to_rate_limit ----

    fn yaml_with_rate_limit(limit: u64, window_secs: u64) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
rate_limit:
  buckets:
    - id: ip-global
      scope: global
      key: ip
      algo: sliding_window
      limit: {limit}
      window: {window_secs}s
"#
        )
    }

    fn yaml_no_rate_limit() -> String {
        r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#
        .into()
    }

    #[test]
    fn rate_limit_no_limiter_returns_no_limiter_outcome() {
        let cfg = parse(&yaml_with_rate_limit(500, 60));
        let outcome = apply_cfg_change_to_rate_limit(&cfg, None);
        assert_eq!(outcome, RateLimitReloadOutcome::NoLimiter);
    }

    #[test]
    fn rate_limit_applies_when_changed() {
        let initial = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        assert_eq!(limiter.config().limit, 100);

        let new_cfg = parse(&yaml_with_rate_limit(500, 30));
        let outcome = apply_cfg_change_to_rate_limit(&new_cfg, Some(&limiter));
        assert_eq!(
            outcome,
            RateLimitReloadOutcome::Applied {
                limit: 500,
                window_secs: 30,
            },
        );
        assert_eq!(limiter.config().limit, 500);
        assert_eq!(limiter.config().window.as_secs(), 30);
    }

    #[test]
    fn rate_limit_unchanged_when_cfg_identical() {
        let cfg = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&cfg)));
        let outcome = apply_cfg_change_to_rate_limit(&cfg, Some(&limiter));
        assert_eq!(outcome, RateLimitReloadOutcome::Unchanged);
    }

    #[test]
    fn rate_limit_falls_back_to_default_when_no_global_ip_bucket() {
        // Boot from a YAML with a bucket; reload to a YAML
        // without one → limiter falls back to library default.
        let initial = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        assert_eq!(limiter.config().limit, 100);

        let no_rl = parse(&yaml_no_rate_limit());
        let outcome = apply_cfg_change_to_rate_limit(&no_rl, Some(&limiter));
        assert!(matches!(
            outcome,
            RateLimitReloadOutcome::Applied { .. },
        ));
        // Default IpRateLimitConfig (1000 / 60s).
        assert_eq!(limiter.config(), IpRateLimitConfig::default());
    }

    #[test]
    fn rate_limit_preserves_per_ip_state_across_reload() {
        use std::net::IpAddr;
        let initial = parse(&yaml_with_rate_limit(100, 60));
        let limiter = Arc::new(IpRateLimiter::new(derive_ip_rate_cfg(&initial)));
        // Pre-seed counts.
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        for _ in 0..50 {
            limiter.consume(ip);
        }
        let tracked_before = limiter.tracked();
        assert_eq!(tracked_before, 1);

        let new_cfg = parse(&yaml_with_rate_limit(500, 60));
        apply_cfg_change_to_rate_limit(&new_cfg, Some(&limiter));
        // Per-IP state intact.
        assert_eq!(limiter.tracked(), tracked_before);
    }

    // ---- apply_cfg_change_to_tls ----

    fn write_pem(dir: &tempfile::TempDir, name: &str, content: &str) -> std::path::PathBuf {
        use std::io::Write;
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn generate_cert(domains: &[&str]) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(
            domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn yaml_with_tls_certs(cert_path: &str, key_path: &str, host: &str) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
tls:
  certificates:
    - hosts: ["{host}"]
      cert_path: "{cert_path}"
      key_ref: "{key_path}"
"#
        )
    }

    fn yaml_no_tls() -> String {
        r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#
        .into()
    }

    fn boot_resolver(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
        host: &str,
    ) -> Arc<DynamicResolver> {
        use arc_swap::ArcSwap;
        let entries = vec![(cert_path.to_path_buf(), key_path.to_path_buf(), vec![host.to_string()])];
        let entries_ref: Vec<(_, _, &[String])> = entries
            .iter()
            .map(|(c, k, h)| (c.clone(), k.clone(), &h[..]))
            .collect();
        let store = CertStore::load(&entries_ref).unwrap();
        Arc::new(DynamicResolver::new(Arc::new(ArcSwap::from_pointee(store))))
    }

    #[test]
    fn tls_reload_no_resolver_returns_no_resolver_outcome() {
        let cfg = parse(&yaml_no_tls());
        let outcome = apply_cfg_change_to_tls(&cfg, None);
        assert_eq!(outcome, TlsReloadOutcome::NoResolver);
    }

    #[test]
    fn tls_reload_swaps_cert_store_atomically() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert_a, key_a) = generate_cert(&["a.example.com"]);
        let cert_a_path = write_pem(&dir, "a.crt", &cert_a);
        let key_a_path = write_pem(&dir, "a.key", &key_a);
        let resolver = boot_resolver(&cert_a_path, &key_a_path, "a.example.com");

        // Hot-reload swaps in cert B for a different host.
        let (cert_b, key_b) = generate_cert(&["b.example.com"]);
        let cert_b_path = write_pem(&dir, "b.crt", &cert_b);
        let key_b_path = write_pem(&dir, "b.key", &key_b);
        let new_cfg = parse(&yaml_with_tls_certs(
            cert_b_path.to_str().unwrap(),
            key_b_path.to_str().unwrap(),
            "b.example.com",
        ));

        let outcome = apply_cfg_change_to_tls(&new_cfg, Some(&resolver));
        assert_eq!(outcome, TlsReloadOutcome::Applied { cert_count: 1 });
    }

    #[test]
    fn tls_reload_skips_when_new_cfg_has_no_tls() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["a.example.com"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);
        let resolver = boot_resolver(&cert_path, &key_path, "a.example.com");

        // New cfg drops `tls:` section entirely.
        let new_cfg = parse(&yaml_no_tls());
        let outcome = apply_cfg_change_to_tls(&new_cfg, Some(&resolver));
        assert_eq!(outcome, TlsReloadOutcome::SkippedEmpty);
    }

    #[test]
    fn tls_reload_fails_on_missing_cert_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["a.example.com"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);
        let resolver = boot_resolver(&cert_path, &key_path, "a.example.com");

        // New cfg points at a path that doesn't exist.
        let new_cfg = parse(&yaml_with_tls_certs(
            "/nonexistent/path/cert.pem",
            "/nonexistent/path/key.pem",
            "a.example.com",
        ));
        let outcome = apply_cfg_change_to_tls(&new_cfg, Some(&resolver));
        match outcome {
            TlsReloadOutcome::Failed { reason } => {
                assert!(!reason.is_empty(), "failure reason should be populated");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn tls_reload_failed_keeps_old_resolver_responsive() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["original.example.com"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);
        let resolver = boot_resolver(&cert_path, &key_path, "original.example.com");
        let store_handle = resolver.store_handle();
        let original_default = store_handle.load().resolve(None);
        assert!(original_default.is_some(), "boot store has a default cert");

        // Trigger a reload with a bogus path.
        let bad_cfg = parse(&yaml_with_tls_certs(
            "/nonexistent/path/cert.pem",
            "/nonexistent/path/key.pem",
            "x.example.com",
        ));
        let _ = apply_cfg_change_to_tls(&bad_cfg, Some(&resolver));

        // Original cert is still resolvable (live store unchanged).
        let after = store_handle.load().resolve(None);
        assert!(after.is_some(), "old cert store still live after failed reload");
    }

    #[test]
    fn route_reload_keeps_old_table_on_validation_error() {
        let ctx = boot_ctx(&yaml_with_route("v1", "/api/v1"));

        // PR2: "no catch-all" no longer fails — deny-by-default
        // covers it. To exercise the validation-error path use the
        // new invariant: two `default: true` routes in the same
        // host scope is rejected.
        let bad_yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: a
    path: "/api"
    default: true
    upstream: pool
  - id: b
    path: "/web"
    default: true
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let bad_cfg = parse(bad_yaml);
        let outcome = apply_cfg_change_to_routes(&bad_cfg, Some(&ctx));
        match outcome {
            RouteReloadOutcome::Failed { reason } => {
                assert!(
                    reason.contains("default") && reason.contains("at most one"),
                    "expected double-default error, got: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // Old route table unchanged.
        let r = ctx
            .route_table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(r.route_id, "v1");
    }

    // ---------------- MTLS-T5 — apply_cfg_change_to_client_auth ----------------

    /// Issue a self-signed CA in PEM form. Returns the bytes
    /// + the path it was written to.
    fn write_test_ca(name: &str) -> (Vec<u8>, std::path::PathBuf) {
        use std::io::Write;
        let mut params =
            rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem().into_bytes();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{name}.pem"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&pem).unwrap();
        f.sync_all().unwrap();
        // Leak the tempdir so the path stays valid for the test.
        std::mem::forget(dir);
        (pem, path)
    }

    fn yaml_with_client_auth(ca_path: &std::path::Path, mode: &str) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
tls:
  certificates: []
  client_auth:
    mode: {mode}
    ca_bundle: {ca_path}
    apply_to: [data]
"#,
            ca_path = ca_path.display(),
        )
    }

    #[test]
    fn client_auth_no_store_when_caller_passes_none() {
        let (_pem, path) = write_test_ca("ca-a");
        let cfg = parse(&yaml_with_client_auth(&path, "required"));
        let outcome = apply_cfg_change_to_client_auth(&cfg, None);
        assert_eq!(outcome, ClientAuthReloadOutcome::NoStore);
    }

    #[test]
    fn client_auth_skipped_when_disabled_in_new_cfg() {
        let (pem_a, path_a) = write_test_ca("ca-a");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();

        // Build a cfg with client_auth.mode = disabled. The
        // helper must short-circuit; the live store stays.
        let cfg_yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let cfg = parse(cfg_yaml);
        let outcome = apply_cfg_change_to_client_auth(&cfg, Some(&trust));
        assert_eq!(outcome, ClientAuthReloadOutcome::SkippedDisabled);
        // Live store still has the original CA.
        assert!(trust.current().len() >= 1);
        // Path used as a fixture, no swap performed.
        let _ = path_a;
    }

    #[test]
    fn client_auth_applied_swaps_to_new_ca() {
        // Live trust starts with CA-A.
        let (pem_a, _path_a) = write_test_ca("ca-a-1");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let len_before = trust.current().len();

        // New cfg points at CA-B. After reload, the live store
        // is swapped to CA-B's roots.
        let (_pem_b, path_b) = write_test_ca("ca-b-1");
        let cfg = parse(&yaml_with_client_auth(&path_b, "required"));

        let outcome = apply_cfg_change_to_client_auth(&cfg, Some(&trust));
        match outcome {
            ClientAuthReloadOutcome::Applied { cert_count, mode } => {
                assert!(cert_count >= 1);
                assert_eq!(mode, aegis_core::config::ClientAuthMode::Required);
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        // Live store is non-empty after swap.
        assert!(trust.current().len() >= len_before.min(1));
    }

    #[test]
    fn client_auth_failed_keeps_live_store_when_path_does_not_exist() {
        // Live trust starts populated.
        let (pem_a, _path_a) = write_test_ca("ca-a-2");
        let trust = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();

        // New cfg points at a non-existent path. Helper must
        // return Failed and the live store must stay populated.
        let bogus = std::path::PathBuf::from("/does-not-exist/ca.pem");
        let cfg = parse(&yaml_with_client_auth(&bogus, "required"));

        let outcome = apply_cfg_change_to_client_auth(&cfg, Some(&trust));
        match outcome {
            ClientAuthReloadOutcome::Failed { reason } => {
                assert!(
                    reason.contains("does-not-exist")
                        || reason.to_lowercase().contains("ca_bundle"),
                    "expected path or label in error: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Live store stays — operators don't lose trust on a
        // bad reload.
        assert!(trust.current().len() >= 1);
    }
}
