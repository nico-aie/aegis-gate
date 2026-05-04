pub mod host;
pub mod path;

use std::sync::Arc;

use arc_swap::ArcSwap;

use aegis_core::config::{FailureModeConfig, RouteConfig, WafConfig};
use aegis_core::context::RouteCtx;
use aegis_core::tier::{FailureMode, Tier};

use host::HostMatcher;
use path::PathTrie;

/// A compiled route entry ready for matching.
#[derive(Debug)]
struct CompiledRoute {
    id: String,
    #[allow(dead_code)]
    host: HostMatcher,
    methods: Option<Vec<String>>,
    upstream: String,
    tier: Tier,
    failure_mode: FailureMode,
    /// MTLS-T4 — `RouteConfig.auth_required` carried through
    /// to the resolver so the data-plane handler can gate on
    /// client identity. Empty = no gate.
    auth_required: Vec<String>,
    /// TCP-T3c — resolved at compile time from
    /// `cfg.upstreams[upstream].connection.scheme`. Lifted
    /// here so the data-plane CONNECT dispatch is a single
    /// match rather than a second pool lookup.
    pool_scheme: aegis_core::config::UpstreamScheme,
    /// TCP-T3c — pre-parsed CONNECT destination allowlist.
    /// Empty for non-tcp routes; for tcp routes the config
    /// validator already proved every entry parses, so we
    /// `expect` here.
    tcp_destination_allowlist: Vec<aegis_core::tcp_destination::TcpDestinationRule>,
    /// TCP-T3c — per-source-IP cap on concurrent open tunnels.
    /// Routed straight through; `0` is the YAML sentinel for
    /// "use the boot default" and the data plane resolves it
    /// via `aegis_proxy::tcp_tunnel::effective_cap`.
    max_concurrent_tunnels_per_ip: u32,
}

/// Hot-swappable routing table.
///
/// Internally a thin newtype around `Arc<ArcSwap<CompiledRouteTable>>`
/// so config hot-reload can rebuild the compiled table from
/// `new_cfg.routes` and atomic-swap without bouncing the proxy.
/// In-flight requests that already grabbed a snapshot via
/// [`Self::resolve`] finish on the old table; new requests see
/// the new one. Cheap to clone — internals are `Arc`.
#[derive(Debug, Clone)]
pub struct RouteTable {
    inner: Arc<ArcSwap<CompiledRouteTable>>,
    /// FIX 2026-05-04 — RT-T audit-mutated handlers in
    /// `admin_mutate.rs` need to know the *current* route list
    /// (boot snapshot + every runtime upsert/delete so far) to
    /// build the next candidate. The compiled table doesn't keep
    /// the raw `RouteConfig` around, so we shadow it here. Each
    /// successful `apply` swaps both atomically.
    raw: Arc<ArcSwap<Vec<RouteConfig>>>,
}

/// Immutable compiled-route content held inside the [`RouteTable`]
/// `ArcSwap`. A successful [`RouteTable::apply`] replaces the
/// whole `Arc<CompiledRouteTable>` atomically — there's no
/// in-place mutation of route entries.
#[derive(Debug)]
struct CompiledRouteTable {
    /// Per-host group of path tries. Ordered by host priority (exact first).
    groups: Vec<HostGroup>,
}

#[derive(Debug)]
struct HostGroup {
    host: HostMatcher,
    trie: PathTrie<Vec<usize>>, // indices into `routes`
    routes: Vec<CompiledRoute>,
}

impl RouteTable {
    /// Build a [`RouteTable`] from the route configuration.
    ///
    /// Returns an error if no catch-all route (path `"/"` with no host
    /// restriction) exists.
    pub fn build(cfg: &WafConfig) -> aegis_core::Result<Self> {
        let compiled = CompiledRouteTable::build(cfg)?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(compiled)),
            raw: Arc::new(ArcSwap::from_pointee(cfg.routes.clone())),
        })
    }

    /// Hot-reload the route table from a fresh config.
    ///
    /// Validation runs first — on failure the old table stays
    /// live and the error is returned. On success the new table
    /// replaces the old via atomic ArcSwap; in-flight requests
    /// that already loaded a snapshot finish on the old table
    /// (cheap: `Arc<CompiledRouteTable>` is held until the last
    /// request finishes).
    pub fn apply(&self, cfg: &WafConfig) -> aegis_core::Result<()> {
        let compiled = CompiledRouteTable::build(cfg)?;
        self.inner.store(Arc::new(compiled));
        // Shadow the raw list — order matters (first-match-wins).
        self.raw.store(Arc::new(cfg.routes.clone()));
        Ok(())
    }

    /// Snapshot of the current route list — used by the
    /// audit-mutated handlers so each upsert/delete starts from
    /// the live state instead of the stale boot snapshot.
    pub fn current_routes(&self) -> Vec<RouteConfig> {
        (**self.raw.load()).clone()
    }

    /// Resolve a request to a [`RouteCtx`].
    pub fn resolve(
        &self,
        host: &str,
        path: &str,
        method: &http::Method,
    ) -> Option<RouteCtx> {
        self.inner.load().resolve_inner(host, path, method)
    }
}

// RT-T2 — bridge to the audit-mutated PUT/DELETE handlers in
// `admin_mutate.rs`. `aegis-control` defines the trait; the proxy
// implements it on the live route table so dashboard mutations
// can hot-swap routes through the same atomic ArcSwap that
// boot-time hot-reload uses. No new plumbing — `apply` already
// handles validation + atomic swap.
impl aegis_control::api::routes_config::RouteWriter for RouteTable {
    fn apply(
        &self,
        new_cfg: &WafConfig,
    ) -> Result<(), aegis_control::api::routes_config::RouteApplyError> {
        RouteTable::apply(self, new_cfg).map_err(|e| {
            aegis_control::api::routes_config::RouteApplyError::Build(e.to_string())
        })
    }

    fn current_routes(&self) -> Vec<RouteConfig> {
        RouteTable::current_routes(self)
    }
}

impl CompiledRouteTable {
    fn build(cfg: &WafConfig) -> aegis_core::Result<Self> {
        // Group routes by host pattern.
        let mut host_map: std::collections::BTreeMap<String, Vec<(HostMatcher, &RouteConfig)>> =
            std::collections::BTreeMap::new();

        for rc in &cfg.routes {
            let host_key = rc.host.as_deref().unwrap_or("*");
            let matcher = HostMatcher::new(host_key).map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "route '{}' invalid host pattern '{}': {e}",
                    rc.id, host_key
                ))
            })?;
            host_map
                .entry(host_key.to_owned())
                .or_default()
                .push((matcher, rc));
        }

        let mut groups: Vec<HostGroup> = Vec::new();

        for (_key, entries) in host_map {
            // All entries in the same group share the same HostMatcher pattern,
            // so pick from the first.
            let host_matcher = entries[0].0.clone();
            let mut trie = PathTrie::new();
            let mut routes = Vec::new();

            for (_, rc) in &entries {
                let tier = rc.tier_override.unwrap_or(Tier::CatchAll);
                let failure_mode = match &rc.failure_mode {
                    Some(FailureModeConfig::FailClose) => FailureMode::FailClose,
                    Some(FailureModeConfig::FailOpen) => FailureMode::FailOpen,
                    None => tier.default_failure_mode(),
                };
                let methods = rc.methods.as_ref().map(|ms| {
                    ms.iter().map(|m| m.to_ascii_uppercase()).collect()
                });

                // TCP-T3c — resolve the upstream pool's scheme
                // at compile time + parse the route's
                // `tcp_destination_allowlist`. The config
                // validator (aegis_core::config::WafConfig::validate)
                // has already proved every entry parses for tcp
                // routes; for non-tcp routes the field is
                // typically empty. We tolerate parse errors here
                // by skipping the offending entry rather than
                // failing the whole table build — the validator
                // is the source of truth for "is the config sane".
                let pool_scheme = cfg
                    .upstreams
                    .get(&rc.upstream)
                    .map(|p| p.connection.scheme)
                    .unwrap_or(aegis_core::config::UpstreamScheme::Auto);
                let tcp_destination_allowlist: Vec<_> = rc
                    .tcp_destination_allowlist
                    .iter()
                    .filter_map(|s| {
                        aegis_core::tcp_destination::parse_rule(s).ok()
                    })
                    .collect();

                let idx = routes.len();
                routes.push(CompiledRoute {
                    id: rc.id.clone(),
                    host: host_matcher.clone(),
                    methods,
                    upstream: rc.upstream.clone(),
                    tier,
                    failure_mode,
                    auth_required: rc.auth_required.clone(),
                    pool_scheme,
                    tcp_destination_allowlist,
                    max_concurrent_tunnels_per_ip: rc.max_concurrent_tunnels_per_ip,
                });

                // Insert into trie — a single path node can hold multiple
                // route indices (different method filters).
                let existing: Vec<usize> = trie.find(&rc.path).cloned().unwrap_or_default();
                let mut indices = existing;
                indices.push(idx);
                trie.insert(&rc.path, indices);
            }

            groups.push(HostGroup {
                host: host_matcher,
                trie,
                routes,
            });
        }

        // Sort by host priority (exact first, default last).
        groups.sort_by_key(|g| g.host.priority());

        // Verify at least one catch-all route exists.
        let has_catch_all = groups.iter().any(|g| {
            matches!(g.host, HostMatcher::Default)
                && g.trie.find("/").is_some()
        });
        if !has_catch_all {
            return Err(aegis_core::WafError::Config(
                "route table must contain a catch-all route (path '/' with no host restriction)"
                    .into(),
            ));
        }

        Ok(Self { groups })
    }

    /// Resolve a request to a [`RouteCtx`].
    ///
    /// Evaluation order: host match (best priority first) → longest path prefix
    /// → method filter. Falls back to the catch-all.
    fn resolve_inner(
        &self,
        host: &str,
        path: &str,
        method: &http::Method,
    ) -> Option<RouteCtx> {
        for group in &self.groups {
            if !group.host.matches(host) {
                continue;
            }
            if let Some(indices) = group.trie.find(path) {
                // Try method-specific first, then fallback to no-method-filter.
                let mut fallback: Option<&CompiledRoute> = None;
                for &idx in indices {
                    let route = &group.routes[idx];
                    match &route.methods {
                        Some(methods) if methods.iter().any(|m| m == method.as_str()) => {
                            return Some(route.to_ctx());
                        }
                        None => {
                            if fallback.is_none() {
                                fallback = Some(route);
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(route) = fallback {
                    return Some(route.to_ctx());
                }
            }
        }
        None
    }
}

impl CompiledRoute {
    fn to_ctx(&self) -> RouteCtx {
        RouteCtx {
            route_id: self.id.clone(),
            tier: self.tier,
            failure_mode: self.failure_mode,
            upstream: self.upstream.clone(),
            tenant_id: None,
            auth_required: self.auth_required.clone(),
            pool_scheme: self.pool_scheme,
            tcp_destination_allowlist: self.tcp_destination_allowlist.clone(),
            max_concurrent_tunnels_per_ip: self.max_concurrent_tunnels_per_ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn five_route_config() -> WafConfig {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: api-v1
    host: "api.example.com"
    path: "/api/v1/"
    upstream: api-pool

  - id: api-v2
    host: "api.example.com"
    path: "/api/v2/"
    methods: ["GET", "POST"]
    upstream: api-pool

  - id: static
    host: "*.cdn.example.com"
    path: "/assets/"
    upstream: cdn-pool

  - id: health
    path: "/health"
    upstream: default

  - id: catch-all
    path: "/"
    upstream: default

upstreams:
  api-pool:
    members:
      - addr: "127.0.0.1:3000"
  cdn-pool:
    members:
      - addr: "127.0.0.1:3001"
  default:
    members:
      - addr: "127.0.0.1:3002"
state:
  backend: in_memory
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn build_succeeds_with_catch_all() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();
        assert!(!table.inner.load().groups.is_empty());
    }

    #[test]
    fn build_rejects_missing_catch_all() {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: api-only
    host: "api.example.com"
    path: "/api/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let err = RouteTable::build(&cfg).unwrap_err();
        assert!(err.to_string().contains("catch-all"));
    }

    #[test]
    fn resolve_exact_host_and_path() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();

        let ctx = table
            .resolve("api.example.com", "/api/v1/users", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "api-v1");
        assert_eq!(ctx.upstream, "api-pool");
    }

    #[test]
    fn resolve_method_filter() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();

        // GET on /api/v2/ should match api-v2
        let ctx = table
            .resolve("api.example.com", "/api/v2/items", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "api-v2");

        // DELETE on /api/v2/ should NOT match api-v2 (method filter),
        // but falls to catch-all.
        let ctx = table
            .resolve("api.example.com", "/api/v2/items", &http::Method::DELETE)
            .unwrap();
        // Falls through to the catch-all group since api.example.com group
        // has no fallback for /api/v2/ with DELETE.
        assert_eq!(ctx.route_id, "catch-all");
    }

    #[test]
    fn resolve_wildcard_host() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();

        let ctx = table
            .resolve("img.cdn.example.com", "/assets/logo.png", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "static");
        assert_eq!(ctx.upstream, "cdn-pool");
    }

    #[test]
    fn resolve_catch_all() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();

        let ctx = table
            .resolve("unknown.example.com", "/random", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "catch-all");
        assert_eq!(ctx.upstream, "default");
    }

    #[test]
    fn resolve_health_no_host() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();

        let ctx = table
            .resolve("anything", "/health", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "health");
    }

    fn yaml_with_one_route(id: &str, path: &str, upstream: &str) -> String {
        // Catch-all listed LAST per the convention used in
        // `five_route_config` — `RouteTable::build` registers
        // routes into the trie in YAML order, and the more
        // specific path must be inserted before the catch-all
        // gets folded into its prefix indices.
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
    upstream: {upstream}
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
  {upstream}:
    members:
      - addr: "127.0.0.1:3001"
state:
  backend: in_memory
"#
        )
    }

    #[test]
    fn apply_swaps_in_new_routes_atomically() {
        let cfg_v1 = aegis_core::load_config_str(&yaml_with_one_route(
            "v1", "/api/v1", "v1-pool",
        ))
        .unwrap();
        let table = RouteTable::build(&cfg_v1).unwrap();

        // v1 resolves to v1-pool.
        let ctx = table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "v1");
        assert_eq!(ctx.upstream, "v1-pool");

        // Hot-swap to a new config with a different route.
        let cfg_v2 = aegis_core::load_config_str(&yaml_with_one_route(
            "v2", "/api/v2", "v2-pool",
        ))
        .unwrap();
        table.apply(&cfg_v2).unwrap();

        // v1 path no longer resolves to v1; falls through to catch-all.
        let ctx = table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "catch-all");

        // v2 path resolves to v2-pool.
        let ctx = table
            .resolve("any", "/api/v2", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "v2");
        assert_eq!(ctx.upstream, "v2-pool");
    }

    #[test]
    fn apply_validates_and_keeps_old_table_on_error() {
        let cfg_v1 = aegis_core::load_config_str(&yaml_with_one_route(
            "v1", "/api/v1", "v1-pool",
        ))
        .unwrap();
        let table = RouteTable::build(&cfg_v1).unwrap();

        // Build a config with no catch-all — `RouteTable::build`
        // should reject it. The existing table must stay intact.
        let bad_yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: only
    host: "api.example.com"
    path: "/foo"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let bad_cfg = aegis_core::load_config_str(bad_yaml).unwrap();
        assert!(table.apply(&bad_cfg).is_err());

        // Old table unchanged: v1 still resolves.
        let ctx = table
            .resolve("any", "/api/v1", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "v1");
    }

    #[test]
    fn cheap_clone_shares_inner_arc() {
        let cfg = five_route_config();
        let table_a = RouteTable::build(&cfg).unwrap();
        let table_b = table_a.clone();

        // Both clones see updates from each other (they share
        // the same Arc<ArcSwap<…>> internally).
        let cfg2 = aegis_core::load_config_str(&yaml_with_one_route(
            "v2", "/api/v2", "v2-pool",
        ))
        .unwrap();
        table_a.apply(&cfg2).unwrap();

        // table_b sees the swap because internals are shared.
        let ctx = table_b
            .resolve("any", "/api/v2", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "v2");
    }

    // ---------------- MTLS-T4 ----------------

    #[test]
    fn auth_required_default_is_empty_open_route() {
        // Existing routes don't carry `auth_required:` in YAML —
        // their RouteCtx must come back with an empty list so
        // the data-plane gate is a no-op for them.
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();
        let ctx = table
            .resolve("api.example.com", "/api/v1/users", &http::Method::GET)
            .unwrap();
        assert!(ctx.auth_required.is_empty(), "open routes default to no gate");
    }

    #[test]
    fn auth_required_threads_from_yaml_to_route_ctx() {
        // Route declares `auth_required: ["mtls", "spiffe"]` —
        // resolver must pass that list through unchanged.
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: secure-api
    host: "api.example.com"
    path: "/secure/"
    upstream: backend
    auth_required: ["mtls", "spiffe"]
  - id: catch-all
    path: "/"
    upstream: backend
upstreams:
  backend:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();
        let secure = table
            .resolve("api.example.com", "/secure/billing", &http::Method::GET)
            .unwrap();
        assert_eq!(secure.route_id, "secure-api");
        assert_eq!(secure.auth_required, vec!["mtls", "spiffe"]);
        // Catch-all stays open.
        let open = table
            .resolve("api.example.com", "/public", &http::Method::GET)
            .unwrap();
        assert_eq!(open.route_id, "catch-all");
        assert!(open.auth_required.is_empty());
    }

    // -----------------------------------------------------------
    // TCP-T3c — pool_scheme + allowlist propagation
    // -----------------------------------------------------------

    #[test]
    fn route_ctx_carries_pool_scheme_and_allowlist_for_tcp_routes() {
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - id: tcp-tunnel
    path: "/"
    upstream: tcp-mesh
    tcp_destination_allowlist:
      - "10.0.0.0/8:6379"
      - "192.168.1.0/24:443"
    max_concurrent_tunnels_per_ip: 8
upstreams:
  tcp-mesh:
    members: [{ addr: "127.0.0.1:6379" }]
    connection: { scheme: tcp }
state:
  backend: in_memory
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.validate().unwrap();
        let table = RouteTable::build(&cfg).unwrap();
        let ctx = table
            .resolve("api.example.com", "/", &http::Method::GET)
            .unwrap();
        assert_eq!(
            ctx.pool_scheme,
            aegis_core::config::UpstreamScheme::Tcp,
            "pool_scheme must lift from cfg.upstreams[upstream].connection.scheme",
        );
        assert_eq!(
            ctx.tcp_destination_allowlist.len(),
            2,
            "both allowlist entries should parse + propagate",
        );
        assert_eq!(ctx.max_concurrent_tunnels_per_ip, 8);
    }

    #[test]
    fn route_ctx_default_scheme_is_auto_for_normal_routes() {
        let cfg = five_route_config();
        let table = RouteTable::build(&cfg).unwrap();
        let ctx = table
            .resolve("api.example.com", "/api/v1/users", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.pool_scheme, aegis_core::config::UpstreamScheme::Auto);
        assert!(ctx.tcp_destination_allowlist.is_empty());
        assert_eq!(ctx.max_concurrent_tunnels_per_ip, 0);
    }
}
