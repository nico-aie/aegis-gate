pub mod host;
pub mod path;

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
}

/// Compiled routing table. Built once from [`WafConfig`] and used on the hot
/// path to resolve every incoming request.
#[derive(Debug)]
pub struct RouteTable {
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

                let idx = routes.len();
                routes.push(CompiledRoute {
                    id: rc.id.clone(),
                    host: host_matcher.clone(),
                    methods,
                    upstream: rc.upstream.clone(),
                    tier,
                    failure_mode,
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
    pub fn resolve(
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
        assert!(!table.groups.is_empty());
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
}
