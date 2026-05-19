pub mod host;
pub mod path;
pub mod priority;

use std::sync::Arc;

use arc_swap::ArcSwap;

use aegis_core::config::{FailureModeConfig, RouteConfig, WafConfig};
use aegis_core::context::RouteCtx;
use aegis_core::tier::{FailureMode, Tier};

use host::HostMatcher;
use path::PathTrie;
use priority::RoutePriority;

/// A compiled route entry ready for matching.
#[derive(Debug)]
struct CompiledRoute {
    id: String,
    #[allow(dead_code)]
    host: HostMatcher,
    /// PR1 — original path string from `RouteConfig.path`. Stored
    /// here (rather than reverse-walking the trie) so the priority
    /// report and routes API can render the path without extra book-
    /// keeping in `HostGroup`.
    path: String,
    /// 2026-05-12 — precomputed prefix to strip from the request
    /// path before forwarding (resolved at compile time from
    /// `RouteConfig.strip_prefix` + `match_type` gating). `None`
    /// means forward the path unchanged.
    path_strip_prefix: Option<String>,
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
    /// PR1 — derived precedence used to determine the trie
    /// registration order + the `--print-route-priority` audit.
    /// Sorted descending: higher matches first.
    priority: RoutePriority,
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

    /// PR1 — walk every compiled route in **priority-descending
    /// order**, emitting one row per route. Used by the
    /// `--print-route-priority` CLI flag and by the routes API
    /// serializer to expose the effective evaluation order to the
    /// dashboard. Each emitted row carries `(route_id, host_pattern,
    /// path, methods, tier, upstream, priority)`.
    pub fn priorities(&self) -> Vec<RoutePriorityRow> {
        let snap = self.inner.load();
        let mut rows: Vec<RoutePriorityRow> = Vec::new();
        for group in &snap.groups {
            for route in &group.routes {
                rows.push(RoutePriorityRow {
                    route_id: route.id.clone(),
                    host: format_host(&group.host),
                    path: route.path.clone(),
                    methods: route.methods.clone(),
                    tier: route.tier,
                    upstream: route.upstream.clone(),
                    priority: route.priority,
                });
            }
        }
        rows.sort_by(|a, b| b.priority.cmp(&a.priority));
        rows
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

/// PR1 — flattened priority report emitted by [`RouteTable::priorities`].
#[derive(Debug, Clone)]
pub struct RoutePriorityRow {
    pub route_id: String,
    pub host: String,
    pub path: String,
    pub methods: Option<Vec<String>>,
    pub tier: Tier,
    pub upstream: String,
    pub priority: RoutePriority,
}

fn format_host(host: &HostMatcher) -> String {
    match host {
        HostMatcher::Exact(h) => h.clone(),
        HostMatcher::Wildcard(suffix) => format!("*{suffix}"),
        HostMatcher::Regex(re) => format!("/{}/", re.as_str()),
        HostMatcher::Default => "*".to_string(),
    }
}

/// PR2 — idempotent auto-migration. Returns a clone of the routes
/// where any `path: "/"` no-host route in a host scope that has no
/// explicit `default: true` route gets the flag set implicitly.
/// Configs that were valid pre-PR2 keep working post-PR2: the
/// old "the catch-all is `path: \"/\"` no-host" convention is
/// preserved by promoting that route to the explicit default role.
fn apply_default_migration(routes: &[RouteConfig]) -> Vec<RouteConfig> {
    use std::collections::HashSet;
    let scopes_with_explicit_default: HashSet<String> = routes
        .iter()
        .filter(|r| r.default)
        .map(|r| r.host.clone().unwrap_or_else(|| "*".to_string()))
        .collect();

    routes
        .iter()
        .map(|r| {
            let scope = r.host.clone().unwrap_or_else(|| "*".to_string());
            let is_legacy_catch_all = r.path == "/" && r.host.is_none();
            let no_explicit_default_in_scope =
                !scopes_with_explicit_default.contains(&scope);
            let needs_promotion =
                !r.default && is_legacy_catch_all && no_explicit_default_in_scope;
            if needs_promotion {
                let mut promoted = r.clone();
                promoted.default = true;
                promoted
            } else {
                r.clone()
            }
        })
        .collect()
}

/// PR2 — at most one `default: true` route per host scope. Two
/// defaults in the same scope is operator error: the resolver can't
/// pick a fallback deterministically, so we refuse to build the
/// table rather than silently picking one.
fn validate_one_default_per_host(routes: &[RouteConfig]) -> aegis_core::Result<()> {
    use std::collections::HashMap;
    let mut by_scope: HashMap<String, Vec<&str>> = HashMap::new();
    for r in routes {
        if r.default {
            let scope = r.host.clone().unwrap_or_else(|| "*".to_string());
            by_scope.entry(scope).or_default().push(&r.id);
        }
    }
    for (scope, ids) in &by_scope {
        if ids.len() > 1 {
            return Err(aegis_core::WafError::Config(format!(
                "host scope '{scope}' has {n} `default: true` routes ({ids}); \
                 at most one default per scope is allowed",
                n = ids.len(),
                ids = ids.join(", "),
            )));
        }
    }
    Ok(())
}

/// PR1 — single source of truth for the `/api/routes` JSON shape.
/// Computes priority alongside the other fields, then **sorts the
/// returned rows by priority descending** so the dashboard renders
/// the effective evaluation order in receive order — no client-side
/// sort, no need to parse the compact priority string. Used by both
/// the boot path (`accept.rs`) and the audit-mutated upsert/delete
/// handlers (`admin_mutate.rs`).
pub fn route_summaries(
    routes: &[RouteConfig],
) -> Vec<aegis_control::api::routes::RouteSummary> {
    // PR2: surface migrated `default: true` flags to the dashboard
    // so the operator sees the auto-promoted default badge even on
    // legacy configs that don't carry the flag in YAML yet.
    let migrated = apply_default_migration(routes);
    let mut paired: Vec<(RoutePriority, aegis_control::api::routes::RouteSummary)> = migrated
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let host_key = r.host.as_deref().unwrap_or("*");
            // If the host pattern is invalid we still emit the row so
            // the dashboard can surface it; the rank falls to the very
            // bottom (all-zero priority + late position).
            let priority = HostMatcher::new(host_key)
                .map(|matcher| RoutePriority::compute(r, &matcher, idx))
                .unwrap_or(RoutePriority {
                    host: 0,
                    path_kind: 0,
                    path_segments: 0,
                    method: 0,
                    declared: 0,
                    yaml_position_inverted: 0,
                });

            let summary = aegis_control::api::routes::RouteSummary {
                id: r.id.clone(),
                host: r.host.clone(),
                path: r.path.clone(),
                match_type: match r.match_type {
                    aegis_core::config::MatchType::Exact => "exact",
                    aegis_core::config::MatchType::Prefix => "prefix",
                    aegis_core::config::MatchType::Regex => "regex",
                    aegis_core::config::MatchType::Glob => "glob",
                }
                .to_string(),
                methods: r.methods.clone().unwrap_or_default(),
                upstream: r.upstream.clone(),
                tier_override: r.tier_override.map(|t| match t {
                    aegis_core::tier::Tier::Critical => "critical",
                    aegis_core::tier::Tier::High => "high",
                    aegis_core::tier::Tier::Medium => "medium",
                    aegis_core::tier::Tier::Low => "low",
                }
                .to_string()),
                auth_required: r.auth_required.clone(),
                priority: priority.fmt_compact(),
                default: r.default,
                enabled: r.enabled,
            };
            (priority, summary)
        })
        .collect();

    paired.sort_by(|a, b| b.0.cmp(&a.0));
    paired.into_iter().map(|(_, s)| s).collect()
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

    fn resolve_for_test(
        &self,
        host: &str,
        path: &str,
        method: &str,
    ) -> Option<aegis_control::api::routes_config::RouteResolveResult> {
        let m = method.parse::<http::Method>().ok()?;
        let host_for = if host.is_empty() { "*" } else { host };
        let ctx = self.resolve(host_for, path, &m)?;
        let summaries = route_summaries(&self.current_routes());
        let summary = summaries.iter().find(|s| s.id == ctx.route_id);
        Some(aegis_control::api::routes_config::RouteResolveResult {
            route_id: ctx.route_id,
            host: summary.and_then(|s| s.host.clone()),
            path: summary.map(|s| s.path.clone()).unwrap_or_default(),
            methods: summary.map(|s| s.methods.clone()).unwrap_or_default(),
            tier: format!("{:?}", ctx.tier).to_lowercase(),
            upstream: ctx.upstream,
            priority: summary.map(|s| s.priority.clone()).unwrap_or_default(),
            default: summary.map(|s| s.default).unwrap_or(false),
            enabled: summary.map(|s| s.enabled).unwrap_or(true),
        })
    }
}

impl CompiledRouteTable {
    fn build(cfg: &WafConfig) -> aegis_core::Result<Self> {
        // PR2: idempotent auto-migration — any `path: "/"` no-host
        // route that's not yet flagged `default: true` gets the flag
        // implicitly when no explicit default exists in the same
        // host scope. The cfg itself is not mutated; we work on a
        // local view. The migration is what lets old configs (no
        // `default:` field anywhere) keep their fall-back behaviour
        // without operator action.
        let migrated = apply_default_migration(&cfg.routes);

        // PR2: validate "at most one default per host scope". Multi-
        // default within a scope is operator error — we refuse to
        // build the table rather than silently picking one.
        validate_one_default_per_host(&migrated)?;

        // PR1: compute priority once per route from its YAML position
        // so trie registration is deterministic from config content
        // alone. Order in `cfg.routes` only acts as the final
        // tiebreaker — host/path/method specificity dominate.
        // PR2: skip disabled routes from the trie entirely. They
        // still exist in the raw config (for /api/routes display)
        // but never match a request.
        let mut priorities: Vec<(usize, HostMatcher, RoutePriority, &RouteConfig)> =
            Vec::with_capacity(migrated.len());

        for (yaml_idx, rc) in migrated.iter().enumerate() {
            if !rc.enabled {
                continue;
            }
            let host_key = rc.host.as_deref().unwrap_or("*");
            let matcher = HostMatcher::new(host_key).map_err(|e| {
                aegis_core::WafError::Config(format!(
                    "route '{}' invalid host pattern '{}': {e}",
                    rc.id, host_key
                ))
            })?;
            let prio = RoutePriority::compute(rc, &matcher, yaml_idx);
            priorities.push((yaml_idx, matcher, prio, rc));
        }

        // Sort the global route list by priority desc. The trie-build
        // loop below registers in this order, so `find_exact` at the
        // merge site (a more specific path inserted before its
        // ancestors) always sees an empty bucket — no ancestor bleed.
        priorities.sort_by(|a, b| b.2.cmp(&a.2));

        // Group by host_key (the original raw pattern, lowercased
        // would alias collisions — keep the original to surface
        // operator-typed differences in the audit). Within each
        // group, routes stay in priority-desc order.
        let mut host_map: std::collections::BTreeMap<
            String,
            Vec<(HostMatcher, RoutePriority, &RouteConfig)>,
        > = std::collections::BTreeMap::new();

        for (_, matcher, prio, rc) in priorities {
            let host_key = rc.host.as_deref().unwrap_or("*");
            host_map
                .entry(host_key.to_owned())
                .or_default()
                .push((matcher, prio, rc));
        }

        let mut groups: Vec<HostGroup> = Vec::new();

        for (_key, entries) in host_map {
            // All entries in the same group share the same HostMatcher pattern,
            // so pick from the first.
            let host_matcher = entries[0].0.clone();
            let mut trie = PathTrie::new();
            let mut routes = Vec::new();

            for (_, prio, rc) in &entries {
                let tier = rc.tier_override.unwrap_or(Tier::Low);
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
                    path: rc.path.clone(),
                    path_strip_prefix: compile_path_strip_prefix(rc),
                    methods,
                    upstream: rc.upstream.clone(),
                    tier,
                    failure_mode,
                    auth_required: rc.auth_required.clone(),
                    pool_scheme,
                    tcp_destination_allowlist,
                    max_concurrent_tunnels_per_ip: rc.max_concurrent_tunnels_per_ip,
                    priority: *prio,
                });

                // PR1: same-path merge uses `find_exact`, NOT `find`.
                // Routes here are already sorted by priority desc, so
                // a more specific path is registered before its
                // ancestor catch-all — `find_exact` at the ancestor's
                // node returns None (no bleed), and `find_exact` at
                // an exact same-path entry returns the prior method-
                // specific bucket so the two routes can share a node.
                let existing: Vec<usize> =
                    trie.find_exact(&rc.path).cloned().unwrap_or_default();
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

        // PR2: lift the rigid "must contain `path: '/'` no-host
        // route" invariant. We now ALLOW a config with no default
        // route at all — unmatched requests will fall through to
        // the deny-by-default 404 path that PR3 wires into the
        // resolver. The migration above keeps every existing config
        // honest: a `path: "/"` no-host route is auto-flagged
        // `default: true` if no explicit default exists, so configs
        // that worked pre-PR2 keep working post-PR2 with zero edits.
        //
        // The dashboard surface guides operators toward having a
        // default route (it's the safe choice for most deployments)
        // but the data plane no longer refuses to boot without one.

        Ok(Self { groups })
    }

    /// Resolve a request to a [`RouteCtx`].
    ///
    /// Evaluation order: host match (best priority first) → longest path
    /// prefix → method filter. If the longest-prefix node has only
    /// method-filtered routes that don't accept `method`, we fall
    /// through to the next-longer prefix in the same group, and
    /// eventually to a less-specific host group.
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
            // PR1 — walk every matching prefix (longest first) so that
            // a PUT request to a path whose only registered routes are
            // GET/POST falls through to the parent (e.g. the catch-all
            // `/`) instead of returning None. Pre-PR1 this worked
            // accidentally because the catch-all bled into every
            // descendant's index list at build time; with the bleed
            // fixed, the resolver has to do the walk explicitly.
            for indices in group.trie.find_all_prefixes(path) {
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
            auth_required: self.auth_required.clone(),
            pool_scheme: self.pool_scheme,
            tcp_destination_allowlist: self.tcp_destination_allowlist.clone(),
            max_concurrent_tunnels_per_ip: self.max_concurrent_tunnels_per_ip,
            path_strip_prefix: self.path_strip_prefix.clone(),
        }
    }
}

/// 2026-05-12 — resolve the precomputed strip-prefix for a route.
/// Centralised so the unit tests below and the production build
/// agree on the gating rules:
///
///   - `strip_prefix == false`     → `None` (path-preserving).
///   - `match_type == Regex|Glob`  → `None` (no single literal
///     prefix to strip; `regex` captures could express it but
///     that's a separate feature).
///   - `path == "/"`               → `None` (stripping a single
///     slash leaves the request without a path component).
///   - Otherwise                   → `Some(path.clone())`.
fn compile_path_strip_prefix(
    cfg: &RouteConfig,
) -> Option<String> {
    if !cfg.strip_prefix {
        return None;
    }
    use aegis_core::config::MatchType;
    if !matches!(cfg.match_type, MatchType::Prefix | MatchType::Exact) {
        return None;
    }
    if cfg.path == "/" {
        return None;
    }
    Some(cfg.path.clone())
}

#[cfg(test)]
mod strip_prefix_tests {
    use super::*;
    use aegis_core::config::MatchType;

    fn cfg(path: &str, match_type: MatchType, strip: bool) -> RouteConfig {
        RouteConfig {
            id: "t".into(),
            host: None,
            path: path.into(),
            match_type,
            strip_prefix: strip,
            methods: None,
            upstream: "u".into(),
            tier_override: None,
            failure_mode: None,
            quota: None,
            auth_required: Vec::new(),
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            default: false,
            enabled: true,
        }
    }

    #[test]
    fn prefix_match_strips_path_when_enabled() {
        let c = cfg("/news", MatchType::Prefix, true);
        assert_eq!(compile_path_strip_prefix(&c).as_deref(), Some("/news"));
    }

    #[test]
    fn disabled_returns_none_regardless_of_match_type() {
        let c = cfg("/news", MatchType::Prefix, false);
        assert!(compile_path_strip_prefix(&c).is_none());
    }

    #[test]
    fn catch_all_route_never_strips() {
        let c = cfg("/", MatchType::Prefix, true);
        assert!(compile_path_strip_prefix(&c).is_none());
    }

    #[test]
    fn regex_and_glob_skip_stripping() {
        let r = cfg("/api/.*", MatchType::Regex, true);
        assert!(compile_path_strip_prefix(&r).is_none());
        let g = cfg("/files/*", MatchType::Glob, true);
        assert!(compile_path_strip_prefix(&g).is_none());
    }

    #[test]
    fn exact_match_strips_full_path_when_enabled() {
        // Exact match means request_path == route_path, so the
        // strip leaves "/" — the forwarder handles that.
        let c = cfg("/login", MatchType::Exact, true);
        assert_eq!(compile_path_strip_prefix(&c).as_deref(), Some("/login"));
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

    /// PR2 — a config without any catch-all / default route now
    /// builds successfully (deny-by-default, see PR3). Pre-PR2 this
    /// test asserted the build was rejected; the new contract is
    /// that the build accepts the config and the resolver returns
    /// `None` for unmatched requests, which the data plane converts
    /// into a 404 still flowing through the security pipeline.
    #[test]
    fn build_accepts_config_without_default_route() {
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
        let table = RouteTable::build(&cfg).expect("PR2: deny-by-default allows missing catch-all");

        // Matched path resolves normally.
        let ctx = table
            .resolve("api.example.com", "/api/users", &http::Method::GET)
            .expect("matched route still resolves");
        assert_eq!(ctx.route_id, "api-only");

        // Unmatched path returns None — PR3's deny-by-default 404
        // path takes it from there.
        assert!(table.resolve("other.example.com", "/", &http::Method::GET).is_none());
    }

    /// PR2 — multiple `default: true` routes in the same host scope
    /// is operator error and the build rejects it.
    #[test]
    fn build_rejects_two_defaults_in_same_scope() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: a, path: "/api", default: true, upstream: stub }
  - { id: b, path: "/web", default: true, upstream: stub }
upstreams:
  stub: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let err = RouteTable::build(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("default") && msg.contains("at most one"));
    }

    /// PR2 — auto-migration: a legacy `path: "/"` no-host route is
    /// implicitly promoted to `default: true` when no explicit
    /// default exists, so old configs keep working.
    #[test]
    fn legacy_root_route_auto_promoted_to_default() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: legacy-catch-all, path: "/", upstream: stub }
upstreams:
  stub: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        // Pre-migration, the YAML doesn't carry default:true.
        assert!(!cfg.routes[0].default, "input YAML has no default flag");

        // The migration step runs inside RouteTable::build; verify
        // it via the helper directly.
        let migrated = super::apply_default_migration(&cfg.routes);
        assert!(migrated[0].default, "migration promotes legacy / route");

        // The build succeeds.
        let table = RouteTable::build(&cfg).expect("legacy config still builds");
        let ctx = table.resolve("anything", "/random", &http::Method::GET).unwrap();
        assert_eq!(ctx.route_id, "legacy-catch-all");
    }

    /// PR2 — explicit `default: true` on one route blocks the
    /// migration from touching another `path: "/"` route in the
    /// same scope (idempotency).
    #[test]
    fn migration_skipped_when_explicit_default_exists() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: api,            host: "api.example.com", path: "/", default: true, upstream: stub }
  - { id: legacy-default,                          path: "/",                upstream: stub }
upstreams:
  stub: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let migrated = super::apply_default_migration(&cfg.routes);
        // `api` (api.example.com scope) was already default — unchanged.
        assert!(migrated[0].default);
        // `legacy-default` (`*` scope) has no explicit default in its
        // scope — the migration promotes it.
        assert!(migrated[1].default);
    }

    /// PR3 — deny-by-default. A config with no default route at all
    /// should resolve unmatched requests to None, which the data
    /// plane converts to 404 with audit. Matched requests still
    /// resolve normally — only the catch-all role is gone.
    #[test]
    fn deny_by_default_returns_none_for_unmatched() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: api, host: "api.example.com", path: "/v2", upstream: pool }
upstreams:
  pool: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();

        // Matched: still resolves.
        let ctx = table
            .resolve("api.example.com", "/v2/users", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "api");

        // Unmatched: deny-by-default — None, data plane returns 404.
        assert!(table.resolve("other.example.com", "/", &http::Method::GET).is_none());
        assert!(table.resolve("api.example.com", "/v3/users", &http::Method::GET).is_none());
    }

    /// PR3 — explicit `default: true` route catches unmatched paths
    /// (the operator opted in to a fallback). Disabling deny-by-default
    /// is just "add a default: true route to your config".
    #[test]
    fn explicit_default_catches_unmatched() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: api,      host: "api.example.com", path: "/v2", upstream: api-pool }
  - { id: fallback,                          path: "/",   default: true, upstream: stub }
upstreams:
  api-pool: { members: [{ addr: "127.0.0.1:3000" }] }
  stub:     { members: [{ addr: "127.0.0.1:9999" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();
        let ctx = table.resolve("anywhere.com", "/random", &http::Method::GET).unwrap();
        assert_eq!(ctx.route_id, "fallback");
    }

    /// PR2 — disabled routes are skipped from trie registration but
    /// still appear in /api/routes (so dashboard can show them dimmed).
    #[test]
    fn disabled_route_skipped_from_resolve_but_kept_in_summaries() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all, path: "/",      upstream: stub }
  - { id: blocked,   path: "/admin", enabled: false, upstream: stub }
upstreams:
  stub: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();

        // /admin no longer resolves to `blocked` — falls through to
        // the catch-all because the disabled route never registered.
        let ctx = table.resolve("h", "/admin/users", &http::Method::GET).unwrap();
        assert_eq!(ctx.route_id, "catch-all");

        // But it IS visible in route_summaries so the UI can render it.
        let summaries = super::route_summaries(&cfg.routes);
        let ids: Vec<&str> = summaries.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"blocked"), "disabled route still in summaries");
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

    // PR1 NOTE: as of the specificity-sort fix, route registration
    // order in the trie is derived from priority desc — not from
    // YAML position. The `yaml_with_one_route` fixture below still
    // happens to list the catch-all last for readability, but
    // either order would now resolve identically.
    fn yaml_with_one_route(id: &str, path: &str, upstream: &str) -> String {
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

        // PR2: "no catch-all" is no longer an error (deny-by-default
        // covers it). To exercise apply()'s error path we use the
        // new invariant: two `default: true` routes in the same
        // host scope is operator error, build is rejected.
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

    // ---------------- PR1: specificity-derived precedence ----------------

    /// Reproduces the dashboard scenario reported 2026-05-04: a user
    /// adds the catch-all first, then a more specific `/local` prefix
    /// route. Pre-PR1, `/local/game` shadowed to the catch-all because
    /// trie-build merged the catch-all's index into the `/local` node.
    /// Post-PR1: priority-sorted insertion + `find_exact` keep the
    /// buckets disjoint, so `/local/game` resolves to `localhost-3002`
    /// regardless of YAML row order.
    #[test]
    fn catch_all_listed_first_does_not_shadow_specific_prefix() {
        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all,      path: "/",      upstream: stub }
  - { id: localhost-3002, path: "/local", upstream: local }
upstreams:
  stub:  { members: [{ addr: "127.0.0.1:9999" }] }
  local: { members: [{ addr: "127.0.0.1:3002" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();

        let ctx = table
            .resolve("anything", "/local/game", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "localhost-3002");
        assert_eq!(ctx.upstream, "local");

        // Sanity: catch-all still wins for unrelated paths.
        let ctx = table
            .resolve("anything", "/random", &http::Method::GET)
            .unwrap();
        assert_eq!(ctx.route_id, "catch-all");
    }

    /// Permutation invariance — for a fixed set of routes, every YAML
    /// ordering must produce identical resolve results. Proves that
    /// PR1 made route resolution a pure function of config content.
    #[test]
    fn build_is_yaml_order_invariant_for_distinct_paths() {
        let route_blocks = [
            ("api",       r#"  - { id: api,       host: "api.example.com", path: "/api/v2", upstream: api-pool }"#),
            ("static",    r#"  - { id: static,    host: "*.example.com",   path: "/static", upstream: cdn-pool }"#),
            ("local",     r#"  - { id: local,                              path: "/local",  upstream: local-pool }"#),
            ("catch-all", r#"  - { id: catch-all,                          path: "/",       upstream: default-pool }"#),
        ];
        let preamble = r#"
listeners:
  data:  [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
upstreams:
  api-pool:     { members: [{ addr: "127.0.0.1:3000" }] }
  cdn-pool:     { members: [{ addr: "127.0.0.1:3001" }] }
  local-pool:   { members: [{ addr: "127.0.0.1:3002" }] }
  default-pool: { members: [{ addr: "127.0.0.1:3003" }] }
state: { backend: in_memory }
routes:
"#;

        // 4! = 24 permutations.
        let perms: Vec<Vec<usize>> = {
            let mut out = Vec::new();
            let n = route_blocks.len();
            let mut idx: Vec<usize> = (0..n).collect();
            permute(&mut idx, 0, &mut out);
            out
        };
        assert_eq!(perms.len(), 24);

        for perm in &perms {
            let routes_yaml: String = perm
                .iter()
                .map(|&i| route_blocks[i].1)
                .collect::<Vec<_>>()
                .join("\n");
            let yaml = format!("{preamble}{routes_yaml}\n");
            let cfg = aegis_core::load_config_str(&yaml).unwrap_or_else(|e| {
                panic!("yaml load failed for perm {perm:?}: {e}\n{yaml}")
            });
            let table = RouteTable::build(&cfg).unwrap();

            // Every permutation must resolve identically.
            assert_eq!(
                table.resolve("api.example.com", "/api/v2/x", &http::Method::GET).unwrap().route_id,
                "api",
                "perm {perm:?}: /api/v2/x must hit api"
            );
            assert_eq!(
                table.resolve("img.example.com", "/static/logo.png", &http::Method::GET).unwrap().route_id,
                "static",
                "perm {perm:?}: /static/* on *.example.com must hit static"
            );
            assert_eq!(
                table.resolve("anything", "/local/game", &http::Method::GET).unwrap().route_id,
                "local",
                "perm {perm:?}: /local/* on default host must hit local"
            );
            assert_eq!(
                table.resolve("anything", "/totally-random", &http::Method::GET).unwrap().route_id,
                "catch-all",
                "perm {perm:?}: unmatched paths must fall to catch-all"
            );
        }
    }

    fn permute(arr: &mut [usize], start: usize, out: &mut Vec<Vec<usize>>) {
        if start == arr.len() {
            out.push(arr.to_vec());
            return;
        }
        for i in start..arr.len() {
            arr.swap(start, i);
            permute(arr, start + 1, out);
            arr.swap(start, i);
        }
    }

    /// Two routes at literally the same path with different method
    /// filters must both register and dispatch correctly. The merge
    /// at `find_exact(path)` is the mechanism — exercise it with a
    /// permuted YAML order to be sure registration order doesn't
    /// affect dispatch.
    #[test]
    fn same_path_different_methods_both_match() {
        let yaml = r#"
listeners:
  data:  [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all, path: "/",    upstream: stub }
  - { id: get-api,   path: "/api", methods: ["GET"],  upstream: g }
  - { id: post-api,  path: "/api", methods: ["POST"], upstream: p }
upstreams:
  stub: { members: [{ addr: "127.0.0.1:9999" }] }
  g:    { members: [{ addr: "127.0.0.1:3000" }] }
  p:    { members: [{ addr: "127.0.0.1:3001" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();

        assert_eq!(
            table.resolve("h", "/api", &http::Method::GET).unwrap().route_id,
            "get-api"
        );
        assert_eq!(
            table.resolve("h", "/api", &http::Method::POST).unwrap().route_id,
            "post-api"
        );
        // PUT — neither method-filtered route matches; falls through
        // to the catch-all.
        assert_eq!(
            table.resolve("h", "/api", &http::Method::PUT).unwrap().route_id,
            "catch-all"
        );
    }

    /// `route_summaries()` returns rows sorted by priority descending
    /// regardless of YAML order — the dashboard relies on this so it
    /// can render the table in receive order without parsing the
    /// compact priority string client-side.
    #[test]
    fn route_summaries_sorted_by_priority_descending() {
        let yaml = r#"
listeners:
  data:  [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all, path: "/", upstream: stub }
  - { id: api,      host: "api.example.com", path: "/v2", upstream: api-pool }
  - { id: local,    path: "/local", upstream: local-pool }
upstreams:
  stub:       { members: [{ addr: "127.0.0.1:9999" }] }
  api-pool:   { members: [{ addr: "127.0.0.1:3000" }] }
  local-pool: { members: [{ addr: "127.0.0.1:3001" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let summaries = super::route_summaries(&cfg.routes);
        let ids: Vec<&str> = summaries.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["api", "local", "catch-all"]);
    }

    /// `route_summaries()` (the API helper) computes the same
    /// priority string the CLI flag emits, for the same inputs.
    /// Guards against divergence as the priority components evolve.
    #[test]
    fn route_summaries_priority_matches_cli_table() {
        let yaml = r#"
listeners:
  data:  [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - { id: api,      host: "api.example.com", path: "/v2", upstream: api-pool }
  - { id: catch-all, path: "/", upstream: stub }
upstreams:
  api-pool: { members: [{ addr: "127.0.0.1:3000" }] }
  stub:     { members: [{ addr: "127.0.0.1:9999" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();
        let cli_rows = table.priorities();
        let summaries = super::route_summaries(&cfg.routes);

        // Same id → same compact priority string in both surfaces.
        for sum in &summaries {
            let matching = cli_rows
                .iter()
                .find(|r| r.route_id == sum.id)
                .expect("every summary id should appear in the CLI table");
            assert_eq!(
                sum.priority,
                matching.priority.fmt_compact(),
                "API helper priority must match CLI priority for {}",
                sum.id
            );
        }
    }

    /// `RouteTable::priorities()` returns rows in priority-descending
    /// order, with the catch-all last regardless of YAML position.
    #[test]
    fn priorities_returns_rows_descending() {
        let yaml = r#"
listeners:
  data:  [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all, path: "/",      upstream: stub }
  - { id: api,      host: "api.example.com", path: "/v2", upstream: api-pool }
  - { id: local,    path: "/local", upstream: local-pool }
upstreams:
  stub:       { members: [{ addr: "127.0.0.1:9999" }] }
  api-pool:   { members: [{ addr: "127.0.0.1:3000" }] }
  local-pool: { members: [{ addr: "127.0.0.1:3001" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();
        let rows = table.priorities();
        let ids: Vec<_> = rows.iter().map(|r| r.route_id.as_str()).collect();
        assert_eq!(ids, vec!["api", "local", "catch-all"]);
    }

    /// PR1 microbench — measures the cost of `RouteTable::resolve`
    /// on a realistic 9-route table. Run with:
    /// `cargo test -p aegis-proxy --release route_resolve_microbench
    /// -- --nocapture --ignored`. Gated `#[ignore]` so the regular
    /// test suite stays fast.
    #[test]
    #[ignore]
    fn route_resolve_microbench() {
        use std::time::Instant;

        let yaml = r#"
listeners:
  data:    [{ bind: "127.0.0.1:8080" }]
  admin:   { bind: "127.0.0.1:9090" }
routes:
  - { id: api-v1-search, host: "api.example.com",  path: "/v1/search",  methods: ["POST"], upstream: api-pool }
  - { id: api-v1-users,  host: "api.example.com",  path: "/v1/users",                      upstream: api-pool }
  - { id: api-v2-search, host: "api.example.com",  path: "/v2/search",  methods: ["POST"], upstream: api-pool }
  - { id: api-v2-users,  host: "api.example.com",  path: "/v2/users",                      upstream: api-pool }
  - { id: api-v2-orders, host: "api.example.com",  path: "/v2/orders",  methods: ["GET", "POST"], upstream: api-pool }
  - { id: cdn-images,    host: "*.cdn.example.com", path: "/images",                       upstream: cdn-pool }
  - { id: cdn-static,    host: "*.cdn.example.com", path: "/static",                       upstream: cdn-pool }
  - { id: web-default,                              path: "/web",                          upstream: web-pool }
  - { id: catch-all,                                path: "/",                             upstream: stub-pool }
upstreams:
  api-pool:  { members: [{ addr: "127.0.0.1:3000" }] }
  cdn-pool:  { members: [{ addr: "127.0.0.1:3001" }] }
  web-pool:  { members: [{ addr: "127.0.0.1:3002" }] }
  stub-pool: { members: [{ addr: "127.0.0.1:9999" }] }
state: { backend: in_memory }
"#;
        let cfg = aegis_core::load_config_str(yaml).unwrap();
        let table = RouteTable::build(&cfg).unwrap();

        let workload: Vec<(&str, &str, http::Method)> = vec![
            ("api.example.com",     "/v2/search",       http::Method::POST),
            ("api.example.com",     "/v2/users",        http::Method::GET),
            ("api.example.com",     "/v2/orders/123",   http::Method::GET),
            ("api.example.com",     "/v1/search",       http::Method::POST),
            // Method fallthrough — `/v2/orders` only takes GET/POST,
            // so PUT walks back to the catch-all. Exercises the new
            // `find_all_prefixes` code path.
            ("api.example.com",     "/v2/orders/123",   http::Method::PUT),
            ("img.cdn.example.com", "/images/logo.png", http::Method::GET),
            ("img.cdn.example.com", "/static/main.css", http::Method::GET),
            ("anything.com",        "/web/page",        http::Method::GET),
            ("anything.com",        "/random",          http::Method::GET),
            ("any",                 "/",                http::Method::GET),
        ];

        // Warmup
        for _ in 0..10_000 {
            for (h, p, m) in &workload {
                let _ = std::hint::black_box(table.resolve(h, p, m));
            }
        }

        let iterations = 100_000;
        let start = Instant::now();
        for _ in 0..iterations {
            for (h, p, m) in &workload {
                let r = table.resolve(h, p, m);
                std::hint::black_box(r);
            }
        }
        let elapsed = start.elapsed();
        let total = iterations * workload.len();
        let ns_per = elapsed.as_nanos() as u64 / total as u64;
        let per_sec = total as f64 / elapsed.as_secs_f64();

        println!();
        println!("=== route resolve microbench (release-mode) ===");
        println!("routes in table:     {}", cfg.routes.len());
        println!("workload mix:        {} request shapes", workload.len());
        println!("total resolves:      {}", total);
        println!("elapsed:             {:?}", elapsed);
        println!("ns per resolve:      {} ns", ns_per);
        println!("resolves per second: {:.0}", per_sec);
        println!();

        // Sanity gate — even on a bad day, resolve must stay sub-µs.
        // Pre-PR1 baseline was ~150-300 ns; PR1 adds a small Vec
        // allocation per resolve via find_all_prefixes.
        assert!(
            ns_per < 2_000,
            "route resolve regressed past 2µs/op: {ns_per} ns",
        );
    }
}
