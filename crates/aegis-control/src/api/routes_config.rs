//! `/api/routes/{id}` — audit-mutated CRUD for the routing trie.
//!
//! This module owns the *write* side. The read view stays in
//! [`crate::api::routes`] (CI-T5). Splitting the shapes mirrors
//! the [`upstreams`](crate::api::upstreams) /
//! [`upstreams_config`](crate::api::upstreams_config) split:
//! one module emits the live summary the dashboard renders,
//! the other carries validators + the writer trait the
//! audit-mutated PUT/DELETE handlers in `aegis-proxy` consume.
//!
//! What lives here:
//! - [`RouteConfigPatch`] — Serialize+Deserialize wire shape
//!   for a single route (the in-tree [`RouteConfig`] is
//!   `Deserialize`-only — used for boot-time YAML parsing).
//! - [`validate_route`] — pre-flight checks shared between the
//!   read response (so the UI can show the same error before
//!   round-tripping) and the writer.
//! - [`is_only_catchall`] — guard for the DELETE handler so
//!   operators can't brick traffic by removing the last route
//!   that matches `/`.
//! - [`RouteWriter`] — typed-erased writer trait that lets
//!   `aegis-proxy::route::RouteTable` plug into
//!   `services.route_writer` without `aegis-control` depending
//!   on the proxy.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use aegis_core::config::{MatchType, RouteConfig, WafConfig};
use aegis_core::Tier;

// ---------------------------------------------------------------------------
// Wire shape — Serialize+Deserialize patch for a single route
// ---------------------------------------------------------------------------

/// JSON body for `PUT /api/routes/{id}`.
///
/// Mirrors the *user-editable* subset of [`RouteConfig`]. Fields
/// the operator can't sensibly set from the dashboard
/// (`tcp_destination_allowlist`, `max_concurrent_tunnels_per_ip`,
/// `failure_mode`, `quota`) are accepted but optional — when
/// omitted the patch carries the existing route's values forward
/// (handler responsibility, not the patch's).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteConfigPatch {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub path: String,
    #[serde(default = "default_match_type_str")]
    pub match_type: String,
    /// 2026-05-12 — opt-in path-stripping for the matched route
    /// prefix. Defaults to `true` (mount-point semantics) so
    /// route `/news` + request `/news/x` → upstream `/x`. Set to
    /// `false` for path-preserving forwarding. See
    /// `aegis_core::config::RouteConfig.strip_prefix` for the full
    /// gating rules.
    #[serde(default = "default_strip_prefix_patch")]
    pub strip_prefix: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    pub upstream: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_override: Option<String>,
    /// PR2 — explicit "this route is the default fallback for its
    /// host scope". Defaults to false; auto-migration on boot
    /// promotes legacy `path: "/"` no-host routes when no explicit
    /// default exists.
    #[serde(default)]
    pub default: bool,
    /// PR2 — `false` removes this route from trie registration so
    /// the operator can pull it without deleting. Defaults to true.
    #[serde(default = "default_route_enabled_patch")]
    pub enabled: bool,
    /// WS-MSG5 — per-route WebSocket message inspection. `None` (the
    /// common case) keeps the zero-copy bridge; round-trips through the
    /// config plane so a dashboard toggle survives reloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_inspect: Option<aegis_core::config::WsInspectConfig>,
    /// 2026-06-19 — per-route enforcement mode: `"enforce"` (default)
    /// or `"log_only"` (monitor: forward to upstream, downgrade WAF
    /// detector/risk blocks to log-only for this route). Round-trips
    /// through the config plane so a dashboard toggle survives reloads.
    #[serde(default = "default_route_mode_str")]
    pub mode: String,
}

fn default_route_enabled_patch() -> bool {
    true
}

fn default_route_mode_str() -> String {
    "enforce".to_string()
}

fn default_strip_prefix_patch() -> bool {
    true
}

fn default_match_type_str() -> String {
    "prefix".to_string()
}

impl RouteConfigPatch {
    /// Render an existing [`RouteConfig`] into a patch — used by
    /// the audit "before" view so PUTs with partial payloads can
    /// be merged against the live state.
    pub fn from_route(r: &RouteConfig) -> Self {
        Self {
            id: r.id.clone(),
            host: r.host.clone(),
            path: r.path.clone(),
            match_type: match_type_str(&r.match_type).to_string(),
            strip_prefix: r.strip_prefix,
            methods: r.methods.clone(),
            upstream: r.upstream.clone(),
            tier_override: r.tier_override.as_ref().map(tier_str).map(String::from),
            default: r.default,
            enabled: r.enabled,
            ws_inspect: r.ws_inspect.clone(),
            mode: route_mode_str(r.mode).to_string(),
        }
    }

    /// Materialise the patch into a fresh [`RouteConfig`].
    /// Validation must run before this — the conversion does not
    /// reject bad values, it just maps strings to enums.
    pub fn into_route(self) -> Result<RouteConfig, RouteValidationError> {
        let match_type = parse_match_type(&self.match_type)
            .ok_or_else(|| RouteValidationError::BadMatchType(self.match_type.clone()))?;
        let tier_override = self
            .tier_override
            .as_deref()
            .map(parse_tier)
            .transpose()
            .map_err(RouteValidationError::BadTier)?;
        let mode = parse_route_mode(&self.mode)
            .ok_or_else(|| RouteValidationError::BadMode(self.mode.clone()))?;
        Ok(RouteConfig {
            id: self.id,
            host: self.host,
            path: self.path,
            match_type,
            strip_prefix: self.strip_prefix,
            methods: self.methods,
            upstream: self.upstream,
            tier_override,
            failure_mode: None,
            quota: None,
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            default: self.default,
            enabled: self.enabled,
            // WS-MSG5 — carry the dashboard/API `ws_inspect` block onto
            // the live RouteConfig so it threads to the bridge.
            ws_inspect: self.ws_inspect,
            mode,
        })
    }
}

fn match_type_str(m: &MatchType) -> &'static str {
    match m {
        MatchType::Exact => "exact",
        MatchType::Prefix => "prefix",
        MatchType::Regex => "regex",
        MatchType::Glob => "glob",
    }
}

fn parse_match_type(s: &str) -> Option<MatchType> {
    match s {
        "exact" => Some(MatchType::Exact),
        "prefix" => Some(MatchType::Prefix),
        "regex" => Some(MatchType::Regex),
        "glob" => Some(MatchType::Glob),
        _ => None,
    }
}

fn tier_str(t: &Tier) -> &'static str {
    match t {
        Tier::Critical => "critical",
        Tier::High => "high",
        Tier::Medium => "medium",
        Tier::Low => "low",
    }
}

fn route_mode_str(m: aegis_core::config::RouteMode) -> &'static str {
    match m {
        aegis_core::config::RouteMode::Enforce => "enforce",
        aegis_core::config::RouteMode::LogOnly => "log_only",
    }
}

fn parse_route_mode(s: &str) -> Option<aegis_core::config::RouteMode> {
    match s {
        "enforce" => Some(aegis_core::config::RouteMode::Enforce),
        // `monitor` accepted as a friendlier alias for the dashboard.
        "log_only" | "monitor" => Some(aegis_core::config::RouteMode::LogOnly),
        _ => None,
    }
}

fn parse_tier(s: &str) -> Result<Tier, String> {
    match s {
        "critical" => Ok(Tier::Critical),
        "high" => Ok(Tier::High),
        "medium" => Ok(Tier::Medium),
        // `catch_all` / `catchall` kept as accepted aliases so old
        // YAML configs and old API clients keep parsing.
        "low" | "catch_all" | "catchall" => Ok(Tier::Low),
        other => Err(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Failure modes for [`validate_route`]. Each variant carries
/// enough context for the dashboard to surface a precise error
/// without a second round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteValidationError {
    /// `id` was empty or only whitespace.
    EmptyId,
    /// `path` was empty.
    EmptyPath,
    /// `match_type` was not one of `exact | prefix | regex`.
    BadMatchType(String),
    /// `tier_override` was not one of the five tier names.
    BadTier(String),
    /// `mode` was not `enforce | log_only | monitor`.
    BadMode(String),
    /// `upstream` referenced a pool that doesn't exist.
    UnknownUpstream {
        upstream: String,
        known: Vec<String>,
    },
}

impl RouteValidationError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::EmptyId => "empty_id",
            Self::EmptyPath => "empty_path",
            Self::BadMatchType(_) => "bad_match_type",
            Self::BadTier(_) => "bad_tier",
            Self::BadMode(_) => "bad_mode",
            Self::UnknownUpstream { .. } => "unknown_upstream",
        }
    }
}

impl std::fmt::Display for RouteValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => write!(f, "route id must be non-empty"),
            Self::EmptyPath => write!(f, "route path must be non-empty"),
            Self::BadMatchType(s) => {
                write!(f, "match_type {s:?} is not one of exact | prefix | regex")
            }
            Self::BadTier(s) => {
                write!(f, "tier_override {s:?} is not a valid tier name")
            }
            Self::BadMode(s) => {
                write!(f, "mode {s:?} is not one of enforce | log_only | monitor")
            }
            Self::UnknownUpstream { upstream, known } => write!(
                f,
                "upstream {upstream:?} not found; known pools: {known:?}",
            ),
        }
    }
}

impl std::error::Error for RouteValidationError {}

/// Validate a route patch against the live config. The handler
/// runs this **before** building the candidate WafConfig.
pub fn validate_route(
    patch: &RouteConfigPatch,
    cfg: &WafConfig,
) -> Result<(), RouteValidationError> {
    if patch.id.trim().is_empty() {
        return Err(RouteValidationError::EmptyId);
    }
    if patch.path.is_empty() {
        return Err(RouteValidationError::EmptyPath);
    }
    if parse_match_type(&patch.match_type).is_none() {
        return Err(RouteValidationError::BadMatchType(patch.match_type.clone()));
    }
    if let Some(t) = &patch.tier_override {
        parse_tier(t).map_err(RouteValidationError::BadTier)?;
    }
    if !cfg.upstreams.contains_key(&patch.upstream) {
        return Err(RouteValidationError::UnknownUpstream {
            upstream: patch.upstream.clone(),
            known: cfg.upstreams.keys().cloned().collect(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DELETE-side guards
// ---------------------------------------------------------------------------

/// True when `route_id` is the only route in `cfg` whose `path` is
/// `"/"` and `host` is unset — i.e. the last catch-all. Deleting
/// that route would leave the data plane with nothing to match
/// against most requests; `RouteTable::build` rejects the
/// configuration outright. The DELETE handler returns 409 in that
/// case so the operator gets a clear message instead of an opaque
/// build error.
pub fn is_only_catchall(cfg: &WafConfig, route_id: &str) -> bool {
    let catchalls: Vec<&str> = cfg
        .routes
        .iter()
        .filter(|r| r.host.is_none() && r.path == "/")
        .map(|r| r.id.as_str())
        .collect();
    catchalls.len() == 1 && catchalls[0] == route_id
}

// ---------------------------------------------------------------------------
// Writer trait — bridges control plane → proxy without circular deps
// ---------------------------------------------------------------------------

/// RT-T1 — typed-erased writer for the live route table.
///
/// Same indirection as [`UpstreamWriter`](crate::api::upstreams_config::UpstreamWriter):
/// `aegis-control` can't depend on `aegis-proxy`, so the proxy's
/// `RouteTable` implements this trait and is stashed in
/// `DashboardServices::route_writer` at boot. The audit-mutated
/// PUT/DELETE handlers in the proxy then call
/// `services.route_writer.as_ref()` without naming any proxy
/// types.
pub trait RouteWriter: Send + Sync {
    /// Atomically replace the live route table from a candidate
    /// `WafConfig`. The handler clones `cfg`, splices in the
    /// upsert / delete, then calls this. Validates first; on
    /// error the live table is untouched.
    fn apply(&self, new_cfg: &WafConfig) -> Result<(), RouteApplyError>;

    /// Return the route list currently live in the proxy.
    /// Used by audit-mutated handlers to start from the live
    /// state instead of the boot-time `cfg.routes` snapshot —
    /// without this, two consecutive runtime upserts would lose
    /// the first one because each handler builds `next_routes`
    /// from the (stale) boot cfg.
    ///
    /// Default returns an empty list — implementations should
    /// override with the live shape.
    fn current_routes(&self) -> Vec<RouteConfig> {
        Vec::new()
    }

    /// PR3 — drives the "Test route" tool. Asks the live router
    /// "which route would this synthetic request hit?" without
    /// sending real traffic. Returns the matched route id and the
    /// effective priority string, or `None` if the request would
    /// fall through to deny-by-default (404). Default returns
    /// `None` for test bundles that don't wire a router.
    fn resolve_for_test(
        &self,
        _host: &str,
        _path: &str,
        _method: &str,
    ) -> Option<RouteResolveResult> {
        None
    }
}

/// PR3 — flat result of a Test-route call. Mirrors the JSON shape
/// the dashboard renders so the route_id + priority + tier round-trip
/// is unambiguous.
#[derive(Debug, Clone)]
pub struct RouteResolveResult {
    pub route_id: String,
    pub host: Option<String>,
    pub path: String,
    pub methods: Vec<String>,
    pub tier: String,
    pub upstream: String,
    pub priority: String,
    pub default: bool,
    pub enabled: bool,
}

/// Failure modes returned by [`RouteWriter::apply`]. Mirrors
/// `aegis_core::WafError::Config` semantics (the underlying
/// `RouteTable::build` failure) without forcing this crate to
/// depend on `aegis_core::WafError`'s enum shape.
#[derive(Debug, Clone)]
pub enum RouteApplyError {
    /// Compilation of the candidate route table failed (no
    /// catch-all, conflicting hosts, regex compile failure, …).
    Build(String),
}

impl std::fmt::Display for RouteApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Build(msg) => write!(f, "route table build failed: {msg}"),
        }
    }
}

impl std::error::Error for RouteApplyError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_yaml(yaml: &str) -> WafConfig {
        serde_yaml::from_str(yaml).expect("test yaml must parse")
    }

    fn base_cfg() -> WafConfig {
        cfg_yaml(
            r#"
listeners:
  data:
    - bind: "0.0.0.0:8080"
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: api-pool
  - id: api
    path: "/api/"
    match_type: prefix
    upstream: api-pool
upstreams:
  api-pool:
    members:
      - addr: "127.0.0.1:3001"
state:
  backend: in_memory
"#,
        )
    }

    fn good_patch() -> RouteConfigPatch {
        RouteConfigPatch {
            id: "vnexpress".into(),
            host: None,
            path: "/news/".into(),
            match_type: "prefix".into(),
            strip_prefix: true,
            methods: None,
            upstream: "api-pool".into(),
            tier_override: None,
            default: false,
            enabled: true,
            ws_inspect: None,
            mode: "enforce".into(),
        }
    }

    #[test]
    fn valid_patch_passes() {
        let cfg = base_cfg();
        assert!(validate_route(&good_patch(), &cfg).is_ok());
    }

    #[test]
    fn empty_id_rejected() {
        let cfg = base_cfg();
        let mut p = good_patch();
        p.id = "   ".into();
        assert_eq!(
            validate_route(&p, &cfg),
            Err(RouteValidationError::EmptyId),
        );
    }

    #[test]
    fn empty_path_rejected() {
        let cfg = base_cfg();
        let mut p = good_patch();
        p.path = "".into();
        assert_eq!(
            validate_route(&p, &cfg),
            Err(RouteValidationError::EmptyPath),
        );
    }

    #[test]
    fn bad_match_type_rejected() {
        let cfg = base_cfg();
        let mut p = good_patch();
        p.match_type = "fuzzy".into();
        match validate_route(&p, &cfg) {
            Err(RouteValidationError::BadMatchType(s)) => assert_eq!(s, "fuzzy"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_upstream_rejected_with_known_list() {
        let cfg = base_cfg();
        let mut p = good_patch();
        p.upstream = "ghost-pool".into();
        match validate_route(&p, &cfg) {
            Err(RouteValidationError::UnknownUpstream { upstream, known }) => {
                assert_eq!(upstream, "ghost-pool");
                assert!(known.contains(&"api-pool".to_string()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }


    #[test]
    fn last_catchall_flagged() {
        let cfg = base_cfg();
        assert!(is_only_catchall(&cfg, "catch-all"));
        assert!(!is_only_catchall(&cfg, "api"));
    }

    #[test]
    fn second_catchall_means_neither_is_last() {
        let cfg = cfg_yaml(
            r#"
listeners:
  data:
    - bind: "0.0.0.0:8080"
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: catch-a
    path: "/"
    match_type: prefix
    upstream: api-pool
  - id: catch-b
    path: "/"
    match_type: prefix
    upstream: api-pool
upstreams:
  api-pool:
    members:
      - addr: "127.0.0.1:3001"
state:
  backend: in_memory
"#,
        );
        assert!(!is_only_catchall(&cfg, "catch-a"));
        assert!(!is_only_catchall(&cfg, "catch-b"));
    }

    #[test]
    fn round_trip_from_route_into_route_preserves_fields() {
        let cfg = cfg_yaml(
            r#"
listeners:
  data:
    - bind: "0.0.0.0:8080"
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: login
    host: "api.example.com"
    path: "/login"
    match_type: exact
    methods: [POST]
    upstream: auth-pool
    tier_override: critical
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: auth-pool
upstreams:
  auth-pool:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#,
        );
        let original = cfg.routes.iter().find(|r| r.id == "login").unwrap();
        let patch = RouteConfigPatch::from_route(original);
        assert_eq!(patch.id, "login");
        assert_eq!(patch.host.as_deref(), Some("api.example.com"));
        assert_eq!(patch.match_type, "exact");
        assert_eq!(patch.tier_override.as_deref(), Some("critical"));
        let rebuilt = patch.into_route().expect("valid patch round-trips");
        assert_eq!(rebuilt.id, "login");
        assert_eq!(rebuilt.host.as_deref(), Some("api.example.com"));
        assert!(matches!(rebuilt.match_type, MatchType::Exact));
        assert_eq!(rebuilt.methods, Some(vec!["POST".to_string()]));
        // No `mode:` in the YAML ⇒ defaults to enforce on the round trip.
        assert_eq!(rebuilt.mode, aegis_core::config::RouteMode::Enforce);
    }

    #[test]
    fn mode_log_only_round_trips_through_patch() {
        // 2026-06-19 — a monitor-mode route survives from_route →
        // into_route so a dashboard toggle persists across reloads.
        let mut patch = good_patch();
        patch.mode = "log_only".into();
        let rebuilt = patch.into_route().expect("log_only patch is valid");
        assert_eq!(rebuilt.mode, aegis_core::config::RouteMode::LogOnly);

        // …and from_route renders it back to the wire string.
        let back = RouteConfigPatch::from_route(&rebuilt);
        assert_eq!(back.mode, "log_only");
    }

    #[test]
    fn mode_monitor_alias_accepted() {
        let mut patch = good_patch();
        patch.mode = "monitor".into();
        let rebuilt = patch.into_route().expect("monitor alias is valid");
        assert_eq!(rebuilt.mode, aegis_core::config::RouteMode::LogOnly);
    }

    #[test]
    fn bad_mode_rejected() {
        let mut patch = good_patch();
        patch.mode = "observe".into();
        let err = patch.into_route().unwrap_err();
        assert_eq!(err.reason_code(), "bad_mode");
    }

    #[test]
    fn omitted_mode_defaults_to_enforce_on_deserialize() {
        // The wire shape carries no `mode` field for legacy clients.
        let json = r#"{"id":"r","path":"/","upstream":"pool"}"#;
        let patch: RouteConfigPatch = serde_json::from_str(json).unwrap();
        assert_eq!(patch.mode, "enforce");
    }
}
