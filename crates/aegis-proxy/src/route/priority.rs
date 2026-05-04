//! Route precedence — derived from config content alone.
//!
//! Every route gets a [`RoutePriority`] tuple computed at build time.
//! Routes are sorted by priority (descending) before they go into the
//! trie; resolution falls out of "first match in the priority-sorted
//! group". This makes route resolution deterministic from config alone:
//! editing or adding any route never re-orders unrelated routes.
//!
//! Component scoring (lexicographic descending):
//!
//! | Component       | Variant                                                     | Score |
//! |-----------------|-------------------------------------------------------------|-------|
//! | host            | `Exact`                                                     | 3     |
//! |                 | `Regex`                                                     | 2     |
//! |                 | `Wildcard`                                                  | 1     |
//! |                 | `Default` (`*`)                                             | 0     |
//! | path_kind       | `Exact`                                                     | 4     |
//! |                 | `Regex`                                                     | 3     |
//! |                 | `Glob`                                                      | 2     |
//! |                 | `Prefix` (path != `/`)                                      | 1     |
//! |                 | `Prefix` AND path == `/`                                    | 0     |
//! | path_segments   | path.split('/').filter(non_empty).count()                   | u16   |
//! | method          | explicit list                                               | 1     |
//! |                 | `None` (any)                                                | 0     |
//! | declared        | YAML `priority:` field (PR2 will plumb this through schema) | i32   |
//! | yaml_position   | route's index in `cfg.routes` (earlier = wins ties)         | u32   |
//!
//! Higher tuple comparison wins. `yaml_position` is stored inverted at
//! sort time (smaller index = higher score) so the lex compare works
//! cleanly with `cmp + reverse`.

use aegis_core::config::{MatchType, RouteConfig};

use super::host::HostMatcher;

/// Effective precedence of a route. Sort descending — higher matches first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoutePriority {
    /// Host specificity: 3 (Exact) > 2 (Regex) > 1 (Wildcard) > 0 (Default).
    pub host: u8,
    /// Path-kind specificity: 4 (Exact) > 3 (Regex) > 2 (Glob)
    /// > 1 (Prefix on a real path) > 0 (Prefix on the catch-all `/`).
    pub path_kind: u8,
    /// Number of non-empty path segments — longer is more specific
    /// among same-kind routes. `/` has 0; `/api/v2/users` has 3.
    pub path_segments: u16,
    /// 1 if the route declared an explicit method filter, 0 otherwise.
    pub method: u8,
    /// Optional explicit override (PR2 will surface this in the schema).
    /// Default 0. Higher beats lower; ties cascade to YAML position.
    pub declared: i32,
    /// Inverted YAML position. Earlier-declared routes get a higher
    /// score so they win ties. Computed at sort time as `u32::MAX - idx`.
    pub yaml_position_inverted: u32,
}

impl RoutePriority {
    /// Compute a route's priority from its config + host matcher + position.
    pub fn compute(rc: &RouteConfig, host: &HostMatcher, yaml_index: usize) -> Self {
        let host_score = match host {
            HostMatcher::Exact(_) => 3,
            HostMatcher::Regex(_) => 2,
            HostMatcher::Wildcard(_) => 1,
            HostMatcher::Default => 0,
        };

        let segments = path_segment_count(&rc.path);
        let path_kind = match rc.match_type {
            MatchType::Exact => 4,
            MatchType::Regex => 3,
            MatchType::Glob => 2,
            MatchType::Prefix => {
                if segments == 0 {
                    0 // the literal `/` catch-all
                } else {
                    1
                }
            }
        };

        let method = if rc.methods.is_some() { 1 } else { 0 };

        let yaml_position_inverted = u32::MAX.saturating_sub(yaml_index as u32);

        RoutePriority {
            host: host_score,
            path_kind,
            path_segments: segments as u16,
            method,
            declared: 0, // PR2 will read `rc.priority` here
            yaml_position_inverted,
        }
    }

    /// Compact human-readable form for the `--print-route-priority`
    /// CLI: `<host>.<path-kind>.<segs>.<method>.<declared>.<yaml-pos>`.
    /// `yaml_position_inverted` is rendered as the original position
    /// (smaller = earlier) so operators read it left-to-right.
    pub fn fmt_compact(&self) -> String {
        let yaml_pos = u32::MAX.saturating_sub(self.yaml_position_inverted);
        format!(
            "{}.{}.{}.{}.{}.{}",
            self.host, self.path_kind, self.path_segments, self.method, self.declared, yaml_pos,
        )
    }
}

fn path_segment_count(path: &str) -> usize {
    path.split('/').filter(|s| !s.is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rc(path: &str, match_type: MatchType, methods: Option<Vec<&str>>) -> RouteConfig {
        let yaml = format!(
            r#"
id: test
path: "{path}"
match_type: {mt}
{methods_yaml}
upstream: pool
"#,
            mt = match match_type {
                MatchType::Exact => "exact",
                MatchType::Regex => "regex",
                MatchType::Prefix => "prefix",
                MatchType::Glob => "glob",
            },
            methods_yaml = methods
                .map(|ms| format!("methods: [{}]", ms.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ")))
                .unwrap_or_default(),
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn exact_host_outranks_wildcard() {
        let exact = HostMatcher::new("api.example.com").unwrap();
        let wildcard = HostMatcher::new("*.example.com").unwrap();
        let r_exact = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &exact, 0);
        let r_wild = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &wildcard, 1);
        assert!(r_exact > r_wild);
    }

    #[test]
    fn longer_prefix_beats_shorter() {
        let host = HostMatcher::new("*").unwrap();
        let long = RoutePriority::compute(&rc("/api/v2/users", MatchType::Prefix, None), &host, 0);
        let short = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &host, 1);
        assert!(long > short);
    }

    #[test]
    fn explicit_method_beats_any() {
        let host = HostMatcher::new("*").unwrap();
        let with = RoutePriority::compute(
            &rc("/api", MatchType::Prefix, Some(vec!["GET"])),
            &host,
            0,
        );
        let without = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &host, 1);
        assert!(with > without);
    }

    #[test]
    fn yaml_position_breaks_remaining_ties() {
        let host = HostMatcher::new("*").unwrap();
        let early = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &host, 0);
        let late = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &host, 5);
        assert!(early > late, "earlier YAML index should win identical-everything ties");
    }

    #[test]
    fn catch_all_path_is_lowest_path_kind() {
        let host = HostMatcher::new("*").unwrap();
        let catch_all = RoutePriority::compute(&rc("/", MatchType::Prefix, None), &host, 0);
        let any_other = RoutePriority::compute(&rc("/anything", MatchType::Prefix, None), &host, 1);
        assert!(any_other > catch_all, "any concrete prefix must outrank `/`");
    }

    #[test]
    fn exact_path_kind_outranks_prefix() {
        let host = HostMatcher::new("*").unwrap();
        let exact = RoutePriority::compute(&rc("/api", MatchType::Exact, None), &host, 0);
        let prefix = RoutePriority::compute(&rc("/api", MatchType::Prefix, None), &host, 1);
        assert!(exact > prefix);
    }

    #[test]
    fn regex_path_kind_outranks_glob() {
        let host = HostMatcher::new("*").unwrap();
        let re = RoutePriority::compute(&rc("/api/[0-9]+", MatchType::Regex, None), &host, 0);
        let glob = RoutePriority::compute(&rc("/api/*", MatchType::Glob, None), &host, 1);
        assert!(re > glob);
    }

    #[test]
    fn fmt_compact_renders_yaml_pos_uninverted() {
        let host = HostMatcher::new("api.example.com").unwrap();
        let rc = rc("/api/v2", MatchType::Prefix, Some(vec!["POST"]));
        let p = RoutePriority::compute(&rc, &host, 7);
        // host=3 path_kind=1 segs=2 method=1 declared=0 yaml_pos=7
        assert_eq!(p.fmt_compact(), "3.1.2.1.0.7");
    }

    #[test]
    fn full_ordering_lex_descending() {
        let exact_host = HostMatcher::new("api.example.com").unwrap();
        let default_host = HostMatcher::new("*").unwrap();

        // Plausible real-world set, expected sort order top-down:
        let routes = vec![
            ("api-v2-search", &exact_host, "/v2/search", MatchType::Prefix, Some(vec!["POST"]), 0),
            ("api-v2-prefix", &exact_host, "/v2", MatchType::Prefix, None, 1),
            ("local",         &default_host, "/local", MatchType::Prefix, None, 2),
            ("catch-all",     &default_host, "/", MatchType::Prefix, None, 3),
        ];

        let mut priorities: Vec<_> = routes
            .iter()
            .map(|(_, host, path, mt, methods, idx)| {
                RoutePriority::compute(&rc(path, mt.clone(), methods.clone()), host, *idx)
            })
            .collect();

        let original = priorities.clone();
        priorities.sort_by(|a, b| b.cmp(a)); // desc

        assert_eq!(priorities, original, "input was already in descending priority order");
    }
}
