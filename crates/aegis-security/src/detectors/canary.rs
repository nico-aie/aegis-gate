//! 2026-05-18 F-CRITICAL-012 (security audit, Phase F) — canary
//! path detector. Operators configure `risk.canary_paths` in YAML
//! with honeypot URLs that no legitimate caller should ever hit
//! (`/wp-admin`, `/.env`, `/phpmyadmin/*`, etc.). Any request whose
//! path matches one of those entries gets a high-severity signal
//! (score 90) — single-hit-to-block at the §3 §5 risk thresholds.
//!
//! ## Why this lives outside `DetectorClass`
//!
//! `DetectorClass` is a closed-set bitfield with stable bit
//! positions, paired 1-to-1 with `DetectorsConfig` fields. Canary
//! is data-driven (operator-supplied paths), not pattern-class.
//! Treating it as a regular [`Detector`] with `id = "canary"` keeps
//! the mask machinery unchanged — `DetectorClass::from_id("canary")`
//! returns `None` and the mask's `is_enabled_id` runs the detector
//! unconditionally (the "future detector not yet classed" path
//! that mask.rs already documents).
//!
//! ## Match semantics
//!
//! Two entry shapes:
//!
//! - Exact: `/wp-admin` matches only the request path `/wp-admin`.
//! - Suffix glob: `/admin/*` matches `/admin/x`, `/admin/x/y`, …
//!   (anything under that prefix, regardless of depth).
//!
//! No regex — operators configure paths, not patterns. The matcher
//! is a single pass over the configured list; with the audit's
//! example list of ~5-10 honeypots this is trivially fast.

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

/// Honeypot path detector. Constructed from
/// `aegis_core::config::RiskConfig.canary_paths`.
pub struct CanaryDetector {
    paths: Vec<CanaryPattern>,
}

/// One parsed canary entry. `Exact("/wp-admin")` matches that exact
/// path; `Prefix("/admin/")` matches any path that starts with the
/// stored value (the trailing `/` is stripped off the operator's
/// `/admin/*` shape so we can use `starts_with` directly).
enum CanaryPattern {
    Exact(String),
    Prefix(String),
}

impl CanaryDetector {
    /// Build from operator-configured path list. Empty list = the
    /// detector still runs but never fires — saves a constructor
    /// branch upstream.
    pub fn new(paths: &[String]) -> Self {
        let paths = paths
            .iter()
            .filter_map(Self::compile)
            .collect();
        Self { paths }
    }

    fn compile(raw: &String) -> Option<CanaryPattern> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some(prefix) = trimmed.strip_suffix("/*") {
            // `/admin/*` → Prefix("/admin/"). Operators writing
            // bare `/admin*` (no slash) get the literal prefix as
            // typed — they probably meant `/admin/*` but we don't
            // second-guess.
            return Some(CanaryPattern::Prefix(format!("{prefix}/")));
        }
        if let Some(prefix) = trimmed.strip_suffix('*') {
            return Some(CanaryPattern::Prefix(prefix.to_string()));
        }
        Some(CanaryPattern::Exact(trimmed.to_string()))
    }

    /// Number of compiled patterns. Used by the dashboard's
    /// `active_canary_count` surface.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Test whether `path` matches any configured canary. Public
    /// so the dashboard simulator can preview "does this URL hit
    /// a canary?" without going through the full detector chain.
    pub fn matches(&self, path: &str) -> Option<&str> {
        for entry in &self.paths {
            match entry {
                CanaryPattern::Exact(p) if p == path => return Some(p.as_str()),
                CanaryPattern::Prefix(p) if path.starts_with(p.as_str()) => {
                    return Some(p.as_str())
                }
                _ => {}
            }
        }
        None
    }
}

impl Detector for CanaryDetector {
    fn id(&self) -> &'static str {
        "canary"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let path = req.uri.path();
        if let Some(matched) = self.matches(path) {
            return vec![Signal {
                // 90 — high-confidence malicious. Honeypot paths
                // have no legitimate caller; a single hit should
                // push the IP over the v2.3 default block threshold
                // (70) on its own.
                score: 90,
                tag: "canary".into(),
                field: format!("path:{matched}"),
            }];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::{BodyPeek, RequestView};

    fn req(path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let uri: http::Uri = path.parse().unwrap();
        (http::Method::GET, uri, http::HeaderMap::new(), BodyPeek::empty())
    }

    fn view<'a>(
        method: &'a http::Method,
        uri: &'a http::Uri,
        headers: &'a http::HeaderMap,
        body: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method,
            uri,
            version: http::Version::HTTP_11,
            headers,
            peer: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            body,
        }
    }

    #[test]
    fn exact_path_matches() {
        let d = CanaryDetector::new(&vec!["/wp-admin".into(), "/.env".into()]);
        let (m, u, h, b) = req("/wp-admin");
        let signals = d.inspect(&view(&m, &u, &h, &b));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].tag, "canary");
        assert_eq!(signals[0].score, 90);
        assert_eq!(signals[0].field, "path:/wp-admin");
    }

    #[test]
    fn exact_path_does_not_match_prefix() {
        // `/wp-admin` (exact) must NOT match `/wp-admin/foo`.
        let d = CanaryDetector::new(&vec!["/wp-admin".into()]);
        let (m, u, h, b) = req("/wp-admin/foo");
        assert!(d.inspect(&view(&m, &u, &h, &b)).is_empty());
    }

    #[test]
    fn suffix_glob_matches_subpaths() {
        let d = CanaryDetector::new(&vec!["/phpmyadmin/*".into()]);
        let (m, u, h, b) = req("/phpmyadmin/index.php");
        let signals = d.inspect(&view(&m, &u, &h, &b));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].field, "path:/phpmyadmin/");

        let (m, u, h, b) = req("/phpmyadmin/db/foo/bar");
        assert_eq!(d.inspect(&view(&m, &u, &h, &b)).len(), 1);

        // Bare `/phpmyadmin` (no trailing slash) does NOT match a
        // `/phpmyadmin/*` glob — operators who want both add a
        // separate exact entry.
        let (m, u, h, b) = req("/phpmyadmin");
        assert!(d.inspect(&view(&m, &u, &h, &b)).is_empty());
    }

    #[test]
    fn legitimate_path_does_not_fire() {
        let d = CanaryDetector::new(&vec!["/wp-admin".into(), "/.env".into()]);
        for legit in ["/", "/api/users", "/static/main.css", "/health"] {
            let (m, u, h, b) = req(legit);
            assert!(
                d.inspect(&view(&m, &u, &h, &b)).is_empty(),
                "legit path {legit} should not fire",
            );
        }
    }

    #[test]
    fn empty_list_never_fires() {
        let d = CanaryDetector::new(&[]);
        assert!(d.is_empty());
        let (m, u, h, b) = req("/anywhere");
        assert!(d.inspect(&view(&m, &u, &h, &b)).is_empty());
    }

    #[test]
    fn empty_string_entries_are_ignored() {
        let d = CanaryDetector::new(&vec!["".into(), "   ".into(), "/wp-admin".into()]);
        assert_eq!(d.len(), 1);
        let (m, u, h, b) = req("/wp-admin");
        assert_eq!(d.inspect(&view(&m, &u, &h, &b)).len(), 1);
    }

    #[test]
    fn id_is_canary() {
        let d = CanaryDetector::new(&[]);
        assert_eq!(d.id(), "canary");
    }
}
