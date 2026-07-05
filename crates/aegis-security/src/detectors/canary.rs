//! 2026-05-18 F-CRITICAL-012 (security audit, Phase F) — canary
//! path detector. Operators configure `risk.canary_paths` in YAML
//! with honeypot URLs that no legitimate caller should ever hit
//! (`/wp-admin`, `/.env`, `/phpmyadmin/*`, etc.). Any request whose
//! path matches one of those entries gets a high-severity signal
//! (score 100) — single-hit-to-block at the §3 §5 risk thresholds.
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

use std::sync::Arc;

use arc_swap::ArcSwap;

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

/// One parsed canary entry. `Exact("/wp-admin")` matches that exact
/// path; `Prefix("/admin/")` matches any path that starts with the
/// stored value (the trailing `/` is stripped off the operator's
/// `/admin/*` shape so we can use `starts_with` directly).
enum CanaryPattern {
    Exact(String),
    Prefix(String),
}

/// Compiled canary set: the operator's raw strings (for read-back /
/// the GET API) plus the parsed match patterns.
#[derive(Default)]
struct Compiled {
    raw: Vec<String>,
    patterns: Vec<CanaryPattern>,
}

/// 2026-05-20 — shared, hot-swappable canary path set. Cloning shares
/// the same `ArcSwap`, so the data-plane detector and the
/// audit-mutated `PUT /api/risk/canary-paths` handler see each
/// other's updates with no chain rebuild and no restart. The
/// detector always runs (one `ArcSwap::load` + a tiny loop); an empty
/// set is effectively free.
#[derive(Clone, Default)]
pub struct CanaryPaths {
    inner: Arc<ArcSwap<Compiled>>,
}

impl CanaryPaths {
    /// Build from an operator-configured path list (boot path).
    pub fn new(raw: &[String]) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(Self::compile_all(raw))),
        }
    }

    /// Hot-swap the whole path list (audit-mutated PUT). Recompiles
    /// + atomically stores; the next request sees the new set.
    pub fn set(&self, raw: &[String]) {
        self.inner.store(Arc::new(Self::compile_all(raw)));
    }

    /// Current raw paths (for the GET API + audit "before" capture).
    pub fn raw(&self) -> Vec<String> {
        self.inner.load().raw.clone()
    }

    /// Number of compiled patterns — drives the dashboard count.
    pub fn len(&self) -> usize {
        self.inner.load().patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.load().patterns.is_empty()
    }

    /// `Some(pattern)` when `path` hits a canary. Public so the
    /// dashboard simulator can preview a hit without the full chain.
    pub fn matches(&self, path: &str) -> Option<String> {
        for entry in &self.inner.load().patterns {
            match entry {
                CanaryPattern::Exact(p) if p == path => return Some(p.clone()),
                CanaryPattern::Prefix(p) if path.starts_with(p.as_str()) => {
                    return Some(p.clone())
                }
                _ => {}
            }
        }
        None
    }

    fn compile_all(raw: &[String]) -> Compiled {
        let patterns = raw.iter().filter_map(|s| Self::compile(s)).collect();
        // Preserve only the non-empty, trimmed entries in `raw` so
        // the GET read-back matches what's actually compiled.
        let raw = raw
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Compiled { raw, patterns }
    }

    fn compile(raw: &str) -> Option<CanaryPattern> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some(prefix) = trimmed.strip_suffix("/*") {
            // `/admin/*` → Prefix("/admin/").
            return Some(CanaryPattern::Prefix(format!("{prefix}/")));
        }
        if let Some(prefix) = trimmed.strip_suffix('*') {
            return Some(CanaryPattern::Prefix(prefix.to_string()));
        }
        Some(CanaryPattern::Exact(trimmed.to_string()))
    }
}

/// Honeypot path detector. Wraps a shared [`CanaryPaths`] handle so
/// the path set is hot-swappable from the admin control plane.
pub struct CanaryDetector {
    paths: CanaryPaths,
}

impl CanaryDetector {
    /// Build from a path list (owns a fresh handle).
    pub fn new(paths: &[String]) -> Self {
        Self { paths: CanaryPaths::new(paths) }
    }

    /// Build from an existing shared handle (boot path stashes a
    /// clone in `ProxyContext` for the admin PUT to update).
    pub fn from_handle(paths: CanaryPaths) -> Self {
        Self { paths }
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn matches(&self, path: &str) -> Option<String> {
        self.paths.matches(path)
    }
}

impl Detector for CanaryDetector {
    fn id(&self) -> &'static str {
        "canary"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let path = req.uri.path();
        if let Some(matched) = self.paths.matches(path) {
            return vec![Signal {
                // 100 — maximum confidence. Honeypot paths are
                // operator-curated and have no legitimate caller, so
                // the false-positive rate is ~0. A single hit blocks
                // at every tier, including any custom threshold up to
                // the 100 cap.
                score: 100,
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
        assert_eq!(signals[0].score, 100);
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

    #[test]
    fn canary_score_is_max_confidence() {
        let d = CanaryDetector::new(&vec!["/.env".into()]);
        let (m, u, h, b) = req("/.env");
        let signals = d.inspect(&view(&m, &u, &h, &b));
        assert_eq!(signals[0].score, 100, "canary is operator-curated → max confidence");
    }

    #[test]
    fn set_hot_swaps_the_path_set() {
        let paths = CanaryPaths::new(&[]);
        assert!(paths.matches("/wp-admin").is_none());
        paths.set(&vec!["/wp-admin".into(), "/admin/*".into()]);
        assert_eq!(paths.matches("/wp-admin").as_deref(), Some("/wp-admin"));
        assert_eq!(paths.matches("/admin/users").as_deref(), Some("/admin/"));
        // A second set replaces (not merges) the prior set.
        paths.set(&vec!["/.env".into()]);
        assert!(paths.matches("/wp-admin").is_none());
        assert_eq!(paths.matches("/.env").as_deref(), Some("/.env"));
    }

    #[test]
    fn cloned_handle_shares_state_with_detector() {
        // The admin control plane holds a clone of the same handle
        // the data-plane detector wraps; a `set` on one is observed
        // by the other with no rebuild.
        let handle = CanaryPaths::new(&[]);
        let detector = CanaryDetector::from_handle(handle.clone());
        let (m, u, h, b) = req("/phpmyadmin/index.php");
        assert!(detector.inspect(&view(&m, &u, &h, &b)).is_empty());
        handle.set(&vec!["/phpmyadmin/*".into()]);
        assert_eq!(detector.inspect(&view(&m, &u, &h, &b)).len(), 1);
    }

    /// RC-1 (2026-07-05) — every curated default canary path fires
    /// as a single max-confidence signal. Score 100 ≥ every tier's
    /// block threshold, so one probe from a fresh IP blocks — the
    /// distributed-recon counter this list exists for.
    #[test]
    fn rc1_default_curated_paths_single_hit_max_confidence() {
        let defaults = aegis_core::config::RiskConfig::default().canary_paths;
        assert!(!defaults.is_empty(), "RC-1 ships a curated default list");
        let d = CanaryDetector::new(&defaults);
        for path in &defaults {
            let (m, u, h, b) = req(path);
            let signals = d.inspect(&view(&m, &u, &h, &b));
            assert_eq!(signals.len(), 1, "curated path {path} must fire");
            assert_eq!(signals[0].tag, "canary");
            assert_eq!(signals[0].score, 100, "curated path {path} must be max confidence");
        }
    }

    /// RC-1 (2026-07-05) — look-alike paths with legitimate callers
    /// must NOT fire. Canary is a hard single-hit block; a false
    /// entry here is an outage, so the negative space is load-bearing.
    #[test]
    fn rc1_default_curated_lookalikes_do_not_fire() {
        let d = CanaryDetector::new(&aegis_core::config::RiskConfig::default().canary_paths);
        for legit in [
            "/actuator/health",  // monitoring — the classic near-miss
            "/actuator/info",
            "/actuator",         // bare index scores recon 25, never canary
            "/environment",      // exact-match: `/.env` must not prefix-hit
            "/id_rsa.pub",       // public half is not the secret
            "/server.key.pem",   // exact-match: `/server.key` must not prefix-hit
            "/git/config",       // no dot — different path entirely
            "/",
            "/api/users",
        ] {
            let (m, u, h, b) = req(legit);
            assert!(
                d.inspect(&view(&m, &u, &h, &b)).is_empty(),
                "legit look-alike {legit} must not trip the canary",
            );
        }
    }

    #[test]
    fn raw_reads_back_normalized_entries() {
        let paths = CanaryPaths::new(&vec![
            "  /wp-admin  ".into(),
            "".into(),
            "/.env".into(),
        ]);
        // Blanks dropped, surrounding whitespace trimmed.
        assert_eq!(paths.raw(), vec!["/wp-admin".to_string(), "/.env".to_string()]);
    }
}
