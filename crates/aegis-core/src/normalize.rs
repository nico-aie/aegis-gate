//! Path normalization for defense-in-depth matching (RC-4, 2026-07-05).
//!
//! Produces a canonicalized copy of a URL path so evasion variants
//! (`//​x`, `/./x`, `/a/../x`, `/%2ex`) resolve to the same string a
//! detector matches against. This is an **additional** view, never a
//! replacement: the raw percent-encoded form stays the contract every
//! other detector reads (`origin_form_uri`), because framing/encoding
//! attribution depends on seeing exactly what crossed the wire.
//!
//! Currently consumed by the canary tripwire (`detectors::canary`),
//! whose exact/prefix match is otherwise raw-only — so `//​.git/config`
//! or `/%2egit/config` would slip past a `/​.git/config` honeypot entry.

use std::borrow::Cow;

/// Canonicalize a URL path for a second, defense-in-depth match pass.
///
/// - percent-decodes `%XX` (single pass; double-encoding is a documented
///   limitation),
/// - collapses repeated slashes (`//` → `/`),
/// - resolves `.` and `..` path segments.
///
/// The query/fragment (from the first `?`/`#`) is preserved verbatim —
/// it is not a filesystem path. Returns `Cow::Borrowed` unchanged when
/// the path is already canonical (the common benign case → no alloc).
pub fn normalize_path(path: &str) -> Cow<'_, str> {
    // Identity stub (RED) — real normalization lands in GREEN.
    Cow::Borrowed(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_is_borrowed_unchanged() {
        let out = normalize_path("/api/users/123");
        assert_eq!(out, "/api/users/123");
        assert!(matches!(out, Cow::Borrowed(_)), "canonical path must not allocate");
    }

    #[test]
    fn collapses_repeated_slashes() {
        assert_eq!(normalize_path("//.git/config"), "/.git/config");
        assert_eq!(normalize_path("/a//b///c"), "/a/b/c");
    }

    #[test]
    fn drops_dot_segments() {
        assert_eq!(normalize_path("/./.git/config"), "/.git/config");
        assert_eq!(normalize_path("/a/./b"), "/a/b");
    }

    #[test]
    fn resolves_dotdot_segments() {
        assert_eq!(normalize_path("/x/../.git/config"), "/.git/config");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn percent_decodes_dot_and_slash() {
        // %2e = '.', %2f = '/'
        assert_eq!(normalize_path("/%2egit/config"), "/.git/config");
        assert_eq!(normalize_path("/a%2f%2e%2e%2f.git/config"), "/.git/config");
    }

    #[test]
    fn preserves_query_verbatim() {
        // Query is not a path — `//` inside it must survive.
        assert_eq!(normalize_path("/search?q=a//b"), "/search?q=a//b");
        assert_eq!(normalize_path("//search?q=1"), "/search?q=1");
    }

    #[test]
    fn is_idempotent() {
        for p in ["//.git/config", "/x/../.git/config", "/%2egit/config", "/a//b"] {
            let once = normalize_path(p).into_owned();
            let twice = normalize_path(&once).into_owned();
            assert_eq!(once, twice, "normalize not idempotent for {p}");
        }
    }

    #[test]
    fn root_and_empty_are_safe() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("//"), "/");
        assert_eq!(normalize_path("/../.."), "/");
    }
}
