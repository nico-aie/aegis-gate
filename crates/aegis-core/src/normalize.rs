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
    // Fast path: nothing to decode or resolve → borrow, no allocation.
    // This is the overwhelmingly common benign case; it costs one scan.
    if !needs_normalization(path) {
        return Cow::Borrowed(path);
    }
    Cow::Owned(normalize_slow(path))
}

/// True iff `path` contains a `%` escape or a slash immediately followed
/// by another slash or a `.` — the only inputs `normalize_slow` changes.
fn needs_normalization(path: &str) -> bool {
    let b = path.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'%' => return true,
            b'/' => match b.get(i + 1) {
                Some(b'/') | Some(b'.') => return true,
                _ => {}
            },
            _ => {}
        }
    }
    false
}

fn normalize_slow(path: &str) -> String {
    // Normalize the PATH only; keep the query/fragment verbatim (it is
    // not a filesystem path, and `//` / `.` are legal data there).
    let (raw_path, rest) = match path.find(['?', '#']) {
        Some(i) => (&path[..i], &path[i..]),
        None => (path, ""),
    };
    let decoded = percent_decode(raw_path);
    // Resolve segments: `""`/`.` collapse (handles `//` and `/./`),
    // `..` pops the previous segment.
    let mut segs: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = String::with_capacity(decoded.len() + rest.len() + 1);
    out.push('/');
    // join without an intermediate Vec allocation from `.join`.
    for (i, s) in segs.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(s);
    }
    out.push_str(rest);
    out
}

/// Single-pass percent-decode. Double-encoding (`%252e`) is deliberately
/// NOT recursively decoded — one decode matches the standard gateway
/// behavior and avoids over-normalizing a literal `%25`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    if !b.contains(&b'%') {
        return s.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
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
