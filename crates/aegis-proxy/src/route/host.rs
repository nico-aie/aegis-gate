use regex::Regex;

/// Matches an incoming `Host` header (or SNI) value against a configured pattern.
#[derive(Debug, Clone)]
pub enum HostMatcher {
    /// Exact, case-insensitive match (e.g. `api.example.com`).
    Exact(String),
    /// Wildcard with a leading `*.` (e.g. `*.example.com`).
    Wildcard(String),
    /// Arbitrary regex (anchored automatically).
    Regex(Regex),
    /// Catch-all — matches any host.
    Default,
}

impl HostMatcher {
    /// Create the appropriate matcher variant from a pattern string.
    ///
    /// - `"*"` → `Default`
    /// - `"*.suffix"` → `Wildcard`
    /// - `/regex/` → `Regex`
    /// - everything else → `Exact`
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        if pattern == "*" {
            return Ok(Self::Default);
        }
        if pattern.starts_with("*.") {
            // Store suffix lowercased for case-insensitive comparison.
            return Ok(Self::Wildcard(pattern[1..].to_ascii_lowercase()));
        }
        if pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() > 2 {
            let inner = &pattern[1..pattern.len() - 1];
            let re = Regex::new(&format!("(?i)^{inner}$"))?;
            return Ok(Self::Regex(re));
        }
        Ok(Self::Exact(pattern.to_ascii_lowercase()))
    }

    /// Return `true` if `host` matches this pattern. Matching is always
    /// case-insensitive.
    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_ascii_lowercase();
        // Strip optional port (e.g. "example.com:8080" → "example.com").
        let host_name = host_lower.split(':').next().unwrap_or(&host_lower);

        match self {
            Self::Exact(expected) => host_name == expected,
            Self::Wildcard(suffix) => host_name.ends_with(suffix.as_str()),
            Self::Regex(re) => re.is_match(host_name),
            Self::Default => true,
        }
    }

    /// Priority for tie-breaking: lower is better.
    /// `Exact` (0) > `Regex` (1) > `Wildcard` (2) > `Default` (3).
    pub fn priority(&self) -> u8 {
        match self {
            Self::Exact(_) => 0,
            Self::Regex(_) => 1,
            Self::Wildcard(_) => 2,
            Self::Default => 3,
        }
    }
}

/// Fallback host when a request carries no authority at all
/// (HTTP/1.0 without a `Host` header, or an origin-form h2 request
/// with no `:authority`).
pub const DEFAULT_HOST: &str = "localhost";

/// The effective request host, for route matching / tier resolution /
/// cache keys.
///
/// HTTP/1.1 carries the authority in the `Host` header. HTTP/2 and
/// HTTP/3 carry it in the `:authority` pseudo-header, which hyper
/// surfaces on the request URI and does *not* mirror into `Host`.
/// Reading only the header therefore made every h2 request fall back
/// to the literal `DEFAULT_HOST`, collapsing all vhosts onto whichever
/// route matched `localhost` (or 404ing when none did).
///
/// `Host` wins when present so HTTP/1.1 behaviour is unchanged. The
/// returned value may still carry a port; [`HostMatcher::matches`]
/// strips it.
pub fn effective_host<'a>(headers: &'a http::HeaderMap, uri: &'a http::Uri) -> &'a str {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
        .unwrap_or(DEFAULT_HOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_exact() {
        let m = HostMatcher::new("api.example.com").unwrap();
        assert!(matches!(m, HostMatcher::Exact(_)));
    }

    #[test]
    fn new_wildcard() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(matches!(m, HostMatcher::Wildcard(_)));
    }

    #[test]
    fn new_regex() {
        let m = HostMatcher::new("/api-[0-9]+\\.example\\.com/").unwrap();
        assert!(matches!(m, HostMatcher::Regex(_)));
    }

    #[test]
    fn new_default() {
        let m = HostMatcher::new("*").unwrap();
        assert!(matches!(m, HostMatcher::Default));
    }

    // -----------------------------------------------------------------------
    // Exact matching
    // -----------------------------------------------------------------------

    #[test]
    fn exact_matches_same_case() {
        let m = HostMatcher::new("api.example.com").unwrap();
        assert!(m.matches("api.example.com"));
    }

    #[test]
    fn exact_is_case_insensitive() {
        let m = HostMatcher::new("Api.Example.COM").unwrap();
        assert!(m.matches("api.example.com"));
        assert!(m.matches("API.EXAMPLE.COM"));
    }

    #[test]
    fn exact_strips_port() {
        let m = HostMatcher::new("api.example.com").unwrap();
        assert!(m.matches("api.example.com:8080"));
    }

    #[test]
    fn exact_rejects_mismatch() {
        let m = HostMatcher::new("api.example.com").unwrap();
        assert!(!m.matches("other.example.com"));
    }

    // -----------------------------------------------------------------------
    // Wildcard matching
    // -----------------------------------------------------------------------

    #[test]
    fn wildcard_matches_subdomain() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(m.matches("api.example.com"));
        assert!(m.matches("www.example.com"));
    }

    #[test]
    fn wildcard_matches_nested_subdomain() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(m.matches("a.b.example.com"));
    }

    #[test]
    fn wildcard_is_case_insensitive() {
        let m = HostMatcher::new("*.Example.COM").unwrap();
        assert!(m.matches("api.example.com"));
    }

    #[test]
    fn wildcard_rejects_bare_domain() {
        // "*.example.com" should NOT match "example.com" (no subdomain prefix).
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn wildcard_rejects_different_domain() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(!m.matches("api.other.com"));
    }

    // -----------------------------------------------------------------------
    // Regex matching
    // -----------------------------------------------------------------------

    #[test]
    fn regex_matches() {
        let m = HostMatcher::new("/api-[0-9]+\\.example\\.com/").unwrap();
        assert!(m.matches("api-123.example.com"));
        assert!(!m.matches("api-abc.example.com"));
    }

    #[test]
    fn regex_is_case_insensitive() {
        let m = HostMatcher::new("/api\\.example\\.com/").unwrap();
        assert!(m.matches("API.EXAMPLE.COM"));
    }

    // -----------------------------------------------------------------------
    // Default matching
    // -----------------------------------------------------------------------

    #[test]
    fn default_matches_anything() {
        let m = HostMatcher::new("*").unwrap();
        assert!(m.matches("anything.example.com"));
        assert!(m.matches("localhost"));
        assert!(m.matches("127.0.0.1:8080"));
    }

    // -----------------------------------------------------------------------
    // Priority: exact > regex > wildcard > default
    // -----------------------------------------------------------------------

    #[test]
    fn priority_ordering() {
        let exact = HostMatcher::new("api.example.com").unwrap();
        let regex = HostMatcher::new("/api\\.example\\.com/").unwrap();
        let wildcard = HostMatcher::new("*.example.com").unwrap();
        let default = HostMatcher::new("*").unwrap();

        assert!(exact.priority() < regex.priority());
        assert!(regex.priority() < wildcard.priority());
        assert!(wildcard.priority() < default.priority());
    }

    // -----------------------------------------------------------------------
    // SNI mismatch rejected
    // -----------------------------------------------------------------------

    #[test]
    fn sni_mismatch_rejected_by_exact() {
        let m = HostMatcher::new("secure.example.com").unwrap();
        assert!(!m.matches("evil.attacker.com"));
    }

    #[test]
    fn sni_mismatch_rejected_by_wildcard() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(!m.matches("evil.attacker.com"));
    }

    // -----------------------------------------------------------------------
    // effective_host — HTTP/1.1 `Host` vs HTTP/2 `:authority`
    // -----------------------------------------------------------------------

    fn headers_with_host(value: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::HOST, value.parse().unwrap());
        h
    }

    #[test]
    fn effective_host_reads_http1_host_header() {
        let headers = headers_with_host("abc.com");
        let uri: http::Uri = "/admin".parse().unwrap();
        assert_eq!(effective_host(&headers, &uri), "abc.com");
    }

    #[test]
    fn effective_host_falls_back_to_h2_authority() {
        // hyper puts the HTTP/2 `:authority` pseudo-header on the URI
        // and leaves `Host` unset — the shape that used to resolve to
        // DEFAULT_HOST and misroute every h2 request.
        let headers = http::HeaderMap::new();
        let uri: http::Uri = "https://abc.com/admin".parse().unwrap();
        assert_eq!(effective_host(&headers, &uri), "abc.com");
    }

    #[test]
    fn effective_host_prefers_host_header_over_authority() {
        let headers = headers_with_host("abc.com");
        let uri: http::Uri = "https://other.example/admin".parse().unwrap();
        assert_eq!(effective_host(&headers, &uri), "abc.com");
    }

    #[test]
    fn effective_host_keeps_authority_port_for_matcher_to_strip() {
        let headers = http::HeaderMap::new();
        let uri: http::Uri = "https://abc.com:8443/admin".parse().unwrap();
        assert_eq!(effective_host(&headers, &uri), "abc.com:8443");

        let m = HostMatcher::new("abc.com").unwrap();
        assert!(m.matches(effective_host(&headers, &uri)));
    }

    #[test]
    fn effective_host_defaults_when_no_authority_anywhere() {
        let headers = http::HeaderMap::new();
        let uri: http::Uri = "/admin".parse().unwrap();
        assert_eq!(effective_host(&headers, &uri), DEFAULT_HOST);
    }

    #[test]
    fn h2_authority_selects_the_matching_vhost_not_localhost() {
        // The production symptom: two exact-host routes, an h2 request
        // for `abc.com`. Pre-fix the host resolved to "localhost", so
        // the `localhost` route swallowed it (or nothing matched).
        let abc = HostMatcher::new("abc.com").unwrap();
        let local = HostMatcher::new("localhost").unwrap();

        let headers = http::HeaderMap::new();
        let uri: http::Uri = "https://abc.com/".parse().unwrap();
        let host = effective_host(&headers, &uri);

        assert!(abc.matches(host));
        assert!(!local.matches(host));
    }
}
