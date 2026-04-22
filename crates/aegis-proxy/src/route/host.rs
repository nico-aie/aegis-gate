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
}
