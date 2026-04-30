//! HK-T2 — mandatory `X-WAF-*` response headers.
//!
//! The hackathon contract (§5) lists six headers that MUST
//! appear on every WAF response (allow / block / challenge /
//! rate_limit / timeout / circuit_breaker). Names + values must
//! match the spec exactly — typos here fail the benchmark.
//!
//! These are **always-on**, distinct from the existing gated
//! `X-Aegis-*` benchmark-mode headers in `aegis-proxy`.

use http::{HeaderMap, HeaderName, HeaderValue};

// Required header names — lowercase per hyper convention.
pub const REQUEST_ID: &str = "x-waf-request-id";
pub const RISK_SCORE: &str = "x-waf-risk-score";
pub const ACTION: &str = "x-waf-action";
pub const RULE_ID: &str = "x-waf-rule-id";
pub const CACHE: &str = "x-waf-cache";
pub const MODE: &str = "x-waf-mode";

/// One of the six contract decision classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
    Challenge,
    RateLimit,
    Timeout,
    CircuitBreaker,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Block => "block",
            Action::Challenge => "challenge",
            Action::RateLimit => "rate_limit",
            Action::Timeout => "timeout",
            Action::CircuitBreaker => "circuit_breaker",
        }
    }
}

/// `X-WAF-Mode` — `enforce` or `log_only`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    LogOnly,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::LogOnly => "log_only",
        }
    }
}

/// `X-WAF-Cache` — `HIT`, `MISS`, or `BYPASS`. Until the WAF
/// implements an upstream-response cache, every response uses
/// `Bypass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheState {
    Hit,
    Miss,
    Bypass,
}

impl CacheState {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheState::Hit => "HIT",
            CacheState::Miss => "MISS",
            CacheState::Bypass => "BYPASS",
        }
    }
}

/// All six required headers, packaged for stamping onto any
/// response builder.
#[derive(Clone, Debug)]
pub struct Decision {
    pub request_id: String,
    pub risk_score: u32,
    pub action: Action,
    pub rule_id: Option<String>,
    pub cache: CacheState,
    pub mode: Mode,
}

impl Decision {
    /// Lowest-information `allow` decision — used when a request
    /// passes through the WAF cleanly and no detector fired.
    pub fn allow(request_id: String, risk_score: u32, mode: Mode) -> Self {
        Self {
            request_id,
            risk_score,
            action: Action::Allow,
            rule_id: None,
            cache: CacheState::Bypass,
            mode,
        }
    }

    /// `block` decision attributed to a specific rule.
    pub fn block(
        request_id: String,
        risk_score: u32,
        rule_id: impl Into<String>,
        mode: Mode,
    ) -> Self {
        Self {
            request_id,
            risk_score,
            action: Action::Block,
            rule_id: Some(rule_id.into()),
            cache: CacheState::Bypass,
            mode,
        }
    }

    /// Insert all six required headers onto `headers`. Existing
    /// headers with the same name are replaced (not appended) so
    /// downstream layers can't smuggle a different value.
    pub fn stamp(&self, headers: &mut HeaderMap) {
        insert(headers, REQUEST_ID, &self.request_id);
        insert(headers, RISK_SCORE, &self.risk_score.to_string());
        insert(headers, ACTION, self.action.as_str());
        insert(
            headers,
            RULE_ID,
            self.rule_id.as_deref().unwrap_or("none"),
        );
        insert(headers, CACHE, self.cache.as_str());
        insert(headers, MODE, self.mode.as_str());
    }
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
    let name = HeaderName::from_static(name);
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn action_strings_match_spec() {
        // The hackathon contract enumerates these six exact
        // lowercase strings — typos here fail the benchmark.
        assert_eq!(Action::Allow.as_str(), "allow");
        assert_eq!(Action::Block.as_str(), "block");
        assert_eq!(Action::Challenge.as_str(), "challenge");
        assert_eq!(Action::RateLimit.as_str(), "rate_limit");
        assert_eq!(Action::Timeout.as_str(), "timeout");
        assert_eq!(Action::CircuitBreaker.as_str(), "circuit_breaker");
    }

    #[test]
    fn mode_strings_match_spec() {
        assert_eq!(Mode::Enforce.as_str(), "enforce");
        assert_eq!(Mode::LogOnly.as_str(), "log_only");
    }

    #[test]
    fn cache_strings_are_uppercase() {
        // §5.1 requires uppercase exact match.
        assert_eq!(CacheState::Hit.as_str(), "HIT");
        assert_eq!(CacheState::Miss.as_str(), "MISS");
        assert_eq!(CacheState::Bypass.as_str(), "BYPASS");
    }

    #[test]
    fn allow_decision_stamps_every_required_header() {
        let mut h = HeaderMap::new();
        Decision::allow("rid".into(), 12, Mode::Enforce).stamp(&mut h);
        for n in [REQUEST_ID, RISK_SCORE, ACTION, RULE_ID, CACHE, MODE] {
            assert!(h.contains_key(n), "missing {n} after stamp()");
        }
        assert_eq!(h.get(ACTION).unwrap(), "allow");
        assert_eq!(h.get(MODE).unwrap(), "enforce");
        assert_eq!(h.get(RULE_ID).unwrap(), "none");
        assert_eq!(h.get(CACHE).unwrap(), "BYPASS");
        assert_eq!(h.get(RISK_SCORE).unwrap(), "12");
    }

    #[test]
    fn block_decision_carries_rule_id() {
        let mut h = HeaderMap::new();
        Decision::block("rid".into(), 90, "rule-sqli-001", Mode::Enforce).stamp(&mut h);
        assert_eq!(h.get(ACTION).unwrap(), "block");
        assert_eq!(h.get(RULE_ID).unwrap(), "rule-sqli-001");
    }

    #[test]
    fn stamp_replaces_existing_value_not_appends() {
        // Critical for header-consistency rules — a downstream
        // accidentally setting `X-WAF-Action: allow` on a block
        // would corrupt the benchmarker's view.
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static(ACTION),
            HeaderValue::from_static("allow"),
        );
        Decision::block("rid".into(), 90, "rule-1", Mode::Enforce).stamp(&mut h);
        let count = h.get_all(ACTION).iter().count();
        assert_eq!(count, 1, "stamp must replace, not append (got {count})");
        assert_eq!(h.get(ACTION).unwrap(), "block");
    }

    #[test]
    fn risk_score_renders_as_integer_in_header_value() {
        let mut h = HeaderMap::new();
        Decision::allow("rid".into(), 0, Mode::Enforce).stamp(&mut h);
        assert_eq!(h.get(RISK_SCORE).unwrap(), "0");
    }

    #[test]
    fn log_only_mode_renders_as_log_only_underscore() {
        let mut h = HeaderMap::new();
        Decision::block("rid".into(), 90, "rule-1", Mode::LogOnly).stamp(&mut h);
        assert_eq!(h.get(MODE).unwrap(), "log_only");
    }
}
