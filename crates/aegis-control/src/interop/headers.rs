//! Always-on `X-WAF-*` response observability headers.
//!
//! Six headers stamped on every WAF response (allow / block /
//! challenge / rate_limit / timeout / circuit_breaker). External
//! tooling (benchmark harnesses, dashboards, SIEMs) reads them
//! to classify decisions in real time without parsing audit logs.
//!
//! Distinct from the gated, diagnostic `X-Aegis-*` headers in
//! `aegis-proxy::benchmark` — those are opt-in per-request
//! tracing; these are always-on operational metadata.

use http::{HeaderMap, HeaderName, HeaderValue};

// Required header names — lowercase per hyper convention.
pub const REQUEST_ID: &str = "x-waf-request-id";
pub const RISK_SCORE: &str = "x-waf-risk-score";
pub const ACTION: &str = "x-waf-action";
pub const RULE_ID: &str = "x-waf-rule-id";
pub const CACHE: &str = "x-waf-cache";
pub const MODE: &str = "x-waf-mode";

/// 2026-05-08 — bonus telemetry header. Reports the per-request
/// WAF processing time (received → response stamped) in
/// milliseconds with microsecond precision (e.g. `1.234`).
///
/// Captured at the listener `service_fn` entry; covers detector
/// chain + rule engine + risk gate + upstream forward + the
/// stamp itself. NOT on the v2.3 §5 mandatory list — extra
/// observability for operators analyzing per-route WAF cost
/// without spinning up a separate latency probe.
///
/// Side-channel note: precise per-request timing leaks regex-
/// hot-path information. Operators who care about that should
/// disable via the existing detector mask (no separate toggle
/// — the header is cheap enough that gating it would cost more
/// than it saves).
pub const OVERHEAD_LATENCY: &str = "x-waf-overhead-latency";

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

/// Tag attached to a data-plane response so the post-processing
/// stamper knows the *real* contract action and rule attribution
/// instead of inferring from HTTP status. AF-T1: a `challenge`
/// body and a rate-limit response both use status 429 — they
/// cannot be told apart from status alone, so the data-plane
/// handler emits a `DecisionTag` alongside the response.
///
/// `rule_id` is what populates `X-WAF-Rule-Id` and the audit
/// log's `rule_id` field. `None` means "no specific rule
/// applies" — stamper defaults to the literal `none`.
#[derive(Clone, Debug)]
pub struct DecisionTag {
    pub action: Action,
    pub rule_id: Option<String>,
    /// 2026-05-05 — populated by the data plane with the resolved
    /// tier (route override or path heuristic). Lets the listener-
    /// side audit emit attach the real tier label so the dashboard
    /// Live Feed shows `critical / high / medium / low` instead of
    /// falling back to a risk-score bucket. `None` means tier
    /// hadn't been classified at the point of decision (e.g. early
    /// rate-limit blocks pre-tier).
    pub tier: Option<aegis_core::tier::Tier>,
    /// 2026-05-08 NEW-4 — score at decision time.
    ///
    /// Pre-fix the response stamper queried `risk.snapshot(peer.ip())`
    /// on the raw TCP peer. The risk tracker keys on the
    /// XFF-resolved client IP, so any traffic via a trusted
    /// proxy (or a client that injects X-Forwarded-For) accumulated
    /// score under a different key than the stamper queried —
    /// `unwrap_or(0)` → `X-WAF-Risk-Score: 0` always. Downstream
    /// monitoring couldn't distinguish first-time attackers from
    /// repeat offenders.
    ///
    /// Now the data plane stamps the score it just observed
    /// (under the correct XFF-resolved key) onto the
    /// DecisionTag, and the response stamper prefers it over the
    /// peer.ip() snapshot. Allow / no-risk-event paths leave it
    /// `None` and the stamper falls back to a snapshot lookup
    /// (which works for direct-connect clients).
    pub risk_score: Option<u32>,
    /// 2026-05-21 — per-request detector score: the sum of THIS
    /// request's detector signals (capped at 100). Distinct from
    /// `risk_score`, which is the cumulative composite-key score.
    /// Carried on detected-but-allowed decisions so the listener
    /// audit can record `fields.request_score` — letting the dashboard
    /// show "this request scored N" alongside "this source's
    /// accumulated risk is M". Not stamped on a response header.
    pub detector_score: Option<u32>,
    /// SC-1 (2026-06-06) — cache decision for `X-WAF-Cache`. Defaults to
    /// `Bypass`; the smart-cache lookup sets `Hit` (served from cache) or
    /// `Miss` (forwarded, possibly stored). The response stamper copies this
    /// onto the stamped `Decision`.
    pub cache: CacheState,
}

impl DecisionTag {
    pub fn allow() -> Self {
        Self { action: Action::Allow, rule_id: None, tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass }
    }
    pub fn block(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Block, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass }
    }
    pub fn rate_limit(rule_id: impl Into<String>) -> Self {
        Self { action: Action::RateLimit, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass }
    }
    pub fn challenge(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Challenge, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass }
    }
    pub fn timeout(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Timeout, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass }
    }
    pub fn circuit_breaker(rule_id: impl Into<String>) -> Self {
        Self { action: Action::CircuitBreaker, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass }
    }

    /// Attach the per-request detector score (sum of this request's
    /// signals). See [`Self::detector_score`].
    pub fn with_detector_score(mut self, score: u32) -> Self {
        self.detector_score = Some(score);
        self
    }

    /// SC-1 — set the cache decision (Hit/Miss/Bypass) for `X-WAF-Cache`.
    pub fn with_cache(mut self, cache: CacheState) -> Self {
        self.cache = cache;
        self
    }

    /// 2026-05-21 — attach a rule_id to an existing tag. Used by the
    /// data plane to label an under-threshold detection that was
    /// forwarded as `allow` with the fired detector tags, so the
    /// `X-WAF-Rule-Id` response header AND the audit `rule_id` field
    /// both carry the detectors and stay in lock-step (contract:
    /// header and log must match).
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Attach the resolved tier; used by the data plane after
    /// classify_tier resolves so the listener-side audit emit and
    /// `X-WAF-Tier` response header can reflect the truth.
    pub fn with_tier(mut self, tier: aegis_core::tier::Tier) -> Self {
        self.tier = Some(tier);
        self
    }

    /// NEW-4 (2026-05-08) — attach the risk score the data plane
    /// observed at decision time. Stamper prefers this over a
    /// peer.ip()-keyed snapshot lookup (which races XFF
    /// resolution).
    pub fn with_risk_score(mut self, score: u32) -> Self {
        self.risk_score = Some(score);
        self
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

/// 2026-05-08 — stamp the `X-WAF-Overhead-Latency` header from a
/// `Duration`. Format: `<int>.<3-digit>` ms (microsecond
/// precision; cap at 4 fractional digits worth of safety).
///
/// Caller measures `request_start.elapsed()` at the listener
/// service_fn entry; this writes the formatted value.
pub fn stamp_overhead_latency(headers: &mut HeaderMap, elapsed: std::time::Duration) {
    let micros = elapsed.as_micros();
    // Format as ms with µs precision: `12.345` for 12.345 ms.
    // Cheaper than format!("{:.3}") because we avoid float
    // formatting; integer-divide trick gives 3 decimals
    // deterministically. u128 math fits any realistic request.
    let ms_int = micros / 1000;
    let us_frac = micros % 1000;
    let value = format!("{ms_int}.{us_frac:03}");
    insert(headers, OVERHEAD_LATENCY, &value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn action_strings_match_spec() {
        // The contract enumerates these six exact lowercase
        // strings — typos here fail the integration.
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

    /// 2026-05-21 — an under-threshold detection is forwarded as
    /// `allow` but labelled with the fired detectors via
    /// `with_rule_id`, so `X-WAF-Rule-Id` + the audit `rule_id`
    /// both carry them. Action must stay `allow`.
    #[test]
    fn with_rule_id_labels_an_allow_without_changing_action() {
        let tag = DecisionTag::allow().with_rule_id("recon,ai");
        assert_eq!(tag.action, Action::Allow);
        assert_eq!(tag.rule_id.as_deref(), Some("recon,ai"));
    }

    #[test]
    fn cache_strings_are_uppercase() {
        // §5.1 requires uppercase exact match.
        assert_eq!(CacheState::Hit.as_str(), "HIT");
        assert_eq!(CacheState::Miss.as_str(), "MISS");
        assert_eq!(CacheState::Bypass.as_str(), "BYPASS");
    }

    /// SC-1 — the smart-cache verdict must reach the wire. A `Decision`
    /// carrying `CacheState::Hit` stamps `X-WAF-Cache: HIT`; `Miss` stamps
    /// `MISS`. This is the end of the chain the data plane drives:
    /// `PoolCache::lookup` → `DecisionTag::with_cache` → `Decision.cache` →
    /// here. Pre-SC-1 every response was `BYPASS`, so a regression that drops
    /// the field would silently re-bypass and this guards it.
    #[test]
    fn cache_state_is_stamped_onto_the_response_header() {
        for (state, expected) in [
            (CacheState::Hit, "HIT"),
            (CacheState::Miss, "MISS"),
            (CacheState::Bypass, "BYPASS"),
        ] {
            let mut h = HeaderMap::new();
            let decision = Decision {
                request_id: "rid".into(),
                risk_score: 0,
                action: Action::Allow,
                rule_id: None,
                cache: state,
                mode: Mode::Enforce,
            };
            decision.stamp(&mut h);
            assert_eq!(h.get(CACHE).unwrap(), expected, "X-WAF-Cache for {state:?}");
        }
    }

    /// The cache verdict rides on the `DecisionTag` the data plane emits, so a
    /// `Decision` built from a tag (as `stamp_interop_response` does) must
    /// preserve it. Mirrors the field copy at `admin_dispatch.rs` `cache:
    /// decision_tag.cache`.
    #[test]
    fn decision_tag_cache_round_trips_through_a_decision() {
        let tag = DecisionTag::allow().with_cache(CacheState::Hit);
        assert_eq!(tag.cache, CacheState::Hit);
        let decision = Decision {
            request_id: "rid".into(),
            risk_score: tag.risk_score.unwrap_or(0),
            action: tag.action,
            rule_id: tag.rule_id.clone(),
            cache: tag.cache,
            mode: Mode::Enforce,
        };
        let mut h = HeaderMap::new();
        decision.stamp(&mut h);
        assert_eq!(h.get(CACHE).unwrap(), "HIT");
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
    fn stamp_overhead_latency_formats_with_microsecond_precision() {
        let mut h = HeaderMap::new();
        // 12.345 ms = 12_345 microseconds
        stamp_overhead_latency(&mut h, std::time::Duration::from_micros(12_345));
        assert_eq!(h.get(OVERHEAD_LATENCY).unwrap(), "12.345");
    }

    #[test]
    fn stamp_overhead_latency_pads_fractional_zeros() {
        let mut h = HeaderMap::new();
        // 1.005 ms — verifies the {us_frac:03} zero-pad
        stamp_overhead_latency(&mut h, std::time::Duration::from_micros(1_005));
        assert_eq!(h.get(OVERHEAD_LATENCY).unwrap(), "1.005");
    }

    #[test]
    fn stamp_overhead_latency_handles_sub_millisecond() {
        let mut h = HeaderMap::new();
        // 0.250 ms = 250 µs
        stamp_overhead_latency(&mut h, std::time::Duration::from_micros(250));
        assert_eq!(h.get(OVERHEAD_LATENCY).unwrap(), "0.250");
    }

    #[test]
    fn stamp_overhead_latency_handles_zero() {
        let mut h = HeaderMap::new();
        stamp_overhead_latency(&mut h, std::time::Duration::ZERO);
        assert_eq!(h.get(OVERHEAD_LATENCY).unwrap(), "0.000");
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

    // DecisionTag (AF-T1) — exists so the data-plane handler
    // can communicate the real action separately from HTTP status.
    #[test]
    fn decision_tag_constructors_set_action() {
        assert_eq!(DecisionTag::allow().action, Action::Allow);
        assert_eq!(DecisionTag::block("r").action, Action::Block);
        assert_eq!(DecisionTag::rate_limit("r").action, Action::RateLimit);
        assert_eq!(DecisionTag::challenge("r").action, Action::Challenge);
        assert_eq!(DecisionTag::timeout("r").action, Action::Timeout);
        assert_eq!(
            DecisionTag::circuit_breaker("r").action,
            Action::CircuitBreaker,
        );
    }

    #[test]
    fn decision_tag_allow_has_no_rule_id() {
        // Allow paths set X-WAF-Rule-Id: none — the constructor
        // mirrors that.
        assert!(DecisionTag::allow().rule_id.is_none());
    }

    #[test]
    fn decision_tag_block_records_rule_id() {
        let t = DecisionTag::block("rule-sqli-001");
        assert_eq!(t.rule_id.as_deref(), Some("rule-sqli-001"));
    }

    #[test]
    fn decision_tag_with_risk_score_round_trip() {
        // NEW-4 (2026-05-08) — DecisionTag carries the score the
        // data plane saw at decision time so the response stamper
        // doesn't re-query the tracker under a mismatched IP key.
        let t = DecisionTag::block("ai")
            .with_tier(aegis_core::tier::Tier::High)
            .with_risk_score(42);
        assert_eq!(t.risk_score, Some(42));
        assert_eq!(t.rule_id.as_deref(), Some("ai"));
        assert_eq!(t.tier, Some(aegis_core::tier::Tier::High));
    }

    #[test]
    fn decision_tag_default_risk_score_is_none() {
        // Allow path doesn't run the risk gate; carrying None is
        // the contract — stamper falls back to a peer.ip()
        // snapshot.
        assert!(DecisionTag::allow().risk_score.is_none());
        assert!(DecisionTag::block("r").risk_score.is_none());
    }

    #[test]
    fn log_only_mode_renders_as_log_only_underscore() {
        let mut h = HeaderMap::new();
        Decision::block("rid".into(), 90, "rule-1", Mode::LogOnly).stamp(&mut h);
        assert_eq!(h.get(MODE).unwrap(), "log_only");
    }
}
