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

/// Bonus header (§5.2) — the full set of detectors that fired on a
/// multi-detector decision, comma-joined (e.g. `sqli,xss,path-traversal`).
/// `X-WAF-Rule-Id` (§5.1) carries only the single primary detector to
/// stay singular + wire-legal; this preserves the complete attribution
/// machine-readably. Only emitted when more than one detector fired.
pub const DETECTORS: &str = "x-waf-detectors";

/// RF-FP (2026-07-08 QC) — set to `true` on a response whose body the
/// response-filter rungs rewrote (stack-trace scrub / IP mask / DLP redact),
/// so the client can SEE that its payload was scrubbed. Paired with
/// `X-WAF-Rule-Id: response_filter` when the request carried no other rule
/// attribution. Absent on unfiltered responses.
pub const RESPONSE_FILTERED: &str = "x-waf-response-filtered";

/// RF-FP (2026-07-08) — bytes of the body AFTER filtering, so operators can
/// gauge how much was rewritten without ever exposing the redacted value.
pub const FILTERED_BYTES: &str = "x-waf-filtered-bytes";

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

/// Audit-emit ownership for a contract action — the single source of truth
/// that keeps the Live Feed / Investigation table at exactly ONE row per
/// request.
///
/// The data plane (`handle_data_request`) self-audits every decision it
/// terminates itself with a rich Detection event (XFF-resolved client IP,
/// detectors, strikes, route tier): `block`, `challenge`, and `rate_limit`.
/// The connection listener (`accept.rs`) must therefore stay silent for
/// those, or each request lands twice — the bug this consolidated:
/// `rate_limit` used to be emitted by BOTH layers (a BLOCK twin from the
/// data plane + a RATE_LIMIT row from the listener).
///
/// The listener is the SOLE emitter for `allow`, and for the upstream-failure
/// verdicts the data plane does not self-audit (`timeout`, `circuit_breaker`).
///
/// Returns `true` when the LISTENER owns the emit, `false` when the data
/// plane already emitted (listener must skip). Exhaustively matched so a
/// newly-added [`Action`] forces a deliberate ownership choice here rather
/// than silently defaulting into a double-row.
pub fn listener_emits_audit(action: Action) -> bool {
    match action {
        Action::Allow | Action::Timeout | Action::CircuitBreaker => true,
        Action::Block | Action::Challenge | Action::RateLimit => false,
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
    /// SSE (2026-06-14) — `true` when this response was streamed through
    /// (`text/event-stream` etc.) rather than buffered. A streamed response
    /// is **header-inspected only**: its body is not buffered or
    /// response-body-inspected. The listener audit derives
    /// `streamed` / `response_inspection_skipped` / `reason` from this flag
    /// so the security team can see *why* the body wasn't inspected.
    pub streamed: bool,
    /// HIGH-1 (2026-06-19) — `true` when the matched route is in monitor
    /// mode (`RouteConfig.mode == log_only`) AND this decision was
    /// forwarded under that downgrade. The response stamper reads this to
    /// emit `X-WAF-Mode: log_only` (+ the same in the audit row) instead
    /// of re-deriving the mode from the GLOBAL `ModeStore` via
    /// `mode_for_rule`, which has no per-route context. Defaults `false`;
    /// hard blocks (blacklist, enforce-mode 403/429) leave it `false` so
    /// they correctly report `enforce`.
    pub route_log_only: bool,
    /// RF-FP (2026-07-08 QC) — set when the response-filter rungs rewrote the
    /// body. Drives the `X-WAF-Response-Filtered` header, the
    /// `X-WAF-Rule-Id: response_filter` fallback, and the `response_filtered`
    /// field on the request's own audit row — replacing the standalone
    /// Detection "redact" row that used to be emitted separately.
    pub response_filtered: Option<ResponseFilterSignal>,
    /// 2026-07-09 — the redacted request echo (headers + bounded body
    /// preview) for a **detected-but-allowed** request. Blocks build this
    /// echo inside the data plane (where the body is still buffered) and
    /// hand it straight to `blocked_response`; a request that tripped a
    /// detector but stayed under the per-request tier threshold is instead
    /// forwarded as `allow`, and the listener is the sole emitter for
    /// `allow`. The listener has no body (it was consumed by the data
    /// plane), so the data plane captures the echo here and the listener
    /// merges it into the audit `fields` — giving allowed-but-flagged rows
    /// the same forensic detail (headers + body) as blocks. `None` on clean
    /// allows so ordinary traffic keeps a slim audit row.
    pub audit_echo: Option<serde_json::Map<String, serde_json::Value>>,
}

/// RF-FP (2026-07-08 QC) — a body-was-filtered signal. Byte counts only —
/// NEVER the redacted value — so it's safe to surface on the wire
/// (`X-WAF-Filtered-Bytes`) and in the audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseFilterSignal {
    pub bytes_before: usize,
    pub bytes_after: usize,
}

impl DecisionTag {
    pub fn allow() -> Self {
        Self { action: Action::Allow, rule_id: None, tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass, streamed: false, route_log_only: false, response_filtered: None, audit_echo: None }
    }
    pub fn block(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Block, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass, streamed: false, route_log_only: false, response_filtered: None, audit_echo: None }
    }
    pub fn rate_limit(rule_id: impl Into<String>) -> Self {
        Self { action: Action::RateLimit, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass, streamed: false, route_log_only: false, response_filtered: None, audit_echo: None }
    }
    pub fn challenge(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Challenge, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass, streamed: false, route_log_only: false, response_filtered: None, audit_echo: None }
    }
    pub fn timeout(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Timeout, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass, streamed: false, route_log_only: false, response_filtered: None, audit_echo: None }
    }
    pub fn circuit_breaker(rule_id: impl Into<String>) -> Self {
        Self { action: Action::CircuitBreaker, rule_id: Some(rule_id.into()), tier: None, risk_score: None, detector_score: None, cache: CacheState::Bypass, streamed: false, route_log_only: false, response_filtered: None, audit_echo: None }
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

    /// SSE — mark this decision as a streamed (header-inspected-only)
    /// response. The listener audit records `streamed: true`,
    /// `response_inspection_skipped: true`, `reason: "streaming"`.
    pub fn with_streamed(mut self, streamed: bool) -> Self {
        self.streamed = streamed;
        self
    }

    /// HIGH-1 (2026-06-19) — mark this decision as belonging to a route in
    /// monitor mode so the stamper reports `X-WAF-Mode: log_only` (header
    /// + audit) regardless of the global `ModeStore`. See
    /// [`Self::route_log_only`].
    pub fn with_route_log_only(mut self, route_log_only: bool) -> Self {
        self.route_log_only = route_log_only;
        self
    }

    /// RF-FP (2026-07-08 QC) — record that the response-filter rungs rewrote
    /// the body (byte counts only, never the redacted value). See
    /// [`Self::response_filtered`].
    pub fn with_response_filtered(mut self, bytes_before: usize, bytes_after: usize) -> Self {
        self.response_filtered = Some(ResponseFilterSignal { bytes_before, bytes_after });
        self
    }

    /// 2026-07-09 — attach the redacted request echo (headers + bounded body
    /// preview) captured in the data plane for a detected-but-allowed
    /// request, so the listener audit records the same forensic detail a
    /// block does. See [`Self::audit_echo`].
    pub fn with_audit_echo(
        mut self,
        echo: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        self.audit_echo = Some(echo);
        self
    }
}

/// RF-FP (2026-07-08 QC) — resolve the attribution for `X-WAF-Rule-Id` +
/// the audit `rule_id` on a filtered response: when the body was filtered but
/// the request carried no genuine rule attribution (`None` or `none`), name
/// the filter (`response_filter`) so the scrub is clearly attributed; a real
/// allow/block rule id is preserved untouched, and an unfiltered response is
/// returned verbatim.
pub fn rule_id_with_filter_fallback(
    rule_id: Option<String>,
    filtered: bool,
) -> Option<String> {
    if filtered && rule_id.as_deref().map_or(true, |r| r == "none") {
        return Some("response_filter".to_string());
    }
    rule_id
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
    /// RF-FP (2026-07-08 QC) — carried from the `DecisionTag` so `stamp`
    /// emits `X-WAF-Response-Filtered` (+ `X-WAF-Filtered-Bytes`) when the
    /// response body was rewritten. `None` on unfiltered responses.
    pub response_filtered: Option<ResponseFilterSignal>,
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
            response_filtered: None,
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
            response_filtered: None,
        }
    }

    /// Insert all six required headers onto `headers`. Existing
    /// headers with the same name are replaced (not appended) so
    /// downstream layers can't smuggle a different value.
    pub fn stamp(&self, headers: &mut HeaderMap) {
        insert(headers, REQUEST_ID, &self.request_id);
        // §5.1 — `X-WAF-Risk-Score` is an integer 0–100. Clamp here as
        // a backstop so a cumulative score raised past 100 by a
        // non-default operator `risk.max` can never leak out (the audit
        // value is clamped at its own stamp site). See F-V26-003.
        insert(headers, RISK_SCORE, &self.risk_score.min(100).to_string());
        insert(headers, ACTION, self.action.as_str());
        // §5.1 — `X-WAF-Rule-Id` is SINGULAR ("the rule … that most
        // directly caused the decision") and must be alphanumeric +
        // hyphens or `none`. Internal tags are snake_case and
        // multi-detector decisions are comma-joined (most-suspicious
        // first), so emit only the primary detector, sanitized. The
        // full set goes to the bonus `X-WAF-Detectors` header below.
        // The raw (joined) `rule_id` is preserved on the tag for mode
        // re-resolution upstream — only the rendered value collapses.
        let rule_id = self
            .rule_id
            .as_deref()
            .map(sanitize_primary_rule_id)
            .unwrap_or_else(|| "none".to_string());
        insert(headers, RULE_ID, &rule_id);
        // §5.2 bonus — full detector list when more than one fired.
        if let Some(raw) = self.rule_id.as_deref() {
            if raw.contains(',') {
                let all: Vec<String> = raw
                    .split(',')
                    .map(sanitize_rule_id)
                    .filter(|s| s != "none")
                    .collect();
                if !all.is_empty() {
                    insert(headers, DETECTORS, &all.join(","));
                }
            }
        }
        insert(headers, CACHE, self.cache.as_str());
        insert(headers, MODE, self.mode.as_str());
        // RF-FP (2026-07-08 QC) — signal a body that the response filter
        // rewrote. Byte count only (never the redacted value).
        if let Some(sig) = self.response_filtered {
            insert(headers, RESPONSE_FILTERED, "true");
            insert(headers, FILTERED_BYTES, &sig.bytes_after.to_string());
        }
    }
}

/// v2.6 §5.1 — `X-WAF-Rule-Id` is singular. For a multi-detector tag
/// (`sqli,xss`, most-suspicious first) take the primary (first
/// segment) and sanitize it; for a single tag this is just
/// [`sanitize_rule_id`]. The complete list is carried separately on
/// `X-WAF-Detectors`.
pub fn sanitize_primary_rule_id(id: &str) -> String {
    let primary = id.split(',').next().unwrap_or(id);
    sanitize_rule_id(primary)
}

/// v2.6 §5.1 — `X-WAF-Rule-Id` must match `^([A-Za-z0-9-]+|none)$`
/// ("Alphanumeric + hyphens, e.g. `rule-001`, `policy-default`, or
/// `none`"). Internal rule tags are snake_case (`command_injection`)
/// and multi-detector decisions are comma-joined (`sqli,xss`), neither
/// of which is wire-legal. Normalize: map `_`, `,`, and whitespace to
/// `-`, drop any other non-conforming char, collapse runs of `-`, and
/// trim leading/trailing `-`. An empty result (tag was all
/// punctuation) becomes `none`.
///
/// Applied to BOTH the emitted `X-WAF-Rule-Id` header and the audit
/// `rule_id` field so the two stay byte-identical. Internal
/// `rule_to_feature` / `mode_for_rule` lookups operate on the RAW tag
/// (before stamping), so mode mapping is unaffected.
pub fn sanitize_rule_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for c in id.chars() {
        match c {
            c if c.is_ascii_alphanumeric() => out.push(c),
            '_' | ',' | '-' | ' ' | '\t' => {
                if !out.ends_with('-') {
                    out.push('-');
                }
            }
            _ => {} // drop anything else (e.g. ':', '/', '.')
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "none".to_string()
    } else {
        trimmed.to_string()
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

    /// 2026-06-21 — single source of truth for audit-emit ownership.
    /// The data plane (`handle_data_request`) self-emits a rich Detection
    /// row for every decision it terminates itself: `block`, `challenge`,
    /// and `rate_limit`. The listener must NOT re-emit those, or the Live
    /// Feed / Investigation table shows TWO rows per request. `allow` is
    /// the listener's sole responsibility, and the upstream-failure verdicts
    /// (`timeout`, `circuit_breaker`) are not self-audited by the data plane,
    /// so the listener owns them too. This test pins the policy for EVERY
    /// `Action` variant so a newly-added action can't silently regress into
    /// a double-row (the bug this replaced: `rate_limit` was listener-emitted
    /// AND data-plane-emitted).
    #[test]
    fn listener_audit_ownership_is_exhaustive_and_dedup_safe() {
        // Listener is the sole emitter.
        assert!(listener_emits_audit(Action::Allow));
        assert!(listener_emits_audit(Action::Timeout));
        assert!(listener_emits_audit(Action::CircuitBreaker));
        // Data plane already emitted — listener must stay silent.
        assert!(!listener_emits_audit(Action::Block));
        assert!(!listener_emits_audit(Action::Challenge));
        assert!(!listener_emits_audit(Action::RateLimit));
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

    /// A detected-but-allowed request carries the redacted request echo
    /// (headers + body preview) captured in the data plane so the listener
    /// audit shows the same detail a block does. Action must stay `allow`.
    #[test]
    fn with_audit_echo_attaches_fields_without_changing_action() {
        let mut echo = serde_json::Map::new();
        echo.insert(
            "request_body_preview".to_string(),
            serde_json::Value::String("id=1&q=hello".to_string()),
        );
        let tag = DecisionTag::allow().with_audit_echo(echo);
        assert_eq!(tag.action, Action::Allow);
        let carried = tag.audit_echo.expect("echo set");
        assert_eq!(
            carried.get("request_body_preview").and_then(|v| v.as_str()),
            Some("id=1&q=hello"),
        );
        // Untouched tags carry no echo (clean allows stay slim).
        assert!(DecisionTag::allow().audit_echo.is_none());
    }

    // ---- RF-FP (2026-07-08 QC) — response-filter signal -------------------

    #[test]
    fn with_response_filtered_sets_signal_without_changing_action() {
        let tag = DecisionTag::allow().with_response_filtered(120, 96);
        assert_eq!(tag.action, Action::Allow);
        let sig = tag.response_filtered.expect("signal set");
        assert_eq!(sig.bytes_before, 120);
        assert_eq!(sig.bytes_after, 96);
        // Untouched tags carry no signal.
        assert!(DecisionTag::allow().response_filtered.is_none());
    }

    #[test]
    fn decision_stamps_response_filtered_header() {
        let mut h = HeaderMap::new();
        let d = Decision {
            request_id: "r".into(),
            risk_score: 0,
            action: Action::Allow,
            rule_id: None,
            cache: CacheState::Bypass,
            mode: Mode::Enforce,
            response_filtered: Some(ResponseFilterSignal { bytes_before: 120, bytes_after: 96 }),
        };
        d.stamp(&mut h);
        assert_eq!(h.get(RESPONSE_FILTERED).unwrap(), "true");
        // A clean (unfiltered) decision must NOT stamp the header.
        let mut h2 = HeaderMap::new();
        Decision::allow("r".into(), 0, Mode::Enforce).stamp(&mut h2);
        assert!(!h2.contains_key(RESPONSE_FILTERED));
    }

    #[test]
    fn rule_id_with_filter_fallback_only_fills_unattributed() {
        // Filtered + no genuine attribution → name the filter.
        assert_eq!(
            rule_id_with_filter_fallback(None, true).as_deref(),
            Some("response_filter"),
        );
        assert_eq!(
            rule_id_with_filter_fallback(Some("none".into()), true).as_deref(),
            Some("response_filter"),
        );
        // Filtered + a genuine rule id → keep the real attribution.
        assert_eq!(
            rule_id_with_filter_fallback(Some("sqli".into()), true).as_deref(),
            Some("sqli"),
        );
        // Not filtered → unchanged.
        assert_eq!(rule_id_with_filter_fallback(None, false), None);
    }

    /// HIGH-1 (2026-06-19) — a `DecisionTag` defaults to NOT route-monitored
    /// and `with_route_log_only` flips the flag the stamper reads to force
    /// `X-WAF-Mode: log_only` on a forwarded monitored-route decision.
    #[test]
    fn route_log_only_defaults_false_and_builder_sets_it() {
        let plain = DecisionTag::block("xss");
        assert!(!plain.route_log_only, "default tag is not route-monitored");
        let monitored = DecisionTag::block("xss").with_route_log_only(true);
        assert!(monitored.route_log_only);
        // Action is unchanged — the flag only governs the reported mode.
        assert_eq!(monitored.action, Action::Block);
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
                response_filtered: None,
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
            response_filtered: tag.response_filtered,
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

    // ----- F-V26-001: X-WAF-Rule-Id §5.1 format -----

    fn is_wire_legal_rule_id(s: &str) -> bool {
        s == "none" || (!s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    }

    #[test]
    fn sanitize_rule_id_normalizes_underscores_commas_and_junk() {
        assert_eq!(sanitize_rule_id("command_injection"), "command-injection");
        assert_eq!(sanitize_rule_id("sqli,xss"), "sqli-xss");
        assert_eq!(sanitize_rule_id("sqli,brute_force"), "sqli-brute-force");
        assert_eq!(sanitize_rule_id("jwt_alg_none"), "jwt-alg-none");
        // already-legal ids are untouched
        assert_eq!(sanitize_rule_id("risk-challenge"), "risk-challenge");
        assert_eq!(sanitize_rule_id("none"), "none");
        // collapse + trim
        assert_eq!(sanitize_rule_id("a__b,,c"), "a-b-c");
        assert_eq!(sanitize_rule_id("_lead_trail_"), "lead-trail");
        // all-punctuation degrades to none
        assert_eq!(sanitize_rule_id(",,,"), "none");
        // drop other chars (':' '/' '.')
        assert_eq!(sanitize_rule_id("ns:rule/v1.2"), "nsrulev12");
    }

    #[test]
    fn stamp_emits_wire_legal_rule_id_for_snakecase_and_lists() {
        for raw in ["command_injection", "sqli,xss", "websocket_no_upstream_pool"] {
            let mut h = HeaderMap::new();
            Decision::block("rid".into(), 80, raw, Mode::Enforce).stamp(&mut h);
            let got = h.get(RULE_ID).unwrap().to_str().unwrap();
            assert!(
                is_wire_legal_rule_id(got),
                "X-WAF-Rule-Id {got:?} (from {raw:?}) must match ^([A-Za-z0-9-]+|none)$",
            );
        }
    }

    #[test]
    fn stamp_rule_id_is_primary_only_with_full_list_in_detectors() {
        let mut h = HeaderMap::new();
        // most-suspicious-first joined tag set, with a snake_case member
        Decision::block("rid".into(), 90, "sqli,xss,path_traversal", Mode::Enforce)
            .stamp(&mut h);
        // X-WAF-Rule-Id collapses to the single primary detector
        assert_eq!(h.get(RULE_ID).unwrap(), "sqli");
        // X-WAF-Detectors carries the full, per-token-sanitized list
        assert_eq!(h.get(DETECTORS).unwrap(), "sqli,xss,path-traversal");
    }

    #[test]
    fn stamp_single_detector_emits_no_detectors_header() {
        let mut h = HeaderMap::new();
        Decision::block("rid".into(), 90, "command_injection", Mode::Enforce).stamp(&mut h);
        assert_eq!(h.get(RULE_ID).unwrap(), "command-injection");
        assert!(h.get(DETECTORS).is_none(), "single detector → no bonus header");
    }

    // ----- F-V26-003: X-WAF-Risk-Score clamp to 0-100 -----

    #[test]
    fn stamp_clamps_risk_score_over_100_to_100() {
        let mut h = HeaderMap::new();
        Decision::block("rid".into(), 145, "sqli", Mode::Enforce).stamp(&mut h);
        assert_eq!(h.get(RISK_SCORE).unwrap(), "100");
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
