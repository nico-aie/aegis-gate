//! Benchmark mode (B5-T2 — Phase B).
//!
//! Gated, opt-in surface that exposes per-request WAF
//! timing on the response so operators can attribute a slow
//! request to a specific pipeline stage without standing up
//! external tracing. Three concerns:
//!
//! 1. **Config** — [`BenchmarkConfig`] holds the runtime
//!    knob. Off by default; flipping `enabled = true` opts
//!    in.
//! 2. **Timing capture** — [`StageTimings`] records
//!    monotonic durations per stage (route, security pipeline,
//!    upstream forward, total).
//! 3. **Header serialisation** — [`build_aegis_headers`]
//!    formats the captured timings into a fixed list of
//!    `X-Aegis-Stage-*` response headers. ASCII-only,
//!    truncated to 1 KiB total per
//!    [`MAX_HEADER_PAYLOAD_BYTES`] so a misconfigured
//!    benchmark can't blow the response head.
//!
//! This module is **not** the full benchmark plan in
//! [`plans/benchmark-mode.md`](../../../plans/benchmark-mode.md)
//! — IP allowlist, HMAC token gating, per-detector timing,
//! and the `aegis-control` dashboard panel are all
//! deferred. What lands here is the seam: when off, the
//! data plane pays one boolean check per request.

use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderName, HeaderValue};

/// Maximum total bytes the `X-Aegis-*` header set may
/// occupy on a response. RFC 7230 §3.2.5 doesn't cap header
/// size, but most reverse proxies (nginx default 8 KiB,
/// haproxy default 16 KiB) reject larger payloads silently;
/// 1 KiB leaves headroom for the rest of the response head.
pub const MAX_HEADER_PAYLOAD_BYTES: usize = 1024;

/// Header names we emit. Stable strings so a typo in the
/// hot path can't push a name the dashboard doesn't know
/// how to read.
pub mod hdr {
    pub const TOTAL_US: &str = "x-aegis-stage-total-us";
    pub const ROUTE_US: &str = "x-aegis-stage-route-us";
    pub const SECURITY_US: &str = "x-aegis-stage-security-us";
    pub const UPSTREAM_US: &str = "x-aegis-stage-upstream-us";
    pub const TIER: &str = "x-aegis-tier";
    pub const DECISION: &str = "x-aegis-decision";
    pub const RULE_ID: &str = "x-aegis-rule-id";
    pub const REQUEST_ID: &str = "x-aegis-request-id";
    pub const BUILD: &str = "x-aegis-build";
}

/// Runtime config. Loaded from `WafConfig.benchmark` (added
/// as `serde(default)` so existing configs keep working).
#[derive(Clone, Debug, Default)]
pub struct BenchmarkConfig {
    /// Master switch. When `false`, [`build_aegis_headers`]
    /// returns an empty header map and `StageTimings`
    /// allocations are skipped at the call site.
    pub enabled: bool,
    /// Whether to include rule IDs in the
    /// `X-Aegis-Rule-Id` header. Off by default — exposing
    /// rule IDs leaks internal policy structure to clients
    /// in production.
    pub expose_rule_ids: bool,
}

impl BenchmarkConfig {
    pub fn off() -> Self {
        Self::default()
    }

    /// Fast-path probe used by the proxy hot path. The
    /// Boolean check is one cmp + branch — cheaper than
    /// allocating a `StageTimings` per request when
    /// benchmarking is off.
    #[inline]
    pub fn is_on(&self) -> bool {
        self.enabled
    }
}

/// Captured per-request timing. Cheap to construct; only
/// allocated when [`BenchmarkConfig::is_on`].
#[derive(Clone, Debug, Default)]
pub struct StageTimings {
    pub route: Option<Duration>,
    pub security: Option<Duration>,
    pub upstream: Option<Duration>,
    pub total: Option<Duration>,
    pub tier: Option<String>,
    pub decision: Option<String>,
    pub rule_id: Option<String>,
    pub request_id: Option<String>,
}

impl StageTimings {
    /// Start a stopwatch. Use [`Stopwatch::stop_into`] to
    /// fill a `StageTimings` field in one call site.
    pub fn stopwatch() -> Stopwatch {
        Stopwatch {
            start: Instant::now(),
        }
    }
}

/// One-shot stopwatch.
#[derive(Debug)]
pub struct Stopwatch {
    start: Instant,
}

impl Stopwatch {
    /// Time elapsed since construction.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Format a Duration in **microseconds** as an integer
/// string. `42µs` → `"42"`, `2.7ms` → `"2700"`.
pub fn format_us(d: Duration) -> String {
    d.as_micros().to_string()
}

/// Build the response headers. Returns an empty map when
/// `cfg.enabled` is false (operators get zero-cost behaviour
/// without conditional call sites). Truncates aggressively
/// if the payload would exceed [`MAX_HEADER_PAYLOAD_BYTES`].
pub fn build_aegis_headers(
    timings: &StageTimings,
    cfg: &BenchmarkConfig,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    if !cfg.is_on() {
        return out;
    }

    let mut budget = MAX_HEADER_PAYLOAD_BYTES;

    let mut try_insert = |name: &'static str, value: String| {
        let name_len = name.len();
        let value_len = value.len();
        // Header line cost: name + ": " + value + "\r\n" = 4 bytes overhead.
        let cost = name_len + value_len + 4;
        if cost > budget {
            return;
        }
        let header_name = match HeaderName::from_static_safe(name) {
            Some(n) => n,
            None => return,
        };
        let header_value = match HeaderValue::from_str(&value) {
            Ok(v) => v,
            Err(_) => return,
        };
        out.insert(header_name, header_value);
        budget = budget.saturating_sub(cost);
    };

    if let Some(d) = timings.total {
        try_insert(hdr::TOTAL_US, format_us(d));
    }
    if let Some(d) = timings.route {
        try_insert(hdr::ROUTE_US, format_us(d));
    }
    if let Some(d) = timings.security {
        try_insert(hdr::SECURITY_US, format_us(d));
    }
    if let Some(d) = timings.upstream {
        try_insert(hdr::UPSTREAM_US, format_us(d));
    }
    if let Some(t) = &timings.tier {
        try_insert(hdr::TIER, sanitise_ascii(t));
    }
    if let Some(d) = &timings.decision {
        try_insert(hdr::DECISION, sanitise_ascii(d));
    }
    if let Some(rid) = &timings.request_id {
        try_insert(hdr::REQUEST_ID, sanitise_ascii(rid));
    }
    if cfg.expose_rule_ids {
        if let Some(r) = &timings.rule_id {
            try_insert(hdr::RULE_ID, sanitise_ascii(r));
        }
    }

    out
}

/// Drop any non-printable ASCII byte. HTTP header values are
/// 7-bit ASCII per RFC 7230 §3.2.6 — anything else is
/// rejected by `HeaderValue::from_str`. Operators sometimes
/// surface user-provided strings (rule IDs, tenant names) so
/// we sanitise rather than crash.
fn sanitise_ascii(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect()
}

/// Wrapper around [`HeaderName::from_static`] that returns
/// `None` instead of panicking — so a typo in a header
/// constant can't take down the proxy on first request.
trait HeaderNameStaticSafe {
    fn from_static_safe(s: &'static str) -> Option<HeaderName>;
}

impl HeaderNameStaticSafe for HeaderName {
    fn from_static_safe(s: &'static str) -> Option<HeaderName> {
        // `HeaderName::from_static` panics on invalid; we
        // construct from bytes which returns Result.
        HeaderName::from_bytes(s.as_bytes()).ok()
    }
}

/// Apply benchmark headers in-place onto an outbound
/// `Response`. The proxy hot path calls this after the
/// upstream forward returns, so the upstream's own headers
/// are present first and we only stamp ours on top.
pub fn stamp_headers<B>(
    resp: &mut hyper::Response<B>,
    timings: &StageTimings,
    cfg: &BenchmarkConfig,
) {
    if !cfg.is_on() {
        return;
    }
    let extra = build_aegis_headers(timings, cfg);
    let dst = resp.headers_mut();
    for (name, value) in extra.iter() {
        dst.insert(name.clone(), value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timings_full() -> StageTimings {
        StageTimings {
            route: Some(Duration::from_micros(20)),
            security: Some(Duration::from_micros(150)),
            upstream: Some(Duration::from_micros(2500)),
            total: Some(Duration::from_micros(2700)),
            tier: Some("high".into()),
            decision: Some("allow".into()),
            rule_id: Some("R-1234".into()),
            request_id: Some("abc-def-001".into()),
        }
    }

    #[test]
    fn config_off_by_default() {
        let c = BenchmarkConfig::default();
        assert!(!c.is_on());
        assert!(!c.expose_rule_ids);
    }

    #[test]
    fn build_returns_empty_when_disabled() {
        let cfg = BenchmarkConfig::off();
        let headers = build_aegis_headers(&timings_full(), &cfg);
        assert!(headers.is_empty());
    }

    #[test]
    fn build_emits_total_us_when_enabled() {
        let cfg = BenchmarkConfig {
            enabled: true,
            ..Default::default()
        };
        let headers = build_aegis_headers(&timings_full(), &cfg);
        assert_eq!(
            headers.get(hdr::TOTAL_US).unwrap().to_str().unwrap(),
            "2700"
        );
    }

    #[test]
    fn build_emits_per_stage_us_when_enabled() {
        let cfg = BenchmarkConfig {
            enabled: true,
            ..Default::default()
        };
        let headers = build_aegis_headers(&timings_full(), &cfg);
        assert_eq!(
            headers.get(hdr::ROUTE_US).unwrap().to_str().unwrap(),
            "20"
        );
        assert_eq!(
            headers.get(hdr::SECURITY_US).unwrap().to_str().unwrap(),
            "150"
        );
        assert_eq!(
            headers.get(hdr::UPSTREAM_US).unwrap().to_str().unwrap(),
            "2500"
        );
    }

    #[test]
    fn build_omits_rule_id_by_default() {
        let cfg = BenchmarkConfig {
            enabled: true,
            expose_rule_ids: false,
        };
        let headers = build_aegis_headers(&timings_full(), &cfg);
        assert!(!headers.contains_key(hdr::RULE_ID));
    }

    #[test]
    fn build_emits_rule_id_when_explicitly_enabled() {
        let cfg = BenchmarkConfig {
            enabled: true,
            expose_rule_ids: true,
        };
        let headers = build_aegis_headers(&timings_full(), &cfg);
        assert_eq!(
            headers.get(hdr::RULE_ID).unwrap().to_str().unwrap(),
            "R-1234"
        );
    }

    #[test]
    fn build_emits_tier_decision_request_id() {
        let cfg = BenchmarkConfig {
            enabled: true,
            ..Default::default()
        };
        let headers = build_aegis_headers(&timings_full(), &cfg);
        assert_eq!(
            headers.get(hdr::TIER).unwrap().to_str().unwrap(),
            "high"
        );
        assert_eq!(
            headers.get(hdr::DECISION).unwrap().to_str().unwrap(),
            "allow"
        );
        assert_eq!(
            headers.get(hdr::REQUEST_ID).unwrap().to_str().unwrap(),
            "abc-def-001"
        );
    }

    #[test]
    fn build_skips_missing_optional_fields() {
        let cfg = BenchmarkConfig {
            enabled: true,
            ..Default::default()
        };
        let timings = StageTimings {
            total: Some(Duration::from_micros(100)),
            ..Default::default()
        };
        let headers = build_aegis_headers(&timings, &cfg);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(hdr::TOTAL_US));
    }

    #[test]
    fn format_us_micros_below_milli() {
        assert_eq!(format_us(Duration::from_micros(42)), "42");
    }

    #[test]
    fn format_us_milliseconds() {
        assert_eq!(format_us(Duration::from_millis(2)), "2000");
    }

    #[test]
    fn format_us_zero() {
        assert_eq!(format_us(Duration::from_micros(0)), "0");
    }

    #[test]
    fn format_us_large_value() {
        // 1 second.
        assert_eq!(format_us(Duration::from_secs(1)), "1000000");
    }

    #[test]
    fn sanitise_ascii_drops_high_bytes() {
        assert_eq!(sanitise_ascii("héllo"), "hllo");
    }

    #[test]
    fn sanitise_ascii_drops_newlines() {
        assert_eq!(sanitise_ascii("a\nb\rc"), "abc");
    }

    #[test]
    fn sanitise_ascii_keeps_dashes_and_dots() {
        assert_eq!(sanitise_ascii("R-1234.alpha"), "R-1234.alpha");
    }

    #[test]
    fn header_payload_truncates_below_budget() {
        // Construct a `tier` value longer than the budget;
        // the function must drop it rather than emit.
        let cfg = BenchmarkConfig {
            enabled: true,
            ..Default::default()
        };
        let timings = StageTimings {
            tier: Some("X".repeat(2048)),
            total: Some(Duration::from_micros(1)),
            ..Default::default()
        };
        let headers = build_aegis_headers(&timings, &cfg);
        // Total fits, tier doesn't.
        assert!(headers.contains_key(hdr::TOTAL_US));
        assert!(!headers.contains_key(hdr::TIER));
    }

    #[test]
    fn stopwatch_measures_elapsed() {
        let sw = StageTimings::stopwatch();
        std::thread::sleep(Duration::from_millis(2));
        assert!(sw.elapsed() >= Duration::from_millis(2));
    }

    #[test]
    fn stamp_headers_no_op_when_disabled() {
        let cfg = BenchmarkConfig::off();
        let mut resp = hyper::Response::builder()
            .status(200)
            .body(())
            .unwrap();
        stamp_headers(&mut resp, &timings_full(), &cfg);
        assert!(!resp.headers().contains_key(hdr::TOTAL_US));
    }

    #[test]
    fn stamp_headers_attaches_when_enabled() {
        let cfg = BenchmarkConfig {
            enabled: true,
            ..Default::default()
        };
        let mut resp = hyper::Response::builder()
            .status(200)
            .body(())
            .unwrap();
        stamp_headers(&mut resp, &timings_full(), &cfg);
        assert!(resp.headers().contains_key(hdr::TOTAL_US));
        assert_eq!(
            resp.headers().get(hdr::TOTAL_US).unwrap().to_str().unwrap(),
            "2700"
        );
    }

    #[test]
    fn header_constants_are_lowercase() {
        // hyper / http normalise header names to lowercase
        // anyway, but the constants are pinned lowercase so
        // string comparisons on the dashboard side stay
        // exact.
        for c in &[
            hdr::TOTAL_US,
            hdr::ROUTE_US,
            hdr::SECURITY_US,
            hdr::UPSTREAM_US,
            hdr::TIER,
            hdr::DECISION,
            hdr::RULE_ID,
            hdr::REQUEST_ID,
            hdr::BUILD,
        ] {
            assert_eq!(*c, c.to_lowercase(), "{c} should be lowercase");
        }
    }
}
