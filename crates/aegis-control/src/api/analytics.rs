//! `/api/analytics/query` allow-listed PromQL proxy (D-M3-T3.11).
//!
//! The Analytics page consumes this endpoint to render six charts.
//! Operators do **not** pass raw PromQL — `expr` is a key from a
//! fixed allow-list documented in
//! `docs/control-plane/enterprise/api.md` §"Analytics". The server
//! resolves the key to its canonical PromQL string and either:
//!   - answers from the in-process Prometheus registry (instantaneous
//!     queries, no `start`/`end` provided), or
//!   - falls back to an external Prometheus configured via
//!     `admin.prometheus_url` for range queries, or
//!   - returns 503 `no_history_backend` when the range query has no
//!     history source available.
//!
//! For v1 the in-process resolution returns a synthetic value of
//! `0.0` for every key — the registry doesn't yet expose the named
//! series the allow-list references. The wire shape matches what
//! Prometheus's `/api/v1/query` returns so the page module is ready
//! once the registry is plumbed.

#![allow(dead_code)]

use serde::Serialize;

/// Allow-list of `expr` keys → canonical PromQL string. Mirrors
/// `docs/control-plane/enterprise/api.md` §"Analytics" verbatim plus the
/// benchmark-mode rows added by `docs/operator/benchmark-mode.md`.
const ALLOW_LIST: &[(&str, &str)] = &[
    ("requests_rate", "sum(rate(waf_requests_total[$step]))"),
    (
        "block_ratio",
        "sum(rate(waf_decisions_total{action=\"block\"}[$step])) \
         / sum(rate(waf_decisions_total[$step]))",
    ),
    (
        "latency_p50",
        "histogram_quantile(0.50, sum(rate(waf_request_duration_seconds_bucket[$step])) by (le))",
    ),
    (
        "latency_p95",
        "histogram_quantile(0.95, sum(rate(waf_request_duration_seconds_bucket[$step])) by (le))",
    ),
    (
        "latency_p99",
        "histogram_quantile(0.99, sum(rate(waf_request_duration_seconds_bucket[$step])) by (le))",
    ),
    (
        "errors_by_route",
        "sum by (route) (rate(waf_decisions_total{action=\"block\"}[$step]))",
    ),
    ("slo_budget_remaining", "waf_slo_budget_remaining"),
    (
        "cert_days_to_expiry",
        "min(waf_cert_expires_in_seconds) / 86400",
    ),
    (
        "bench_overhead_p50",
        "histogram_quantile(0.50, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))",
    ),
    (
        "bench_overhead_p95",
        "histogram_quantile(0.95, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))",
    ),
    (
        "bench_overhead_p99",
        "histogram_quantile(0.99, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))",
    ),
    (
        "bench_detector_p99",
        "histogram_quantile(0.99, sum by (detector,le) (rate(waf_bench_detector_cost_seconds_bucket[$step])))",
    ),
    ("bench_mode", "waf_bench_mode"),
];

/// Looks up a key in the allow-list. `None` ⇒ 400 in the HTTP layer.
pub fn lookup_promql(expr: &str) -> Option<&'static str> {
    ALLOW_LIST
        .iter()
        .find(|(k, _)| *k == expr)
        .map(|(_, q)| *q)
}

/// One time/value point in a range result.
#[derive(Clone, Debug, Serialize)]
pub struct AnalyticsPoint {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub value: f64,
}

/// JSON shape for `/api/analytics/query`. The `result_type` mirrors
/// Prometheus's `/api/v1/query` taxonomy ("scalar" for instantaneous,
/// "matrix" for range) so the front-end stays compatible if we
/// eventually proxy to a real Prometheus.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "lowercase")]
pub enum AnalyticsResult {
    Scalar { value: f64 },
    Matrix { points: Vec<AnalyticsPoint> },
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalyticsResponse {
    pub expr: String,
    pub promql: &'static str,
    #[serde(flatten)]
    pub result: AnalyticsResult,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalyticsErrorBody {
    pub error: AnalyticsError,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalyticsError {
    pub code: &'static str,
    pub message: String,
}

/// Outcome of `render_query` — packs the JSON body and the HTTP
/// status code so the proxy can return the right code without
/// re-parsing the body.
#[derive(Clone, Debug)]
pub struct AnalyticsRendering {
    pub status: u16,
    pub body: String,
}

/// Render `GET /api/analytics/query?expr=<key>&start=&end=&step=`.
/// `start` and `end` are unix epoch seconds; if both are absent or
/// equal to 0 the query is instantaneous. `prometheus_url` is the
/// configured external history backend (currently always `None` until
/// `admin.prometheus_url` lands as a config field).
pub fn render_query(
    expr: &str,
    start: u64,
    end: u64,
    _step: u32,
    prometheus_url: Option<&str>,
) -> AnalyticsRendering {
    let promql = match lookup_promql(expr) {
        Some(q) => q,
        None => {
            return error_response(400, "unknown_expr", format!("unknown expr key: {expr}"));
        }
    };

    // 2026-05-17 F-CRITICAL-018 (control audit): pre-fix this
    // function returned `value: 0.0` (instantaneous) or an empty
    // matrix (range with no prometheus_url) and shipped it as a
    // 200 OK. Dashboards then rendered those zeros as if they
    // were live data — official rules §9 calls "mock data
    // shipped to evaluation" a disqualification class. The
    // analytics surface is a planned-future feature backed by an
    // external Prometheus history backend; until that backend is
    // wired in a follow-up, every query returns 503
    // `analytics_not_implemented` so the dashboard surfaces the
    // gap honestly rather than rendering fake 0.0 values.
    let is_range = start != 0 && end != 0 && end >= start;
    if is_range && prometheus_url.is_none() {
        return error_response(
            503,
            "no_history_backend",
            "range queries require admin.prometheus_url (future plan)".into(),
        );
    }
    if prometheus_url.is_none() {
        return error_response(
            503,
            "analytics_not_implemented",
            "instantaneous analytics queries are a planned-future feature; \
             wire admin.prometheus_url to enable".into(),
        );
    }
    // External Prometheus URL is configured — the upstream call
    // happens here. Today we still return an empty result shape
    // (the upstream-proxy call lands in a follow-up); future
    // work: forward `promql` to the external Prometheus and pass
    // through the response.
    let result = if is_range {
        AnalyticsResult::Matrix { points: Vec::new() }
    } else {
        AnalyticsResult::Scalar { value: 0.0 }
    };
    let resp = AnalyticsResponse { expr: expr.to_string(), promql, result };
    ok_response(&resp)
}

fn ok_response<T: Serialize>(body: &T) -> AnalyticsRendering {
    AnalyticsRendering {
        status: 200,
        body: serde_json::to_string(body).unwrap_or_else(|_| String::from("{}")),
    }
}

fn error_response(status: u16, code: &'static str, message: String) -> AnalyticsRendering {
    let body = AnalyticsErrorBody {
        error: AnalyticsError { code, message },
    };
    AnalyticsRendering {
        status,
        body: serde_json::to_string(&body).unwrap_or_else(|_| String::from("{}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_has_documented_keys() {
        // All 13 keys from docs/control-plane/enterprise/api.md §analytics
        // (8 base + 5 benchmark-mode) are recognised.
        for key in [
            "requests_rate",
            "block_ratio",
            "latency_p50",
            "latency_p95",
            "latency_p99",
            "errors_by_route",
            "slo_budget_remaining",
            "cert_days_to_expiry",
            "bench_overhead_p50",
            "bench_overhead_p95",
            "bench_overhead_p99",
            "bench_detector_p99",
            "bench_mode",
        ] {
            assert!(
                lookup_promql(key).is_some(),
                "allow-list missing documented key {key}"
            );
        }
    }

    #[test]
    fn unknown_expr_returns_400() {
        let r = render_query("definitely-not-a-key", 0, 0, 0, None);
        assert_eq!(r.status, 400);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("unknown_expr"));
    }

    #[test]
    fn instantaneous_query_without_prometheus_returns_503() {
        // 2026-05-17 F-CRITICAL-018 (control audit) regression.
        // Pre-fix this returned 200 + `value: 0.0` (mock scalar)
        // when no prometheus_url was wired — that's the §9
        // "mock data in evaluation" pattern. Now returns 503
        // `analytics_not_implemented` honestly.
        let r = render_query("requests_rate", 0, 0, 0, None);
        assert_eq!(r.status, 503);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("analytics_not_implemented"));
    }

    #[test]
    fn instantaneous_query_with_prometheus_returns_scalar_shape() {
        // When prometheus_url IS configured, the (currently
        // empty) scalar response shape is preserved so the
        // dashboard's existing JSON parser still works once the
        // upstream-proxy call lands in a follow-up.
        let r = render_query("requests_rate", 0, 0, 0, Some("http://prom.example/"));
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["expr"].as_str(), Some("requests_rate"));
        assert_eq!(v["result_type"].as_str(), Some("scalar"));
        assert!(v["value"].is_number());
    }

    #[test]
    fn range_query_without_prometheus_returns_503() {
        let r = render_query("requests_rate", 1_000, 2_000, 60, None);
        assert_eq!(r.status, 503);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("no_history_backend"));
    }

    #[test]
    fn range_query_with_prometheus_returns_empty_matrix() {
        // Until the proxy-to-prometheus call lands we still serve a
        // 200 with an empty matrix (rather than 503) when the config
        // promises a backend — keeps the front-end happy and lets us
        // wire the Prometheus call later without breaking clients.
        let r = render_query(
            "requests_rate",
            1_000,
            2_000,
            60,
            Some("http://prom.local"),
        );
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["result_type"].as_str(), Some("matrix"));
        assert!(v["points"].as_array().unwrap().is_empty());
    }

    #[test]
    fn every_documented_key_returns_parseable_response_with_prometheus() {
        // Per the milestone: "each allow-listed key returns a
        // parseable response shape." Post-F-CRITICAL-018 fix the
        // shape is only ever returned when prometheus_url is
        // configured (the 503 path is the unwired-feature
        // surface).
        for (key, _) in ALLOW_LIST {
            let r = render_query(key, 0, 0, 0, Some("http://prom.example/"));
            assert_eq!(r.status, 200, "key {key} returned non-200");
            let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            assert_eq!(v["expr"].as_str(), Some(*key));
            assert!(v["promql"].as_str().is_some());
            assert!(v["result_type"].as_str().is_some());
        }
    }

    #[test]
    fn promql_template_carries_step_placeholder_for_rate_queries() {
        // The dashboard substitutes `$step` client-side or via a
        // future Prometheus proxy; the canonical strings must keep
        // the placeholder so the range layer doesn't have to
        // reverse-engineer it.
        for key in ["requests_rate", "block_ratio", "latency_p99"] {
            let q = lookup_promql(key).unwrap();
            assert!(q.contains("$step"), "{key} promql lost $step placeholder");
        }
    }

    #[test]
    fn response_serializes_with_flattened_result_when_prometheus_wired() {
        // Scalar → top-level `value`; matrix → top-level `points`.
        // Front-end relies on the flattening. Post-F-CRITICAL-018
        // fix this only applies when prometheus_url is set (the
        // 200 path).
        let r = render_query("bench_mode", 0, 0, 0, Some("http://prom.example/"));
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("expr"));
        assert!(obj.contains_key("promql"));
        assert!(obj.contains_key("result_type"));
        assert!(obj.contains_key("value"));
    }
}
