//! `/api/analytics/query` allow-listed PromQL proxy (D-M3-T3.11,
//! completed by PE-2 2026-07-04).
//!
//! Operators do **not** pass raw PromQL — `expr` is a key from a
//! fixed allow-list documented in
//! `docs/control-plane/enterprise/api.md` §"Analytics". The server
//! resolves the key to its canonical PromQL string and proxies it
//! to the external Prometheus configured via `admin.prometheus_url`
//! (`/api/v1/query` for instantaneous, `/api/v1/query_range` when
//! `start`+`end` are given). Without a configured backend the
//! endpoint keeps the honest F-CRITICAL-018 503s
//! (`analytics_not_implemented` / `no_history_backend`).
//!
//! This module owns the pure layers — plan ([`plan_query`]),
//! `$step` substitution ([`substitute_step`]), Prometheus wire-shape
//! parsing ([`parse_prometheus_body`]), and rendering. The HTTP
//! fetch lives proxy-side (`aegis-proxy::admin_get::
//! handle_analytics_query`) where the client stack is.


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
/// "matrix" for range). `Scalar.value` is `None` (wire: `null`) when
/// Prometheus returned an empty result — "no data yet" is a normal
/// state and must never render as a fake `0.0`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "lowercase")]
pub enum AnalyticsResult {
    Scalar { value: Option<f64> },
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

/// Validated query plan for `GET /api/analytics/query`.
#[derive(Clone, Copy, Debug)]
pub struct QueryPlan {
    pub promql: &'static str,
    pub is_range: bool,
}

/// Validate `expr` against the allow-list and classify the query.
/// `start`/`end` are unix epoch seconds; both non-zero with
/// `end >= start` ⇒ range query, anything else ⇒ instantaneous.
pub fn plan_query(expr: &str, start: u64, end: u64) -> Result<QueryPlan, AnalyticsRendering> {
    let promql = lookup_promql(expr).ok_or_else(|| {
        error_response(400, "unknown_expr", format!("unknown expr key: {expr}"))
    })?;
    let is_range = start != 0 && end != 0 && end >= start;
    Ok(QueryPlan { promql, is_range })
}

/// The honest no-backend 503s (F-CRITICAL-018: never 200-with-zeros).
pub fn unconfigured_response(is_range: bool) -> AnalyticsRendering {
    if is_range {
        error_response(
            503,
            "no_history_backend",
            "range queries require admin.prometheus_url".into(),
        )
    } else {
        error_response(
            503,
            "analytics_not_implemented",
            "wire admin.prometheus_url to enable analytics queries".into(),
        )
    }
}

/// Substitute the `$step` placeholder in a canonical PromQL string
/// with a concrete `<step>s` window.
pub fn substitute_step(promql: &str, step: u32) -> String {
    promql.replace("$step", &format!("{step}s"))
}

/// Parse a Prometheus `/api/v1/query[_range]` response body into the
/// wire result. Errors are human-readable strings for the 502
/// envelope; a Prometheus-side `"status":"error"` surfaces its
/// `error` detail.
pub fn parse_prometheus_body(body: &str, is_range: bool) -> Result<AnalyticsResult, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON from Prometheus: {e}"))?;
    match v["status"].as_str() {
        Some("success") => {}
        Some("error") => {
            let detail = v["error"].as_str().unwrap_or("unknown error");
            return Err(format!("Prometheus query error: {detail}"));
        }
        _ => return Err("Prometheus response missing status field".into()),
    }
    let data = &v["data"];
    let result = &data["result"];
    if is_range {
        // resultType "matrix": series of {metric, values: [[ts,"v"],..]}.
        // Single-series queries (all allow-listed range exprs aggregate
        // with sum()/quantile) — take the first series.
        let mut points = Vec::new();
        if let Some(series) = result.as_array().and_then(|a| a.first()) {
            for pair in series["values"].as_array().into_iter().flatten() {
                if let (Some(ts), Some(val)) = (pair[0].as_f64(), sample_value(&pair[1])) {
                    if let Some(ts) = chrono::DateTime::from_timestamp(ts as i64, 0) {
                        points.push(AnalyticsPoint { ts, value: val });
                    }
                }
            }
        }
        Ok(AnalyticsResult::Matrix { points })
    } else {
        match data["resultType"].as_str() {
            // "scalar": result is one [ts, "v"] pair.
            Some("scalar") => Ok(AnalyticsResult::Scalar {
                value: sample_value(&result[1]),
            }),
            // "vector": instant samples per series; empty = no data.
            Some("vector") => {
                let value = result
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|s| sample_value(&s["value"][1]));
                Ok(AnalyticsResult::Scalar { value })
            }
            other => Err(format!("unexpected Prometheus resultType: {other:?}")),
        }
    }
}

/// Prometheus encodes sample values as JSON strings ("4.2").
fn sample_value(v: &serde_json::Value) -> Option<f64> {
    v.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| v.as_f64())
}

/// 200 envelope around a parsed upstream result.
pub fn render_success(
    expr: &str,
    promql: &'static str,
    result: AnalyticsResult,
) -> AnalyticsRendering {
    ok_response(&AnalyticsResponse {
        expr: expr.to_string(),
        promql,
        result,
    })
}

/// 502 envelope — Prometheus unreachable / errored / unparseable.
pub fn upstream_error(message: String) -> AnalyticsRendering {
    error_response(502, "prometheus_unreachable", message)
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
mod pe2_prometheus_proxy_tests {
    // PE-2 (committee round-2 🔴3) — the Prometheus proxy call is
    // real now: plan → substitute $step → fetch (proxy side) →
    // parse the Prometheus wire shape → render. These tests pin the
    // pure layers (plan/substitute/parse/render); the HTTP fetch
    // itself is tested in aegis-proxy against a stub server.
    use super::*;

    #[test]
    fn plan_query_rejects_unknown_expr_with_400() {
        let err = plan_query("definitely-not-a-key", 0, 0).unwrap_err();
        assert_eq!(err.status, 400);
        let v: serde_json::Value = serde_json::from_str(&err.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("unknown_expr"));
    }

    #[test]
    fn plan_query_detects_range_vs_instant() {
        assert!(!plan_query("requests_rate", 0, 0).unwrap().is_range);
        assert!(plan_query("requests_rate", 1_000, 2_000).unwrap().is_range);
        // end < start is not a range — treated as instant.
        assert!(!plan_query("requests_rate", 2_000, 1_000).unwrap().is_range);
    }

    #[test]
    fn unconfigured_response_keeps_honest_503_codes() {
        // F-CRITICAL-018 regression — never 200-with-zeros when no
        // backend is wired.
        let r = unconfigured_response(false);
        assert_eq!(r.status, 503);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("analytics_not_implemented"));

        let r = unconfigured_response(true);
        assert_eq!(r.status, 503);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("no_history_backend"));
    }

    #[test]
    fn substitute_step_replaces_placeholder_with_seconds() {
        let q = substitute_step("sum(rate(waf_requests_total[$step]))", 60);
        assert_eq!(q, "sum(rate(waf_requests_total[60s]))");
        // No placeholder → unchanged.
        assert_eq!(substitute_step("waf_bench_mode", 60), "waf_bench_mode");
    }

    #[test]
    fn parse_instant_vector_takes_first_sample() {
        let body = r#"{"status":"success","data":{"resultType":"vector",
            "result":[{"metric":{},"value":[1751600000.0,"4.2"]}]}}"#;
        match parse_prometheus_body(body, false).unwrap() {
            AnalyticsResult::Scalar { value } => assert_eq!(value, Some(4.2)),
            other => panic!("expected scalar, got {other:?}"),
        }
    }

    #[test]
    fn parse_instant_scalar_result_type() {
        let body = r#"{"status":"success","data":{"resultType":"scalar",
            "result":[1751600000.0,"7.5"]}}"#;
        match parse_prometheus_body(body, false).unwrap() {
            AnalyticsResult::Scalar { value } => assert_eq!(value, Some(7.5)),
            other => panic!("expected scalar, got {other:?}"),
        }
    }

    #[test]
    fn parse_instant_empty_vector_is_null_value() {
        // "No data yet" is a normal state, not an upstream error —
        // surfaced as value: null, never a fake 0.0.
        let body = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        match parse_prometheus_body(body, false).unwrap() {
            AnalyticsResult::Scalar { value } => assert_eq!(value, None),
            other => panic!("expected scalar, got {other:?}"),
        }
    }

    #[test]
    fn parse_range_matrix_maps_points() {
        let body = r#"{"status":"success","data":{"resultType":"matrix",
            "result":[{"metric":{},"values":[[1751600000.0,"1.5"],[1751600060.0,"2.5"]]}]}}"#;
        match parse_prometheus_body(body, true).unwrap() {
            AnalyticsResult::Matrix { points } => {
                assert_eq!(points.len(), 2);
                assert_eq!(points[0].value, 1.5);
                assert_eq!(points[1].value, 2.5);
                assert!(points[1].ts > points[0].ts);
            }
            other => panic!("expected matrix, got {other:?}"),
        }
    }

    #[test]
    fn parse_range_empty_matrix_is_empty_points() {
        let body = r#"{"status":"success","data":{"resultType":"matrix","result":[]}}"#;
        match parse_prometheus_body(body, true).unwrap() {
            AnalyticsResult::Matrix { points } => assert!(points.is_empty()),
            other => panic!("expected matrix, got {other:?}"),
        }
    }

    #[test]
    fn parse_surfaces_prometheus_error_status() {
        let body = r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#;
        let err = parse_prometheus_body(body, false).unwrap_err();
        assert!(err.contains("parse error"), "error detail lost: {err}");
    }

    #[test]
    fn parse_rejects_garbage_body() {
        assert!(parse_prometheus_body("not json", false).is_err());
        assert!(parse_prometheus_body("{}", false).is_err());
    }

    #[test]
    fn render_success_flattens_result() {
        let r = render_success(
            "requests_rate",
            "sum(rate(waf_requests_total[$step]))",
            AnalyticsResult::Scalar { value: Some(4.2) },
        );
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["expr"].as_str(), Some("requests_rate"));
        assert_eq!(v["result_type"].as_str(), Some("scalar"));
        assert_eq!(v["value"].as_f64(), Some(4.2));
    }

    #[test]
    fn upstream_error_returns_502_envelope() {
        let r = upstream_error("connect refused".into());
        assert_eq!(r.status, 502);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("prometheus_unreachable"));
        assert!(v["error"]["message"].as_str().unwrap().contains("connect refused"));
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
    fn every_documented_key_plans_successfully() {
        // Each allow-listed key must resolve to a plan (PE-2 —
        // the render path is exercised in pe2_prometheus_proxy_tests
        // and the proxy-side stub-server tests).
        for (key, _) in ALLOW_LIST {
            let plan = plan_query(key, 0, 0).unwrap_or_else(|_| panic!("key {key} rejected"));
            assert!(!plan.promql.is_empty());
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

}
