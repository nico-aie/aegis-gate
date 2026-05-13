//! PRE-T1 — shared response-builder helpers extracted from
//! `lib.rs` so the rest of the refactor (PRE-T2 onwards) can
//! land focused submodules without each one re-implementing
//! the same `Response::builder()` boilerplate.
//!
//! ## Scope
//!
//! Pure functions only — no closures, no I/O, no
//! lifetime-coupled types. Six helpers:
//!
//! - [`json_response`] — JSON body from a `serde_json::Value`.
//! - [`json_body_response`] — JSON body from a pre-rendered
//!   `String`, with explicit `Cache-Control`.
//! - [`apply_dashboard_security_headers`] — single
//!   application point for `aegis_control::dashboard::security::SECURITY_HEADERS`.
//! - [`dashboard_response`] — convert a
//!   `DashboardResponse` (Shell / Asset / AssetNotFound) into
//!   a hyper response with the right headers.
//! - [`dashboard_shell_response`] — serve the SPA shell or
//!   the legacy v1 shell.
//! - [`mutation_error_response`] — render a
//!   `MutationError` into a JSON error response with the
//!   right HTTP status.
//!
//! Visibility is `pub(crate)` — these are internal to
//! aegis-proxy. Call sites in `lib.rs` (and the upcoming
//! `admin/`, `data_plane.rs`, `run.rs` submodules) `use`
//! them by-name so the refactor is invisible at the call
//! site.

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

/// Build a JSON response from a `serde_json::Value`. Uses a
/// fallback `"{}"` body if serialisation fails — the only way
/// this can happen with our shapes is OOM, so the fallback
/// keeps the handler infallible.
pub(crate) fn json_response(
    status: u16,
    value: &serde_json::Value,
) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// JSON response from a pre-rendered body. Adds
/// `Cache-Control` per the per-endpoint TTLs documented in
/// `docs/control-plane/enterprise/api.md` §"Caching".
pub(crate) fn json_body_response(
    status: u16,
    body: String,
    cache_control: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", cache_control)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Apply the documented dashboard security headers to a
/// response builder. Single application point for the
/// `aegis_control::dashboard::security::SECURITY_HEADERS`
/// table — see
/// `docs/control-plane/enterprise/security.md`
/// §"Headers (full set …)".
pub(crate) fn apply_dashboard_security_headers(
    mut builder: hyper::http::response::Builder,
) -> hyper::http::response::Builder {
    for (name, value) in aegis_control::dashboard::security::SECURITY_HEADERS {
        builder = builder.header(*name, *value);
    }
    builder
}

/// Convert an
/// [`aegis_control::dashboard::dispatch::DashboardResponse`]
/// into a hyper response. Centralises the dashboard transport
/// rules so security headers, ETags, and cache-control all
/// sit in one place.
///
/// `use_legacy` selects between the v1 single-file shell and
/// the enterprise SPA for the `Shell` variant only; asset
/// routes are independent of the toggle.
pub(crate) fn dashboard_response(
    r: aegis_control::dashboard::dispatch::DashboardResponse,
    use_legacy: bool,
) -> Response<Full<Bytes>> {
    use aegis_control::dashboard::dispatch::DashboardResponse;
    match r {
        DashboardResponse::Shell => dashboard_shell_response(use_legacy),
        DashboardResponse::Asset(asset) => apply_dashboard_security_headers(
            Response::builder()
                .status(200)
                .header("content-type", asset.content_type)
                .header("etag", format!("\"{}\"", asset.etag))
                // 2026-05-11 post-QA HIGH-01 — per-asset
                // cache-control. App-bundled assets (app.js,
                // index.html, aegis.css, i18n.json) ride on
                // `no-cache, must-revalidate`; vendored React UMD
                // bundles keep the 1-hour long cache. See
                // `aegis_control::dashboard::assets::EmbeddedAsset.
                // cache_control` for the policy table.
                .header("cache-control", asset.cache_control),
        )
        .body(Full::new(Bytes::from_static(asset.bytes)))
        .unwrap(),
        DashboardResponse::AssetNotFound => apply_dashboard_security_headers(
            Response::builder()
                .status(404)
                .header("content-type", "application/json"),
        )
        .body(Full::new(Bytes::from_static(
            br#"{"error":"asset not found"}"#,
        )))
        .unwrap(),
    }
}

/// Serve the SPA shell (`index.html`) by default, or the
/// legacy v1 shell when `use_legacy` is `true` (admin opt-in
/// via `cfg.admin.dashboard.legacy_shell`).
pub(crate) fn dashboard_shell_response(
    use_legacy: bool,
) -> Response<Full<Bytes>> {
    let shell = aegis_control::dashboard::dispatch::shell_for(use_legacy);
    apply_dashboard_security_headers(
        Response::builder()
            .status(200)
            .header("content-type", shell.content_type)
            .header("cache-control", "no-store"),
    )
    .body(Full::new(Bytes::from_static(shell.bytes)))
    .unwrap()
}

/// Convert a
/// [`aegis_control::api::mutation::MutationError`] into a
/// JSON error response with the right HTTP status code +
/// `Cache-Control: private, no-store` (mutations should never
/// be cached).
pub(crate) fn mutation_error_response(
    err: aegis_control::api::mutation::MutationError,
) -> Response<Full<Bytes>> {
    json_body_response(err.http_status(), err.to_body(), "private, no-store")
}

/// Pull a single named cookie value out of a `Cookie:` header
/// payload. Returns `None` if the cookie isn't present.
///
/// Shared helper — used by 7+ call sites across login/logout,
/// CSRF-gated mutation handlers, and SSE auth. Pure str-slice
/// scan, no allocation.
pub(crate) fn extract_named_cookie<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some(rest) = trimmed.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_to_string(resp: Response<Full<Bytes>>) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn json_response_serialises_value() {
        let resp = json_response(200, &serde_json::json!({"ok": true}));
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json",
        );
        let body = body_to_string(resp).await;
        assert_eq!(body, "{\"ok\":true}");
    }

    #[tokio::test]
    async fn json_body_response_uses_provided_cache_control() {
        let resp = json_body_response(
            201,
            String::from("{\"created\":true}"),
            "private, max-age=2",
        );
        assert_eq!(resp.status(), 201);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json; charset=utf-8",
        );
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "private, max-age=2",
        );
        let body = body_to_string(resp).await;
        assert_eq!(body, "{\"created\":true}");
    }

    #[tokio::test]
    async fn json_response_falls_back_when_value_unrepresentable() {
        // A serde_json::Value can technically always serialise,
        // but this test pins the fallback contract so a future
        // change to a different shape can't silently break the
        // infallibility guarantee.
        let resp = json_response(500, &serde_json::Value::Null);
        let body = body_to_string(resp).await;
        assert_eq!(body, "null");
    }

    #[test]
    fn apply_dashboard_security_headers_adds_table_headers() {
        let builder = apply_dashboard_security_headers(Response::builder().status(200));
        let resp = builder.body(Full::new(Bytes::new())).unwrap();
        for (name, _value) in
            aegis_control::dashboard::security::SECURITY_HEADERS
        {
            assert!(
                resp.headers().contains_key(*name),
                "expected security header {name:?}",
            );
        }
    }
}
