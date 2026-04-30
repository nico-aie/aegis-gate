//! HTTP dispatch table for the dashboard surface (D-M1-T1.3).
//!
//! Centralises the `/dashboard/**` routing rules so every transport
//! layer (today: `aegis-proxy::admin_router`) calls one function and
//! gets the same answer.
//!
//! ```text
//!   GET /dashboard/                  → DashboardResponse::Shell
//!   GET /dashboard/<any-path>        → DashboardResponse::Shell   (SPA fall-through)
//!   GET /dashboard/assets/<known>    → DashboardResponse::Asset(EmbeddedAsset)
//!   GET /dashboard/assets/<unknown>  → DashboardResponse::AssetNotFound
//!   GET /dashboard/sse               → None  (SSE handler keeps ownership)
//!   anything else                    → None  (caller decides)
//! ```
//!
//! The dispatcher does not depend on `hyper`, `axum`, or any HTTP
//! framework — it's pure logic over `&str`. The caller converts the
//! [`DashboardResponse`] into its framework's response type.

use super::assets::{lookup, EmbeddedAsset};

/// Outcome of routing a request path under `/dashboard/`.
#[derive(Debug, Clone, Copy)]
pub enum DashboardResponse {
    /// Serve the SPA shell (`index.html`). Used for `/dashboard/`,
    /// `/dashboard/<route>`, and any deep link the client-side router
    /// owns. The caller looks the bytes up via [`spa_shell`].
    Shell,
    /// A known asset under `/dashboard/assets/<path>`.
    Asset(EmbeddedAsset),
    /// `/dashboard/assets/<path>` where `<path>` is unknown. The
    /// caller should reply with HTTP 404.
    AssetNotFound,
}

const DASHBOARD_PREFIX: &str = "/dashboard";
const ASSETS_PREFIX: &str = "/dashboard/assets/";
const SSE_PATH: &str = "/dashboard/sse";

/// The SPA shell asset (`index.html`). Always present at runtime —
/// the embedder is built at compile time.
pub fn spa_shell() -> EmbeddedAsset {
    lookup("index.html").expect("index.html must be in the embedded asset table")
}

/// Return the dashboard shell. Kept as a function (rather than
/// inlining `spa_shell()` everywhere) so future shell-variant work
/// has a single hook to extend.
///
/// `_use_legacy` is preserved as a no-op argument for one release
/// to avoid churning every caller; it is ignored. The legacy shell
/// and `admin.dashboard.legacy_shell` config flag were removed
/// in D-M6-T6.9.
pub fn shell_for(_use_legacy: bool) -> EmbeddedAsset {
    spa_shell()
}

/// Resolve a request path to a [`DashboardResponse`].
///
/// Returns `None` for paths the dashboard surface doesn't own
/// (`/dashboard/sse`, `/api/...`, `/healthz/...`, etc.) — the caller
/// keeps responsibility for those.
pub fn dispatch(path: &str) -> Option<DashboardResponse> {
    // SSE is a streaming surface; the caller (admin router) keeps it.
    if path == SSE_PATH {
        return None;
    }

    // /dashboard/assets/<rest>: serve the embedded asset (or 404).
    if let Some(rest) = path.strip_prefix(ASSETS_PREFIX) {
        return Some(match lookup(rest) {
            Some(asset) => DashboardResponse::Asset(asset),
            None => DashboardResponse::AssetNotFound,
        });
    }

    // /dashboard or /dashboard/<anything>: SPA shell fall-through.
    // Match on `/dashboard` exactly *or* `/dashboard/...` — the trailing
    // check stops `/dashboards`, `/dashboardish` from matching.
    if path == DASHBOARD_PREFIX
        || path
            .strip_prefix(DASHBOARD_PREFIX)
            .map(|rest| rest.starts_with('/'))
            .unwrap_or(false)
    {
        return Some(DashboardResponse::Shell);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_root_returns_shell() {
        assert!(matches!(dispatch("/dashboard/"), Some(DashboardResponse::Shell)));
        assert!(matches!(dispatch("/dashboard"), Some(DashboardResponse::Shell)));
    }

    #[test]
    fn dispatch_unknown_subpath_falls_through_to_shell() {
        // Server-side fall-through is the contract that lets the
        // client-side router own deep links.
        for path in [
            "/dashboard/overview",
            "/dashboard/live",
            "/dashboard/foo",
            "/dashboard/anything/with/segments",
            "/dashboard/whitelist/edit/42",
        ] {
            assert!(
                matches!(dispatch(path), Some(DashboardResponse::Shell)),
                "expected Shell for {path:?}"
            );
        }
    }

    #[test]
    fn dispatch_known_asset_returns_asset() {
        // DD-T1: the redesign ships index.html + app.js + aegis.css
        // + react UMD bundles + i18n.json. Per-page splits and the
        // per-component module folder were removed.
        for asset in [
            "/dashboard/assets/index.html",
            "/dashboard/assets/app.js",
            "/dashboard/assets/aegis.css",
            "/dashboard/assets/react.min.js",
            "/dashboard/assets/react-dom.min.js",
            "/dashboard/assets/i18n.json",
        ] {
            let r = dispatch(asset).expect("must resolve");
            assert!(matches!(r, DashboardResponse::Asset(_)), "missing {asset}");
        }
    }

    #[test]
    fn dispatch_unknown_asset_returns_not_found() {
        let r = dispatch("/dashboard/assets/missing.js").expect("must resolve");
        assert!(matches!(r, DashboardResponse::AssetNotFound));
        let r = dispatch("/dashboard/assets/").expect("must resolve");
        assert!(matches!(r, DashboardResponse::AssetNotFound));
    }

    #[test]
    fn dispatch_sse_returns_none() {
        // SSE is owned by the streaming handler, not the asset router.
        assert!(dispatch("/dashboard/sse").is_none());
    }

    #[test]
    fn dispatch_non_dashboard_returns_none() {
        for path in [
            "/",
            "/admin/login",
            "/api/config",
            "/healthz/live",
            "/metrics",
            "/dashboards",       // not /dashboard/
            "/dashboardish",
        ] {
            assert!(dispatch(path).is_none(), "expected None for {path:?}");
        }
    }

    #[test]
    fn dispatch_does_not_walk_outside_assets_dir() {
        // Both relative and absolute traversal attempts must miss.
        assert!(matches!(
            dispatch("/dashboard/assets/../etc/passwd"),
            Some(DashboardResponse::AssetNotFound)
        ));
        assert!(matches!(
            dispatch("/dashboard/assets/..%2fetc"),
            Some(DashboardResponse::AssetNotFound)
        ));
    }

    #[test]
    fn spa_shell_returns_index_html() {
        let shell = spa_shell();
        assert!(!shell.bytes.is_empty());
        assert_eq!(shell.content_type, "text/html; charset=utf-8");
        // DD-T1: the new shell mounts at #root via React 18.
        assert!(std::str::from_utf8(shell.bytes).unwrap().contains(r#"id="root""#));
    }

    #[test]
    fn shell_for_returns_index_html_regardless_of_legacy_flag() {
        // The legacy-shell branch was retired in D-M6-T6.9 and the
        // dashboard was rebuilt in DD-T1. `shell_for(true|false)`
        // both return the new React 18 shell.
        for flag in [true, false] {
            let shell = shell_for(flag);
            let html = std::str::from_utf8(shell.bytes).unwrap();
            assert!(html.contains(r#"id="root""#));
        }
        let a = shell_for(true);
        let b = shell_for(false);
        assert_eq!(a.etag, b.etag);
    }

    // ---------- app.js structural tests (DD-T1 bundle) ---------------

    fn app_js() -> &'static str {
        let bytes = lookup("app.js").expect("app.js must resolve").bytes;
        std::str::from_utf8(bytes).expect("app.js must be utf-8")
    }

    #[test]
    fn app_js_references_all_pages() {
        // DD-T1: the bundle declares every page component as a global
        // (window.PageOverview, window.PageLiveFeed, …).
        let js = app_js();
        for page in [
            "PageOverview", "PageLiveFeed", "PageAttackEvents",
            "PageAnalytics", "PageAuditLog", "PageRuleManager",
            "PageTierConfig", "ListPage", "PageSettings",
            "PageTracking", "PageHelp",
        ] {
            assert!(js.contains(page), "bundle missing global {page}");
        }
    }

    #[test]
    fn app_js_mounts_react_18() {
        let js = app_js();
        assert!(
            js.contains("createRoot"),
            "bundle must call ReactDOM.createRoot (React 18)"
        );
    }

    #[test]
    fn app_js_uses_hash_routing() {
        // The DD-T1 redesign uses hash routing inside the SPA so
        // server-side fall-through is a no-op (any
        // /dashboard/<anything> serves the same HTML).
        let js = app_js();
        assert!(
            js.contains("location.hash") || js.contains("hashchange"),
            "bundle must use hash-based routing"
        );
    }

    #[test]
    fn app_js_default_route_is_overview() {
        let js = app_js();
        assert!(
            js.contains(r#""overview""#) || js.contains(r#"'overview'"#),
            "expected default route = overview"
        );
    }
}
