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

/// Choose the dashboard shell based on the
/// `admin.dashboard.legacy_shell` config flag (D-M1-T1.6). When the
/// flag is `true` the v1 single-file dashboard is served instead of
/// the enterprise SPA shell. Default (`false`) returns the SPA.
pub fn shell_for(use_legacy: bool) -> EmbeddedAsset {
    if use_legacy {
        super::legacy::legacy_shell()
    } else {
        spa_shell()
    }
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
        let r = dispatch("/dashboard/assets/index.html").expect("must resolve");
        assert!(matches!(r, DashboardResponse::Asset(_)));
        let r = dispatch("/dashboard/assets/app.js").expect("must resolve");
        assert!(matches!(r, DashboardResponse::Asset(_)));
        let r = dispatch("/dashboard/assets/pages/overview.js").expect("must resolve");
        assert!(matches!(r, DashboardResponse::Asset(_)));
        let r = dispatch("/dashboard/assets/components/stat-card.js").expect("must resolve");
        assert!(matches!(r, DashboardResponse::Asset(_)));
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
        assert!(std::str::from_utf8(shell.bytes).unwrap().contains(r#"id="aegis-app""#));
    }

    #[test]
    fn shell_for_false_returns_spa_shell() {
        // D-M1-T1.6: legacy flag off -> new enterprise SPA shell.
        let shell = shell_for(false);
        let html = std::str::from_utf8(shell.bytes).unwrap();
        assert!(html.contains(r#"id="aegis-app""#));
    }

    #[test]
    fn shell_for_true_returns_legacy_v1() {
        // D-M1-T1.6: legacy flag on -> v1 single-file dashboard.
        let shell = shell_for(true);
        let html = std::str::from_utf8(shell.bytes).unwrap();
        assert!(html.contains("EventSource"));
        // Sentinel that's only in V1, not the SPA shell.
        assert!(!html.contains(r#"id="aegis-app""#));
    }

    #[test]
    fn shell_for_branches_carry_distinct_etags() {
        // The two shells should never collide; if they did, browsers
        // would 304 across the toggle and stick on the wrong shell.
        let a = shell_for(true);
        let b = shell_for(false);
        assert_ne!(a.etag, b.etag);
    }

    // ---------- app.js structural tests (D-M1-T1.3 router) ----------

    fn app_js() -> &'static str {
        let bytes = lookup("app.js").expect("app.js must resolve").bytes;
        std::str::from_utf8(bytes).expect("app.js must be utf-8")
    }

    #[test]
    fn app_js_declares_route_table_for_all_pages() {
        let js = app_js();
        for route in [
            "overview", "live", "attacks", "analytics", "audit",
            "rules", "tiers", "blacklist", "whitelist", "settings", "tracking",
        ] {
            // Each route key appears as a property and as a dynamic
            // import of the matching page module.
            assert!(
                js.contains(&format!("/dashboard/assets/pages/{route}.js")),
                "router must dynamically import pages/{route}.js"
            );
        }
    }

    #[test]
    fn app_js_uses_dynamic_import_per_route() {
        // ES dynamic import keeps the initial bundle tiny and lets
        // pages load on demand — design call in milestone-1-shell.md
        // task T1.3.
        let js = app_js();
        assert!(
            js.contains("import("),
            "router must use dynamic import() for code splitting"
        );
    }

    #[test]
    fn app_js_has_mount_destroy_lifecycle() {
        let js = app_js();
        assert!(js.contains(".mount("), "expected page.mount() call");
        assert!(js.contains("destroy"), "expected destroy() lifecycle");
    }

    #[test]
    fn app_js_uses_history_api() {
        let js = app_js();
        assert!(
            js.contains("history.pushState") || js.contains("pushState("),
            "router must use history.pushState"
        );
        assert!(
            js.contains("popstate"),
            "router must subscribe to popstate for back/forward"
        );
    }

    #[test]
    fn app_js_has_default_route_overview() {
        // layout.md: /dashboard/ redirects to /dashboard/overview.
        let js = app_js();
        assert!(
            js.contains(r#""overview""#) || js.contains(r#"'overview'"#),
            "expected DEFAULT_ROUTE = overview"
        );
    }

    #[test]
    fn app_js_highlights_active_link() {
        let js = app_js();
        assert!(
            js.contains("data-route") || js.contains("aegis-nav-active"),
            "expected active-link highlighting via data-route attribute"
        );
    }
}
