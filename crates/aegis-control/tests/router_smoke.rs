//! D-M1-T1.3: dashboard router smoke test.
//!
//! Asserts the server-side fall-through contract: every path under
//! `/dashboard/` (except `/dashboard/sse` and `/dashboard/assets/*`)
//! resolves to the SPA shell so the client-side router owns deep
//! links. Calls the public dispatch API directly — no TCP listener
//! required, the proxy delegates to the same function.

use aegis_control::dashboard::dispatch::{dispatch, spa_shell, DashboardResponse};

#[test]
fn deep_link_returns_spa_shell() {
    let r = dispatch("/dashboard/foo").expect("dashboard path must dispatch");
    assert!(matches!(r, DashboardResponse::Shell));
}

#[test]
fn shell_bytes_match_index_html() {
    // DD-T1: the new design mounts at #root via React 18.
    let shell = spa_shell();
    let html = std::str::from_utf8(shell.bytes).expect("utf-8");
    assert!(html.contains(r#"id="root""#));
}

#[test]
fn nested_segments_still_fall_through() {
    // The client router sees /dashboard/whitelist/edit/42 and mounts
    // the whitelist page in edit mode. The server only needs to ship
    // the shell — JS does the rest.
    let r = dispatch("/dashboard/whitelist/edit/42").expect("must dispatch");
    assert!(matches!(r, DashboardResponse::Shell));
}

#[test]
fn assets_path_does_not_fall_through_to_shell() {
    // /dashboard/assets/<known> must serve the asset, not the shell —
    // otherwise CSS / JS requests would all return HTML.
    let r = dispatch("/dashboard/assets/app.js").expect("must dispatch");
    match r {
        DashboardResponse::Asset(asset) => {
            assert_eq!(asset.content_type, "application/javascript; charset=utf-8");
        }
        other => panic!("expected Asset, got {other:?}"),
    }
}

#[test]
fn unknown_asset_is_404_not_shell() {
    let r = dispatch("/dashboard/assets/does-not-exist.js").expect("must dispatch");
    assert!(matches!(r, DashboardResponse::AssetNotFound));
}

#[test]
fn sse_path_is_left_to_streaming_handler() {
    assert!(dispatch("/dashboard/sse").is_none());
}
