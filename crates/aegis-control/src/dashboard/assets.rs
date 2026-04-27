//! Embedded dashboard asset table for the enterprise SPA shell (D-M1-T1.1).
//!
//! Assets are embedded at compile time via `include_bytes!`. Each entry
//! exposes its raw bytes, a static `Content-Type`, and a stable `ETag`
//! derived from the BLAKE3 digest of the bytes (lowercase hex).
//!
//! The [`lookup`] API takes a relative path under `/dashboard/assets/`
//! (e.g. `"index.html"`, `"pages/overview.js"`). Unknown paths return
//! `None`. The lookup table is built lazily on first call via
//! [`std::sync::OnceLock`] so ETag computation runs exactly once per
//! process — see `docs/dashboard-enterprise/assets.md`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::OnceLock;

/// A single asset served from `/dashboard/assets/<path>`.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedAsset {
    /// Raw bytes of the asset, embedded at compile time.
    pub bytes: &'static [u8],
    /// MIME type with charset where appropriate.
    pub content_type: &'static str,
    /// Strong ETag — lowercase hex of the BLAKE3 digest of `bytes`.
    pub etag: &'static str,
}

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "application/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const SVG: &str = "image/svg+xml";
const JSON: &str = "application/json; charset=utf-8";

/// Build a `(path, &'static bytes, content_type)` triple from a path
/// literal under `crates/aegis-control/assets/dashboard/`. Path is
/// relative to this source file.
macro_rules! embed {
    ($path:literal, $ct:expr) => {
        (
            $path,
            include_bytes!(concat!("../../assets/dashboard/", $path)) as &[u8],
            $ct,
        )
    };
}

/// Master inventory of embedded assets. Adding/removing an asset here
/// must be matched in the M1 design spec
/// (`docs/dashboard-enterprise/assets.md`) and the test inventory
/// (`EXPECTED_ASSETS` in this module).
const RAW: &[(&str, &[u8], &str)] = &[
    // Top-level shell
    embed!("index.html", HTML),
    embed!("app.js", JS),
    embed!("aegis.css", CSS),
    embed!("theme.js", JS),
    embed!("icons.svg", SVG),
    // i18n
    embed!("i18n/en.json", JSON),
    // Pages (11)
    embed!("pages/overview.js", JS),
    embed!("pages/live.js", JS),
    embed!("pages/attacks.js", JS),
    embed!("pages/analytics.js", JS),
    embed!("pages/audit.js", JS),
    embed!("pages/rules.js", JS),
    embed!("pages/tiers.js", JS),
    embed!("pages/blacklist.js", JS),
    embed!("pages/whitelist.js", JS),
    embed!("pages/settings.js", JS),
    embed!("pages/tracking.js", JS),
    // Components (14)
    embed!("components/stat-card.js", JS),
    embed!("components/line-chart.js", JS),
    embed!("components/donut.js", JS),
    embed!("components/sparkline.js", JS),
    embed!("components/table.js", JS),
    embed!("components/badge.js", JS),
    embed!("components/drawer.js", JS),
    embed!("components/modal.js", JS),
    embed!("components/toast.js", JS),
    embed!("components/confirm.js", JS),
    embed!("components/diff.js", JS),
    embed!("components/cmdk.js", JS),
    embed!("components/banner.js", JS),
    embed!("components/skeleton.js", JS),
];

static ASSETS: OnceLock<HashMap<&'static str, EmbeddedAsset>> = OnceLock::new();

fn build_table() -> HashMap<&'static str, EmbeddedAsset> {
    RAW.iter()
        .map(|(path, bytes, content_type)| {
            // BLAKE3 to_hex() yields lowercase hex; leaking the boxed
            // string promotes the ETag to a 'static lifetime so it
            // satisfies `EmbeddedAsset::etag: &'static str`. Leaks are
            // bounded: one allocation per asset, lives for the process.
            let etag: &'static str =
                Box::leak(blake3::hash(bytes).to_hex().to_string().into_boxed_str());
            (
                *path,
                EmbeddedAsset {
                    bytes,
                    content_type,
                    etag,
                },
            )
        })
        .collect()
}

/// Resolve a relative asset path to its embedded representation.
///
/// `path` is the suffix after `/dashboard/assets/`, e.g. `"app.js"` or
/// `"pages/overview.js"`. Returns `None` for unknown paths.
///
/// In debug builds (`cfg(debug_assertions)`) the call additionally
/// re-reads the file from disk under
/// `crates/aegis-control/assets/dashboard/<path>` so saves to the
/// asset tree take effect without rebuilding aegis-control. The
/// embedded inventory is still consulted first (to gate the request
/// to known paths and to source `content_type`); if the disk read
/// fails for any reason the embedded bytes are returned as a safe
/// fallback. Release builds skip this branch entirely. See
/// `plans/dashboard-enterprise/milestone-1-shell.md` task D-M1-T1.7.
pub fn lookup(path: &str) -> Option<EmbeddedAsset> {
    let embedded = ASSETS.get_or_init(build_table).get(path).copied()?;

    #[cfg(debug_assertions)]
    if let Some(fresh) = read_asset_from_disk(path, embedded) {
        return Some(fresh);
    }

    Some(embedded)
}

/// Dev-only hot reload of an asset. Returns `None` on any error so
/// the caller can fall back to the embedded bytes.
///
/// Memory note: each successful call leaks one `Box<[u8]>` for the
/// bytes and one `Box<str>` for the ETag so the returned
/// [`EmbeddedAsset`] satisfies its `'static` lifetime contract. This
/// is acceptable for a dev workflow (process exits when you stop
/// the binary) and the branch is excluded from release builds.
#[cfg(debug_assertions)]
fn read_asset_from_disk(
    path: &str,
    embedded: EmbeddedAsset,
) -> Option<EmbeddedAsset> {
    // Defensive: the inventory keys are constants and never traverse,
    // but reject any caller that smuggles `..` segments anyway.
    if path.split('/').any(|seg| seg == "..") {
        return None;
    }
    let assets_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("dashboard");
    let full = assets_root.join(path);

    let bytes = std::fs::read(&full).ok()?;
    let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
    let etag: &'static str =
        Box::leak(blake3::hash(bytes).to_hex().to_string().into_boxed_str());

    Some(EmbeddedAsset {
        bytes,
        content_type: embedded.content_type,
        etag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every asset listed in the M1 directory tree must resolve. This
    /// is the canonical inventory; if the manifest changes, update both
    /// this list and the embedded table together.
    const EXPECTED_ASSETS: &[&str] = &[
        // top-level
        "index.html",
        "app.js",
        "aegis.css",
        "theme.js",
        "icons.svg",
        // i18n
        "i18n/en.json",
        // pages
        "pages/overview.js",
        "pages/live.js",
        "pages/attacks.js",
        "pages/analytics.js",
        "pages/audit.js",
        "pages/rules.js",
        "pages/tiers.js",
        "pages/blacklist.js",
        "pages/whitelist.js",
        "pages/settings.js",
        "pages/tracking.js",
        // components
        "components/stat-card.js",
        "components/line-chart.js",
        "components/donut.js",
        "components/sparkline.js",
        "components/table.js",
        "components/badge.js",
        "components/drawer.js",
        "components/modal.js",
        "components/toast.js",
        "components/confirm.js",
        "components/diff.js",
        "components/cmdk.js",
        "components/banner.js",
        "components/skeleton.js",
    ];

    #[test]
    fn lookup_resolves_every_known_asset() {
        for path in EXPECTED_ASSETS {
            assert!(
                lookup(path).is_some(),
                "expected asset {path:?} to resolve via lookup()",
            );
        }
    }

    #[test]
    fn lookup_unknown_path_returns_none() {
        assert!(lookup("does-not-exist.txt").is_none());
        assert!(lookup("../etc/passwd").is_none());
        assert!(lookup("").is_none());
        assert!(lookup("pages/nope.js").is_none());
    }

    #[test]
    fn etag_is_deterministic_across_calls() {
        for path in EXPECTED_ASSETS {
            let first = lookup(path).expect("known asset must resolve").etag;
            let second = lookup(path).expect("known asset must resolve").etag;
            assert_eq!(first, second, "etag for {path:?} must be deterministic");
        }
    }

    #[test]
    fn etag_is_lowercase_hex_of_expected_length() {
        // BLAKE3 default digest is 32 bytes -> 64 lowercase hex chars.
        for path in EXPECTED_ASSETS {
            let etag = lookup(path).expect("known asset must resolve").etag;
            assert_eq!(etag.len(), 64, "etag for {path:?} should be 64 hex chars");
            assert!(
                etag.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
                "etag for {path:?} must be lowercase hex, got {etag:?}",
            );
        }
    }

    #[test]
    fn etag_matches_blake3_of_bytes() {
        for path in EXPECTED_ASSETS {
            let asset = lookup(path).expect("known asset must resolve");
            let expected = blake3::hash(asset.bytes).to_hex().to_string();
            assert_eq!(asset.etag, expected, "etag mismatch for {path:?}");
        }
    }

    #[test]
    fn content_type_matches_extension() {
        let cases: &[(&str, &str)] = &[
            ("index.html", "text/html; charset=utf-8"),
            ("app.js", "application/javascript; charset=utf-8"),
            ("aegis.css", "text/css; charset=utf-8"),
            ("icons.svg", "image/svg+xml"),
            ("i18n/en.json", "application/json; charset=utf-8"),
            ("pages/overview.js", "application/javascript; charset=utf-8"),
            (
                "components/stat-card.js",
                "application/javascript; charset=utf-8",
            ),
        ];
        for (path, expected_ct) in cases {
            let asset = lookup(path).expect("known asset must resolve");
            assert_eq!(asset.content_type, *expected_ct, "content_type for {path:?}");
        }
    }

    #[test]
    fn inventory_size_matches_manifest() {
        // Guard against accidental drift between RAW and EXPECTED_ASSETS.
        assert_eq!(RAW.len(), EXPECTED_ASSETS.len());
    }

    #[test]
    fn bytes_are_non_empty() {
        for path in EXPECTED_ASSETS {
            let asset = lookup(path).expect("known asset must resolve");
            assert!(!asset.bytes.is_empty(), "asset {path:?} has empty bytes");
        }
    }

    // ---------- D-M1-T1.2: SPA shell HTML structure ---------------------

    fn index_html() -> &'static str {
        let bytes = lookup("index.html").expect("index.html must resolve").bytes;
        std::str::from_utf8(bytes).expect("index.html must be valid utf-8")
    }

    #[test]
    fn index_html_starts_with_doctype() {
        let html = index_html();
        let head = html.trim_start();
        // Match either casing; HTML5 is case-insensitive for the DOCTYPE.
        assert!(
            head.to_ascii_lowercase().starts_with("<!doctype html>"),
            "index.html must start with HTML5 doctype, got: {:?}",
            &head[..head.len().min(40)]
        );
    }

    #[test]
    fn index_html_declares_lang_and_charset() {
        let html = index_html();
        assert!(html.contains(r#"<html lang="en">"#), "missing lang attribute");
        assert!(
            html.contains(r#"<meta charset="utf-8">"#),
            "missing utf-8 charset meta"
        );
        assert!(
            html.contains(r#"name="viewport""#),
            "missing viewport meta"
        );
    }

    #[test]
    fn index_html_has_app_and_toasts_sentinels() {
        // Canonical sentinel ids for the SPA mount points.
        let html = index_html();
        assert!(
            html.contains(r#"id="aegis-app""#),
            "missing #aegis-app sentinel"
        );
        assert!(
            html.contains(r#"id="aegis-toasts""#),
            "missing #aegis-toasts sentinel"
        );
    }

    #[test]
    fn index_html_has_landmark_chrome() {
        // Top bar + sidebar + content + status bar per layout.md frame.
        let html = index_html();
        for (tag, role) in [
            ("header", "banner"),
            ("nav", "navigation"),
            ("main", "main"),
            ("footer", "contentinfo"),
        ] {
            assert!(
                html.contains(&format!(r#"<{tag} "#))
                    || html.contains(&format!(r#"<{tag}>"#)),
                "missing <{tag}> landmark"
            );
            assert!(
                html.contains(&format!(r#"role="{role}""#)),
                "missing role={role} on {tag}"
            );
        }
    }

    #[test]
    fn index_html_lists_all_sidebar_routes() {
        // Every route in layout.md must have a sidebar link in the shell.
        let html = index_html();
        const ROUTES: &[&str] = &[
            "/dashboard/overview",
            "/dashboard/live",
            "/dashboard/attacks",
            "/dashboard/analytics",
            "/dashboard/audit",
            "/dashboard/rules",
            "/dashboard/tiers",
            "/dashboard/blacklist",
            "/dashboard/whitelist",
            "/dashboard/settings",
            "/dashboard/tracking",
        ];
        for route in ROUTES {
            assert!(
                html.contains(&format!(r#"href="{route}""#)),
                "missing sidebar link for {route}"
            );
        }
    }

    #[test]
    fn index_html_inlines_svg_sprite() {
        // Sprite is inlined so first paint has icons without a separate fetch.
        let html = index_html();
        assert!(
            html.contains("<svg") && html.contains("</svg>"),
            "expected at least one inlined <svg> block"
        );
        assert!(
            html.contains(r#"<symbol id="icon-shield""#),
            "expected logo shield symbol in inlined sprite"
        );
        assert!(
            html.contains(r#"<symbol id="icon-overview""#),
            "expected overview nav icon in inlined sprite"
        );
    }

    #[test]
    fn index_html_loads_app_module() {
        // app.js is a real ES module, served from the assets route.
        let html = index_html();
        assert!(
            html.contains(r#"type="module""#)
                && html.contains(r#"src="/dashboard/assets/app.js""#),
            "expected module script for /dashboard/assets/app.js"
        );
    }

    #[test]
    fn index_html_links_stylesheet() {
        let html = index_html();
        assert!(
            html.contains(r#"href="/dashboard/assets/aegis.css""#),
            "expected link to aegis.css"
        );
    }

    #[test]
    fn index_html_has_skip_link_for_a11y() {
        // Skip-to-content link is required for keyboard a11y per
        // docs/dashboard-enterprise/accessibility.md.
        let html = index_html();
        assert!(
            html.contains(r##"href="#aegis-content""##),
            "expected skip-to-content link"
        );
    }

    #[test]
    fn icons_svg_is_a_real_sprite() {
        // The editable source mirrors the inlined sprite shape.
        let bytes = lookup("icons.svg").expect("icons.svg must resolve").bytes;
        let svg = std::str::from_utf8(bytes).expect("icons.svg must be utf-8");
        assert!(svg.starts_with("<svg") || svg.contains("<svg"));
        assert!(svg.contains(r#"id="icon-shield""#));
        assert!(svg.contains(r#"id="icon-overview""#));
    }

    // ---------- D-M1-T1.4: chrome stylesheet + theme bootstrap ---------

    fn aegis_css() -> &'static str {
        let bytes = lookup("aegis.css").expect("aegis.css must resolve").bytes;
        std::str::from_utf8(bytes).expect("aegis.css must be utf-8")
    }

    fn theme_js() -> &'static str {
        let bytes = lookup("theme.js").expect("theme.js must resolve").bytes;
        std::str::from_utf8(bytes).expect("theme.js must be utf-8")
    }

    #[test]
    fn aegis_css_is_non_trivial() {
        // The placeholder is ~70 bytes; the real chrome sheet is
        // several thousand. Guard against the placeholder leaking
        // into a release.
        let css = aegis_css();
        assert!(
            css.len() > 1500,
            "aegis.css too small to be the real chrome stylesheet ({} bytes)",
            css.len()
        );
    }

    #[test]
    fn aegis_css_defines_core_design_tokens() {
        // Every token from docs/dashboard-enterprise/theme.md that a
        // page module is allowed to reference. If a page reaches for
        // a token, the page test will reasonably expect this list.
        let css = aegis_css();
        for token in [
            "--surface-0",
            "--surface-1",
            "--surface-2",
            "--surface-active",
            "--surface-hover",
            "--border-subtle",
            "--border-default",
            "--text-primary",
            "--text-secondary",
            "--text-muted",
            "--color-accent",
            "--color-ok",
            "--color-warn",
            "--color-err",
            "--font-sans",
            "--font-mono",
            "--space-4",
            "--radius-md",
            "--radius-pill",
            "--shadow-md",
            "--duration-base",
            "--ease",
        ] {
            assert!(
                css.contains(token),
                "aegis.css missing design token {token}"
            );
        }
    }

    #[test]
    fn aegis_css_styles_chrome_landmarks() {
        let css = aegis_css();
        for selector in [
            ".aegis-app",
            ".aegis-topbar",
            ".aegis-sidebar",
            ".aegis-content",
            ".aegis-statusbar",
            ".aegis-skip-link",
            ".aegis-nav-active",
            ".aegis-toasts",
        ] {
            assert!(
                css.contains(selector),
                "aegis.css missing chrome selector {selector}"
            );
        }
    }

    #[test]
    fn aegis_css_has_visible_focus_ring() {
        // a11y requirement from docs/dashboard-enterprise/accessibility.md
        let css = aegis_css();
        assert!(
            css.contains(":focus-visible") || css.contains(":focus "),
            "aegis.css must define a visible focus ring"
        );
    }

    #[test]
    fn aegis_css_respects_reduced_motion() {
        // a11y requirement: prefers-reduced-motion collapses transitions.
        let css = aegis_css();
        assert!(
            css.contains("prefers-reduced-motion"),
            "aegis.css must respect prefers-reduced-motion"
        );
    }

    #[test]
    fn aegis_css_has_light_theme_override() {
        // theme.md: light theme overrides via [data-theme="light"].
        let css = aegis_css();
        assert!(
            css.contains(r#"[data-theme="light"]"#),
            "aegis.css must override tokens under [data-theme=\"light\"]"
        );
    }

    #[test]
    fn theme_js_is_not_an_es_module() {
        // theme.js is loaded synchronously in <head> so the data-theme
        // attribute is set before first paint. ES `import`/`export`
        // would force `type=module` (deferred) and reintroduce
        // flash-of-wrong-theme.
        let js = theme_js();
        assert!(
            !js.contains("export ") && !js.contains("export{"),
            "theme.js must not use `export` — needs to load as a classic script"
        );
        assert!(
            !js.contains("import "),
            "theme.js must not use `import` — needs to load as a classic script"
        );
    }

    #[test]
    fn theme_js_reads_the_documented_localstorage_key() {
        // theme.md: "persisted in localStorage under aegis.dashboard.theme"
        let js = theme_js();
        assert!(
            js.contains("aegis.dashboard.theme"),
            "theme.js must use the documented localStorage key"
        );
    }

    #[test]
    fn theme_js_sets_data_theme_attribute() {
        let js = theme_js();
        assert!(
            js.contains("data-theme") || js.contains(r#""data-theme""#),
            "theme.js must set the data-theme attribute"
        );
        assert!(
            js.contains("documentElement"),
            "theme.js must apply data-theme to documentElement (avoid FOUC)"
        );
    }

    #[test]
    fn theme_js_exports_chart_palette() {
        // Pages later read window.AegisTheme.chart for the palette
        // from docs/dashboard-enterprise/theme.md §charts.
        let js = theme_js();
        assert!(
            js.contains("AegisTheme") && js.contains("chart"),
            "theme.js must publish window.AegisTheme.chart"
        );
    }

    #[test]
    fn app_js_handles_theme_toggle() {
        // Wired to the data-action="toggle-theme" button in index.html.
        let js = lookup("app.js").expect("app.js must resolve").bytes;
        let s = std::str::from_utf8(js).expect("utf-8");
        assert!(
            s.contains("toggle-theme"),
            "app.js must intercept clicks on data-action=toggle-theme"
        );
        assert!(
            s.contains("AegisTheme"),
            "app.js must call window.AegisTheme to flip the theme"
        );
    }

    // ---------- D-M1-T1.7: dev-only hot reload --------------------------

    #[cfg(debug_assertions)]
    #[test]
    fn dev_assets_directory_exists() {
        // The hot-reload path joins env!("CARGO_MANIFEST_DIR") with
        // assets/dashboard. If the layout drifts, every dev lookup
        // silently falls back to the embedded copy and devs lose
        // hot-reload without noticing — fail loudly instead.
        let assets_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("dashboard");
        assert!(
            assets_root.is_dir(),
            "dev hot-reload expects {assets_root:?} to be a directory"
        );
        // Spot-check one well-known asset is on disk.
        assert!(assets_root.join("aegis.css").is_file());
        assert!(assets_root.join("pages/overview.js").is_file());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn dev_lookup_returns_disk_bytes_for_known_asset() {
        // Indirectly verifies the cfg(debug_assertions) branch took
        // effect: the bytes returned by lookup() match `std::fs::read`
        // of the same path on disk, byte-for-byte.
        let on_disk = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("assets/dashboard/aegis.css"),
        )
        .expect("aegis.css must be on disk");
        let asset = lookup("aegis.css").expect("must resolve");
        assert_eq!(asset.bytes, on_disk.as_slice());
    }

    // ---------- D-M1-T1.8: i18n loader -----------------------------------

    fn en_json_value() -> serde_json::Value {
        let bytes = lookup("i18n/en.json")
            .expect("en.json must resolve")
            .bytes;
        serde_json::from_slice(bytes).expect("en.json must be valid JSON")
    }

    /// Crude attribute-scanner — walks `data-i18n="…"` occurrences and
    /// returns the unique keys. Good enough for HTML the WAF authors,
    /// avoids pulling in a parser dep just for tests.
    fn extract_data_i18n_keys(haystack: &str) -> Vec<String> {
        let mut keys = Vec::new();
        let mut rest = haystack;
        while let Some(idx) = rest.find("data-i18n=\"") {
            let after = &rest[idx + "data-i18n=\"".len()..];
            if let Some(end) = after.find('"') {
                keys.push(after[..end].to_string());
                rest = &after[end..];
            } else {
                break;
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }

    /// `app.js` writes data-i18n via `dataset.i18n = "..."`.
    /// Pattern: `dataset.i18n = "key"` or `dataset.i18n = 'key'`.
    fn extract_dataset_i18n_keys(js: &str) -> Vec<String> {
        let mut keys = Vec::new();
        let needle = "dataset.i18n";
        let mut rest = js;
        while let Some(idx) = rest.find(needle) {
            let after = &rest[idx + needle.len()..];
            // Skip whitespace + '=' + whitespace.
            let after = after.trim_start();
            let after = after.strip_prefix('=').map(str::trim_start).unwrap_or(after);
            // Now we expect a string literal.
            if let Some(stripped) = after.strip_prefix('"').or_else(|| after.strip_prefix('\'')) {
                let quote = if after.starts_with('"') { '"' } else { '\'' };
                if let Some(end) = stripped.find(quote) {
                    keys.push(stripped[..end].to_string());
                    rest = &stripped[end..];
                    continue;
                }
            }
            rest = after;
        }
        keys.sort();
        keys.dedup();
        keys
    }

    #[test]
    fn en_json_parses_as_object() {
        let v = en_json_value();
        assert!(v.is_object(), "en.json must be a JSON object");
    }

    #[test]
    fn every_index_html_data_i18n_key_exists_in_en_json() {
        let html = index_html();
        let json = en_json_value();
        let keys = extract_data_i18n_keys(html);
        assert!(!keys.is_empty(), "index.html should have data-i18n attributes");
        for key in &keys {
            assert!(
                json.get(key).is_some(),
                "en.json missing key {key:?} (referenced from index.html)"
            );
        }
    }

    #[test]
    fn every_app_js_dataset_i18n_key_exists_in_en_json() {
        let js = lookup("app.js").expect("app.js must resolve").bytes;
        let s = std::str::from_utf8(js).expect("utf-8");
        let json = en_json_value();
        for key in extract_dataset_i18n_keys(s) {
            assert!(
                json.get(&key).is_some(),
                "en.json missing key {key:?} (referenced from app.js)"
            );
        }
    }

    #[test]
    fn app_js_loads_i18n_synchronously_before_render() {
        // Loader contract: fetch en.json + await before the first
        // route mount, so first paint isn't a flash of un-translated
        // text.
        let bytes = lookup("app.js").expect("app.js must resolve").bytes;
        let js = std::str::from_utf8(bytes).expect("utf-8");
        assert!(
            js.contains("/dashboard/assets/i18n/en.json"),
            "app.js must fetch /dashboard/assets/i18n/en.json"
        );
        assert!(
            js.contains("await ") || js.contains("async function"),
            "app.js must await the i18n payload before mounting"
        );
    }

    #[test]
    fn app_js_exposes_t_function() {
        let bytes = lookup("app.js").expect("app.js must resolve").bytes;
        let js = std::str::from_utf8(bytes).expect("utf-8");
        // Either a top-level `function t(` or an exported `export function t(`.
        let has_t = js.contains("function t(")
            || js.contains("export function t(")
            || js.contains("export const t");
        assert!(has_t, "app.js must define a translation helper t()");
    }

    #[test]
    fn app_js_walks_data_i18n_to_apply_translations() {
        let bytes = lookup("app.js").expect("app.js must resolve").bytes;
        let js = std::str::from_utf8(bytes).expect("utf-8");
        assert!(
            js.contains("[data-i18n]") || js.contains(r#"data-i18n""#),
            "app.js must querySelectorAll('[data-i18n]')"
        );
        assert!(
            js.contains("textContent"),
            "app.js must apply translations via textContent"
        );
    }

    #[test]
    fn en_json_has_no_orphan_keys() {
        // An i18n bundle that grows past what the UI references is a
        // smell — refactors leave dead strings behind. This is a
        // hard guard during M1; loosen if a future feature ships
        // strings ahead of the UI that uses them.
        let json = en_json_value();
        let object = json.as_object().expect("object");
        let html_keys: std::collections::HashSet<_> =
            extract_data_i18n_keys(index_html()).into_iter().collect();
        let js_bytes = lookup("app.js").expect("app.js").bytes;
        let js = std::str::from_utf8(js_bytes).unwrap();
        let js_keys: std::collections::HashSet<_> =
            extract_dataset_i18n_keys(js).into_iter().collect();
        for key in object.keys() {
            if key.starts_with('_') {
                // Keys prefixed with `_` are metadata (e.g. _meta).
                continue;
            }
            assert!(
                html_keys.contains(key) || js_keys.contains(key),
                "en.json key {key:?} is not referenced from any UI surface"
            );
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn dev_lookup_rejects_traversal_attempts() {
        // The release-mode inventory already returns None for unknown
        // keys; verify the dev branch doesn't unintentionally widen
        // that surface by walking the file system.
        assert!(lookup("../Cargo.toml").is_none());
        assert!(lookup("pages/../../Cargo.toml").is_none());
    }

    #[test]
    fn index_html_loads_theme_js_before_stylesheet() {
        // Order matters: theme.js must run before the stylesheet
        // resolves variables, otherwise the dark-by-default render
        // flashes through before the user's preference applies.
        let html = index_html();
        let theme_pos = html
            .find(r#"src="/dashboard/assets/theme.js""#)
            .expect("theme.js must be referenced");
        let css_pos = html
            .find(r#"href="/dashboard/assets/aegis.css""#)
            .expect("aegis.css link must be present");
        assert!(
            theme_pos < css_pos,
            "theme.js must be loaded before aegis.css to avoid FOUC \
             (theme.js at {theme_pos}, css at {css_pos})"
        );
    }
}
