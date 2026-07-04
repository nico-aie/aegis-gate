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
//! process — see `docs/control-plane/enterprise/assets.md`.


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
    /// Cache-Control header value to serve with this asset.
    ///
    /// **2026-05-11 (post-QA HIGH-01).** App-bundled assets that
    /// change on every dashboard rebuild (`app.js`, `index.html`,
    /// `aegis.css`, `i18n.json`) get `no-cache, must-revalidate`
    /// — browser asks every time but the ETag/304 short-circuits
    /// to a 304 Not Modified when the bundle hasn't changed, so
    /// bandwidth cost is unchanged. The shipping QA found the
    /// previous blanket `public, max-age=3600` masked a freshly-
    /// rebuilt dashboard for up to an hour after each rebuild.
    ///
    /// Third-party UMD bundles that ship unchanged across
    /// dashboard rebuilds (`react.min.js`, `react-dom.min.js`)
    /// keep the long cache — their content doesn't churn so
    /// there's no staleness risk.
    pub cache_control: &'static str,
}

/// Cache-Control for assets that rebuild with every dashboard
/// change. Browser revalidates on every request; ETag/304
/// short-circuits to 0 bytes when content matches.
pub const ASSET_CACHE_NO_CACHE: &str = "no-cache, must-revalidate";

/// Cache-Control for vendored third-party assets whose content
/// is byte-stable across dashboard rebuilds (React UMD bundles).
/// The 1-hour TTL bounds the staleness window for accidental
/// version bumps without making every page nav re-fetch ~150 KB.
pub const ASSET_CACHE_LONG: &str = "public, max-age=3600, must-revalidate";

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "application/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JSON: &str = "application/json; charset=utf-8";

/// Build a `(path, &'static bytes, content_type, cache_control)`
/// tuple from a path literal under
/// `crates/aegis-control/assets/dashboard/`. Path is relative to
/// this source file.
macro_rules! embed {
    ($path:literal, $ct:expr, $cc:expr) => {
        (
            $path,
            include_bytes!(concat!("../../assets/dashboard/", $path)) as &[u8],
            $ct,
            $cc,
        )
    };
}

/// Master inventory of embedded assets. The dashboard SPA was
/// rebuilt as the **Aegis WAF Console** in DD-T1 (see
/// `plans/dashboard-redesign.md`). The new bundle is a single
/// pre-compiled `app.js` produced by
/// `crates/aegis-control/assets/dashboard/build.sh`; the source
/// JSX lives under `assets/dashboard/src/`.
///
/// **Cache policy (per-asset, post-2026-05-11 QA HIGH-01).** The
/// fourth column picks `ASSET_CACHE_NO_CACHE` for assets that
/// rebuild on every dashboard change (`app.js`, `index.html`,
/// `aegis.css`, `i18n.json`) and `ASSET_CACHE_LONG` for vendor
/// UMD bundles that ship unchanged across dashboard rebuilds
/// (`react.min.js`, `react-dom.min.js`).
const RAW: &[(&str, &[u8], &str, &str)] = &[
    embed!("index.html",      HTML, ASSET_CACHE_NO_CACHE),
    embed!("app.js",          JS,   ASSET_CACHE_NO_CACHE),
    embed!("aegis.css",       CSS,  ASSET_CACHE_NO_CACHE),
    embed!("react.min.js",    JS,   ASSET_CACHE_LONG),
    embed!("react-dom.min.js",JS,   ASSET_CACHE_LONG),
    embed!("i18n.json",       JSON, ASSET_CACHE_NO_CACHE),
];

static ASSETS: OnceLock<HashMap<&'static str, EmbeddedAsset>> = OnceLock::new();

fn build_table() -> HashMap<&'static str, EmbeddedAsset> {
    RAW.iter()
        .map(|(path, bytes, content_type, cache_control)| {
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
                    cache_control,
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
/// fallback. Release builds skip this branch entirely.
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
        cache_control: embedded.cache_control,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DD-T1 redesign ships a single pre-compiled `app.js`
    /// alongside React UMD + a CSS file + an i18n strings JSON.
    /// Keep RAW and this list aligned.
    const EXPECTED_ASSETS: &[&str] = &[
        "index.html",
        "app.js",
        "aegis.css",
        "react.min.js",
        "react-dom.min.js",
        "i18n.json",
    ];

    #[test]
    fn inventory_size_matches_manifest() {
        assert_eq!(RAW.len(), EXPECTED_ASSETS.len());
    }

    #[test]
    fn lookup_known_returns_asset() {
        for path in EXPECTED_ASSETS {
            assert!(lookup(path).is_some(), "missing asset {path:?}");
        }
    }

    #[test]
    fn lookup_unknown_returns_none() {
        for path in ["does-not-exist.js", "../etc/passwd", "pages/old.js"] {
            assert!(lookup(path).is_none(), "unexpected asset for {path:?}");
        }
    }

    #[test]
    fn bytes_are_non_empty() {
        for path in EXPECTED_ASSETS {
            let asset = lookup(path).unwrap();
            assert!(!asset.bytes.is_empty(), "{path:?} bytes empty");
        }
    }

    #[test]
    fn etag_matches_blake3_of_bytes() {
        for path in EXPECTED_ASSETS {
            let asset = lookup(path).unwrap();
            let expected = blake3::hash(asset.bytes).to_hex().to_string();
            assert_eq!(asset.etag, expected, "etag mismatch for {path:?}");
        }
    }

    #[test]
    fn cache_control_per_asset_matches_policy() {
        // 2026-05-11 post-QA HIGH-01 — app-bundled assets must
        // serve `no-cache, must-revalidate` so a rebundle reaches
        // operators on next nav. Vendor UMD bundles keep the
        // 1-hour public cache.
        let no_cache: &[&str] = &["index.html", "app.js", "aegis.css", "i18n.json"];
        let long_cache: &[&str] = &["react.min.js", "react-dom.min.js"];
        for path in no_cache {
            let asset = lookup(path).unwrap();
            assert_eq!(
                asset.cache_control, ASSET_CACHE_NO_CACHE,
                "{path:?} must ship with `no-cache, must-revalidate`",
            );
        }
        for path in long_cache {
            let asset = lookup(path).unwrap();
            assert_eq!(
                asset.cache_control, ASSET_CACHE_LONG,
                "{path:?} must ship with the long cache header",
            );
        }
    }

    #[test]
    fn cache_control_policies_disjoint() {
        // Belt-and-braces against a typo that picks the long
        // cache for a churning asset.
        assert_ne!(ASSET_CACHE_NO_CACHE, ASSET_CACHE_LONG);
        assert!(ASSET_CACHE_NO_CACHE.contains("no-cache"));
        assert!(ASSET_CACHE_LONG.contains("max-age"));
    }

    #[test]
    fn content_type_matches_extension() {
        let cases: &[(&str, &str)] = &[
            ("index.html", "text/html; charset=utf-8"),
            ("app.js", "application/javascript; charset=utf-8"),
            ("aegis.css", "text/css; charset=utf-8"),
            ("react.min.js", "application/javascript; charset=utf-8"),
            ("i18n.json", "application/json; charset=utf-8"),
        ];
        for (path, expected_ct) in cases {
            let asset = lookup(path).unwrap();
            assert_eq!(asset.content_type, *expected_ct, "ct for {path:?}");
        }
    }

    fn index_html() -> &'static str {
        let bytes = lookup("index.html").unwrap().bytes;
        std::str::from_utf8(bytes).expect("index.html utf-8")
    }

    #[test]
    fn index_html_starts_with_doctype() {
        let head = index_html().trim_start();
        assert!(head.to_ascii_lowercase().starts_with("<!doctype html>"));
    }

    #[test]
    fn index_html_mounts_react_app() {
        // The new design mounts at #root via React 18 createRoot.
        let html = index_html();
        assert!(
            html.contains(r#"id="root""#),
            "index.html missing #root mount point"
        );
        assert!(
            html.contains(r#"app.js"#),
            "index.html must reference app.js"
        );
    }

    #[test]
    fn index_html_loads_local_react_only() {
        // Hard requirement: no unpkg / cdn dependency in production.
        let html = index_html();
        assert!(
            !html.to_ascii_lowercase().contains("unpkg.com"),
            "index.html must not load from unpkg.com (DD-T1)"
        );
        assert!(
            !html.to_ascii_lowercase().contains("cdn.jsdelivr.net"),
            "index.html must not load from jsdelivr CDN"
        );
    }
}
