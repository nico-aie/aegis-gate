//! D-M6 polish tests carried forward into the DD-T1 redesign.
//! T6.1 a11y / T6.2 contrast / T6.3 security headers / T6.6 bundle
//! size remain in scope. Tests tied to the old SPA structure
//! (per-page module split, specific aria-labels, landmark roles
//! at HTML level) were removed because the new design lives almost
//! entirely inside React components — the structural assertions now
//! belong to the screenshot regression in run-10 + the live smoke
//! checks in `tests/dashboard/round1-acceptance.sh` (DD-T8).

use aegis_control::dashboard::assets::{lookup, EmbeddedAsset};
use aegis_control::dashboard::security::SECURITY_HEADERS;

// ---------- T6.2 contrast ---------------------------------------------

/// WCAG 2.1 relative-luminance + contrast-ratio.
fn relative_luminance(hex: &str) -> f64 {
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap() as f64 / 255.0;
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap() as f64 / 255.0;
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap() as f64 / 255.0;
    let lin = |c: f64| {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

fn contrast_ratio(fg: &str, bg: &str) -> f64 {
    let lf = relative_luminance(fg);
    let lb = relative_luminance(bg);
    let (lighter, darker) = if lf > lb { (lf, lb) } else { (lb, lf) };
    (lighter + 0.05) / (darker + 0.05)
}

#[test]
fn text_on_surface_meets_wcag_aa() {
    // Tokens from the new design's `aegis.css`. Dark theme only —
    // the redesign is dark-only by intent (see plan, "out of scope").
    let pairs: &[(&str, &str)] = &[
        // ink (#EAECEF) on canvas (#0B0E11)
        ("EAECEF", "0B0E11"),
        // ink on surface (#14181D)
        ("EAECEF", "14181D"),
        // ink on canvas-2 (#0F1418)
        ("EAECEF", "0F1418"),
    ];
    for (fg, bg) in pairs {
        let r = contrast_ratio(fg, bg);
        assert!(
            r >= 4.5,
            "WCAG AA fail: text #{fg} on #{bg} = {r:.2}:1"
        );
    }
}

#[test]
fn brand_yellow_on_canvas_meets_aa_for_large_text() {
    // Brand yellow (#FCD535) on canvas (#0B0E11). Large text /
    // accent strokes only need 3:1 (WCAG 2.1 SC 1.4.3).
    let r = contrast_ratio("FCD535", "0B0E11");
    assert!(r >= 3.0, "brand yellow contrast {r:.2}:1 below 3.0");
}

// ---------- T6.3 security headers e2e ---------------------------------

#[test]
fn security_header_set_is_complete_and_documented() {
    let names: Vec<&str> = SECURITY_HEADERS.iter().map(|(n, _)| *n).collect();
    for required in [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Strict-Transport-Security",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    ] {
        assert!(
            names.contains(&required),
            "security header table missing {required}"
        );
    }
}

// ---------- T6.6 bundle size budget -----------------------------------

#[test]
fn bundle_under_documented_budget() {
    // The DD-T1 bundle is one pre-compiled `app.js` + the React UMD
    // bundles (10.8 KB + 131 KB) + CSS + a tiny HTML shell + i18n.
    // Cap the raw total at ~600 KB. React UMD makes up most of the
    // weight today; we measured ~315 KB at v1.
    const RAW_BUDGET_BYTES: usize = 600_000;
    let mut total = 0usize;
    for path in ["index.html", "app.js", "aegis.css", "react.min.js", "react-dom.min.js", "i18n.json"] {
        let asset: EmbeddedAsset = lookup(path).unwrap_or_else(|| panic!("{path} must resolve"));
        total += asset.bytes.len();
    }
    assert!(
        total < RAW_BUDGET_BYTES,
        "asset bundle raw size {total} > budget {RAW_BUDGET_BYTES}"
    );
}

#[test]
fn app_js_under_per_bundle_budget() {
    // The pre-compiled app.js holds every page + every widget. Cap
    // at 420 KB to catch accidental dependency bloat — v1 was ~158 KB,
    // post-Phase-3 (Investigation pivot, Incidents queue with
    // ack/snooze/resolve, Threat Intel, Compliance, Reports CSV) is
    // ~263 KB. Bumped 2026-05-04 from 320 → 360 KB after the
    // Routing & Upstreams page was restructured. Bumped 2026-05-09
    // from 360 → 400 KB after Run-5: 4 new detector classes added
    // to the mask grid + the DetectorScorePanel. Bumped 2026-05-09
    // from 400 → 420 KB after the new Traffic Gates page surfacing
    // the four request-flow gates (access list, strike-block,
    // rate-limit, DDoS) with telemetry cards + operator guide.
    // Bumped 2026-05-10 from 420 → 432 KB after the Detectors page
    // UX overhaul (renamed to "Detectors & Tiers", inline score
    // badges + tier tints on every chip) and the Help & Guide
    // currency audit (added Traffic Gates step, How-it-works card,
    // glossary entries for traffic gates / rate limit / DDoS gate,
    // mid-incident workflow, and Rate-Limit-vs-DDoS FAQ).
    // Real dependency growth (new React lib, etc.) needs an
    // explicit budget bump + comment here, not a silent overrun.
    const APP_JS_BUDGET: usize = 432_000;
    let bytes = lookup("app.js").unwrap().bytes.len();
    assert!(
        bytes < APP_JS_BUDGET,
        "app.js = {bytes} bytes exceeds budget {APP_JS_BUDGET}"
    );
}
