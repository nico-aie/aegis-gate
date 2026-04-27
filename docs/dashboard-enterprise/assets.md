# Asset & Embedding Strategy

> No build step. No `npm install`. Every byte the dashboard serves
> is checked in to the repo and embedded in the binary at compile
> time.

## Layout on disk

```
crates/aegis-control/
  assets/dashboard/
    index.html          ← SPA shell
    app.js              ← router + page loader
    aegis.css           ← aggregated component styles
    theme.js            ← exports window.AegisTheme tokens
    icons.svg           ← SVG sprite (single file)
    chart.umd.min.js    ← pinned Chart.js 4.x
    chart.umd.min.js.LICENSE
    pages/
      overview.js
      live.js
      attacks.js
      analytics.js
      audit.js
      rules.js
      tiers.js
      blacklist.js
      whitelist.js
      settings.js
      tracking.js
    components/
      stat-card.js
      line-chart.js
      donut.js
      sparkline.js
      table.js
      badge.js
      drawer.js
      modal.js
      toast.js
      confirm.js
      diff.js
      cmdk.js
      banner.js
      skeleton.js
    openapi.json        ← snapshot of /api/openapi.json
```

The directory is committed under `crates/aegis-control/assets/`
so the embedding is local to the crate.

## Embedding

```rust
// crates/aegis-control/src/dashboard/assets.rs
pub static INDEX_HTML: &[u8]  = include_bytes!("../../assets/dashboard/index.html");
pub static APP_JS:     &[u8]  = include_bytes!("../../assets/dashboard/app.js");
pub static AEGIS_CSS:  &[u8]  = include_bytes!("../../assets/dashboard/aegis.css");
// …per file…
```

A `pub fn lookup(path: &str) -> Option<EmbeddedAsset>` returns a
`{ bytes, content_type, etag }` struct. Content-types are derived
by extension; ETags are the blake3 of the bytes computed once at
crate-load time (via `OnceCell`).

## Server route

```
GET /dashboard/                  → INDEX_HTML
GET /dashboard/{any-path}        → INDEX_HTML  (SPA fall-through)
GET /dashboard/assets/<path>     → embedded asset by path
```

Headers:

- `Cache-Control: public, max-age=3600, must-revalidate` for
  assets under `/dashboard/assets/`.
- `ETag: "<blake3>"`.
- `Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'; object-src 'none'; base-uri 'self';
  frame-ancestors 'none'`.

`'unsafe-inline'` for styles is needed only because Chart.js
injects a few inline styles for tooltips. If we move to uPlot
(see below) we can drop it.

## Third-party dependencies

Only one runtime dependency: **Chart.js 4.x**, vendored at
`assets/dashboard/chart.umd.min.js`.

- Version pin tracked in
  `crates/aegis-control/assets/dashboard/CHARTJS_VERSION`
  (single line, e.g. `4.4.4`).
- License file vendored alongside.
- Update procedure: a CI job runs `scripts/update-chartjs.sh`,
  which downloads the release tarball, verifies the GPG signature
  against the maintainer's published key, copies the UMD build
  in, and bumps the version file. PR template requires a
  changelog link and a `cargo audit` summary.

### Why vendored, not CDN?

- Air-gapped deployments (fintech, public sector) can't reach a
  CDN.
- Reproducible builds.
- CSP stays tight (`script-src 'self'` only).
- Trade-off: ~250KB extra binary size. Acceptable.

### uPlot alternative

uPlot is ~40KB and has a tighter API surface. We're starting with
Chart.js because the line / pie / bar / stacked-bar mix on the
target pages is broader than uPlot covers natively. A migration
to uPlot is in scope for a later milestone if the Chart.js bundle
size becomes a concern.

## Fonts

System font stack only — see [`theme.md`](theme.md). No webfont
asset.

## Icons

Single SVG sprite, ~6KB. Each icon has an `<svg id="icon-…">` and
the page references it via `<use href="#icon-…"/>`. The sprite is
inlined into `index.html` rather than served separately so it's
available before the first paint.

## i18n

Single language (en) for v1. Strings live in
`assets/dashboard/i18n/en.json` and the SPA reads them
synchronously at boot. Adding more languages = ship more JSON
files; the loader picks one based on `Accept-Language`. No string
is hardcoded in HTML/JS — every label goes through `t("key")`.

## Build / verification

A `cargo test` run validates the asset directory:

- Each entry referenced from `assets.rs` exists on disk.
- `index.html` parses as HTML (via the `html5ever` test dep).
- `aegis.css` parses as CSS (via `lightningcss` test dep, dev-only).
- `theme.js` parses as JS (via a `swc_ecma_parser` test dep,
  dev-only).
- The Chart.js bundle's blake3 matches a known-good in
  `tests/dashboard/CHARTJS_DIGEST` (regenerated on each pinned
  bump).

## Size budget

| Asset | Max gzipped |
|-------|-------------|
| `index.html` (with sprite) | 12 KB |
| `app.js` (router + page loader) | 8 KB |
| `aegis.css` | 16 KB |
| Per-page JS | 6 KB each (×11 = 66 KB) |
| Components combined | 24 KB |
| `chart.umd.min.js` | 80 KB |
| **Total** | ~210 KB gzipped |

Budget enforced by a test: each file is gzipped in-test and
asserted against the limit.

## Hot reload (dev only)

`cfg(debug_assertions)` in `assets.rs` reads from disk on every
request instead of `include_bytes!`. Useful when iterating on
HTML/CSS/JS without rebuilding the binary. Disabled in release.

## Backup shell

The legacy `DASHBOARD_HTML` constant is renamed `DASHBOARD_HTML_V1`
and served at `/dashboard/legacy` for one release. Operators can
toggle the default via `admin.dashboard.legacy_shell: true`.
