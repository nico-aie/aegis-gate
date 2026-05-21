# Milestone D-M1 — SPA Shell

> **Status:** Closed — D-M1 shipped.
>
> See [`README.md`](../../README.md) for the track status board.

**Goal.** Replace the embedded single-file dashboard with a real SPA
shell: sidebar nav, top bar, status bar, client-side router,
asset embedder. Pages are placeholder ("Coming soon") at this
milestone — M2 fills the Overview page.

**Crate touched.** `aegis-control` only.
**Verification.** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`.

---

## Scope

### Files added

```
crates/aegis-control/assets/dashboard/index.html
crates/aegis-control/assets/dashboard/app.js
crates/aegis-control/assets/dashboard/aegis.css
crates/aegis-control/assets/dashboard/theme.js
crates/aegis-control/assets/dashboard/icons.svg
crates/aegis-control/assets/dashboard/i18n/en.json
crates/aegis-control/assets/dashboard/pages/{overview,live,attacks,analytics,
                                              audit,rules,tiers,blacklist,
                                              whitelist,settings,tracking}.js
                              (placeholders rendering "Coming soon")
crates/aegis-control/assets/dashboard/components/{stat-card,line-chart,donut,
                                                  sparkline,table,badge,
                                                  drawer,modal,toast,confirm,
                                                  diff,cmdk,banner,skeleton}.js
                              (skeleton stubs that mount empty divs)
crates/aegis-control/src/dashboard/assets.rs
crates/aegis-control/src/dashboard/router.rs
crates/aegis-control/src/dashboard/legacy.rs   ← keeps DASHBOARD_HTML_V1
```

### Files modified

- `crates/aegis-control/src/dashboard/mod.rs` — switches the
  `/dashboard/` handler to serve `INDEX_HTML` and adds
  `/dashboard/assets/*` route. Re-exports `DASHBOARD_HTML_V1`
  from `legacy.rs`.
- `crates/aegis-control/src/server.rs` — registers the new
  asset route + sets the security headers from
  [`docs/control-plane/enterprise/security.md`](../../../docs/control-plane/enterprise/security.md).
- `crates/aegis-control/Cargo.toml` — **no new deps**. Confirm
  `mime_guess` (or equivalent already present) is available
  for content-type lookup; if not, hand-roll a small extension
  match.

### Files unchanged

- All auth, audit, SIEM, SLO, GitOps, compliance modules.

## Tasks

### D-M1-T1.1 Asset embedder

- File: `src/dashboard/assets.rs`
- API:
  ```rust
  pub struct EmbeddedAsset {
      pub bytes: &'static [u8],
      pub content_type: &'static str,
      pub etag: &'static str,
  }
  pub fn lookup(path: &str) -> Option<EmbeddedAsset>;
  ```
- ETag = lowercase hex of `blake3` of bytes; computed once at
  module init via `OnceCell`.
- Test: every asset listed in the directory tree above resolves
  via `lookup`. Unknown path returns `None`. ETag is deterministic
  across calls.

### D-M1-T1.2 SPA shell HTML

- File: `assets/dashboard/index.html`
- Skeleton matches [`docs/control-plane/enterprise/layout.md`](../../docs/control-plane/enterprise/layout.md):
  top bar + sidebar + content + status bar.
- Inline the SVG sprite from `icons.svg` (CI step or Rust build
  step — but since we have no build step, the simplest path is
  to commit the inlined sprite directly into `index.html` and
  treat `icons.svg` as the editable source).
- SRI hash for `chart.umd.min.js` written as a literal string
  in `index.html`; an embedded test asserts it matches the file
  digest. (Chart.js itself isn't loaded at M1 — only at M2 when
  the first chart appears.)
- Test: parses as HTML; contains the expected sentinel ids
  (`#aegis-app`, `#aegis-toasts`).

### D-M1-T1.3 Router

- File: `assets/dashboard/app.js`
- Pure-vanilla, ~120 lines.
- Map: path → `() => import("/dashboard/assets/pages/<name>.js")`.
- Mount lifecycle: `mount(el, route)`, `destroy()` on navigation.
- History API; back/forward works; deep links work.
- Test: a `tests/dashboard/router_smoke.rs` integration test
  boots the server, requests `/dashboard/foo`, asserts the SPA
  shell HTML is returned (server-side fall-through).

### D-M1-T1.4 Sidebar + top bar (chrome only)

- Files: `assets/dashboard/index.html`, `assets/dashboard/app.js`,
  `assets/dashboard/aegis.css`.
- Sidebar items render and highlight the active page from URL.
- Top bar: logo, version (placeholder), env label (placeholder),
  user menu (just a sign-out link wired to `POST /admin/logout`).
- Status bar: SSE connection state pill (placeholder
  `Disconnected` until M2 wires SSE), last sync placeholder.
- Theme toggle in user menu; persists to `localStorage`.
- Test: server-side test asserts CSS file loads with `text/css`
  and is non-empty.

### D-M1-T1.5 Security headers

- File: `src/server.rs`
- Add the headers from [`docs/control-plane/enterprise/security.md`](../../../docs/control-plane/enterprise/security.md)
  to every `/dashboard/*` response. Place behind a small tower
  middleware so it's reused.
- Test: integration test fetches `/dashboard/` and asserts:
  `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Strict-Transport-Security`,
  `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-*-Policy` headers all present and match the spec.

### D-M1-T1.6 Legacy shell carve-out

- File: `src/dashboard/legacy.rs`
- Move the existing `DASHBOARD_HTML` constant into this module
  and re-export as `DASHBOARD_HTML_V1`.
- Add a config-flag-gated route: when
  `cfg.admin.dashboard.legacy_shell == true`, `/dashboard/`
  serves the legacy HTML; default `false`.
- Add the new config field in `aegis-core::config::AdminConfig`
  with a `serde(default)` so existing `waf.yaml` files keep
  working.
- Test: with the flag off, `/dashboard/` returns the new shell;
  with the flag on, returns the legacy HTML.

### D-M1-T1.7 Hot-reload (dev only)

- File: `src/dashboard/assets.rs` (cfg-gated)
- `#[cfg(debug_assertions)]` reads from disk under
  `crates/aegis-control/assets/dashboard/<path>` instead of
  `include_bytes!`.
- No test required; protected by cfg.

### D-M1-T1.8 i18n loader

- File: `assets/dashboard/app.js`
- Loads `/dashboard/assets/i18n/en.json` synchronously (via
  fetch + await before first render) and exposes `t(key)`.
- All strings in `index.html` and `app.js` go through `t()`.
- Test: `i18n/en.json` parses; every key referenced from
  `app.js` exists.

## Exit gate

- `/dashboard/` returns the new SPA shell with all chrome,
  even though pages are placeholders.
- `/dashboard/legacy` (optional) still returns the v1 shell when
  the config flag is set.
- All 14 component stubs and 11 page stubs resolve via
  `lookup()`.
- Security headers verified by integration test.
- Existing `dashboard_html_is_valid` and SSE tests still pass —
  the legacy constant lives on under a new name.

## Implement-Progress.md update

After M1 completes:

```
## Last Completed
- Task: D-M1 SPA shell + asset embedder
- Crate: aegis-control
- Files changed: <list>
- Status: DONE
- Date: <YYYY-MM-DD>

## Next Task
- Task: D-M2-T2.1 Stats endpoints
- Plan: plans/dashboard-enterprise/milestone-2-overview.md
- Notes: starts the Overview page wiring
```
