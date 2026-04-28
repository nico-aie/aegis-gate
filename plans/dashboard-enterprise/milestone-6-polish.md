# Milestone D-M6 — Polish & Sunset Legacy

**Goal.** Tighten everything: accessibility audit, security
headers verified end-to-end, perf budget enforced in CI, doc
updates, legacy shell removed.

**Crate touched.** `aegis-control` (mostly tests + assets);
small touch to `docs/`.

**Verification.** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`.

**References.**
- [`docs/control-plane/enterprise/accessibility.md`](../../docs/control-plane/enterprise/accessibility.md)
- [`docs/control-plane/enterprise/security.md`](../../docs/control-plane/enterprise/security.md)
- [`docs/control-plane/enterprise/assets.md`](../../docs/control-plane/enterprise/assets.md)

---

## Tasks

### D-M6-T6.1 Accessibility audit

- New tests: `tests/dashboard/a11y.rs` — boots admin listener,
  drives a headless Chromium via `fantoccini` (or, if the build
  becomes finicky, a hand-rolled CDP client) through each page,
  injects `axe-core`, asserts zero violations of severity ≥
  serious.
- Fix violations as they arise; common offenders are missing
  `aria-label` on icon-only buttons and insufficient
  contrast on hover states.

### D-M6-T6.2 Contrast matrix

- New test: `tests/dashboard/contrast.rs` — walks every
  documented token pair from [`theme.md`](../../docs/control-plane/enterprise/theme.md)
  through the WCAG formula. Fails on regression.

### D-M6-T6.3 Security headers e2e

- New test: `tests/dashboard/headers.rs` — fetches one URL per
  surface (asset, page route, API endpoint, SSE stream) and
  asserts every header in [`security.md`](../../docs/control-plane/enterprise/security.md)
  §"Headers (full set)".

### D-M6-T6.4 XSS regression

- New test: `tests/dashboard/xss.rs` — feeds a corpus of
  malicious audit events (existing `tests/security/corpus/malicious/`)
  through `/dashboard/sse`, drives a headless browser, asserts
  no script executes (CSP `report-uri` is hit zero times).

### D-M6-T6.5 SRI assertion

- New test: `tests/dashboard/sri.rs` — reads
  `assets/dashboard/index.html`, extracts the
  `integrity="sha384-…"` literal for `chart.umd.min.js`,
  recomputes the digest from disk, asserts equality.

### D-M6-T6.6 Bundle size budget

- New test: `tests/dashboard/budget.rs` — walks
  `assets/dashboard/`, gzips each file, asserts each ≤ the
  budget in [`assets.md` §size-budget](../../docs/control-plane/enterprise/assets.md#size-budget),
  total ≤ 220 KB gzipped.

### D-M6-T6.7 Lighthouse

- New `tests/dashboard/lighthouse.rs` (cfg-gated, optional in
  CI): run lighthouse-ci against `/dashboard/overview` and
  assert perf/a11y/best-practices ≥ 95.

### D-M6-T6.8 Docs touch-up

- Update `docs/control-plane/dashboard.md` to point at
  `docs/control-plane/enterprise/` for the v2 surface; keep the v1
  contract section unchanged.
- Update `docs/README.md` index with the new
  `docs/control-plane/enterprise/` entry.
- Update `README.md` "Documentation" table.

### D-M6-T6.9 Remove legacy shell

- Delete `src/dashboard/legacy.rs` and the
  `admin.dashboard.legacy_shell` config flag.
- Bump the minor version (`Cargo.toml`s) to flag the breaking
  change for any operator that flipped the flag on.
- Migration note in `Implement-Progress.md`.

### D-M6-T6.10 Final progress overwrite

- Overwrite `Implement-Progress.md` per [`../plan.md`](../plan.md) §0.3 with:
  - The full Completed Tasks Log appended with all D-M1..D-M6 tasks.
  - `## Next Task` reset to the next non-dashboard remaining
    item (e.g. "Production Dockerfile + Helm chart" from the
    pre-existing roadmap).

## Exit gate

- All 18+ new tests added across milestones M6 pass.
- Full workspace test count is whatever the running total is —
  ≥ 1,477 + ~150 added across D-M1..D-M6.
- Lighthouse run produces ≥ 95 across perf / a11y / best-practices.
- `cargo clippy --workspace -- -D warnings` clean.
- `docs/README.md` and `README.md` updated.
- Legacy shell removed; the minor version bump documented in
  the changelog (or in `Implement-Progress.md` if no changelog
  yet exists).
