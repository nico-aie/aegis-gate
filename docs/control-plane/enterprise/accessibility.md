# Accessibility

> Targeting WCAG 2.1 AA. Operators sometimes work in dim SOC rooms,
> sometimes on a single screen at 200% zoom — the dashboard has to
> hold up.

## Keyboard

- `Tab` reaches every interactive element, in document order.
- Visible focus ring on every focusable element. Ring colour
  `--color-accent` at 2px outside the element box.
- `Esc` closes the topmost modal / drawer.
- `⌘K` / `Ctrl+K` opens the Cmd-K palette from anywhere.
- `?` opens a keyboard-shortcuts cheat sheet.
- Sidebar navigation: `Up/Down` between items, `Enter` to follow.
- Tables: `Up/Down` between rows, `Enter` to expand drawer,
  `Space` to select row when checkboxes are present.
- Forms: `Enter` submits primary form, `Esc` cancels modal.
- Toast stack: `Esc` dismisses focused toast.

## Focus management

- Modals trap focus and restore focus to the originating control
  on close.
- Drawers trap focus while open; closing returns focus to the
  trigger row.
- Page navigation moves focus to the page header `<h1>` so screen
  readers announce the new page title.

## ARIA

- Sidebar: `<nav aria-label="Primary">`, each section is a
  `<ul role="list">` with a `<h2 class="visually-hidden">` for the
  section name.
- Each section header has `role="heading" aria-level="2"`.
- Stat cards: `role="group" aria-label="..."`, value uses
  `aria-live="polite"` so screen readers announce updates.
- Live Feed table: `role="log" aria-live="polite"
  aria-relevant="additions"`.
- Charts: include a `<figure>` with a hidden `<figcaption>`
  describing the trend in plain language ("Traffic spiked at
  16:40 to 12 req/s, blocked count followed at 5"). Refreshes
  whenever the chart updates.
- Status pills: `role="status"`, colour is paired with an icon or
  text label, never colour-only.

## Colour & contrast

- Body text on background: ≥ 4.5:1.
- Non-text UI (icons, borders): ≥ 3:1.
- Status colours never carry meaning alone — pair with text or
  icon. (Cf. the screenshot's pure-colour pie slices: legend
  required.)
- Light theme passes the same thresholds.
- Test matrix in `tests/dashboard/contrast.rs` walks every
  documented token pair through the WCAG formula and fails the
  build on regression.

## Motion

- Respect `prefers-reduced-motion: reduce`: collapse all
  transitions and chart animations to 0.
- No content shifts after first paint.
- No auto-playing animations.

## Screen reader

- All icons that convey meaning have `<title>` inside the SVG or
  an `aria-label` on the parent.
- Decorative icons have `aria-hidden="true"`.
- Live regions update at most every 2s to avoid flooding screen
  readers on busy traffic.

## Zoom

- Layout works at 200% browser zoom without horizontal scroll on
  a 1280px viewport.
- No fixed pixel sizes that would clip text on zoom — line
  heights are unitless, font sizes are pixels but containers are
  flex/grid.

## Localisation

- Single language (en) at v1, but no string is hardcoded — the
  i18n table in [`assets.md`](assets.md) is the single source of
  truth so right-to-left and longer translations don't break the
  layout when added.

## Testing

- Manual: every page navigated keyboard-only at least once before
  release.
- Automated: `axe-core` integration test loads each page in a
  headless Chromium and asserts no violations of severity ≥
  serious. Run as part of `cargo test` via a `dev-dependency`
  WebDriver harness.

## References

- [WCAG 2.1 Quick Reference](https://www.w3.org/WAI/WCAG21/quickref/)
- [WAI-ARIA Authoring Practices 1.2](https://www.w3.org/WAI/ARIA/apg/)
- [Inclusive Components](https://inclusive-components.design/)
