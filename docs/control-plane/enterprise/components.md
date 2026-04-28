# Component Library

> Vanilla, no framework. Each component is a small JS module with a
> `mount(el, props)` function and a `destroy()` cleanup. Styles
> live in `dashboard/assets/components.css`. All components consume
> the design tokens from [`theme.md`](theme.md).

## Stat card

```
<div class="aegis-stat" role="group" aria-label="Requests/s">
  <div class="aegis-stat__head">
    <h3>Requests/s</h3>
    <svg class="aegis-stat__icon"><use href="#icon-activity"/></svg>
  </div>
  <div class="aegis-stat__value">0.1</div>
  <div class="aegis-stat__sub">last 10 seconds</div>
</div>
```

Props: `title`, `value`, `subtitle`, `icon`, `status`
(`ok|warn|err|info|none`), `href` (optional click target).

## Line chart

`mount(el, { series: [{ name, color, points: [{x,y}] }], live: true })`

- Wraps Chart.js. Live mode rebuilds the dataset incrementally
  via `chart.update('none')`.
- Tooltip uses the theme palette; gridlines from
  `--border-subtle`.

## Donut / pie

`mount(el, { slices: [{ name, value, color }] })`

- Inner radius 60%, animated reveal capped at 220ms.
- Legend orientation prop: `"right" | "bottom"`.
- Click handler returns the slice name.

## Sparkline

A 60×20px canvas chart used inside table rows.
`mount(el, { points: [n, n, ...], color })`. No axes, no tooltip.

## Table

`mount(el, { columns, rows, sortBy, paged, virtualized, onRowClick })`

- Columns: `{ key, label, render?(row) }`.
- Sorting: client-side; `sortable: false` per column.
- Pagination: `paged: { pageSize: 100, cursor }` (server-side
  cursor) or `paged: { pageSize: 50 }` (client-side).
- Virtualization: only used for the Live Feed and Audit Log
  tables. The table mounts a sentinel-based windowing helper
  (no library).

## Badge / pill

`mount(el, { tone: 'ok|warn|err|info|neutral', label })`

- `--radius-pill`, height 22px, font-size 12px.

## Drawer

A right-anchored 480px overlay. Trapped focus, ESC to close,
click-out to close, persistent only while loading async data.
`mount(el, { title, body, footer, onClose })`.

## Modal

Centred 480px or 640px modal. Backdrop blocks clicks; ESC closes
unless `dismissable: false`. Same focus-trap as Drawer.

## Toast

Top-right stack, max 3 visible, autoclose at 4000ms unless
`tone: 'err'` (sticky, requires manual dismiss). Use for action
results: "Saved", "Validation failed", "Session revoked".

## Confirm dialog

Specialised Modal: title, body, optional "type the resource
name to confirm" input, OK / Cancel. Returns a Promise<boolean>.
Used for every destructive action (delete rule, remove
blacklist, rotate session secret).

## Diff viewer

Read-only unified-diff renderer. Line-level highlight on
additions / deletions, soft-wrap, optional line numbers.
Powered by a small in-house LCS implementation (~150 lines).

## Form primitives

Minimal set: `<input>`, `<select>`, `<textarea>`, multi-select
chip group, date-time picker (native `<input type="datetime-local">`
on supporting browsers, fall-back combo otherwise). All sized
to the spacing scale.

## Cmd-K palette

Top-bar global search. Open via `⌘K` / `Ctrl+K`. Fuzzy-matches
page names, rule ids, blacklist/whitelist entries (search the
last cached server snapshot — no per-keystroke server hit).

## Notification banner

Full-width banner under the top bar, used for:
- Break-glass override active.
- Audit chain broken.
- GitOps drift detected.
- Cert expiring < 7 days.

Tone `err` is sticky; `warn` is dismissable.

## Status pill (sidebar / top bar)

Small dot + text next to a label. States: `ok|warn|err|info`.
Used for the global health LED, environment label, audit-chain
status, and SSE connection state in the status bar.

## Skeleton

A pulse-animated grey block sized to the content it'll replace.
Used while initial data is loading. Auto-removes when the
component receives its first data point. No skeleton runs longer
than 1s — it falls back to a static "Loading…" then.

## Implementation notes

- Each component is < 200 lines of JS. Tree-shaking is moot
  because we ship the whole bundle (≈25 KB gzipped).
- All components dispatch DOM `CustomEvent`s for interactions
  (`aegis:row-click`, `aegis:slice-click`, `aegis:save`) instead
  of forcing a callback prop. This keeps page modules decoupled
  from component internals.
- A single `aegis.css` file aggregates the per-component CSS for
  cache friendliness; each component sets its own
  `data-component` attribute so styles are scoped.
