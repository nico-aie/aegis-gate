# Design System — single source of truth

> **Status:** Queued — supporting — Design tokens, fonts, motion, spacing for the dashboard-redesign track.
>
> See [`README.md`](../README.md) for the track status board.

> **Purpose.** One canonical token set, typography pairing,
> spacing scale, motion grammar, and theme rules. The Claude
> design workflow ([`workflow.md`](./workflow.md)) feeds this
> document into every stage. Page milestones may NOT
> introduce new tokens without naming them here first.

The current dashboard already has a token block at the top
of `crates/aegis-control/assets/dashboard/aegis.css` and a
theme switcher in `theme.js`. Treat those as legacy — M0
replaces them with what's below.

## 1. Visual direction

The WAF control plane is **a serious, dense, operator-facing
tool**. Pick one direction and commit. Defaulting to "clean
modern" is exactly what produces the current state.

| Option | Why it might fit | Why it might not |
|---|---|---|
| **Editorial / monochrome** with one accent | Operators read columns of audit events for hours; high text contrast + restrained color works | Risks looking sterile; needs craft on type pairing |
| **Dark-first terminal-adjacent** | Familiar to ops staff; status colours pop against neutral panel | Light theme needs equal investment, not an afterthought |
| **Bento layout** with intentional density | Glanceable Overview / Tracking pages; gives heterogenous widgets room | Risks playfulness on a security tool |

**Decision (M0):** *editorial monochrome with one signal
hue*. Light theme is the default; dark theme is full-fat
(not just inverted). Density target: 14 px body, 12 px
captions, 8-row stat grids visible above the fold at 1440 px
× 900 px.

## 2. Color tokens

OKLCH for perceptual uniformity. Tokens are surface- /
intent-named, never hue-named.

### Surfaces

| Token | Light | Dark | Used for |
|---|---|---|---|
| `--surface-app` | `oklch(98.4% 0.005 250)` | `oklch(15.5% 0.015 260)` | App background |
| `--surface-panel` | `oklch(99.6% 0.002 250)` | `oklch(19% 0.020 260)` | Cards, drawers |
| `--surface-sunken` | `oklch(96% 0.006 250)` | `oklch(13% 0.014 260)` | Code blocks, inline diffs |
| `--surface-raised` | `oklch(100% 0 0)` | `oklch(22% 0.018 260)` | Modals, command palette |
| `--border-subtle` | `oklch(91% 0.005 250)` | `oklch(28% 0.012 260)` | Card edges, table rules |
| `--border-strong` | `oklch(78% 0.008 250)` | `oklch(40% 0.014 260)` | Drawer divider, focus ring base |

### Text

| Token | Light | Dark | Notes |
|---|---|---|---|
| `--text-primary` | `oklch(18% 0.010 260)` | `oklch(96% 0.005 250)` | Body, table cells |
| `--text-secondary` | `oklch(45% 0.010 260)` | `oklch(72% 0.008 250)` | Captions, labels |
| `--text-muted` | `oklch(60% 0.008 260)` | `oklch(58% 0.008 260)` | Placeholder, idle status |
| `--text-on-accent` | `oklch(100% 0 0)` | `oklch(98% 0 0)` | On filled accent surfaces |

Contrast: every primary-on-surface pair clears WCAG AA
(4.5:1 for body, 3:1 for ≥18px). Compute and verify; do not
trust the eye.

### Signal palette

One hue per intent. Do not use a colour decoratively. If a
new state appears on a page, map it to an existing intent
before adding a new colour.

| Token | Light | Dark | Intent |
|---|---|---|---|
| `--signal-accent` | `oklch(58% 0.18 254)` | `oklch(72% 0.16 250)` | Brand, primary action, focus ring |
| `--signal-ok` | `oklch(62% 0.14 152)` | `oklch(74% 0.13 158)` | Healthy, allowed, mode=normal |
| `--signal-warn` | `oklch(72% 0.15 75)` | `oklch(80% 0.13 80)` | Degraded, mode=elevated, lockout pending |
| `--signal-error` | `oklch(57% 0.21 27)` | `oklch(70% 0.18 30)` | Block, mode=critical, fail-closed |
| `--signal-info` | `oklch(64% 0.10 220)` | `oklch(76% 0.10 220)` | System events, "no data yet" |

## 3. Typography

Two families, both system-stack-fallbacked. No CDN.

```css
--font-sans: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
--font-mono: "JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
```

### Type scale

| Token | Size | Line height | Use |
|---|---|---|---|
| `--text-xs` | `clamp(0.6875rem, 0.66rem + 0.1vw, 0.75rem)` | 1.4 | Status pills, table column headers |
| `--text-sm` | `clamp(0.8125rem, 0.78rem + 0.15vw, 0.875rem)` | 1.45 | Captions, secondary text |
| `--text-base` | `clamp(0.875rem, 0.85rem + 0.15vw, 0.9375rem)` | 1.5 | Body, table cells |
| `--text-md` | `1rem` | 1.45 | Card body, drawer body |
| `--text-lg` | `clamp(1.125rem, 1.05rem + 0.4vw, 1.25rem)` | 1.3 | Section headings |
| `--text-xl` | `clamp(1.5rem, 1.3rem + 0.8vw, 1.875rem)` | 1.2 | Page titles |
| `--num-stat` | `clamp(2rem, 1.6rem + 1.6vw, 2.75rem)` | 1.05 | Stat tiles only — feature numerals |

Numerics: enable `font-feature-settings: "tnum" 1, "ss01" 1`
on stat tiles + table numeric columns so columns of digits
align.

## 4. Spacing scale

Eight steps. Page widgets snap to multiples of 4 px.

```css
--space-1: 0.25rem;   /*  4px */
--space-2: 0.5rem;    /*  8px */
--space-3: 0.75rem;   /* 12px */
--space-4: 1rem;      /* 16px */
--space-5: 1.5rem;    /* 24px */
--space-6: 2rem;      /* 32px */
--space-8: 3rem;      /* 48px */
--space-10: 5rem;     /* 80px */
```

Rhythm: card padding `--space-5`, card gap `--space-3`,
section gap `--space-6`. Do **not** apply uniform padding
everywhere — that's how the current dashboard reads as
template-default.

## 5. Radius + elevation

| Token | Value | Used for |
|---|---|---|
| `--radius-1` | `4px`  | Pills, chips, inline tags |
| `--radius-2` | `8px`  | Buttons, inputs, table cells |
| `--radius-3` | `12px` | Cards, drawer header, modal |
| `--radius-4` | `16px` | Large hero panels (Overview only) |

Shadows are **functional**, not decorative. Two only:

| Token | Value | Used for |
|---|---|---|
| `--shadow-pop` | `0 1px 2px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.06)` | Drawer, modal, dropdown |
| `--shadow-focus` | `0 0 0 3px var(--signal-accent)` (alpha 0.35) | Focus ring on interactive |

Cards do not get shadows. Borders + surface delta carry
hierarchy.

## 6. Motion

Three durations, one easing curve. Anything else is a sign
the design is doing too much.

```css
--motion-fast:    120ms;     /* hover, focus, status pill flip */
--motion-normal:  220ms;     /* drawer slide-in, modal entry */
--motion-slow:    360ms;     /* layout transitions on resize */
--motion-ease:    cubic-bezier(0.16, 1, 0.3, 1);   /* expo-out */
```

Hard rule: **only animate `transform` and `opacity`**. No
`width` / `height` / `top` / `left` transitions — the
ongoing risk-table refresh would jank.

`prefers-reduced-motion: reduce` collapses every duration to
0.01 ms (already in `aegis.css`).

## 7. Layout chrome

| Region | Width / height | Notes |
|---|---|---|
| Sidebar | 240 px collapsed → 280 px expanded | Fixed; flush left; full height |
| Topbar | 56 px | Sticky; carries page title, search, command-palette trigger, user menu |
| Status bar | 32 px | Sticky bottom; carries connection pill, load-mode pill, verbosity pill, audit-chain pill |
| Content | fills remainder | 12-column grid; 1 480 px max content width on ≥1920 viewports |

The current shell is close to this — what M0 changes is the
density of the topbar (currently hosts too many controls
that should be hidden in the command palette) and the
status bar (currently mixes informational with interactive
slots).

## 8. Component grammar

Every component lives in
`crates/aegis-control/assets/dashboard/components/<name>.js`
and exposes the same shape:

```js
export default {
  mount(el, props),     // creates DOM under el, returns state
  update(state, props), // applies new props in place
  destroy(state),       // releases listeners + RAFs
};
```

Anything that holds a timer, an `EventSource`, or a
`MutationObserver` registers it on the returned state object
so `destroy` can release it deterministically. Forgetting
this is the most common source of the "page feels laggy
after navigating around" bug.

Existing components and what M0 expects of them:

| Component | M0 status | Notes |
|---|---|---|
| `badge`, `banner` | refresh | Move to `--signal-*` tokens; no semantic-vs-decorative drift |
| `cmdk` | rebuild | Currently a stub. Becomes the topbar-search target with `Cmd+K`/`Ctrl+K` shortcut. |
| `confirm`, `modal` | refresh | Add focus-trap; ESC + click-outside dismiss |
| `diff` | keep | Powers Rule Manager + Config diff |
| `donut`, `line-chart`, `sparkline` | rebuild | Single chart axis-style; SVG only (no Chart.js — that decision sticks per D-M2-T2.9 deferral) |
| `drawer` | refresh | Right-side, sticky on Live Feed + Audit Log |
| `skeleton` | keep | Used by every page in loading state |
| `stat-card` | refresh | Numeric-feature font, sparkline slot, trend pill |
| `table` | rebuild | Virtual rows on >500 entries, sticky header, sortable, keyboard-navigable |
| `toast` | refresh | Bottom-right stack; auto-dismiss; tied to status pills |

## 9. Density target table

Sets the floor each page negotiates against during stage 1
of the workflow. If a page can't hit these numbers it needs
a layout rethink.

| Page | Above-fold target at 1440×900 |
|---|---|
| Overview | 6 stat tiles + 1 chart + top-5 attackers row |
| Live Feed | Filter bar + 18 event rows + drawer trigger |
| Audit Log | 14 chain rows + verify pill + cursor controls |
| Attack Events | 12 rows + filter chip row + drawer trigger |
| Analytics | Time-window picker + 3 chart panels |
| Rule Manager | Rule list (8 rows) + editor panel + diff |
| Tier Config | 4 tier rows + override grid for the selected tier |
| Blacklist / Whitelist | 18 list rows + bulk-action bar + add field |
| Tracking | 6 widgets in a 3×2 grid + risk-clients table preview |
| Settings | 4 settings panels + footer with save / discard |

## 10. Theme switching

Implemented via `data-theme="light"|"dark"` on `<html>`.
Every token resolves through CSS variables — no JS theme
swaps mid-page; the system attribute change does the work.
Persistence in `localStorage("aegis_theme")`; default
follows `prefers-color-scheme`.

## 11. Out of scope for M0

- Custom illustrations
- Brand voice copy review (separate pass)
- Print stylesheet (we don't print this UI)
- High-contrast theme (separate accessibility ticket)
- Tenant-specific theme overrides (waiting on RBAC track)
