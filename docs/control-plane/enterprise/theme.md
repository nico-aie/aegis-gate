# Theme — Design Tokens

> Tokens are CSS custom properties on `:root`. Light/dark variants
> swap via `data-theme="light|dark"` on `<html>`. Default: `dark`
> (matches the screenshot reference).

## Colour scale

```
--surface-0:        #0b1020   /* page background          */
--surface-1:        #0f172a   /* primary panel            */
--surface-2:        #1e293b   /* card                     */
--surface-3:        #273449   /* card hover               */
--surface-active:   #1c3454   /* sidebar active row       */
--surface-hover:    #1a2540   /* sidebar hover row        */

--border-subtle:    #1f2a44
--border-default:   #334155
--border-strong:    #475569

--text-primary:     #e2e8f0
--text-secondary:   #94a3b8
--text-muted:       #64748b
--text-inverse:     #0f172a

--color-accent:     #06b6d4   /* cyan — active nav, primary CTA */
--color-accent-2:   #3b82f6   /* electric blue — links          */

--color-ok:         #10b981   /* healthy / allow                */
--color-warn:       #f59e0b   /* degraded / amber               */
--color-err:        #ef4444   /* blocked / down                 */
--color-info:       #60a5fa
--color-violet:     #a78bfa   /* used in attack categories      */
--color-pink:       #ec4899
--color-teal:       #2dd4bf
```

Light theme (override on `data-theme="light"`):

```
--surface-0:        #f8fafc
--surface-1:        #ffffff
--surface-2:        #f1f5f9
--surface-3:        #e2e8f0
--text-primary:     #0f172a
--text-secondary:   #475569
--text-muted:       #64748b
```

All colour pairs must clear WCAG AA (4.5:1 for body, 3:1 for
non-text). Spec in [`accessibility.md`](accessibility.md).

## Typography

```
--font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
             "Helvetica Neue", Arial, sans-serif;
--font-mono: ui-monospace, SFMono-Regular, "JetBrains Mono",
             Menlo, Consolas, monospace;

--font-size-xs:   11px / 16px
--font-size-sm:   12px / 18px
--font-size-base: 14px / 20px
--font-size-lg:   16px / 24px
--font-size-xl:   20px / 28px
--font-size-2xl:  28px / 36px      /* stat-card value */
--font-size-3xl:  40px / 48px      /* hero KPI on Overview */

--font-weight-regular: 400
--font-weight-medium:  500
--font-weight-semi:    600
--font-weight-bold:    700
```

System font stack only — no webfont. Saves a TLS round-trip and
avoids a CSP exception.

## Spacing & sizing

```
--space-0:  0
--space-1:  4px
--space-2:  8px
--space-3:  12px
--space-4:  16px
--space-5:  20px
--space-6:  24px
--space-8:  32px
--space-10: 40px
--space-12: 48px
--space-16: 64px

--radius-sm: 4px
--radius-md: 8px
--radius-lg: 12px
--radius-pill: 999px

--shadow-sm: 0 1px 2px rgba(0,0,0,.18)
--shadow-md: 0 4px 12px rgba(0,0,0,.24)
--shadow-lg: 0 12px 32px rgba(0,0,0,.32)
```

## Motion

```
--duration-fast:   80ms
--duration-base:  120ms
--duration-slow:  220ms
--ease:           cubic-bezier(.2, .8, .2, 1)
```

`prefers-reduced-motion: reduce` collapses all transitions to 0ms.

## Status semantics

| Concept | Token | Where it shows |
|---------|-------|----------------|
| Healthy / Allow / Pass | `--color-ok` | Stat-card value, sidebar LED, table row badge |
| Degraded / Throttled | `--color-warn` | Pool partial-down, SLO 50% burn, GitOps drift |
| Down / Block / Fail | `--color-err` | Stat value, attack count, lockout banner |
| Info / Audited | `--color-info` | "1,234 events recorded" notes |
| Recon / Bot | `--color-violet` | Attack-distribution slices |

## Charts

Chart.js palette derived from the tokens above:

```
chart.line.traffic   = --color-info
chart.line.blocked   = --color-err
chart.area.fill      = rgba(96, 165, 250, .12)
chart.pie.recon      = --color-violet
chart.pie.ssrf       = --color-violet
chart.pie.ssti       = --color-pink
chart.pie.path_trav  = --color-warn
chart.pie.cmdi       = --color-err
chart.pie.lfi        = --color-teal
chart.pie.honeypot   = --color-err
chart.grid           = --border-subtle
chart.text           = --text-secondary
```

The mapping lives in `dashboard/assets/theme.js`, exported as
`window.AegisTheme.chart` so each page can read it without a parse.

## Iconography

Single inline SVG sprite at `/dashboard/assets/icons.svg`. Embedded
in the binary. Icons match Lucide stroke style at 1.5px stroke,
20×20 px viewbox. Tokens used: `currentColor`. Set the `color`
property to recolour. Initial set:

`shield`, `activity`, `siren`, `bar-chart`, `book`, `layers`,
`ban`, `check`, `server`, `globe`, `lock`, `clipboard`, `settings`,
`gauge` (Tracking page), `key`, `cpu`, `radio`.

## Theme toggle

The user menu in the top bar exposes Light / Dark / System. Selection
is persisted in `localStorage` under `aegis.dashboard.theme`. On load
the SPA reads this synchronously before first paint to avoid a
flash-of-wrong-theme.
