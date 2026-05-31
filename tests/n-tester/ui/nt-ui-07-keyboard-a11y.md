# NT-UI-07 · Keyboard navigation + ARIA — operators can drive the threshold without a mouse

**Covers:** baseline a11y on the new AI threshold control ·
**Prereq:** cluster running, Chrome logged in to http://127.0.0.1:9443 ·
**Expected duration:** ~5 min · **Severity if failing:** Medium

## Test

**Given** the AI row is collapsed.

**When** the operator uses Tab / Shift+Tab / Enter / arrow keys to
navigate to and adjust the threshold input.

**Then** focus visibly lands on each interactive element in a sensible
order, the input is announced by Chrome's accessibility tree with a
meaningful label, and the operator can change + save the value with
keyboard alone (no mouse).

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/Detectors. Make sure focus is
> at the top of the page (click somewhere neutral like the page header,
> or use Cmd+L then Tab once).
>
> Open Chrome DevTools → **Accessibility** tab (Cmd+Opt+I, then under
> the Elements panel switch to "Accessibility").
>
> 1. Tab through the page (press Tab repeatedly). Count how many tabs
>    it takes to reach **the AI row's "▸ details" toggle**. Tell me the
>    count and what the focused element looks like (focus ring style).
>
> 2. Press Enter on the details toggle to expand. Then Tab into the
>    expanded section. Tell me, in order, every element Tab lands on
>    until you reach the Save button. For each, report:
>      - What the element is (input, button, link).
>      - The Accessibility tab's Name / Role / Value.
>      - Whether the focus ring is visible.
>
> 3. Focus on the threshold input. Use **only** the keyboard to:
>      a) Clear it (Cmd+A then Delete, or Backspace through).
>      b) Type `0.55`.
>      c) Tab to Save and press Enter / Space.
>    Tell me if the save fires and the toast appears.
>
> 4. After save, use Shift+Tab to walk back. Does focus return
>    sensibly, or does it jump to the top of the page?
>
> Take a screenshot of the Accessibility panel showing the threshold
> input's Name + Role.

## Pass criteria

- [ ] Tab reaches the details toggle in a reasonable number of stops
      (≤ 25 for a typical Detectors page; if much more, flag).
- [ ] The threshold input has a non-empty **accessible name**
      (something like "Confidence threshold", NOT empty / "input" /
      raw HTML id).
- [ ] Role is `spinbutton` (HTML `<input type="number">`) or
      equivalently `textbox`; **NOT** missing.
- [ ] Focus ring is visible on every focused element (not removed by
      `outline: none` with no replacement).
- [ ] Keyboard-only edit + save works end-to-end (no mouse needed).
- [ ] Save with Enter behaves the same as click.

## Why this matters

Operators in incident response often work in tmux + a tiny browser tab
on a phone, or with screen readers. A control that requires mouse
hover or has no name is silently inaccessible.

## Findings template

- Tab count to reach the input.
- Accessibility name / role of the input (exact strings).
- Any element with no visible focus ring.
- Screenshot of the Accessibility panel.
- If keyboard save failed: which step (e.g. "Enter on Save did
  nothing — needed Space").
