# NT-UI-03 · "default" vs "current" — input pre-filled with live value, label shows cfg default

**Covers:** the "default show value from config" half of the AI
threshold spec ·
**Prereq:** cluster running, Chrome logged in to http://127.0.0.1:9443 ·
**Expected duration:** ~3 min · **Severity if failing:** High

## Test

**Given** a fresh browser session with no prior threshold changes on
this cluster.

**When** the operator opens Detectors → AI row → details.

**Then** the **input** is pre-filled with the **live** value (matches
`/api/ai/confidence.confidence_threshold`) AND the **"default: X"**
label below it shows the **cfg-loaded** number (matches
`/api/ai/confidence.default`). After a Save, those two numbers
diverge: input + live stay in sync at the new value; default stays at
the cfg number.

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/Detectors. Find the AI (ml)
> row, click **▸ details** to expand it.
>
> Step 1 — at boot (before any change), tell me:
>   a) The number in the input field.
>   b) The "default: X" number under the label.
>   c) The "live: X" number near the Save button.
>
>   Assertion (a == b == c) at boot — confirm or report mismatch.
>
> Step 2 — change the input to `0.70` and Save. After the toast, tell me:
>   d) Input value now.
>   e) Default label number now.
>   f) Live number now.
>
>   Assertion (d == 0.70, f == 0.70, e UNCHANGED from b) — confirm or
>   report mismatch.
>
> Step 3 — RELOAD the page (Cmd+R / Ctrl+R). Re-expand the AI row, tell
> me the three numbers again. Assertion: input + live both `0.70`,
> default unchanged.

## Pass criteria

- [ ] At boot: input == default == live.
- [ ] After Save with 0.70: input = live = 0.70; default unchanged.
- [ ] After reload: input + live still 0.70 (config plane persisted);
      default unchanged.

## Why this matters

The "default" label is the operator's safety net — it tells them what
to type if they want to **reset** to the seeded config. If "default"
silently tracked the live value (a common bug), the operator would
lose the reference point and any drift becomes the new normal.

## Findings template

- Whether the three numbers agreed at boot.
- Whether default ever moved (it shouldn't).
- Screenshot of all three states (boot / post-save / post-reload).
