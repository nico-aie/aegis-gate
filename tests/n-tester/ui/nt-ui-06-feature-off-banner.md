# NT-UI-06 · Feature-off banner — input disabled with rebuild hint

**Covers:** graceful degradation when the binary lacks `--features ai` ·
**Prereq:** cluster running with the **no-ai** binary
(`make build FEATURES="redis geoip alerts affinity"` — note: no `ai`) ·
**Expected duration:** ~2 min · **Severity if failing:** Medium

## Test

**Given** the binary was built **without** `--features ai`.

**When** the operator opens Detectors → AI row → details.

**Then** the AI row's status pill reads **"🔒 feature off"**, the
threshold input is **disabled (greyed out)** and shows the cfg-loaded
default, the Save + reset buttons are disabled, and a hint reads
something like *"rebuild with `--features ai`"*.

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/Detectors. Find the AI (ml)
> row.
>
> 1. Read the status pill on the right side of the row. Is it green
>    ("enabled"), grey ("disabled"), or "🔒 feature off"? Tell me which.
>
> 2. If the pill is "🔒 feature off", click **▸ details** to expand
>    anyway. Tell me:
>      a) Is the threshold input greyed out / non-interactive?
>      b) What number is shown in the input?
>      c) What's the "default: X" label say?
>      d) Is the Save button disabled?
>      e) Is there any visible rebuild hint? Quote it exactly.
>
> 3. Try clicking the Enable button at the right of the row anyway.
>    What toast appears (if any)?
>
> If step 1 showed the pill as green or grey, this binary HAS the AI
> feature — STOP and tell me; this test needs a no-ai build.

## Pass criteria

- [ ] Pill reads "🔒 feature off".
- [ ] Threshold input is disabled / non-editable.
- [ ] Input still shows a usable number (the cfg default,
      typically 0.85).
- [ ] Save button is disabled.
- [ ] A clear rebuild hint is present (the AI Enable disabled-state
      message + `--features ai` hint is acceptable; the threshold row
      doesn't need its own duplicate hint if the row-level one is
      visible).
- [ ] Enable button (if clickable) toasts a clear "feature not built"
      message — not a 500.

## Why this matters

Operators reading the dashboard without context shouldn't be left
guessing why the input is greyed out. A blank input with no hint is
indistinguishable from a broken UI.

## Findings template

- Pill text, input state, hint text (quote verbatim).
- Any case where the input was editable but the PUT silently 409'd or
  500'd — that's a worse failure mode than honest disabled state.
- Screenshot of the row.
