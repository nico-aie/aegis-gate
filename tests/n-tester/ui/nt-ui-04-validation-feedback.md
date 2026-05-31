# NT-UI-04 · Validation feedback — invalid values show a toast and do NOT PUT

**Covers:** client- and server-side validation of `confidence_threshold` ·
**Prereq:** cluster running, Chrome logged in to http://127.0.0.1:9443 ·
**Expected duration:** ~4 min · **Severity if failing:** High

## Test

**Given** the AI row is expanded.

**When** the operator enters an out-of-range, non-numeric, or otherwise
invalid value and clicks Save.

**Then** a **red** toast appears with a clear message, the network tab
shows **no PUT** (client-side reject) OR a 400 (server-side reject)
that the UI surfaces, and the **live value does NOT change**.

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/Detectors. Open Chrome
> DevTools → Network tab (Cmd+Opt+I, then Network). Filter to "ai".
>
> Find the AI (ml) row, expand details. Note the current "live: X"
> value — call it L. We'll try four invalid inputs and one valid.
> Report what happens for each:
>
> 1. Clear the input. Type `-0.5`. Click Save.
>    - Toast text + colour?
>    - Did a PUT to /api/ai/confidence fire in the Network tab? (yes/no)
>    - If yes, what status code did it return?
>    - Did "live" change? (it should still be L)
>
> 2. Clear the input. Type `1.5`. Click Save. Same four questions.
>
> 3. Clear the input. Type `abc`. (Some browsers block typing letters
>    in a number input — if so, report that and skip the click.) Then
>    click Save. Same four questions.
>
> 4. Clear the input. Type nothing (empty). Click Save. Same four
>    questions — note whether the Save button is disabled when empty.
>
> 5. Clear the input. Type `0.55`. Click Save. Same four questions —
>    this one should SUCCEED so we know the form isn't permanently
>    broken.
>
> Take a screenshot after each invalid attempt showing the toast.

## Pass criteria

- [ ] `-0.5`, `1.5`, `abc`, empty → red toast + **no live change**.
- [ ] If the client surfaces the error before PUT (client-side
      validation), the Network tab shows NO PUT.
- [ ] If the server is the gate, the PUT returns 400/422 and the UI
      surfaces it (NOT a silent failure).
- [ ] `0.55` (valid) succeeds with a green toast and live updates.

## Why this matters

A WAF whose threshold can be silently set out-of-range will
mis-classify every request (validation in the AiDetector treats
`prob_attack >= threshold`; with threshold = `NaN` or negative, every
request becomes an attack — or none does). The handler validates
server-side; the UI should surface that without forcing the operator
to dig in DevTools.

## Findings template

- For each input: toast text, PUT status (if any), final live value.
- Screenshots of the toasts.
- Note any case where the UI fired a PUT for an obviously-invalid
  value (`-0.5`, `1.5`) — that's a UX finding even if the server 400s.
