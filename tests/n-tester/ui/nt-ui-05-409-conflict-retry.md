# NT-UI-05 · Version conflict (409) — second tab shows conflict + auto-reload

**Covers:** dashboard 409 auto-retry (commit `38d6fb2`) and the
config-plane CAS contract ·
**Prereq:** cluster running, Chrome logged in to http://127.0.0.1:9443 ·
**Expected duration:** ~5 min · **Severity if failing:** Medium

## Test

**Given** two browser tabs open on Detectors → AI row → details.

**When** the operator saves a new threshold in **Tab A** and then,
without refreshing, saves a *different* threshold in **Tab B**.

**Then** Tab B's PUT returns `409 version_conflict`, the dashboard
auto-retries (csrfMutate handles 409 by re-fetching the latest version
and re-issuing), and the operator sees either a brief "version
conflict — reloading" toast or a successful save against the new
version.

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/Detectors. Open the AI (ml)
> row's details.
>
> 1. Open a SECOND tab to the same URL — let's call them **Tab A** and
>    **Tab B**. Expand the AI row in both.
>
> 2. In Tab A, change the threshold to `0.40`, click Save, wait for
>    the green toast. DO NOT switch to Tab B yet.
>
> 3. Switch to Tab B (which still believes the old version). Change
>    its threshold to `0.60`, click Save. Tell me:
>      a) The toast text in Tab B.
>      b) Whether the Network tab shows ONE PUT or TWO (the dashboard
>         is supposed to auto-retry on 409 by re-fetching `current`
>         and re-issuing).
>      c) The final "live" value in Tab B after the smoke clears.
>      d) The final "live" value in Tab A after a few seconds.
>
> 4. Take a screenshot of Tab B at the moment the conflict surfaces.

## Pass criteria

- [ ] Tab B's first PUT response is **409** with
      `error: "version_conflict"` (visible in DevTools).
- [ ] The dashboard either:
      - auto-retries (you see two PUTs in Tab B's Network tab, the
        second 200), OR
      - surfaces a toast like "version conflict — reload" and Tab B
        ends up showing `0.40` (Tab A's value, after the auto-reload).
- [ ] Both tabs eventually converge to the same live value.
- [ ] No "Internal Server Error" or silent failure.

## Why this matters

The cluster config plane is **multi-writer + CAS** by design — there's
no "leader-only writes" lock. Two operators (or two tabs of one
operator) editing at once is a normal case; if the UI doesn't handle
it gracefully, operators learn to treat the dashboard as flaky and
either avoid it or batch all their changes through one tab.

## Findings template

- Was the 409 visible to the operator at all (or silently absorbed)?
- Did the retry actually take Tab B's value, or did Tab A's win?
  (Both are valid as long as the user understands which.)
- Screenshot of the conflict.
