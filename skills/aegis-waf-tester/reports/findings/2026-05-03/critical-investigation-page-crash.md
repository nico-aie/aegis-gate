---
id: 2026-05-03-critical-investigation-page-crash
date: 2026-05-03T17:35Z
severity: CRITICAL
area: dashboard
component: investigation-page
status: fixed
test_mode: full-qc
---

# Investigation page crashes on render — `useEffectW is not defined`

## Summary
The Investigation page never mounts. The error boundary catches a
ReferenceError and renders "Page render error · useEffectW is not
defined." This kills the most important SOC-analyst workflow:
clicking **Pivot** on a Top Attackers row sends the user to
`#/investigation?pivot=<ip>&kind=ip`, where they expect a focused
timeline + summary panels for that attacker. Instead they get the
error card. The Top Attackers Pivot link visibly updates the URL
hash but the React app never replaces the page body — Overview
stays mounted, sidebar loses its active state — until you click
Investigation directly, at which point you see the crash.

The bug is a one-character typo. `pages.jsx` aliases React hooks
with a `P` suffix at the top of the module:

```js
// crates/aegis-control/assets/dashboard/src/pages.jsx:2
const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP, Fragment } = React;
```

The Investigation component at `pages.jsx:5718` calls
`useEffectW(...)` instead of `useEffectP(...)`. `useEffectW` is the
alias used over in `widgets.jsx:2`; somebody pasted code across
files and missed the rename.

## Repro
1. Boot a dev WAF (`make redis-up && make run-dev`).
2. Send any attack traffic so Top Attackers has rows
   (`curl -H "X-Forwarded-For: 8.8.8.8" "http://127.0.0.1:8080/?q=<script>alert(1)</script>"`
   a few times).
3. Sign in to `http://127.0.0.1:9443/admin/login`, navigate to
   **Top Attackers**, click **Pivot** on the 8.8.8.8 row.
4. URL becomes `…/dashboard/#/investigation?pivot=8.8.8.8&kind=ip`,
   page body still shows Overview.
5. Click **Investigation** in the sidebar.

## Expected
Investigation page mounts with the pivot pre-applied, showing a
timeline filtered to the attacker plus the summary panels.

## Actual
```
Page render error
This page hit a JavaScript error while rendering.
The shell + sidebar still work — pick a different page or reload.

useEffectW is not defined
```

The error UI itself is good (Retry render / Back to Overview /
Reload page buttons, sidebar still works). The page never recovers.

## Suggested fix
At `crates/aegis-control/assets/dashboard/src/pages.jsx:5718`,
rename `useEffectW` → `useEffectP`:

```diff
-  useEffectW(() => {
+  useEffectP(() => {
     if (typeof location === 'undefined') return;
     const m = location.hash.match(/\?(.+)$/);
```

Add a Playwright smoke test that opens every sidebar item and
asserts no error-boundary card renders. This whole class of bug
(typo'd hook alias inside a JSX file with no module-level lint)
recurs without it.

Bonus: the Pivot link from Top Attackers should also navigate the
shell, not just rewrite the hash. Today, going from Top Attackers
to Investigation via Pivot doesn't change the page; only the
sidebar click does. That's a routing-listener miss in the page
component (it doesn't react to hashchange to remount), and it's
what hides the Investigation crash from operators who only ever
click Pivot.

## Severity rationale
CRITICAL. The Investigation page is the central SOC-analyst
workflow — "what did this attacker do?" is the question the
Pivot button promises to answer. Right now the answer is a stack
trace. Top Attackers / Audit Trail / Live Feed all work, so the
operator can manually piece together what an attacker did, but
that's directly counter to the dashboard's design pitch
("one-click Pivot to investigate").
