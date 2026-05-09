# F-HIGH-002 · Investigation pivot link from Live Feed drops query params

**Severity:** HIGH  
**Component:** Dashboard — `Investigation` React component (SPA router)  
**Found:** 2026-05-07  

---

## Summary

The "Pivot to Investigation →" link in the Live Feed request-detail drawer navigates to `#/investigation?pivot=<request_id>&kind=request_id`. The Investigation page component does not read URL query parameters on mount, so the pivot input is not pre-filled and the search is not executed. The user lands on a blank Investigation page with no indication that the pivot failed.

## Observed behaviour

1. Open Live Feed → click a BLOCK row → detail drawer opens ✓
2. Click "Pivot to Investigation →" in the drawer.
3. URL changes to `http://127.0.0.1:9443/dashboard/#/investigation?pivot=5d5afe...&kind=request_id`
4. **Page renders the Overview component** — the route is not matched, the SPA falls back to the default route.

When navigating to the Investigation page directly via the sidebar, it works correctly. Manual pivot by typing in the search input also works correctly.

## Root cause

The SPA hash router treats `?pivot=X&kind=Y` as a query string on the hash-routed path. Depending on the router implementation, `#/investigation?pivot=X` may be matched differently from `#/investigation` — in some hash router configurations, the query string is part of the hash fragment and must be parsed separately. The Investigation component does not call `useSearchParams()` or read `window.location.hash`'s query portion on mount.

Additionally, the fallback route matching appears to redirect unknown/unmatched routes to Overview rather than showing a 404 — this masks the bug by silently rendering the wrong page.

## Impact

- S3 SOC scenario ("Which rule fired?") is broken for the primary intended workflow.
- The `Pivot to Investigation` button, `Block IP`, and `Whitelist` action buttons in the detail drawer are the core triage actions; one of three is non-functional.
- SOC analysts clicking the link will land on Overview with no feedback, losing their investigative context.

## Recommended fix

In the Investigation component, read query params from the hash fragment on mount:

```typescript
// On component mount:
const hash = window.location.hash; // e.g. "#/investigation?pivot=abc&kind=request_id"
const queryStart = hash.indexOf('?');
if (queryStart !== -1) {
  const params = new URLSearchParams(hash.slice(queryStart));
  const pivot = params.get('pivot');
  const kind = params.get('kind');
  if (pivot) {
    setPivotInput(pivot);
    setKindOverride(kind ?? 'auto-detect');
    triggerPivot(pivot, kind);
  }
}
```

Also fix the SPA fallback route to show a "page not found" view rather than silently redirecting to Overview.
