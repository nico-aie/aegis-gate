---
id: 2026-05-11-not-wired-pill-on-wired-feature
date: 2026-05-11T17:25Z
severity: HIGH
area: dashboard
component: settings · response-filtering-card
status: resolved
resolved_at: 2026-05-11T18:00Z
test_mode: full-qc
---

> **RESOLVED 2026-05-11T18:00Z.** Closed as a downstream of HIGH-01.
> After `make dashboard` + a `Cmd+Shift+R` hard-reload of the
> dashboard, the Response Filtering card on Settings now renders:
> no "not wired" pill, three toggle rows (Scrub stack traces /
> Mask internal IPs / Redact DLP payloads), per-rung descriptions,
> and the subtitle "Hot-reloadable via audit-mutated PUT
> /api/response-filter · applied to every upstream response body
> via `Pipeline::on_body_frame`". Hooks `window.useResponseFilterApi`
> and `window.responseFilterPut` are present in the running bundle.

---

# Response Filtering card claims "not wired" on a build where the backend IS wired

## Summary

Same root cause as HIGH-01 (stale bundle) — separated as its own
finding because the operator-visible misrepresentation is severe
enough on its own: a SOC analyst looking at Settings will conclude
that stack-trace scrubbing and DLP redaction are dead, when in fact
both run on every upstream response chunk in this build.

## Repro

1. Sign into `:9443`, navigate to **Settings**.
2. Scroll to **Response Filtering** card.
3. Observe: warn pill "not wired" + tooltip *"Toggles are local-only.
   Backend uses cfg.observability + cfg.dlp from waf.yaml."*
4. In DevTools / console:
   ```js
   fetch("/api/response-filter", {credentials:"include"}).then(r => r.json())
   // { wired: true, scrub_stack_traces: true, mask_internal_ips: true, redact_dlp: true }
   ```
5. Confirm backend wiring in source:
   ```
   crates/aegis-bin/src/main.rs:213-231           // Pipeline::new(...) (not NoopPipeline)
   crates/aegis-proxy/src/data_plane.rs:1445       // pipeline.on_body_frame(...).await
   ```

## Expected

When `/api/response-filter.wired === true`, the card shows three
toggles — `scrub_stack_traces`, `mask_internal_ips`, `redact_dlp` —
mirrors the API state, and PUTs to `/api/response-filter` on flip.
No warn pill. (This is exactly what `pages.jsx:4567-4660`
implements.)

## Actual

The card shows two toggles with the older labels ("Block stack
traces in responses", "Redact JSON fields…") and an unconditional
"not wired" warn pill whose tooltip wrongly tells operators that
runtime config must come from `waf.yaml`.

## Suggested fix

Same as HIGH-01 — rebuild and commit `app.js`. After the rebuild,
verify in DevTools:

```js
// Should print true on the live bundle
window.useResponseFilterApi !== undefined
```

Until that lands, the operator workaround is to PUT directly:

```bash
csrf=$(grep aegis_csrf cookie.jar | awk '{print $7}')
curl -s -b cookie.jar -H "x-csrf-token: $csrf" \
     -X PUT -H "content-type: application/json" \
     -d '{"scrub_stack_traces": true, "mask_internal_ips": true, "redact_dlp": false}' \
     http://127.0.0.1:9443/api/response-filter
```

## Severity rationale

HIGH because the dashboard tells operators a real security feature
is off when it's actually on. The opposite framing ("we're shipping
DLP redaction but the UI hides it") is just as bad — it means
operators can't trust the Settings page as the source of truth for
the feature surface.

