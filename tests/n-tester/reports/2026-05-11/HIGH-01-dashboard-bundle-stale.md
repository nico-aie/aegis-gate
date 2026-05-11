---
id: 2026-05-11-dashboard-bundle-stale
date: 2026-05-11T17:25Z
severity: HIGH
area: dashboard
component: build / bundling
status: resolved
resolved_at: 2026-05-11T18:00Z
test_mode: full-qc
---

> **RESOLVED 2026-05-11T18:00Z.** Operator ran `make dashboard`
> (which invokes `bash crates/aegis-control/assets/dashboard/build.sh`)
> — `make build` only rebuilds the Rust binary. After the dashboard
> rebuild the bundle was 432489 bytes (up from 430066) with the new
> ETag, ships `useResponseFilterApi` + `responseFilterPut` + the
> hostname placeholder, and is served with the new ETag.
>
> Hard-reload was required to bust the browser cache because the
> server sets `Cache-Control: public, max-age=3600, must-revalidate`
> on `/dashboard/assets/app.js` — within the 1-hour window Chrome
> uses the cached copy without revalidating. After `Cmd+Shift+R`
> the Response Filtering card rendered three toggles + no "not
> wired" pill, and the Add Route modal placeholder shows
> `IP:port (10.0.1.10:8080) or hostname:port (api.example.com:443)`.
>
> **Recommendations carry over even though this incident is closed**:
> (1) document `make dashboard` next to `make build` in the README;
> (2) drop `app.js`'s `max-age` to `0, must-revalidate` (or use a
> hashed filename) so future bundle swaps land on the next page
> nav; (3) add the CI gate
> `git diff --exit-code crates/aegis-control/assets/dashboard/app.js`
> after a dashboard build step so the same miss can't recur.

---

# Dashboard `app.js` bundle is stale — PR #7 and PR-DNS-1 dashboard surfaces never reached operators

## Summary

The compiled dashboard bundle `crates/aegis-control/assets/dashboard/app.js`
was last touched on commit `2f50176` (Policy QA Phase 1 · 2026-05-11
08:58). Three later commits — `e705eff` (PR #7 response-filter dashboard
surface), `9a73a99` (PR-DNS-1 Add-Route hostname placeholder), and
`b77111b` (PR-DNS-2 — JSX touch-ups for the DNS feature) — updated
`pages.jsx` **but never regenerated the bundle**.

Operators run the bundle, not the source. So everything those three
commits added to the dashboard is invisible in production. Two concrete
operator-impact effects today:

1. **Response Filtering looks dead even though it's wired.** The
   Settings page renders the old 2-toggle "Block stack traces in
   responses" + "Redact JSON fields (password, secret, token, ssn)"
   card with a hardcoded `"not wired"` warn pill whose tooltip reads
   *"Toggles are local-only. Backend uses cfg.observability + cfg.dlp
   from waf.yaml."* In reality `Pipeline::on_body_frame` is called for
   every upstream chunk (`data_plane.rs:1445`) and `/api/response-filter`
   returns `wired: true` with the three live rungs. A SOC analyst
   reading the dashboard would file a CRITICAL "stack-trace scrub
   doesn't work" ticket they shouldn't need.

2. **DNS hostnames look unsupported in the Add Route modal.** The
   placeholder is the old `Type a new backend: IP:port (e.g.
   10.0.1.10:8080)` — no mention of hostnames, no helper text.
   Operators who haven't read the release notes will keep `dig`-ing.
   The feature works (I verified `addr: example.com:443` resolves to
   two members via the dashboard), they just won't try it.

## Repro

```bash
# 1. Confirm bundle's most-recent commit
cd <repo>
git log --oneline crates/aegis-control/assets/dashboard/app.js | head -1
# 2f50176 fix(dashboard): Policy QA Phase 1 — 7 findings closed (F-01 thru F-08)

# 2. Confirm source has the later updates
git log --oneline crates/aegis-control/assets/dashboard/src/pages.jsx | head -3
# 9a73a99 feat(upstream): PR-DNS-1 — hostname-addressed members (Phase 1)
# e705eff feat(dashboard): PR #7 — response-filter rung toggles + writer trait
# 2f50176 fix(dashboard): Policy QA Phase 1 — 7 findings closed (F-01 thru F-08)

# 3. Look for source-only strings missing from the bundle
grep -c "useResponseFilterApi" crates/aegis-control/assets/dashboard/app.js                     # 0
grep -c "useResponseFilterApi" crates/aegis-control/assets/dashboard/src/pages.jsx              # 3
grep -o "Type a new backend[^\"]*" crates/aegis-control/assets/dashboard/app.js | head -1
# Type a new backend: IP:port  (e.g. 10.0.1.10:8080)
grep -n "api.example.com:443" crates/aegis-control/assets/dashboard/src/pages.jsx | head -1
# 9805:    placeholder="IP:port (10.0.1.10:8080) or hostname:port (api.example.com:443)"
```

```text
# 4. Live dashboard reproduction (Chrome, logged into :9443):
# 4a. Settings page — Response Filtering card
#     Observed: 2 toggles ("Block stack traces in responses" + "Redact
#     JSON fields (password, secret, token, ssn)") + "not wired" warn
#     pill. Tooltip on the pill: "Toggles are local-only. Backend uses
#     cfg.observability + cfg.dlp from waf.yaml."
#
# 4b. In DevTools/console:
fetch("/api/response-filter", {credentials:"include"}).then(r => r.json())
# → { wired: true, scrub_stack_traces: true, mask_internal_ips: true, redact_dlp: true }
# ↑ API says wired:true with three rungs. Card shows two rungs and "not wired". Mismatch.
#
# 4c. Routing & Upstreams → "+ Add route" modal, focus the "Forward to" input
#     Observed placeholder: "Type a new backend: IP:port  (e.g. 10.0.1.10:8080)"
#     Expected per source: "IP:port (10.0.1.10:8080) or hostname:port (api.example.com:443)"
```

## Expected

The bundle a SOC operator's browser downloads matches the source the
team committed. After `e705eff` and `9a73a99` were merged into
`develop`, the dashboard should ship the three-rung Response Filter
card hooked to `/api/response-filter`, and the Add Route modal should
nudge operators toward hostnames.

## Actual

The bundle ships the pre-PR #7 / pre-DNS-1 dashboard. PR #7's
operator-facing deliverable ("toggle response-filter rungs from the
dashboard without a restart") and PR-DNS-1's dashboard half ("operators
can author hostname members from the Add Route modal") are absent
from production. Both PRs claim completion in the commit messages and
the fix plan's Suggested PR sequence.

## Suggested fix

1. **Rebuild the bundle.** Whatever the team's dashboard build step is
   (likely `npm run build` from `crates/aegis-control/assets/dashboard/`
   or a `make dashboard` target), run it and re-commit `app.js`. The
   bundle size hint in the commit message of `2f50176` was ~430 KB
   (under a 444 KB cap); confirm that's still the case after the
   rebuild.

2. **Make a CI gate of it.** A PR check that diffs `app.js` against a
   freshly-built bundle would catch every future "merged source, forgot
   to recompile" miss. The simplest version: `git diff --exit-code
   crates/aegis-control/assets/dashboard/app.js` after a build step in
   CI.

3. **Add a smoke test that hits the dashboard surface that proves
   PR #7 and PR-DNS-1 landed.** A 5-line Playwright check:
   - On the Settings page, the Response Filtering card has THREE
     toggle rows (third is "Mask internal IPs") and no "not wired"
     pill when `/api/response-filter.wired === true`.
   - On the Add Route modal, the "Forward to" input placeholder
     contains the literal substring `api.example.com:443`.

## Severity rationale

HIGH, not CRITICAL, because the underlying features work (verified
via API + via the dashboard's other surfaces) and operators
*technically* can still configure them via direct PUT or `waf.yaml`.
But this is the worst class of "operator confusion" bug — the UI
actively misrepresents the system's state ("not wired" claim is
false). The fix is trivial (one `npm run build` + commit). The
not-CRITICAL line is "ship this in the next dashboard PR, but a
running cluster is still safe."

