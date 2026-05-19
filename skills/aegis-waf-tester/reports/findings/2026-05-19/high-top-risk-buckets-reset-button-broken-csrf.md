---
id: 2026-05-19-high-top-risk-buckets-reset-button-broken-csrf
date: 2026-05-19T12:30Z
severity: HIGH
area: dashboard
component: top-risk-buckets / surgical-reset
status: open
test_mode: functional
---

# "Reset bucket" button on Top risk buckets card silently fails (broken CSRF helper reference)

## Summary

The new `TopRiskBucketsCard` on the Traffic Gates page renders the
composite-key data correctly, but its per-row "Reset bucket" button
never actually resets anything. The button's `surgicalReset` handler
references `window.getCsrfToken`, which is **not defined anywhere in
the dashboard codebase**. The ternary `window.getCsrfToken ?
window.getCsrfToken() : ''` falls to the empty string every time, the
backend rejects the request with `admin_csrf_invalid` (HTTP 403), and
the failure path goes through `aegisToast('Reset failed: …')` — which
in the live dashboard is a small ephemeral toast that's easy to miss
on a 5-second polling card.

End result: the entire surgical-reset affordance — the whole point of
shipping a composite-key UI in the first place — is non-functional.
Operators can see the per-(IP, device_fp, session) rows but cannot
clear one without disturbing the others.

The same buggy `surgicalReset` is copy-pasted at pages.jsx:10758,
which appears to be the Top Attackers RiskKey view (see the
`view === 'riskkey'` URL-sync block right above it). So the same
break shows up in two places.

## Repro

1. `make redis-up && make run-dev`, sign in to
   `http://127.0.0.1:9443/admin/login` as admin / aegis-test-1234.
2. From the dashboard tab's devtools console, drive traffic with
   two distinct session cookies on `http://127.0.0.1:8080`:
   ```js
   document.cookie = "sessionid=alice-session-1234567890; path=/";
   for (let i=0;i<5;i++) await fetch(`/?q=' OR 1=1-- a${i}`);
   document.cookie = "sessionid=bob-session-aaaaaaaaaa; path=/";
   for (let i=0;i<8;i++) await fetch(`/?q=<script>alert(${i})</script>`);
   ```
3. Open `/#/traffic-gates`; scroll to "6. Top risk buckets". Three
   rows render (bob-sess… 8 strikes, alice-se… 5 strikes, anon 3
   strikes). ✅
4. Click "Reset bucket" on the bob-sess… row.
5. Wait 6 s (past the 5 s polling interval).

## Expected

- bob-sess… row disappears.
- alice-se… (5) and anon (3) remain.
- A success toast: "Reset bucket 127.0.0.1|…|bob-session-aaaaaaaaaa".
- A `risk_reset_key` audit event in `/api/audit/since` with `actor`,
  `request_id`, before/after diff, chain hash.

## Actual

- All three rows remain unchanged.
- `GET /api/risk?limit=50` after the click still returns
  `{strikes:[8,5,3]}` — no bucket cleared.
- No `risk_reset_key` event in audit.
- Patched `window.fetch` confirms the request *did* fire (`POST
  /api/risk/reset_key`) but came back `403 {ok:false, reason:
  "admin_csrf_invalid"}`. Driving the same request manually with a
  valid CSRF cookie + `x-csrf-token` header works on the server
  side, so the server endpoint is fine.
- No visible error toast in the screenshot (the live `aegisToast`
  may pop and vanish before the operator notices; on my Cowork
  sandbox the toast region was empty by the time I polled).

## Suggested fix

Replace the bare `fetch` with the dashboard's standard CSRF helper.
Three other audit-mutated mutations in the same file already do this
(`pages.jsx:9904` `/api/gates/strikes`, `pages.jsx:10152`
`/api/rate-limit`, `pages.jsx:10383` `/api/gates/ddos`):

```jsx
// pages.jsx:9474 (TopRiskBucketsCard) and pages.jsx:10758 (top-attackers RiskKey view)
async function surgicalReset(row) {
  const id = `${row.ip}|${row.device_fp ?? ''}|${row.session ?? ''}`;
  setResetBusy(id);
  try {
    const r = await window.csrfMutate('/api/risk/reset_key', {
      method: 'POST',
      body: JSON.stringify({
        ip: row.ip,
        device_fp: row.device_fp ?? null,
        session: row.session ?? null,
      }),
    });
    if (r.status === 200 && r.ok !== false) {
      window.aegisToast(`Reset bucket ${id}`, 'ok');
      risk.reload && risk.reload();
    } else {
      window.aegisToast(
        `Reset failed: ${r.message || r.reason || `status ${r.status}`}`,
        'err',
      );
    }
  } catch (e) {
    window.aegisToast(`Reset error: ${e.message || e}`, 'err');
  } finally {
    setResetBusy(null);
  }
}
```

Note that `csrfMutate` returns `{ status, ...body }` rather than a
`Response`, so the success/failure check changes accordingly.

`grep -rn 'getCsrfToken' crates/aegis-control/assets/dashboard/src`
confirms both call sites (9490 and 10767) are the only references —
removing them clears the orphan reference entirely. Worth adding a
lint or `eslint-no-restricted-globals` for `getCsrfToken` so a
regression can't sneak back in.

## Severity rationale

HIGH — primary surface of a shipping feature is broken. The
composite-key storage + data-plane work landed correctly (verified
end-to-end below in
`info-risk-composite-key-data-plane-works.md`), but the UI
affordance that lets the operator *act* on the per-bucket view does
not function. A SOC analyst who hits this card with an active
incident cannot clear the offending session — they have to fall
back to the IP-only `PUT /api/risk/<ip>/reset`, which wipes every
sibling bucket on the same IP. That's exactly the failure mode the
composite key was designed to prevent. Not CRITICAL because no data
plane security gate is bypassed; the gates still work. Not MEDIUM
because the feature's headline use case is unusable.
