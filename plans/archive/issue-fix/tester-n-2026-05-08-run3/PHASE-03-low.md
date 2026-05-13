# Phase 3 — LOW (Run-3)

> **Branch:** all changes target `develop`.

---

## RUN3-NEW-3 · SPA redirects to `/admin/login` after `reset_state`

**Source:** Run-3 §NEW-3.

### Verified state (2026-05-08, on `develop`)

`crates/aegis-control/assets/dashboard/src/data.jsx:563-591` global fetch interceptor:

```js
window.fetch = async (...args) => {
    const r = await _origFetch(...args);
    if (r.status === 403 && !window.__aegisCsrfRedirecting) {
      try {
        const cloned = r.clone();
        const body = await cloned.json();
        if (typeof body?.reason === 'string' && body.reason.startsWith('csrf_')) {
          window.__aegisCsrfRedirecting = true;
          ...
          setTimeout(() => { window.location.href = '/admin/login'; }, 1500);
        }
      } catch (_e) { /* non-fatal */ }
    }
    return r;
};
```

The interceptor only fires when **both** conditions hold:
1. HTTP status is 403, and
2. Response body is JSON with `reason` field starting with `csrf_`.

`reset_state` itself is in the `/__waf_control/*` namespace (interop dispatcher), which uses `X-Benchmark-Secret` auth, **not** CSRF. Its 403 responses (e.g. missing/wrong secret) carry `error: "..."` not `reason: "csrf_*"`. So `reset_state` itself can't trigger this interceptor.

The QA's described chain ("call reset_state → SPA dumps to login despite valid session") doesn't match any code path that's directly triggered by `reset_state`. Most likely root cause: a parallel SPA polling fetch (e.g. `/api/audit/since`, `/api/risk`, dashboard SSE reconnect) hit a 403 with a `csrf_*` body around the same time — coincidence with the `reset_state` call rather than causation. The most plausible underlying issue: the operator's CSRF cookie expired naturally while the session cookie remained valid, so a mutating SPA fetch tripped `csrf_missing_cookie` and the interceptor caught it.

This is **not** a behavior bug we should change today — the interceptor's job is to redirect on session-expiry shapes, and `csrf_*` reasons genuinely indicate the operator can't mutate without re-auth. What's missing is **diagnostic data**: the next time it happens, we want to know which URL fired, with what body, to confirm or refute the coincidence theory.

### Plan

**Step 1 — capture diagnostic context when the redirect fires.**

```js
(function installCsrfFetchInterceptor() {
  if (typeof window === 'undefined' || window.__aegisCsrfFetchInstalled) {
    return;
  }
  window.__aegisCsrfFetchInstalled = true;
  const _origFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const r = await _origFetch(...args);
    if (r.status === 403 && !window.__aegisCsrfRedirecting) {
      try {
        const cloned = r.clone();
        const body = await cloned.json();
        if (typeof body?.reason === 'string'
            && body.reason.startsWith('csrf_')
            && body.ok === false) {                         // ← NEW: tighter shape match
          window.__aegisCsrfRedirecting = true;
          // RUN3-NEW-3 (2026-05-08) — capture context so the
          // next operator hitting the redirect has actionable
          // evidence. Stored in localStorage so it survives
          // the navigation to /admin/login.
          try {
            const url = typeof args[0] === 'string'
              ? args[0]
              : (args[0]?.url ?? 'unknown');
            const method = (args[1]?.method ?? args[0]?.method ?? 'GET').toUpperCase();
            window.localStorage.setItem('__aegisLastRedirect', JSON.stringify({
              ts:     new Date().toISOString(),
              url,
              method,
              status: r.status,
              reason: body.reason,
              note:   'global fetch interceptor → /admin/login',
            }));
          } catch (_storage) {
            // localStorage might be disabled; non-fatal.
          }
          const toast = window.aegisToast
            || ((m) => console.warn('[csrf]', m));
          toast('Session expired — redirecting to login…', 'warn');
          setTimeout(() => {
            window.location.href = '/admin/login';
          }, 1500);
        }
      } catch (_e) {
        // Body wasn't JSON or already consumed; non-fatal.
      }
    }
    return r;
  };
})();
```

The two changes:

1. **Tighten the heuristic** by also requiring `body.ok === false`. The existing CSRF reject shape from `aegis_control::api::mutation::MutationError` always includes `{"ok": false, ...}`. Bodies that happen to have a `reason` field starting with `csrf_*` but a different shape (e.g. an audit log entry being passed through somewhere) won't trip the redirect.
2. **Stash the trigger context in `localStorage.__aegisLastRedirect`**. Survives the navigation. Operators reporting the issue can paste back the URL + method + body, giving us actionable evidence for a real fix.

**Step 2 — surface the diagnostic on the login page** (one-line affordance).

When the login page renders, check `localStorage.__aegisLastRedirect`. If present + recent (< 5 min), show a small note: "You were redirected here after a session-expiry signal at `<url>` (method=`<method>`)."

This lives in `admin_login.html` or wherever the login page assets are. Cheap to add; gives operators a hint without dumping technical detail in their face.

If the login page isn't easily edited (it's a server-rendered template, not the SPA), skip this step and rely on operators reading `localStorage` from devtools when they report. Step 1's storage write is the load-bearing change.

**Step 3 — manual verification.**

```js
// In browser devtools console, simulate the redirect trigger:
fetch('/api/blacklist', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },  // no x-csrf-token
  credentials: 'same-origin',
  body: JSON.stringify({ id: 'x', kind: 'ip', value: '1.2.3.4' }),
});
// Expect: toast appears, 1.5s later /admin/login loads,
// localStorage.__aegisLastRedirect populated with:
//   { url: "/api/blacklist", method: "POST", status: 403,
//     reason: "csrf_missing_header", ts: "<iso>" }
```

**Step 4 — no Rust changes.** Pure dashboard JSX edit + bundle rebuild.

### Acceptance

- [ ] Interceptor still redirects on legitimate CSRF-expiry shapes
- [ ] `localStorage.__aegisLastRedirect` contains the URL/method/status/reason of the trigger
- [ ] Tighter heuristic (`body.ok === false`) doesn't break the existing redirect path (verify with the manual trigger above)
- [ ] Dashboard JSX rebuild produces a clean `app.js` bundle
- [ ] No regression in any existing redirect flow (logout button, session-expiry timeout)

**Effort:** ~30 min. Pure dashboard edit.

---

## Sequencing

Single PR: `fix(dashboard): tighten CSRF interceptor + capture redirect diagnostic (RUN3-NEW-3)`.

---

## What this round does NOT solve

- The actual reproduction of RUN3-NEW-3. Without a reliable repro, we can't confirm whether the QA hit a coincidence or a deeper bug. The diagnostic capture is the right next step — once the operator hits this again, they'll paste back the localStorage entry and we'll know for sure.
- CSRF auto-refresh (the proper fix if this turns out to be a real session/CSRF asymmetry). Plan as a follow-up under `plans/csrf-auto-refresh/` once the diagnostic data confirms the trigger.
- Browser-side blake3 fixture for Run-3's positive PoW path (separate gap; not blocking).
