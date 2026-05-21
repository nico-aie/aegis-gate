# Front-end Security

> The dashboard is the most privileged surface in the product —
> session cookies on the admin's browser can mutate every WAF
> setting. The bar for shipping client-side code is correspondingly
> high.

## Threat model

- **Untrusted upstream traffic.** Audit events shown in the Live
  Feed contain attacker-controlled strings (URIs, headers, body
  excerpts). They will probe for XSS.
- **Compromised CDN.** Mitigated by vendoring; we never load
  third-party scripts.
- **Operator phishing.** Mitigated by tight session policy and
  confirm-with-typed-name on destructive actions.
- **CSRF.** Existing double-submit cookie pattern.
- **Clickjacking.** `X-Frame-Options: DENY` + `frame-ancestors
  'none'` in CSP.

## Content Security Policy

```
default-src 'self';
script-src  'self';
style-src   'self' 'unsafe-inline';
img-src     'self' data:;
connect-src 'self';
font-src    'self';
object-src  'none';
base-uri    'self';
form-action 'self';
frame-ancestors 'none';
report-uri  /api/csp/report;
```

`'unsafe-inline'` for styles is a Chart.js requirement (see
`assets.md`). All other directives are tight.

We log CSP violations to the audit chain (class `system`, action
`csp_violation`) so any drift in third-party assets surfaces fast.

## XSS hardening

- Every audit event field rendered in the UI passes through a
  string sanitiser: HTML-escape via the standard `&`, `<`, `>`,
  `"`, `'` replacements; reject any string containing
  control characters by replacing with `\x..` escapes.
- We **never** call `innerHTML` with operator-unbounded data. The
  table renderer always uses `textContent` for cell values.
- Diff viewer renders strings, never HTML — `<` becomes `&lt;`
  before LCS.
- The CodeMirror-style rule editor is built on `<textarea>` not a
  contenteditable overlay, eliminating an entire class of
  injection vectors.

## CSRF

- Existing `aegis_csrf` cookie + `X-CSRF-Token` header. Mutating
  fetches in the SPA always include the header.
- The SPA reads the cookie on first load and stores it in a
  module-private variable. It does **not** stash the value in
  `localStorage` or a global to avoid leakage to extensions.

## Session safety

- The session cookie remains `HttpOnly; Secure; SameSite=Strict`.
- The SPA never reads or writes the session cookie — its only
  knowledge of "logged in" comes from successful API calls.
- 401 responses trigger a global redirect to `/admin/login?next=…`
  via a fetch interceptor. No silent retries.

## Subresource integrity

For vendored Chart.js: an SRI hash is embedded in `index.html`:

```html
<script src="/dashboard/assets/chart.umd.min.js"
        integrity="sha384-…" defer></script>
```

The hash matches the bytes in
`crates/aegis-control/assets/dashboard/chart.umd.min.js`.
A test asserts the literal string in `index.html` matches the
file digest, so a stealth bytes-edit fails CI.

## Supply chain

- Single bundled JS dependency (Chart.js). Update procedure
  documented in `assets.md` requires GPG verification
  + `cargo audit` clean before merge.
- Zero npm. No `node_modules`. The repo has no `package.json`.
- Embedded fonts: none. We use the system stack.

## Headers (full set on dashboard responses)

```
Content-Security-Policy: …
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: accelerometer=(), camera=(), geolocation=(),
                    gyroscope=(), magnetometer=(), microphone=(),
                    payment=(), usb=()
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

## Error surfacing

- Server errors map to a generic toast: "Something went wrong —
  request id `…`". The full error body never reaches the user;
  the request id correlates to the audit chain for after-the-fact
  investigation.
- 4xx with structured body (`{ error: { code, message } }`) gets
  rendered on the field that produced it. We don't echo
  attacker-supplied error strings into the UI without escaping.

## Tests

- `tests/dashboard/csp.rs` — boots the admin listener, fetches
  `/dashboard/`, parses the CSP header, asserts each directive
  matches the spec.
- `tests/dashboard/xss.rs` — feeds malicious audit events through
  `/dashboard/sse`, asserts the rendered DOM contains the string
  as text, never as HTML, never executes a script.
- `tests/dashboard/csrf.rs` — issues a mutating call without the
  CSRF header, asserts 403.
- `tests/dashboard/sri.rs` — asserts `index.html` SRI string
  matches `chart.umd.min.js` digest.

## Audit

Every front-end-driven mutation produces an admin audit entry,
same as today. New CSP violation reports add a `system` audit
entry with the violation directive + blocked URI (sanitised).
