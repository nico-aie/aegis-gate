---
id: 2026-05-12-add-route-saves-tls-false-on-https
date: 2026-05-12T13:05Z
severity: HIGH
area: dashboard
component: routing-upstreams · add-route-modal
status: open
test_mode: full-qc
---

# Add Route modal saves `scheme: "https"` and `tls: false` together — the resulting upstream client talks plain HTTP to a TLS port, yielding "400 The plain HTTP request was sent to HTTPS port"

## Summary

The Add Route modal accepts a hostname:port backend (e.g.
`znews.vn:443`) and auto-selects `scheme: https` when the port is
443. The modal saves the pool. The saved pool config looks
plausible on inspection:

```json
{
  "connection": {
    "scheme": "https",
    "tls": false,           ← but the legacy TLS flag is false
    ...
  }
}
```

`scheme: "https"` should imply TLS (per the source comment + test
`explicit_https_uses_tls_regardless_of_legacy_flag` at
`crates/aegis-core/src/config.rs:996`). But the operator-visible
behaviour disagrees:

```
GET http://127.0.0.1:8080/news
→ 400 Bad Request
   Server: TTTT
   <html><head><title>400 Bad Request</title></head>...
```

`TTTT` is znews.vn's edge tag and the message body matches
nginx's canonical *"The plain HTTP request was sent to HTTPS
port"* — the upstream connection went plain HTTP to znews.vn:443.

This is the operator's primary repro path. They wired their
first real backend through the dashboard exactly as the page's
"How it works" copy advertises — and the data-plane forwarding
silently fails.

## Repro

1. Sign in to `:9443`, navigate to **Routing & Upstreams**.
2. Click **+ Add route**.
3. Fill Route ID = `znews-route`, Path = `/news`, Host = blank.
4. In the "Type a new backend" input, type `znews.vn:443`.
5. Modal auto-expands: Scheme picker shows `https`, Host header
   field appears (placeholder `api.example.com (for multi-vhost
   / public TLS)`). The "Will create pool…" subtitle reads
   *"Will create pool znews-route with this single member."*
6. Click **Create route**. Modal closes; route appears in the
   table.
7. In a separate tab on the data plane (`:8080`):
   ```js
   fetch("/news", {headers: {"X-Forwarded-For": "192.0.2.50"}})
     .then(r => r.text())
   ```
   → 400 with the nginx-canonical body.

API confirmation:

```bash
curl -s -b /tmp/jar http://127.0.0.1:9443/api/upstreams/config | jq '.pools["znews-route"].connection'
# {
#   "scheme": "https",
#   "tls": false,
#   "idle_timeout_ms": 30000,
#   "keep_alive": true,
#   "max_idle_per_host": 32
# }
```

The Edit Pool modal exposes the legacy `tls` flag as a separate
"Upstream TLS (legacy `tls` flag)" checkbox — but the Add Route
modal does NOT expose it at all. The operator picking the
scheme dropdown has no way to opt in to TLS from the Add Route
surface today.

## Expected

When the operator picks `scheme: "https"` (or the port-443
auto-selection picks it for them), the pool save body should
include `tls: true`. The data plane builds an HTTPS client; the
upstream connection succeeds; the user gets znews.vn's actual
response, not a 400 from a TLS handshake mismatch.

## Actual

The save body sends `scheme: "https", tls: false`. The data
plane behaves as if `tls: false` is dominant.

## Suggested fix

Two-part fix:

### Dashboard side — Add Route modal should derive `tls` from `scheme`

In `crates/aegis-control/assets/dashboard/src/pages.jsx`, the
Add Route modal's pool-build code. When the operator picks (or
the port auto-selects) `scheme: "https" | "grpc"`, the pool body
should set `tls: true`. When they pick `scheme: "http" | "h2c" |
"tcp"`, set `tls: false`. When they pick `scheme: "auto"`, leave
`tls` to the user (it's the legacy override anyway).

```js
const tlsFromScheme = (scheme) => {
  switch (scheme) {
    case "https":
    case "grpc":
      return true;
    case "http":
    case "h2c":
    case "tcp":
      return false;
    case "auto":
    default:
      return tlsCheckboxState; // operator-controlled
  }
};
```

Same fix applies to the Edit Pool modal — the Scheme picker
there should also drive the TLS checkbox state automatically
(operator can still override for the "auto" case).

### Server side — make `tls` derived, not an independent flag

The "legacy" framing on the Edit Pool modal hints at this:
`tls` is meant to be deprecated in favour of the canonical
`scheme`. Today the dashboard's `tls` flag still exists in the
config schema. Long-term:

- Server: rename `tls` to `tls_legacy` in the wire shape with a
  `#[serde(rename = "tls", alias = "tls_legacy")]` for back-compat
  and make it `Option<bool>` (None = derive from scheme).
- Server: at config-load, if `scheme` is explicit (not `auto`)
  and `tls` was set, log a deprecation warning and prefer
  scheme.
- Dashboard: hide the `tls` checkbox when scheme is explicit;
  show it only when scheme is `auto`.

This is the design `uses_tls(self, tls_legacy: bool)` in
`config.rs:955` clearly wants — `Auto` consults the legacy flag;
all other variants ignore it. Make the dashboard match.

## Severity rationale

HIGH. The Add Route modal is the dashboard's primary "wire a
real backend" surface. The operator's first attempt at using it
with a real hostname produces a silently-broken upstream:

- Pool persists with `referenced_by_routes` populated → looks
  configured
- Route persists, table row reads `https · 2 members` → looks
  healthy
- Data-plane forwarding fails with an upstream-side 400 → no
  WAF-side error to triage
- Dashboard has no diagnostic that flags the scheme/tls mismatch

Not CRITICAL because no security boundary is breached — the
WAF's inbound detection still runs, and the upstream 400 is
contained. But operator trust in "the dashboard wires what it
says it wires" takes a real hit.

The fix is a couple-line dashboard change + a one-line server
default. Ship in the next dashboard PR.

