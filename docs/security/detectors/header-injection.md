# HTTP Header Injection

> **Status:** Implemented — `aegis-security/src/detectors/header_injection.rs`.
>
> See [`../../../plans/plan.md`](../../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

## Purpose

Detect CRLF injection attacks — attempts to inject newlines into headers, which can lead to header smuggling, cache poisoning, response splitting, and cookie injection.

## Attack pattern

An attacker passes a value containing `\r\n` (CRLF) into a parameter that ends up reflected in an HTTP response header. The injected CRLF terminates the current header and lets the attacker inject new headers or even a new response.

Example payload in a `redirect` parameter:

```
http://example.com/?redirect=foo%0d%0aSet-Cookie:%20session=attacker
```

If the backend reflects this into a `Location:` header, the resulting response contains an attacker-controlled `Set-Cookie`.

## Patterns

The detector scans for these byte sequences in request inputs that could end up in response headers:

- `\r\n` (raw CRLF)
- `%0d%0a`, `%0D%0A`, `%0d%0A`, `%0D%0a`
- `\u000d\u000a`
- `%0a` alone (some servers treat LF as line terminator)
- `%0d` alone
- `\n` in header-destined contexts

## Surfaces

- All query parameters (most common injection point for `Location:` headers)
- Request headers **whose values are reflected back by the backend** (e.g., `Referer` ends up in logs; a crafted `Host` header can end up in generated URLs)
- Cookie values
- Request body fields that end up in redirects

The detector doesn't know what the backend does with which field, so it scans broadly and relies on scoring to avoid false positives.

## Incoming-header sanity checks

Separate from CRLF detection, the WAF also validates incoming headers:

- Header names must match `[!-9;-~]+` (RFC 7230 tchar set)
- Header values must not contain raw CTL characters (`\x00`-`\x1f` except `\t`)
- `Host` header must be present and parseable
- `Content-Length` must be a positive integer
- No duplicate `Content-Length` or mixed `Content-Length` + `Transfer-Encoding` (smuggling defense)

Malformed headers are rejected with 400 immediately.

## X-Forwarded-Host poisoning

Added 2026-05-08 (SEC-L002). The detector inspects the **value** of the
`X-Forwarded-Host` (XFH) request header for shape-suspicious patterns
that backends would treat as the public hostname for cache keys, OAuth
redirect URIs, password-reset email links, etc.

The check is conservative — many legit reverse-proxy chains set XFH to
the public hostname while `Host` is the proxy's internal address, so a
bare "XFH ≠ Host" mismatch isn't enough to alert. The detector flags
when the XFH carries:

| Shape | Example | Why suspicious |
|---|---|---|
| Attacker-keyword + Host mismatch | `Host: a.com`, `XFH: evil.attacker.com` | Classic poisoning probe |
| `javascript:` / `data:` URI | `XFH: javascript:alert(1)` | XSS pivot via cache-bound link |
| Quoting / angle-bracket chars | `XFH: <script>` | HTML-context injection |
| Three or more comma-separated hosts | `XFH: a.com, proxy.com, evil.com` | Attacker appended a host to a legitimate proxy chain |
| Control bytes (NUL/CR/LF) | (defense-in-depth — hyper rejects upstream) | Header smuggling |
| **Internal-IP literal** (added 2026-05-09 GAP-005) | `XFH: 127.0.0.1`, `XFH: 10.0.0.1`, `XFH: 169.254.169.254`, `XFH: ::1`, `XFH: fe80::1` | Cache-key poisoning / internal-admin code-path bypass / host-allowlist evasion. Legit proxy chains carry **public hostnames** in XFH; an RFC 1918 / loopback / link-local IP literal here has no benign use case. |

Score: `35` (slightly below CRLF since the heuristic is broader).
Field tag: `x-forwarded-host` so the audit log + dashboard can
distinguish XFH poisoning from query-CRLF.

#### Internal-IP literal — what specifically flags

The `xfh_is_internal_ip_literal` helper (added GAP-005) checks the **first** comma-segment of the XFH value (after stripping an optional `:port`) against:

| Range | Examples |
|---|---|
| IPv4 loopback (`127.0.0.0/8`) | `127.0.0.1`, `127.55.0.1` |
| IPv4 RFC 1918 (`10.0.0.0/8`, `172.16-31.0.0/12`, `192.168.0.0/16`) | `10.0.0.1`, `172.20.5.5:8080`, `192.168.1.1` |
| IPv4 link-local (`169.254.0.0/16`) | `169.254.169.254` (cloud metadata) |
| IPv6 loopback | `::1`, `[::1]` |
| IPv6 link-local | `fe80::1`, `[fe80::1]` |

Public addresses like `8.8.8.8` or just-outside-RFC1918 addresses like `172.32.0.1` do **not** flag — the helper is a narrow internal-range check, not a generic IP-literal flag (legitimate origin servers may have IP-literal hostnames in some setups).

**Why not also block "arbitrary domain mismatch":** many legit proxy chains do exactly that (`Host: internal-svc:8080`, `XFH: api.example.com`). Bare mismatch is too broad without an operator allowlist. Internal-IP-literal-in-XFH is the narrow shape with no legitimate use case, so it's safe to flag without operator config.

## URL-override-header bypass (added 2026-05-09 GAP-011)

Some app frameworks (older Rails versions, IIS, Apache `mod_rewrite` setups) honor a small set of headers as a "rewrite the URL before processing" hint. An attacker behind a misconfigured proxy can supply the rewrite header pointing to an admin path while making a public-route request — the gateway sees the public route, the framework processes the admin path, and **auth middleware that gates by the raw URL is bypassed**.

The detector watches four header names (case-insensitive) for path values that have no benign use case in a request header:

| Header | Why dangerous |
|---|---|
| `X-Original-URL` | IIS / mod_rewrite "use this URL instead" hint — auth middleware that gates by raw URL is bypassed |
| `X-Rewrite-URL` | Apache `mod_rewrite` rewrite hint — same primitive |
| `X-Override-URL` | Less-common variant seen in CVE writeups |
| `X-HTTP-Method-Override-URL` | Compound override (method + URL) used by some REST gateways |

Path shapes that flag (after URL-decode):

| Shape | Examples | Why |
|---|---|---|
| Admin-prefix path | `/admin/users`, `/wp-admin/options.php`, `/manage`, `/console`, `/__internal/health` | Privileged route, attacker-supplied — no benign reason for a header to override the URL to one of these |
| Recon-shape path | `/.env`, `/wp-config.php`, `/.git/config`, `/.aws/credentials`, `/.ssh/id_rsa` | Same recon targets the [`recon`](./recon.md) detector watches in URL paths — stacks signal when the same shape arrives via header override |
| Path-traversal shape | `../`, `%2e%2e/`, `%252e%252e` | Directory traversal smuggled through the override — would also fire the [`path_traversal`](./path-traversal.md) detector if the override were processed as the URL |

**Sub-tag:** `url_override_bypass` (class stays `header_injection`). Field reports the actual header that fired (`x-original-url`, `x-rewrite-url`, etc.) so audit grep is straightforward.

**Score:** `40` (header-heuristic tier — same as CRLF). One hit doesn't reach `challenge_at: 40` on its own, but stacks with `recon` / `path_traversal` when the override value also matches those shapes — combined risk crosses `block_at: 80`.

**No FP surface in production:** legitimate URL-rewriting happens in proxy / load-balancer config, not in attacker-controlled request headers. Operators who genuinely need to send these headers (rare) can disable the `header_injection` class for the affected tier via `set_profile { policies: ["header_injection"], mode: "log_only" }`.

### Method-override bypass (added 2026-05-09 INFO-002)

A sibling header class — frameworks (older Spring, Rails, WebDAV middleware) can be configured to honor `X-HTTP-Method-Override`, `X-Method-Override`, or `X-HTTP-Method` to rewrite the request method. An attacker sending `GET /resource` with `X-HTTP-Method-Override: DELETE` can bypass GET-only auth middleware that didn't anticipate the override.

The detector flags **only destructive verbs** in the override value (DELETE, PUT, PATCH, CONNECT, TRACE). Sub-tag: `method_override_bypass`. Score: 35 (XFH tier).

| Header | Value | Fires? |
|---|---|---|
| `X-HTTP-Method-Override` | `DELETE` / `PUT` / `PATCH` / `CONNECT` / `TRACE` | ✅ |
| `X-Method-Override` | same destructive verbs | ✅ |
| `X-HTTP-Method` | same destructive verbs | ✅ |
| Any of the above | `POST` | ❌ — Rails / Express form-post overrides use it legitimately |
| Any of the above | `GET` / `HEAD` / `OPTIONS` | ❌ — safe verbs, no risk |

The narrow allowlist (POST excluded) keeps FP near zero on legit Rails / Express traffic while catching the documented attack shape.

Test corpus:

- Positive: `X-Original-URL: /admin/users`, `X-Rewrite-URL: /administrator/index.php`, `X-Original-URL: /.env`, `X-Original-URL: /../../../etc/passwd`, `X-Original-URL: /__internal/health`, URL-encoded `/%2Fadmin%2Fusers`.
- Negative: `X-Original-URL: /api/users`, `X-Original-URL: /products/123`, `X-Original-URL: /health`, `X-Original-URL: /metrics`, header absent or empty.

## HTTP request smuggling hygiene (added 2026-06-12, workstream B1)

Request smuggling (CWE-444) exploits a front-end/back-end disagreement over
`Content-Length` (CL) vs `Transfer-Encoding` (TE) framing. The detector emits
**one** signal per request (first match in priority order) at the block tier
(score 70) for these shapes:

| Sub-tag | Fires when | Report rule |
|---|---|---|
| `smuggling_h2_forbidden` | HTTP/2 request carries a forbidden connection-specific header (`transfer-encoding` or `connection`, RFC 9113 §8.2.2) | SMUG-004 |
| `smuggling_cl_te` | request carries **both** `Content-Length` and `Transfer-Encoding` | SMUG-001 |
| `smuggling_multi_cl` | multiple `Content-Length` headers | SMUG-001 |
| `smuggling_multi_te` | multiple `Transfer-Encoding` headers, or a single obfuscated value (`xchunked`, `chunked, identity`; valid set: `chunked`/`identity`/`gzip`/`x-gzip`/`deflate`/`compress`/`br`) | SMUG-002 |

Class stays `header_injection`; field tag is `headers`. CRLF-in-header-value
(SMUG-003) is covered by the CRLF patterns above — a `Transfer-Encoding:
chunked\r\n…`-style value is caught as header/query CRLF.

### Important: the hyper-normalisation caveat

The data plane runs on **hyper**, whose HTTP/1 parser resolves or rejects most
CL/TE ambiguity **before this detector runs** — conflicting `Content-Length` →
400; `Transfer-Encoding` takes precedence over `Content-Length` per RFC 7230;
the upstream request is re-serialised with fresh framing. So the **h1** rules
here are **defense-in-depth + attribution**: they fire only for a shape that
slips through hyper (or a future code path that forwards raw framing), and when
they do they produce a labelled `request_smuggling`-class audit event instead of
an unattributed 400. **`smuggling_h2_forbidden` is the rule with standalone
runtime value** — forbidden connection-specific headers can reach the service
over HTTP/2 and are the H2-downgrade-smuggling primitive.

Live verification (does hyper deliver a given shape to the detector?) needs raw
sockets, not a normalising client — see the report's testing section
(`plans/issues/HTTP_SMUGGLING_REPORT.md` §6: `printf … | nc`, `curl --http2`).

FP surface is effectively nil on legitimate traffic: well-behaved clients send a
single `Content-Length` **or** a single `Transfer-Encoding: chunked`, never both
and never the obfuscated forms; compliant HTTP/2 clients never send
`transfer-encoding`/`connection`. Operators can still scope the class to
`log_only` via `set_profile { policies: ["header_injection"], mode: "log_only" }`.

## Configuration

```yaml
detection:
  header_injection:
    enabled: true
    risk_increment: 50
    reject_malformed_headers: true
    reject_smuggling: true
```

## Actions

- CRLF in a parameter: +50 risk, almost always blocked (CRLF in form inputs has no legitimate use)
- Malformed header: hyper rejects with 400 before the pipeline, no backend contact
- Smuggling-shaped request: a 70-score `smuggling_*` signal → blocked + attributed in the audit log for any shape that reaches the detector (most h1 ambiguity is already rejected by the hyper parser; the HTTP/2 forbidden-header rule is the one that fires in normal operation — see the smuggling-hygiene section above)

## Implementation

- `src/detection/header_injection.rs`
- Header validation is also done at the proxy core level before the pipeline runs

## Design notes

- Smuggling defense is **layered**: the hyper HTTP/1 parser is the primary,
  structural defense (it rejects conflicting CL/TE framing at parse time and
  re-serialises the upstream request with fresh framing), and the detector's
  `smuggling_*` rules add attribution + a defense-in-depth backstop for shapes
  that reach the pipeline (notably HTTP/2 forbidden headers).
- Any smuggling-shaped request that reaches the detector is blocked outright —
  there's no legitimate reason to send one.
