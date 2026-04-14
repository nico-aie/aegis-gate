# Request/Response Transformations & CORS (v2, new)

> **New in v2.** Header manipulation, URL rewrite, redirect, and a full
> CORS handler — per route. Previously only available via external tools.

## Purpose

Rewrite requests and responses inline so backends don't need per-client
compatibility shims, and so a single edge policy can enforce CORS.

## Header transforms

```yaml
transforms:
  request_headers:
    add:    { "x-forwarded-host": "$host" }
    set:    { "x-real-ip": "$client_ip" }
    remove: ["cookie.internal_admin", "x-debug"]
  response_headers:
    add:    { "x-powered-by": "safety" }
    set:    { "cache-control": "private, max-age=0" }
    remove: ["server", "x-aspnet-version"]
```

Variables:

- `$host`, `$client_ip`, `$request_id`, `$route_id`, `$tenant_id`
- `$jwt.<claim>` — claim from validated JWT
- `$cookie.<name>`, `$header.<name>`

## URL rewrite / prefix strip / redirect

```yaml
transforms:
  rewrite:
    - from: "^/old/(.*)$"
      to:   "/new/$1"
  strip_prefix: "/api/v1"
  add_prefix:   "/v2"
  redirect:
    from:   "/legacy/"
    to:     "/"
    status: 301
```

Rewrite is applied before upstream forward; redirect short-circuits
before reaching the upstream.

## CORS handler

Declarative per-route CORS with preflight handling:

```yaml
transforms:
  cors:
    allow_origins: ["https://app.example.com", "https://*.example.com"]
    allow_methods: [GET, POST, PUT, DELETE]
    allow_headers: [authorization, content-type, x-request-id]
    expose_headers: [x-request-id]
    allow_credentials: true
    max_age_s: 86400
    preflight_continue: false
```

Preflight (`OPTIONS` + `Access-Control-Request-Method`) is answered by
the WAF directly unless `preflight_continue: true`. Origin matching
supports exact + wildcard subdomain.

## Response-body rewrite hooks

For sanitization only — reuses the streaming filter from
[`response-filtering.md`](./response-filtering.md). Arbitrary body
rewrite is intentionally out of scope (would break caching semantics).

## Order of operations

```
inbound:
  normalize → auth → rule engine → request-transform → rewrite → forward

outbound:
  upstream response → response-transform → dlp/response-filter → cors headers → client
```

## Configuration (shared block)

Transforms can be defined inline on a route or referenced from a shared
block:

```yaml
transform_sets:
  internal_api:
    request_headers: { remove: ["cookie.session"] }
    cors: { allow_origins: ["https://app.example.com"] }

routes:
  - id: api
    transforms_ref: internal_api
```

## Implementation

- `src/transform/headers.rs` — add/set/remove + variable expansion
- `src/transform/rewrite.rs` — regex rewrite + prefix strip/add
- `src/transform/redirect.rs` — short-circuit responder
- `src/transform/cors.rs` — preflight handler + origin matcher
- `src/transform/vars.rs` — `$var` expansion

## Performance notes

- Header ops are in-place on the hyper `HeaderMap`; zero allocation for
  `remove`, minimal for `add`/`set`
- Rewrite regex is compiled once at config load
- CORS preflight answers don't enter the security pipeline
