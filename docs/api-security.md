# API Security (v2, enterprise)

> **Enterprise addendum.** Positive security for REST and GraphQL:
> **OpenAPI 3 schema enforcement**, **GraphQL query validation**,
> depth / cost limits, and response-shape validation.

## Purpose

Bad requests never reach the backend, and leaky responses never reach
the client. Positive security defines what is allowed and rejects
everything else — strictly stronger than pattern-based OWASP detectors.

## OpenAPI 3 enforcement

Attach an OpenAPI spec to a route:

```yaml
routes:
  - id: api_public
    host: "api.example.com"
    path: "/v1/"
    match: prefix
    upstream_ref: api_pool
    api_schema:
      type: openapi3
      path: "/etc/waf/specs/public-v1.yaml"
      mode: enforce      # enforce | monitor | learn
```

Modes:

- **enforce** — request/response must conform; violations → block
- **monitor** — violations logged only, not blocked
- **learn** — build a synthesized spec from observed traffic

Validated at request time:

- Path + method must exist in the spec
- Path/query/header params must match their schema (type, format,
  pattern, enum, required)
- Request body must validate against `requestBody.content.<ct>.schema`
- Response (if enforcement enabled) validates against declared status
  codes and schemas

## Request / response validation

Powered by `jsonschema-rs` with draft-2020-12, compiled once at config
load. Schema refs resolved through a local registry. Validation errors
carry a JSON-pointer path for precise audit:

```
schema violation at /items/0/email: pattern mismatch
```

## GraphQL

GraphQL traffic is parsed with `async-graphql-parser`. Enforcement
covers:

- **Depth limit** — reject queries deeper than N (default 10)
- **Node count** — reject queries with more than N total nodes
- **Complexity cost** — weighted cost per field; reject above budget
- **Introspection gate** — block or allowlist `__schema`/`__type`
- **Persisted queries** — optional allowlist keyed by hash
- **Operation allowlist** — production can require that every query
  hashes to a known, vetted operation

```yaml
routes:
  - id: graphql
    path: /graphql
    api_schema:
      type: graphql
      sdl_path: /etc/waf/specs/schema.graphql
      depth_limit: 8
      node_limit: 1000
      cost_budget: 5000
      introspection: deny
      persisted_only: false
```

## Discovery / learn mode

`mode: learn` records every observed request pattern into a synthesized
spec that operators can review in the dashboard and promote to
`enforce` once stable. Learn mode is time-bounded and capped so it
can't bloat forever.

## Positive-vs-negative layering

Positive enforcement runs **before** the negative detectors
(SQLi, XSS, …). A request rejected by schema never runs detectors,
reducing CPU. A request accepted by schema still runs detectors
(defense in depth).

## Error surface

Violations respond with a **minimal** error (configurable) so
enumeration attacks don't reveal schema details:

- 400 with `{"error":"bad_request","request_id":"..."}` (default)
- 422 with per-field details (dev mode only)

## Configuration

```yaml
api_security:
  registries:
    public_v1: "/etc/waf/specs/public-v1.yaml"
  defaults:
    mode: enforce
    response_validation: true
    error_detail: minimal
  graphql:
    depth_limit: 10
    node_limit: 1000
    cost_budget: 5000
```

## Implementation

- `src/api/openapi.rs` — spec loader + per-route index
- `src/api/validate_req.rs` — request validation
- `src/api/validate_resp.rs` — response validation
- `src/api/graphql.rs` — parser + depth/cost/persistence checks
- `src/api/learn.rs` — synthesized-spec recorder

## Performance notes

- Schemas compiled once; validation is O(request size)
- GraphQL parse is a single pass; depth/cost computed in one walk
- Persisted-query lookup is a hashmap hit
