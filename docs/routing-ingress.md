# Routing & Ingress (v2, new)

> **New in v2.** The WAF gains a k8s-ingress / nginx `server` style route
> table: host + path matching, wildcards, regex, longest-prefix-wins,
> and per-route policy attachment. Replaces v1's single-upstream model.

## Purpose

Decide, for each incoming request, **which backend pool serves it**,
**which tier policy applies**, and **which transforms run**. The route
table sits between TLS termination and the security pipeline.

## Route model

```rust
pub struct Route {
    pub id: String,                // stable, used in metrics + audit
    pub host: HostMatcher,         // exact | wildcard | regex
    pub path: PathMatcher,         // exact | prefix | regex | longest
    pub methods: Option<Vec<Method>>,
    pub upstream_ref: String,      // pool name
    pub tier_override: Option<String>,
    pub transforms: TransformSet,  // see transformations-cors.md
    pub auth: Option<AuthRef>,     // see external-auth.md
    pub quotas: QuotaSet,          // see per-route-quotas.md
    pub tenant_id: Option<String>,
}
```

## Matching algorithm

1. **Host index** — `HashMap<&str, Vec<&Route>>` for exact hosts, plus a
   sorted `Vec<(WildcardHost, Vec<&Route>)>` for `*.example.com` style
2. **Path trie** per host bucket, built from prefix routes, with a
   secondary ordered list of regex routes
3. **Specificity ordering** — longest exact > longest wildcard > regex
4. **Method filter** on the matched route
5. **First match wins** among ties of equal specificity

Built at config load, swapped via `ArcSwap<RouteTable>`, zero-allocation
on the hot path.

## Host matching

- Exact: `api.example.com`
- Wildcard: `*.example.com` (single label)
- Regex: `^(api|www)\\.example\\.com$` (opt-in; slower)
- SNI-aware: if TLS is terminated, the SNI value feeds host matching

## Path matching

- Exact: `/health`
- Prefix: `/api/` (matches `/api/foo` and `/api/`)
- Longest-prefix-wins: `/api/v2/` beats `/api/`
- Regex: `^/u/\\d+$` (opt-in)

## Default route

A catch-all (`host: "*"`, `path: "/"`, `upstream_ref: "default"`) is
required — the loader rejects a config that has none.

## Configuration

```yaml
routes:
  - id: api_v2_login
    host: "api.example.com"
    path: "/v2/login"
    match: exact
    methods: [POST]
    upstream_ref: auth_pool
    tier_override: critical
    auth: { type: none }

  - id: api_v2_catch
    host: "api.example.com"
    path: "/v2/"
    match: prefix
    upstream_ref: api_pool
    tier_override: high

  - id: static
    host: "*.example.com"
    path: "/static/"
    match: prefix
    upstream_ref: cdn_origin
    tier_override: medium

  - id: default
    host: "*"
    path: "/"
    match: prefix
    upstream_ref: default_pool
```

## Backwards compatibility

A v1 `upstream.address` is auto-wrapped into a synthetic `default_pool`
with a single member and a catch-all route, so v1 configs keep working
unchanged.

## Implementation

- `src/routing/table.rs` — `RouteTable` + `ArcSwap`
- `src/routing/host_index.rs` — exact + wildcard host index
- `src/routing/path_trie.rs` — prefix trie with longest-match
- `src/routing/regex_routes.rs` — ordered regex list fallback
- `src/routing/match.rs` — matcher algorithm

## Performance notes

- Exact host + prefix match: two hashmap gets + trie walk; sub-µs
- Regex routes are off the hot path when not configured
- No per-request allocation: all matchers borrow from the `ArcSwap` load
