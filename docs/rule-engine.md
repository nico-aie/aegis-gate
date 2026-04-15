# Rule Engine (v2)

> **v1 scope.** The rule engine evaluates a priority-ordered AST and
> sits alongside **schema-based** positive-security guards (OpenAPI +
> GraphQL — see [`api-security.md`](./api-security.md)). It references
> JWT claims, threat-intel feed id, and bot class. Tenant-scoped rules
> are deferred with multi-tenancy — see
> [`deferred/multi-tenancy.md`](./deferred/multi-tenancy.md).

## Purpose

Declarative, hot-reloadable rules express security policy in YAML: "block
requests matching X", "challenge if Y", "add N risk if Z". The engine walks
the rules in priority order and either short-circuits with a terminal action
or accumulates risk for downstream stages.

## AST

```
Rule := { id, priority, enabled, scope, conditions, actions }

Scope := Global | Tier(name) | Route(path)
         # Tenant(id) reserved for the deferred multi-tenancy work

Condition := Ip(IpMatcher)
           | Path(StringMatcher)
           | Header(name, StringMatcher)
           | Cookie(name, StringMatcher)
           | Method([...])
           | RiskAbove(u32)
           | BotClass(class)
           | JwtClaim(name, StringMatcher)
           | ThreatFeed(feed_id)
           | SchemaViolation
           | And([...]) | Or([...]) | Not(Condition)

Action := Allow
        | Block { status, body }
        | Challenge
        | Redirect(url)
        | AddRisk(u32)
        | Log(label)
        | RateLimit(override)                 # v2
        | Transform(TransformOp)              # v2: header set/remove, rewrite
```

Rules with a terminal action (`Allow`/`Block`/`Challenge`/`Redirect`) short-
circuit evaluation. Non-terminal actions (`AddRisk`, `Log`, `Transform`,
`RateLimit`) accumulate and the engine continues.

## Matchers

- **StringMatcher**: `Exact`, `Prefix`, `Suffix`, `Contains`, `Regex` (pre-compiled at load via `regex` crate)
- **IpMatcher**: `Exact`, `Cidr` (via `ipnet`)

All regex and CIDR compilation happens in `RuleLoader::load_from_dir` so the
hot path never parses.

## Evaluation order

1. Rules are loaded and sorted **ascending by priority** (lower priority =
   earlier). Ties break by declaration order.
2. For each request, the engine iterates rules, filters by `scope`, and
   evaluates the condition tree. Short-circuit eval on `And` / `Or`.
3. Accumulated `risk_delta` is pushed into `RequestContext` before the
   risk-decision stage.

## Scope matching

- `Global` — always
- `Tier(name)` — matches when `ctx.tier == name` (after any route-level override)
- `Route(path)` — matches when `ctx.route.id == path` or path prefix

## Configuration

Rules live in YAML files under `rules_dir` and are hot-reloaded with
[`config-hot-reload.md`](./config-hot-reload.md)'s dry-run validator.

```yaml
rules:
  - id: block_sqlmap_ua
    priority: 10
    scope: { type: global }
    conditions:
      type: header
      name: user-agent
      matcher: { type: contains, value: "sqlmap" }
    actions:
      - { type: block, status: 403 }

  - id: challenge_on_risk
    priority: 100
    scope: { type: tier, name: high }
    conditions:
      type: risk_above
      value: 50
    actions:
      - { type: challenge }

  - id: admin_api_jwt_only
    priority: 5
    scope: { type: route, path: "/admin" }
    conditions:
      type: not
      item: { type: jwt_claim, name: "role", matcher: { type: exact, value: "admin" } }
    actions:
      - { type: block, status: 403, body: "admin only" }
```

## Relationship to schema guards

The rule engine is the **negative security model** (list what to block).
The OpenAPI / GraphQL guards are the **positive security model** (list what
is allowed). Schema violations are surfaced as `SchemaViolation` conditions
so rules can decide the terminal action (block vs log-only vs challenge).

## Implementation

- `src/rules/ast.rs` — `Rule`, `Condition`, `Action` enums
- `src/rules/matcher.rs` — `StringMatcher`, `IpMatcher`
- `src/rules/engine.rs` — `RuleEngine::evaluate`
- `src/rules/loader.rs` — YAML → AST with validation
- `src/rules/context.rs` — extended context accessors (claims, bot class, feed id)

## Performance notes

- Recursive AST eval is iterative in practice (short trees); depth is
  bounded by the config loader to prevent pathological configs
- Regex pre-compilation + `aho-corasick` literal prefilters for large rulesets
- Rules snapshot held in `Arc<Vec<Rule>>` swapped atomically via `ArcSwap`
