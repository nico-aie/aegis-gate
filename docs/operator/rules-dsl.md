# Custom Rules DSL — operator reference

The Rules page (dashboard → Rules) manages **operator rules**: YAML documents
evaluated by `aegis_security::rules` against every proxied request. This is the
full reference the dashboard's "Syntax help" cheatsheet summarizes.

> A structural guard test
> (`aegis-security` → `rules::ast::tests::dsl_docs_and_dashboard_cheatsheet_cover_every_variant`)
> fails the build when a DSL keyword is added to the parser without updating
> this document and the dashboard cheatsheet. If you extend the AST, extend
> both.

## Rule shape

Each rule is one YAML list item:

```yaml
- id: block-admin-path        # required — unique, 1-64 alphanumerics + hyphens/underscores
  priority: 100               # optional — higher evaluates first; default 0
  scope: global               # optional — global (default) or { route: "<route-id>" }
  when: <condition>           # required — see Conditions
  then: <action>              # required — see Actions
```

The dashboard's editor PUTs the body to `POST /api/rules` / `PUT /api/rules/{id}`
(audit-chained, CSRF-gated); the engine hot-swaps the active ruleset — no
restart, in-flight requests finish on the old table.

## Evaluation order

1. Rules are sorted by `priority` **descending** (higher wins).
2. Route-scoped rules are skipped unless the request resolved to that route.
3. The first matching rule with a **terminal** action decides:
   `allow`, `block`, `challenge`, `rate_limit` are terminal.
4. **Non-terminal** actions (`log_only`, `raise_risk`) record the match and
   evaluation continues.
5. No terminal match → the request proceeds to the detector chain as usual.

### How rules interact with the detector chain (enforcement, v1)

The data plane consults rules at two points:

- **Before detectors** — an explicit terminal `then: allow` match skips the
  detector chain entirely (a *dynamic allowlist*, same trust contract as the
  static whitelist). It does **not** override the blacklist, DDoS, rate-limit,
  or strike-block gates, which run earlier.
- **On the forward path** — a matching `block: { status }` rule returns that
  status with `x-waf-rule-id` and emits a block audit event.

Everything else is currently **audit-visible but not enforced**:

| Action | Enforced today? | Notes |
|---|---|---|
| `allow` | ✅ | Detector-chain bypass (not blacklist/DDoS/volumetric) |
| `block` | ✅ | Custom status honored; audit event emitted |
| `challenge` | ❌ | Falls through — no challenge is issued by the rule path |
| `rate_limit` | ❌ | No rule-scoped limiter backend wired — matches allow |
| `log_only` | — | By design: match recorded, decision unchanged |
| `raise_risk` | ❌ | Accumulated score not fed into the per-request gate |

The Rule Simulator reports these matches with `enforced: false` so a preview
never claims a verdict the live engine would not serve.

## Conditions (`when:`)

### Request shape

```yaml
method:                       # any of the listed methods (case-insensitive)
  - POST
  - PUT

path_matches:                 # URI path (no query string)
  contains: "/admin"

host_matches:                 # Host header (falls back to URI host)
  suffix: ".internal.example.com"

body_matches:                 # first 8 KiB of the request body, UTF-8
  contains: "ABC"

query_matches:                # one named query parameter
  name: "test"
  op:
    exact: "zxc"

header_matches:               # one named request header
  name: "User-Agent"
  op:
    contains: "sqlmap"

cookie_matches:               # one named cookie value
  name: "session"
  op:
    prefix: "legacy-"
```

### Identity

```yaml
ip_in:                        # exact peer-IP list (no CIDR — use Access Lists for ranges)
  - "203.0.113.10"
  - "198.51.100.42"

country:                      # ISO-3166 alpha-2, case-insensitive
  - "CN"
  - "RU"

asn:                          # autonomous system numbers
  - 64496
```

> ⚠️ `country` / `asn` require a GeoIP lookup wired into the rule evaluator's
> `EvalContext`. The current data plane evaluates rules with an empty context,
> so these conditions **match nothing** today (GeoIP powers the blacklist and
> attack map, not the rule engine yet). They parse and are reserved for the
> GeoIP wiring follow-up.

### Advanced

```yaml
jwt_claim:                    # dot-path into the (unverified) JWT payload
  path: "role"
  op:
    exact: "admin"

bot_class:                    # classifier labels, e.g. scanner / crawler
  - scanner

threat_feed:                  # entry present in a configured feed at ≥ confidence
  id: "abuse-ipdb"
  min_confidence: 80

schema_violation              # request failed the configured API schema (string form)

true                          # always matches — combine with scope/priority for catch-alls
```

### Combinators

```yaml
all:                          # every child must match
  - method: [POST]
  - query_matches: { name: "test", op: { exact: "zxc" } }
any:                          # at least one child matches
  - path_matches: { contains: "/v1/" }
  - path_matches: { contains: "/v2/" }
not:                          # negate one child
  path_matches: { prefix: "/health" }
```

## Match operators (`<op>`)

Every string matcher takes exactly one of:

| Op | Semantics |
|---|---|
| `exact: "v"` | full-string equality |
| `prefix: "v"` | starts with |
| `suffix: "v"` | ends with |
| `contains: "v"` | substring |
| `regex: "v"` | Rust `regex` syntax; compiled per evaluation — prefer the cheaper ops when they suffice |

`path_matches`, `host_matches`, `body_matches` take the op map directly.
`query_matches`, `header_matches`, `cookie_matches`, `jwt_claim` nest it under
`op:` next to `name:`/`path:` — this is the form the original Syntax-help
cheatsheet omitted:

```yaml
query_matches:
  name: "test"
  op:
    exact: "zxc"
```

## Actions (`then:`)

```yaml
then: allow                   # terminal — dynamic allowlist (detector bypass)

then: log_only                # non-terminal — audit the match, change nothing

then:
  block:
    status: 403               # terminal — optional; defaults to 403

then:
  challenge:
    level: js                 # js | pow | captcha (NOT enforced by the v1 engine)

then:
  rate_limit:
    key: ip                   # bucket key: {rule_id}:{key}:{client_ip}
    limit: 100
    window_s: 60              # (NOT enforced — no rule-scoped limiter backend wired)

then:
  raise_risk: 20              # non-terminal — reserved; not fed into the per-request gate yet
```

## Testing rules — the Simulator

Rules page → **Simulator** tab replays a synthetic request against the live
custom rules + detector chain with no traffic and no audit emit:

- method, path (+ query), body, Host, headers (`Name: value` lines), and a
  simulated **peer IP** (for `ip_in`) are all configurable;
- the verdict shows the matched rule (id, action, block status), whether the
  detector chain was bypassed by an `allow` rule, and any
  matched-but-not-enforced warning;
- the simulator evaluates at **global scope** — route-scoped rules are listed
  as "not evaluated", not silently ignored;
- the cumulative-risk challenge band is not simulated (it depends on an IP's
  accumulated history, which a stateless preview lacks).

## API surface

| Endpoint | Purpose |
|---|---|
| `GET /api/rules` | list `{id, body, enabled}` |
| `POST /api/rules` | create (`enabled: false` saves a draft) |
| `PUT /api/rules/{id}` | replace body/enabled |
| `PUT /api/rules/{id}/toggle` | flip enabled |
| `DELETE /api/rules/{id}` | remove |
| `POST /api/rules/validate` | parse + lint a body without saving |
| `POST /api/rules/simulate` | preview a request against rules + detectors |
| `POST /api/copilot/rule` | AI-draft a rule body from a natural-language intent (advisory; requires Copilot) |

All mutations are audit-chained and CSRF-gated.
