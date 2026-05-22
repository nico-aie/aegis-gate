# NoSQL Injection Detection

> **Status:** Implemented — `aegis-security/src/detectors/nosql_injection.rs`.
>
> **Landed:** 2026-05-08 (QA Run-5 GAP-007 follow-up).
>
> See [`../../../plans/issue-fix/tester-n-2026-05-08-run5/PHASE-01-high.md`](../../../plans/archive/issue-fix/tester-n-2026-05-08-run5/PHASE-01-high.md) for the design.

## Purpose

Detect MongoDB-flavored operator injection in HTTP request values. NoSQL operator injection is an **auth bypass / data exfiltration** class: a successful exploit can authenticate as any user (`{$ne: null}` in a password field) or dump entire collections (`{$regex: ".*"}`), without ever crossing the kind of boundary sqli detectors look at.

Common attack shapes:

- **Query-string operator injection:** `?username[$ne]=invalid`, `?id[$gt]=0`, `?q[$regex]=.*`, `?q[$where]=1`
- **JSON body operator injection:** `{"$ne":"x"}`, `{"$where":"function(){return true}"}`, `{"$or":[{"a":1},{"b":2}]}`
- **CouchDB / legacy serialization:** `{$where: function(){...}}` — same semantics, comma-omitted form

## Why this exists separately from `sqli`

sqli patterns target SQL syntax — keywords (`UNION`, `SELECT`, `OR 1=1`), comment markers (`--`, `/* */`), boolean injection. NoSQL operator injection has a completely different syntax — bracketed operator names in query strings (`?param[$ne]=foo`) and `$`-prefixed keys in JSON bodies (`{"$where": "..."}`). Folding these into sqli would break the cohesion of the sqli pattern set and dilute its signature value. **It does not depend on the AI detector** — works in any rule-only pipeline.

## Detection logic

The MongoDB query-operator vocabulary is **closed** and **documented** — `$ne`, `$gt`, `$where`, etc. The detector matches **only** the documented operator names. Bare `$` in URL values (e.g. `?cost=$10` for currency, `?id=$1` for Postgres parameter placeholders) doesn't match because the pattern requires the surrounding shape:

| Surface | Pattern | What's required |
|---|---|---|
| **Query string** | `[$<op>]` | Bracket-wrapped operator (`?username[$ne]=invalid`). Legit URL params don't wrap operator names in brackets. |
| **JSON body** | `"$<op>":` | Leading `"` + closing `":`. Distinguishes a `$` in the **key** position (operator) from a `$` in the **value** position (legit currency/template strings). |
| **Legacy `$where`** | `$where:\s*function(` | Catches comma-omitted serializers like `{$where: function(){return true}}`. |

The operator allowlist (29 entries) is the documented MongoDB query-operator vocabulary:

`$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`, `$nin`, `$eq`, `$regex`, `$where`, `$or`, `$and`, `$not`, `$nor`, `$exists`, `$type`, `$elemMatch`, `$all`, `$size`, `$expr`, `$jsonSchema`, `$mod`, `$geoIntersects`, `$geoWithin`, `$near`, `$nearSphere`, `$text`, `$search`, `$comment`.

**Why not parse the JSON body to find `$`-prefixed keys?** Parsing every JSON body would add real cost on every request (regex is faster). The string-match `"$<op>":` pattern is cheap and equivalent for valid JSON; for malformed JSON, neither approach is reliable. We accept the regex cost.

## Surfaces inspected

For each request:

- **URI string** (path + query) — both raw and URL-decoded
- **Request body** — first 8 KiB, both raw and URL-decoded

## Score: 50

High-confidence injection tier (same as sqli, xss, ssrf, cmdi). NoSQL operator injection is auth-bypass / data-exfil class — same impact ceiling as sqli. The pattern is so specific (closed operator vocabulary) that legit traffic essentially never matches.

| Threshold | Outcome with score=50 |
|---|---|
| 1 hit | risk_score = 50 → above `challenge_at: 40` → challenge tier |
| 2 hits | risk_score caps at 100 → block tier |

## Field tag

`nosql_injection`. Audit log row carries `rule_id: "nosql_injection"`; dashboard's by-detector chart shows it as a discrete bucket from sqli.

## Configuration

The detector is class-toggleable via `cfg.detectors.nosql_injection.enabled` (default `true`):

```yaml
detectors:
  nosql_injection:
    enabled: true
```

Surfaces in the v2.3 control plane as a **toggleable policy under `rules_engine`**:

```sh
# Move into log_only at runtime (no restart):
curl -X POST http://127.0.0.1:8080/__waf_control/set_profile \
  -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","feature":"rules_engine","policies":["nosql_injection"],"mode":"log_only"}'
```

Short alias `nosqli` also accepted by the control plane.

## False positive mitigation

| Input | Triggers? | Why |
|---|---|---|
| `?username[$ne]=invalid` | **Yes** | `$ne` operator in bracketed-key shape |
| `?id[$gt]=0` | **Yes** | `$gt` operator |
| `?cost=$10.50` | No | `$` in value, not in key shape |
| `?q=$1` | No | Postgres parameter placeholder |
| `?msg=hello+$user` | No | `$` in value, not in key/bracket shape |
| `?items[]=a&items[]=b` | No | PHP-style array param, no `$` |
| `{"$ne":"x"}` (in body) | **Yes** | `$ne` JSON key |
| `{"item":"$cost"}` (in body) | No | `$` in value position, not key |
| `{"_id":"abc"}` (in body) | No | Single underscore, not an operator |
| `{$where: function(){...}}` | **Yes** | `$where` + `function(` legacy form |

For deployment-specific tuning, the v2.3 `set_profile` runtime knob lets operators move `nosql_injection` into `log_only` without a restart while collecting live FP data.

## Implementation

- `crates/aegis-security/src/detectors/nosql_injection.rs` — pattern set (3 regex), regex-only (~150 lines)
- `crates/aegis-security/src/detectors/mod.rs` — registered in `default_detectors()` after `template_injection`
- `crates/aegis-security/src/detectors/mask.rs` — `DetectorClass::NoSqlInjection` (bit 10) + serde-default field on `DetectorMaskBody`
- `crates/aegis-control/src/interop/rule_map.rs` — `"nosql_injection" | "nosqli" => ("rules_engine", "nosql_injection")`
- `crates/aegis-control/src/api/rules.rs` — added to `RESERVED_RULE_IDS`
- `crates/aegis-control/src/metrics/detector_hits.rs` — added to `class_label::ALL`

## Performance

- Regex-only — no Hyperscan / Aho-Corasick, fully `safe` Rust with no FFI cost.
- 3 patterns compiled once via `LazyLock`; per-request cost is a regex sweep over the URI + body, with early exit on first match.
- Body scan bounded at 8 KiB.

## Tests

22 cases in `nosql_injection.rs::tests`:

- 2 QA Run-5 reproductions (`?username[$ne]=invalid`, `?id[$gt]=0`)
- 5 query-string operator variants (`$regex`, `$where`, `$in`, `$exists`, URL-encoded brackets)
- 3 body-side JSON-key forms (`$ne`, `$where`, `$where: function()`)
- 12 negative cases (Postgres `$1` placeholder, currency strings, template `$user` in value, bare `ne` outside brackets, PHP array params, single-underscore `_id`, etc.)

Plus rule_map regression test in `aegis-control::interop::rule_map::tests::nosql_injection_maps_to_rules_engine`.

## See also

- [`../security-engine.md`](../security-engine.md) — pipeline overview
- [`../tiered-protection.md`](../tiered-protection.md) — per-tier mask resolution
- [`./README.md`](./README.md) — detector index
- [`./sqli.md`](./sqli.md) — SQL injection detector (different syntax bucket)
- [MongoDB Query Operators reference](https://www.mongodb.com/docs/manual/reference/operator/query/)
