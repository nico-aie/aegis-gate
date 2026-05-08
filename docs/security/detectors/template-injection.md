# Server-Side Template Injection (SSTI) Detection

> **Status:** Implemented — `aegis-security/src/detectors/template_injection.rs`.
>
> **Landed:** 2026-05-08 (QA Run-5 GAP-006 follow-up).
>
> See [`../../../plans/issue-fix/tester-n-2026-05-08-run5/PHASE-01-high.md`](../../../plans/issue-fix/tester-n-2026-05-08-run5/PHASE-01-high.md) for the design.

## Purpose

Detect attempts to inject template-engine syntax into HTTP request values. SSTI is one of the highest-impact server-side vulnerabilities — successful exploitation typically yields arbitrary code execution under the WAF's upstream service. Common attack shapes:

- **Jinja2 / Twig / Liquid:** `{{7*7}}`, `{{config}}`, `{{x.__class__.__mro__}}`
- **Spring SpEL:** `${T('java.lang.Runtime')}`, `${#root.foo}`, `${@beanName.method}`
- **Freemarker:** `<#assign x=...>`, `<#list ...>`
- **Velocity:** `#set($x = ...)`, `#evaluate(...)`
- **Mako:** `<%! code %>`, `<% expr %>`
- **Handlebars / Mustache:** `{{#with ctx}}`, `{{lookup (a b)}}`

## Why this exists separately from `command_injection`

SSTI's syntax (`{{ }}`, `${ }`, `<#...>`, `#set(...)`) is template-engine-specific and distinct from shell-meta cmdi (`$()`, `|cmd`). SSTI also has its own characteristic payloads (`{{config}}`, `{{__class__.__mro__}}`) that aren't shell-shaped at all. Bundling would dilute the cmdi pattern set. **It does not depend on the AI detector** — it works in any rule-only pipeline.

## Detection logic

Each pattern requires **both** the brace/tag syntax AND a suspicious internal — bare matched braces alone do **not** fire. This avoids false positives on legit JSON responses, web-framework debug pages, or template-output APIs that echo the brace syntax in error messages.

| Pattern | Catches | Why specific |
|---|---|---|
| `{{<int> * <int>}}` | The canonical SSTI POC `{{7*7}}` | No legit template echoes a multiplication expression in URL/body |
| `{{...__\w+__}}` | Python attribute access (`__class__`, `__mro__`, `__subclasses__`) | Jinja2/Mako sandbox-escape primitives |
| `{{config}}`, `{{cycler.}}`, `{{joiner.}}`, `{{namespace(}}`, `{{request.}}`, `{{self.}}`, `{{lipsum.}}`, `{{url_for}}` | Jinja2 globals | Not legit URL/body content; closed list |
| `{% set %}`, `{% for %}`, `{% if %}`, `{% import %}`, `{% with %}` | Jinja2 / Twig statement tags | Execution-side constructs, not template output |
| `<#assign>`, `<#list>`, `<#if>`, `<#include>`, `<#import>` | Freemarker directives | Engine-specific; legit body content rarely uses `<#...>` |
| `#set(`, `#if(`, `#foreach(`, `#evaluate(` | Velocity directives | Same — engine-specific syntax |
| `<%!...%>`, `<%...%>` | Mako server-block syntax | Mako template blocks; non-Mako apps don't include `<%` |
| `${<int> * <int>}` | SpEL / Mako arithmetic POC | Same idea as `{{7*7}}` |
| `${T('...')}` | SpEL type reference | Used for `T('java.lang.Runtime').getRuntime()...` exploits |
| `${#root.}`, `${@bean.}` | SpEL bean / root accessors | SpEL-specific; no legit URL/body equivalent |
| `${new Class}` | SpEL instantiation | Constructor invocation in expression context |
| `{{#with}}`, `{{#each}}`, `{{lookup ...}}` | Handlebars exec helpers | `with`/`each` allow arbitrary expression evaluation; `lookup` is a known Handlebars RCE primitive |

## Surfaces inspected

For each request:

- **URI string** (path + query) — both raw and URL-decoded
- **Request body** — first 8 KiB, both raw and URL-decoded

The detector does **not** inspect:

- Headers — Log4Shell-style header payloads use `${jndi:...}` shapes; if SSTI patterns appear in headers, they're caught by `command_injection`'s Log4Shell tier (different bucket, same RCE-class score).
- Cookies — bypass-prone; operators can add via rule engine.
- Body beyond 8 KiB — bounded to keep the detector cheap.

## Score: 50

High-confidence injection tier (same as sqli, xss, ssrf, cmdi). SSTI is RCE-class. The patterns require both syntax + suspicious internal, so FP rate matches sqli's profile.

| Threshold | Outcome with score=50 |
|---|---|
| 1 hit | risk_score = 50, no IP-level effect (below `challenge_at: 40`? No — exceeds) → reaches challenge tier on first hit |
| 2 hits | risk_score caps at 100 (max-clamp), reaches block tier |

## Field tag

`template_injection`. Audit log row carries `rule_id: "template_injection"`; dashboard's by-detector chart shows it as a discrete bucket from cmdi.

## Configuration

The detector is class-toggleable via `cfg.detectors.template_injection.enabled` (default `true`):

```yaml
detectors:
  template_injection:
    enabled: true
```

Surfaces in the v2.3 control plane as a **toggleable policy under `rules_engine`**:

```sh
# Move into log_only at runtime (no restart):
curl -X POST http://127.0.0.1:8080/__waf_control/set_profile \
  -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","feature":"rules_engine","policies":["template_injection"],"mode":"log_only"}'
```

After the call, SSTI-flagged requests still emit `X-WAF-Action: block` + `X-WAF-Rule-Id: template_injection` but with `X-WAF-Mode: log_only` and the request reaches upstream — same `log_only` semantics as every other rules_engine policy.

## False positive mitigation

| Input | Triggers? | Why |
|---|---|---|
| `?q={{user.name}}` | No | Bare brace template-output, no suspicious internal |
| `?q={{7*7}}` | **Yes** | Numeric arithmetic POC |
| `?q={{config}}` | **Yes** | Jinja2 global accessor |
| `?q=${HOME}` | No | Plain envvar; matched only by cmdi pattern (different score) |
| `?q=${T('java.lang.Runtime')}` | **Yes** | SpEL type reference |
| `?q=%7B%7D` | No | URL-encoded bare `{}` |
| `?q=(a+b)` | No | Plain parenthesized expression, no `{{` or `${` |

For deployment-specific tuning, the v2.3 `set_profile` runtime knob lets operators move `template_injection` into `log_only` without a restart while collecting live FP data.

## Implementation

- `crates/aegis-security/src/detectors/template_injection.rs` — pattern set, regex list, scorer (~180 lines, regex-only)
- `crates/aegis-security/src/detectors/mod.rs` — registered in `default_detectors()` after `command_injection`
- `crates/aegis-security/src/detectors/mask.rs` — `DetectorClass::TemplateInjection` (bit 9) + serde-default field on `DetectorMaskBody`
- `crates/aegis-control/src/interop/rule_map.rs` — `"template_injection" | "ssti" => ("rules_engine", "template_injection")`
- `crates/aegis-control/src/api/rules.rs` — added to `RESERVED_RULE_IDS`
- `crates/aegis-control/src/metrics/detector_hits.rs` — added to `class_label::ALL`

## Performance

- Regex-only — no Hyperscan / Aho-Corasick, fully `safe` Rust with no FFI cost.
- Patterns compiled once via `LazyLock`; per-request cost is `regex.is_match()` over the URI + body, with early exit on first match.
- Body scan bounded at 8 KiB.
- Adds approximately one regex-set sweep to the detector pipeline — same shape as sqli/xss/ssrf, no new architectural cost.

## Tests

30 cases in `template_injection.rs::tests`:

- 2 QA Run-5 reproductions (`{{7*7}}`, `${7*7}`)
- 7 Jinja2 classic payloads (`{{config}}`, `{{__class__.__mro__}}`, `{{cycler.next}}`, `{{request.application}}`, `{{self.foo}}`, `{{__subclasses__}}`, `{{url_for}}`)
- 2 statement tags (`{% set %}`, `{% for %}`)
- 4 Freemarker / Velocity / Mako (`<#assign>`, `#set(`, `#evaluate(`, `<%!...%>`)
- 4 Spring SpEL (`${T('...')}`, `${#root.}`, `${@bean.}`, `${new ...}`)
- 2 Handlebars / Mustache (`{{#with}}`, `{{lookup}}`)
- 9 negative cases (bare `{{var}}`, plain envvars, URL-encoded `{}`, simple queries, etc.)

Plus rule_map regression test in `aegis-control::interop::rule_map::tests::template_injection_maps_to_rules_engine`.

## See also

- [`../security-engine.md`](../security-engine.md) — pipeline overview
- [`../tiered-protection.md`](../tiered-protection.md) — per-tier mask resolution
- [`./README.md`](./README.md) — detector index
- [`./command-injection.md`](./command-injection.md) — cmdi class (Log4Shell `${jndi:...}` payloads live there)
