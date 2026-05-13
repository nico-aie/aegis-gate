# Phase 2 — P2 (MEDIUM) Run-6

> **Branch:** `develop`. Two pattern-extension tasks on existing detectors. Bundle as one PR.

---

## GAP-006b · SSTI Twig + Freemarker variants

**Source:** Run-6 §5 + §8 row 3.

### Verified state

`grep -E 'Twig|7\*7|freemarker|<#assign' crates/aegis-security/src/detectors/template_injection.rs` — current `SSTI_PATTERNS`:

```rust
// Numeric expression in {{...}} — POC
r"(?i)\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
// Freemarker directives
r"(?i)<#\s*(?:assign|list|if|include|import|setting|escape)\b",
```

### Claim 1 — Twig `{{7*'7'}}` missed

**Verified true.** The current pattern requires `\d+\s*\*\s*\d+` — bare digits on both sides. Twig's `{{7*'7'}}` has the second operand as a quoted string literal which Twig coerces to `7` and multiplies, so the result `49` is sandbox-escape-worthy. Quotes break the regex.

### Claim 2 — Freemarker `<#assign>` missed

**Likely false (regex already covers this).** The pattern `(?i)<#\s*(?:assign|...)` matches `<#assign`. Hypothesis: same as Log4Shell — corpus-vs-deployment timing. Verify with a regression test.

### Detection logic

**Why broaden the multiplication pattern (not split into a new detector):** Quoted-operand multiplication (`7*'7'`, `'7'*7`, `"7"*7`) is the same SSTI proof-of-concept shape as `7*7` — the engine evaluates both and the result is identical. Splitting would fragment patterns; one-liner extension is cleaner.

**Why not match all `{{ ... }}` with arithmetic operators:** That FPs on JSON / debug responses that legitimately echo template-style braces (every Vue.js / Angular debug page would trip it). The narrow `\d+\s*\*\s*['"]?\d+['"]?` shape preserves the canonical-POC trigger without expanding into legit content.

**Score: 50** (existing template_injection score, unchanged).

**Field tag:** `template_injection` (existing).

### Plan

Replace pattern #1 with a quote-tolerant version, keep the rest:

```rust
// Numeric expression in {{...}} — the canonical SSTI POC.
// Allows quoted operands (Twig `{{7*'7'}}`, Jinja `{{ '7' * 7 }}`)
// because the engine coerces both to numeric. Conservative enough
// that legit JSON `{{x:1}}` doesn't fire (the `\*` is required).
r#"(?i)\{\{\s*['"]?\d+['"]?\s*\*\s*['"]?\d+['"]?\s*\}\}"#,
```

Same ladder for `${...}` SpEL multiplication (line 66):

```rust
r#"(?i)\$\{\s*['"]?\d+['"]?\s*\*\s*['"]?\d+['"]?\s*\}"#,
```

Add Freemarker regression tests covering `<#assign>`, `<#if>`, `<#list>` to confirm coverage.

**Tests:**
- Positive: `{{7*'7'}}`, `{{'7'*7}}`, `{{ "7" * 7 }}`, `{{7 * '7'}}` (whitespace variants), `${'7'*7}`, `<#assign x=7*'7'>`, `<#if x>...</#if>`, `<#list ...>`.
- Negative: `{{user.name}}` (no `*`), `{{ items.length }}`, `<#-- comment -->` (Freemarker comment, no directive).

**Doc:** update `docs/security/detectors/template-injection.md` with the quoted-operand variant note + Freemarker coverage confirmation.

### Acceptance

- [ ] 8+ positive variants block, 4+ negatives stay green
- [ ] Existing 30+ SSTI tests pass
- [ ] Doc updated

**Effort:** ~20 min.

---

## GAP-001b · Recon: bare `/actuator`, `/rails/info`, `phpinfo.php`

**Source:** Run-6 §5 + §8 row 4.

### Verified state

| Probe | Current pattern | Behaviour |
|---|---|---|
| `/actuator` (bare) | `(?i)/actuator/(?:heapdump\|env\|...)` requires subpath | **Misses** |
| `/actuator/health` | Same — `health` not in subpath list | **Stays green** ✅ (operator-controlled) |
| `/metrics` (bare) | `(?i)/metrics\?(?:format=\|target=\|module=)` requires query | **Misses by design** — operator-hosted endpoint |
| `/rails/info/properties` | Not in patterns | **Misses** |
| `phpinfo.php` | `(?i)(?:phpinfo\(\))` matches function call, not file | **Misses** |
| `/info.php` | Not in patterns | **Misses** |

### Detection logic

**Why bare `/actuator` is recon-worthy:** Spring Boot Actuator's root endpoint (`/actuator`, no subpath) is the **discovery page** — it returns a JSON list of every available actuator endpoint. Probing `/actuator` is the universal first-step recon: an attacker doesn't yet know which dangerous subpaths are enabled, so they hit the index. Operators legitimately exposing actuator typically expose `/actuator/health` and `/actuator/info` only (the unauthenticated subset) — bare `/actuator` redirects or 404s in safe configurations. **The pattern stays narrow:** match `/actuator` followed by **end-of-path-or-query**, not a slash. So `/actuator` and `/actuator?refresh=true` flag, but `/actuator/health` (subpath) does not.

**Why `/rails/info/properties` and `/rails/info/routes`:** Rails exposes a debug page at `/rails/info/*` in development that leaks installed gems, environment, and route table. The page is supposed to be development-only; if it's reachable in production the attacker gets a free reconnaissance dump. Same recon class as the Spring actuator endpoints.

**Why `phpinfo.php`, `/info.php`, `/test.php`:** classic PHP-developer-debug-leftover files. Hitting them returns the full `phpinfo()` output (loaded modules, paths, environment, configuration) — recon goldmine. The current `phpinfo\(\)` regex only matches the function call, not the file path. Add file-shape patterns.

**Why bare `/metrics` stays NOT flagged:** legitimately operator-hosted Prometheus endpoint. We documented this trade-off in Run-5 (`recon.md`). To force flagging, operators add a custom rule on `/metrics` for their environment. The QA report's "missed" verdict is treated as a documentation issue, not a detection gap.

**Score: 25** (existing recon-path score, unchanged).

**Field tag:** `recon_path` (existing).

### Plan

Extend `RECON_PATHS` in `recon.rs`:

```rust
// GAP-001b (Run-6, 2026-05-09) — bare actuator discovery page.
// Spring Boot Actuator's root index lists every available
// endpoint. Operators legitimately expose /actuator/health and
// /actuator/info (the safe subset) but rarely the bare index.
// Pattern matches /actuator at end-of-path or ?-prefixed query;
// /actuator/health (subpath) does NOT match (already covered by
// the dangerous-subpath pattern above).
r"(?i)/actuator(?:$|\?|#)",

// Rails debug surface — /rails/info/* leaks gems, env, routes.
// Development-only page; reachable in prod = recon dump.
r"(?i)/rails/info(?:/|$)",

// Classic PHP-developer-debug files — phpinfo() output.
// Distinct from the existing `phpinfo\(\)` function-call match,
// which catches the shape inside a body or query value.
r"(?i)/(?:phpinfo|info|test|i)\.php(?:$|\?|/)",
```

**Tests:**
- Positive: `/actuator`, `/actuator?refresh=true`, `/rails/info/properties`, `/rails/info/routes`, `/phpinfo.php`, `/info.php`, `/test.php`.
- Negative (must stay green): `/actuator/health`, `/actuator/info`, `/health`, `/metrics` (bare), `/api/v1/users`, `/rails/api/users` (legitimate Rails app path that happens to start with `/rails/`), `/index.php` (general PHP entry — too common to flag).

**Doc:** update `docs/security/detectors/recon.md` with:
- The bare-actuator + rails-info entries in the framework-recon table.
- An explicit note explaining why bare `/metrics` is **not** flagged (operator-hosted Prometheus endpoint; per-environment custom rule available).

### Acceptance

- [ ] 7+ positive probes block
- [ ] All listed negatives stay green (especially `/actuator/health`, `/index.php`, `/api/v1/users`)
- [ ] Doc updated with the explicit `/metrics` trade-off note
- [ ] Existing 30+ recon tests pass

**Effort:** ~30 min.

---

## Sequencing

Single bundled PR: `feat(detectors): SSTI quoted-operand + recon framework discovery paths (GAP-006b + GAP-001b)`. Both touch detector pattern lists + tests + per-detector docs; same review surface.
