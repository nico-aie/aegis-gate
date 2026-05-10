# Phase 2 — MEDIUM coverage (Run-5)

> **Branch:** all changes target `develop`. Three coverage extensions.

---

## GAP-001 · Framework recon paths — extend `recon.rs`

**Source:** Run-5 §GAP-001.

### Verified state

`grep -n 'actuator\|swagger\|graphql\|kibana\|jenkins\|cgi-bin' crates/aegis-security/src/detectors/recon.rs` → no matches. The QA found 14/15 framework-specific paths pass.

### Detection logic

**Why extend `recon.rs` (not new detector):** Framework-specific recon is the same semantic class as the existing `/.env`, `/wp-admin`, `/.git/config` patterns — operator-side info disclosure rather than RCE. Same audit class, same Prometheus bucket, same `set_profile` policy — no reason to split.

**Why these specific framework paths and not bare `/health` / `/metrics`:** Many operators legitimately host `/health`, `/metrics`, `/info`, `/status` on their own services. Pattern-matching on bare `/actuator` or `/health` would FP on every Spring-Boot-style operator endpoint that's intentionally public. Each pattern below targets the **known-dangerous subpath** specifically:

| Pattern | Why dangerous |
|---|---|
| `/actuator/(heapdump\|env\|threaddump\|jolokia\|...)` | Spring Boot — heapdump leaks memory; env leaks secrets; jolokia is RCE if writable |
| `/_ignition/execute-solution` | Laravel Ignition — CVE-2021-3129, direct RCE |
| `/swagger-ui.html`, `/v\d+/api-docs` | API surface enumeration; not always sensitive but standard recon target |
| `/graphql`, `/graphiql`, `/playground` | GraphQL introspection often disabled in prod; flag for visibility |
| `/api/v1/(namespaces\|pods)`, `/apis/apps/v1/deployments` | Kubernetes API — full cluster takeover if reachable |
| `/.kibana/_search`, `/_cat/indices`, `/_cluster/health` | Elastic / Kibana internals — data exposure |
| `/script(?:Text)?`, `/jnlpJars/jenkins-cli.jar` | Jenkins — Groovy console = RCE; CLI jar = unauth admin |
| `/cgi-bin/(printenv\|test-cgi\|php-cgi)` | Legacy CGI — Shellshock + classic info disclosure |

`/metrics` bare is **NOT** in the pattern list — too operator-specific. We flag `/metrics?(format=|target=|module=)` only, which is the Prometheus federation/scrape probe attackers use to enumerate scrape targets.

**Score: existing recon score (25–30 depending on path).** Justification: same impact tier as the existing recon paths. Recon is info disclosure, not exec — the detector's job is signal accumulation across multiple probes, not one-shot block. A determined scanner hitting `/actuator/env` once doesn't deserve a block; the third recon probe in a row should.

**Field tag:** `recon` (existing).

### Plan

Extend `RECON_PATHS` in `recon.rs` with framework signatures. **Conservative**: require the full known-vulnerable shape (e.g. `/actuator/heapdump`, not bare `/actuator/health` which is operator-controlled). Operators self-hosting their own `/health` or `/metrics` endpoints under non-Spring shapes don't FP.

```rust
// recon.rs RECON_PATHS additions:

// Spring Boot actuator — danger endpoints leak heapdump,
// env vars, mappings. /actuator/health and /actuator/info
// are typically intentional and safe; we flag the dangerous
// subpaths specifically.
r"(?i)/actuator/(?:heapdump|threaddump|env|configprops|loggers|trace|httptrace|auditevents|dump|jolokia|liquibase|flyway|gateway|conditions|beans|mappings|metrics/.*|sessions|shutdown)\b",

// Laravel Ignition (CVE-2021-3129) — RCE
r"(?i)/_ignition/(?:execute-solution|health-check|update-config)\b",

// Swagger / OpenAPI — info disclosure
r"(?i)/(?:swagger-ui\.html|swagger\.json|swagger\.yaml|v\d+/api-docs|api-docs|openapi\.json|openapi\.yaml)\b",

// GraphQL introspection — usually-disabled-in-prod
// surface. Operators with intentional public GraphQL
// can disable this class via `set_profile`.
r"(?i)/graphql(?:/|\?|$)",
r"(?i)/graphiql(?:/|\?|$)",
r"(?i)/playground(?:/|\?|$)",

// Kubernetes API — same shape as Docker REST (already
// covered) but the K8s namespaces / pods endpoints.
r"(?i)/api/v1/namespaces\b",
r"(?i)/api/v1/pods\b",
r"(?i)/apis/apps/v1/deployments\b",

// Kibana / Elastic
r"(?i)/(?:app/kibana|\.kibana(?:/|/_search)|_cat/indices|_cluster/health)\b",

// Jenkins — script console (Groovy RCE), CLI jar
r"(?i)/(?:script(?:Text)?|jnlpJars/jenkins-cli\.jar|manage|computer/(?:\(master\)|\(built-in\))/script)\b",

// CGI legacy — printenv, test-cgi, php-cgi
r"(?i)/cgi-bin/(?:printenv\.pl|test-cgi|php-cgi|\.\.)\b",

// Prometheus (when public) — not RCE but info-disclosure
// often paired with recon. Flag `/metrics` ONLY when
// followed by suspicious query — bare `/metrics` is a
// legit Prometheus endpoint operators may host
// themselves. (Conservative: drop this if FPs appear.)
r"(?i)/metrics\?(?:format=|target=|module=)",
```

**Tests** (add to `recon.rs::tests`):
- Positive: `/actuator/heapdump`, `/_ignition/execute-solution`, `/swagger-ui.html`, `/v3/api-docs`, `/graphql`, `/api/v1/namespaces`, `/.kibana/_search`, `/script`, `/cgi-bin/printenv.pl`.
- Negative: `/actuator/health` (legit), `/actuator/info` (legit), `/health` (bare, app-owned), `/metrics` (bare, operator-hosted), `/api/v1/users` (operator path), `/api/v2.1/products` (semver-shaped).

**Doc:** update `docs/security/detectors/recon.md` with the new "Framework reconnaissance" subsection (mirroring the Docker REST API row added in Run-4 SEC-L001).

### Acceptance

- [ ] 9/9 QA framework-recon probes block (compared to 1/9 today)
- [ ] Bare `/actuator/health`, `/health`, `/metrics` don't FP
- [ ] Per-doc updated; cross-refs unchanged (extending existing detector)

**Effort:** ~45 min.

---

## GAP-009 · Open redirect — new lightweight detector

**Source:** Run-5 §GAP-009.

### Verified state

No redirect-param scanning anywhere. QA probe `/redirect?next=http://evil.com` passes.

### Detection logic

**Why a dedicated detector (not part of `ssrf`):** SSRF and open redirect look syntactically similar (both feature URL-shaped values in query parameters) but have **opposite enforcement models**. SSRF should always block external URLs in fetch-style params (`?url=`, `?fetch=`) regardless of destination — the WAF doesn't know which internal service is dangerous to fetch. Open redirect should allow external URLs in redirect-style params **when the destination is on an operator-approved allowlist** (legitimate OAuth `redirect_uri=https://google.com/oauth2/...` is the canonical example). Folding into SSRF would force one of those policies onto the other.

**Why a closed list of redirect-param names:** Only specific param names (`next`, `redirect`, `redirect_uri`, `return`, `goto`, `callback`, `continue`, `url`, `to`, `destination`, `forward`, `rurl`) are conventionally used for redirect-on-success. Any external-URL value in those params is suspicious. Bare `?url=` could be an SSRF param OR a redirect param — when both detectors flag, the audit row carries both rule_ids and the operator sees the combined signal.

**Why scan for `^\s*(https?|//|javascript:|data:)` not just `https?://`:** Real-world bypasses use:
- `//evil.com` (protocol-relative — most browsers follow it)
- `javascript:alert(1)` (XSS pivot via redirect)
- `data:text/html,...` (HTML injection via redirect)
- URL-encoded scheme prefixes (`%2F%2Fevil.com`, `%6A%61%76%61%73%63%72%69%70%74:`) — round-trip through URL-decode catches these.

**Operator allowlist:** the most common FP source is a legitimate redirect to a known partner domain. The detector reads `cfg.detectors.open_redirect.allowed_domains` (default empty); when the value's host matches an entry (literal or `*.example.com` glob), the signal is suppressed. Empty allowlist = strict mode = flag every external URL.

**Score: 30** (phishing / info-disclosure tier). Justification:
- Open redirect's exploitability is real but indirect — it enables phishing, OAuth token theft, CSRF bypass. It's not a direct compromise vector like sqli/cmdi.
- Pattern is heuristic — false positives on legit OAuth flows are realistic without operator config.
- Score 30 means a single hit doesn't reach `challenge_at: 40`; the signal accumulates only when the IP shows multiple suspicious behaviors. That's the right calibration for a phishing-class probe.
- Operators who care more can raise the score via rule engine override OR move to `enforce` from `log_only`.

**Field tag:** `open_redirect`.

### Plan

New `crates/aegis-security/src/detectors/open_redirect.rs`. The risk: operators have legitimate redirect endpoints (OAuth callbacks, login-flow returns) — false-positive surface is real. **Default: detect the most common attack shapes; require operator config (allowed_domains list) for stricter enforcement.**

```rust
//! Open-redirect detector. Flags suspicious external-URL
//! values in known redirect-parameter names. Conservative
//! default (no allowed_domains list = flag external-domain
//! values in redirect params); operators with legitimate
//! redirect targets configure `cfg.detectors.open_redirect.
//! allowed_domains` to skip those.

static REDIRECT_PARAM_NAMES: &[&str] = &[
    "next", "url", "to", "redirect", "redirect_uri", "redirect_url",
    "return", "return_to", "return_url", "rurl", "destination",
    "goto", "continue", "forward", "callback", "checkout_url",
    "image_url", "domain",
];

static REDIRECT_VALUE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Absolute external URL with scheme. Flag-worthy
        // when the value is an http(s):// URL OR a
        // protocol-relative `//` reference.
        r"(?i)^\s*https?://",
        r"(?i)^\s*//\w",
        // JavaScript: / data: schemes — XSS pivot.
        r"(?i)^\s*javascript\s*:",
        r"(?i)^\s*data\s*:",
        // URL-encoded scheme prefix.
        r"(?i)^\s*(?:%2[fF])?(?:%2[fF])?(?:https?|javascript|data)\s*(?:%3[aA]|:)",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("redirect regex compiles"))
    .collect()
});
```

**Detector logic:** parse query string, iterate (key, value) pairs; if `key` matches `REDIRECT_PARAM_NAMES` AND `value` matches one of `REDIRECT_VALUE_PATTERNS`, AND the host portion isn't on the operator allowlist (if any), emit a signal. Score 30 (lower than RCE classes; redirect is phishing-class, not exec).

**Operator config:**

```yaml
detectors:
  open_redirect:
    enabled: true
    # Optional: hostnames considered safe redirect targets.
    # When unset, ANY external http(s):// URL in a redirect
    # param flags. When set, only off-list domains flag.
    allowed_domains:
      - "example.com"
      - "*.example.com"
```

**Wiring:** same nine-step pattern as cmdi/SSTI/NoSQL.

**Tests:**
- Positive: `?next=http://evil.com`, `?redirect=//evil.com`, `?redirect_uri=javascript:alert(1)`, `?url=data:text/html,...`, `?next=%2F%2Fevil.com`.
- Negative (default): `?next=/local/path` (relative), `?next=` (empty), `?next=?param=value` (no scheme).
- Negative (with allowlist `example.com`): `?next=https://example.com/login` doesn't fire.

**Doc:** `docs/security/detectors/open-redirect.md`.

### Acceptance

- [ ] 3/3 QA open-redirect probes block
- [ ] Relative path redirects don't FP
- [ ] Operator allowlist works (allowlisted domain doesn't fire)
- [ ] Toggleable via `set_profile`
- [ ] Per-detector doc + cross-refs

**Effort:** ~1 h.

---

## GAP-010 · Prototype pollution — extend `body_abuse.rs`

**Source:** Run-5 §GAP-010.

### Verified state

`grep -n '__proto__\|constructor\.prototype' crates/aegis-security/src/detectors/body_abuse.rs` → no matches. `body_abuse.rs` already handles JSON-shape attacks (XXE, mass-assignment, oversized nesting), so prototype pollution is a natural fit.

### Detection logic

**Why fold into `body_abuse` (not new detector):** Prototype pollution is a body-shape attack on JSON deserialization — same audit class as XXE and mass-assignment which already live in `body_abuse.rs`. Splitting would fragment the "JSON-shape attacks" bucket without operational benefit.

**Why exact-match `"__proto__"` and not loose `proto`:** Single-underscore variants (`_proto_`, `proto`) are legitimate field names in some APIs (e.g. protobuf serialization, internal app schemas). Double-underscore `__proto__` is the JavaScript prototype reserved name — exact match avoids the FP.

**Why also catch `constructor` + `prototype`:** Object-prototype pollution can also be triggered via the `constructor.prototype` chain (e.g. `{"constructor":{"prototype":{"polluted":"x"}}}`). The detector requires **both** keywords to appear in the body to fire on this pattern — a JSON with `"constructor":"NamedClass"` (constructor as a string value) doesn't fire because `prototype` isn't present.

**Cheap pre-filter:** the function bails immediately if the body doesn't contain any of `__proto__`, `constructor`, or `"prototype"` as substrings. Only then does it apply the full pattern check. Avoids regex cost on every body.

**Score: 45** (high-impact, broader pattern tier). Justification:
- Prototype pollution can lead to RCE in Node.js apps via `child_process.exec` or unsafe merge functions — same impact ceiling as sqli when exploited.
- Pattern is more permissive than sqli/cmdi (string-match in body, not regex over query params), so slight downgrade from 50.
- Sub-tag emitted on the audit log: `body_abuse:proto_pollution` so operators can grep for this specifically.

**Field tag:** `body_abuse` (existing).

### Plan

Extend `body_abuse.rs` to scan JSON body keys for `__proto__` and `constructor`/`prototype` paths.

```rust
// body_abuse.rs additions:

static PROTO_POLLUTION_KEYS: &[&str] = &[
    "__proto__",
    "constructor",  // when followed by a `prototype` child
    "prototype",
];

fn check_proto_pollution(body: &str, signals: &mut Vec<Signal>) {
    // Cheap pre-filter: any of the dangerous strings appear.
    if !body.contains("__proto__") && !body.contains("constructor")
       && !body.contains("\"prototype\"") {
        return;
    }
    // Confirm shape: `"__proto__":` or `"constructor":{"prototype":`
    // patterns. Pre-filter avoids JSON parsing on every body.
    let lc = body.to_ascii_lowercase();
    if lc.contains("\"__proto__\"") {
        signals.push(Signal {
            score: 45,
            tag: "body_abuse".into(),
            field: "body".into(),
        });
        return;
    }
    if lc.contains("\"constructor\"") && lc.contains("\"prototype\"") {
        signals.push(Signal {
            score: 45,
            tag: "body_abuse".into(),
            field: "body".into(),
        });
    }
}
```

Add a sub-tag `proto_pollution` for audit-log clarity (the QA report lists `body_abuse` aggregating XXE, mass-assignment, etc. — adding proto pollution under the same class keeps the bucket cohesive).

**Tests** (in `body_abuse.rs::tests`):
- Positive: `POST /api/config {"__proto__":{"exec":"id"}}`, `POST {"constructor":{"prototype":{"polluted":"x"}}}`.
- Negative: `{"_proto_":"x"}` (single underscore), `{"item":"__proto__-string"}` (string value, not key), `{"constructor":"NamedClass"}` (constructor as string value, no prototype path).

**Doc:** update `docs/security/detectors/body-abuse.md` with a "Prototype pollution" subsection.

### Acceptance

- [ ] Both QA proto-pollution probes block
- [ ] `_proto_` (single-underscore) and string-value cases don't FP
- [ ] Per-doc subsection added; no new detector class

**Effort:** ~30 min.

---

## Sequencing

Three items, two PRs:

1. `feat(detectors): framework recon paths + prototype pollution (GAP-001 + GAP-010)` — both are extensions to existing detectors, easy to bundle.
2. `feat(detectors): open_redirect class with operator allowlist (GAP-009)` — new detector, separate review.
