# Adversarial Regex Dataset — Aegis-Gate WAF

**Generated:** 2026-05-20  
**Generator script:** `gen_regex_dataset.py` (seed=42)  
**Purpose:** Stress-test the regex detection rules in `crates/aegis-security` — **not** the AI/ONNX detector.  
**Total records:** 300,000 — **15,000 attack + 15,000 normal per detector class × 10 classes**

---

## Files

| File | Records | Label | Expected WAF outcome |
|------|---------|-------|---------------------|
| `evasion_attacks.ndjson` | 150,000 (15,000 × 10 classes) | `"attack"` | `"miss"` — WAF should catch these but may not |
| `fp_candidates.ndjson`   | 150,000 (15,000 × 10 classes) | `"normal"` | `"allow"` — WAF should pass these but may flag them |

---

## Record Schema

Each line is a self-contained JSON object:

```json
{
  "id":                   "ev-12727",
  "label":                "attack",
  "expected_waf_outcome": "miss",
  "detector_class":       "command_injection",
  "technique":            "blind_rce_sleep",
  "method":               "GET",
  "path":                 "/backend/filter",
  "query":                "host=%3Btimeout%2B5%2Becho%2Bok",
  "headers":              {},
  "body":                 "",
  "note":                 "Blind RCE via time-delay: ;timeout+5+echo+ok"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique ID — prefix `ev-` for evasion, `fp-` for FP candidates |
| `label` | `"attack"` \| `"normal"` | Ground-truth label |
| `expected_waf_outcome` | `"miss"` \| `"allow"` | `"miss"` = WAF fails to block a real attack; `"allow"` = WAF correctly allows legitimate traffic |
| `detector_class` | string | Which regex detector this record targets (see table below) |
| `technique` | string | Specific bypass/FP technique used |
| `method` | string | HTTP method (`GET`, `POST`, `PUT`, …) |
| `path` | string | URL path component |
| `query` | string | Raw query string (without leading `?`) |
| `headers` | object | Header name → value pairs (may be empty `{}`) |
| `body` | string | Request body (may be empty) |
| `note` | string | Human-readable explanation of the test case |

---

## Detector Class Coverage

### Evasion Attacks (`evasion_attacks.ndjson`)

Real attack payloads crafted to **bypass** the regex rules in `crates/aegis-security`.

| Detector Class | Count | Key Bypass Techniques |
|---------------|------:|----------------------|
| `sqli` | ~1,891 | Comment-based whitespace (`UNION/**/SELECT`), double URL encoding (`%2527`), hex/CHAR encoding, blind time-based (`WAITFOR`/`SLEEP`), cookie/body vector injection |
| `xss` | ~2,569 | Null-byte injection in `<script>`, tab/comment breaks in event handlers, JS protocol with newlines, data URIs, DOM bracket notation (`window['alert']`), unicode escapes, fromCharCode chains |
| `path_traversal` | ~1,346 | Quadruple dots (`....//`), URL-encoded traversal (`%2e%2e%2f`), null byte extension bypass, UNC path prefix (`\\?\\UNC\\`), `/proc/self/cwd` relative |
| `command_injection` | ~1,738 | IFS variable space substitution (`$IFS`), brace expansion (`{cat,/etc/passwd}`), quote breaking (`c'a't`), blind RCE sleep/timeout, Log4Shell deep nesting (`${${::-j}${::-n}...}`), reverse shell variants |
| `ssrf` | ~1,312 | Decimal IP (`2130706433` = 127.0.0.1), octal IP (`0177.0.0.1`), hex IP (`0x7f000001`), IPv6-mapped (`::ffff:7f00:1`), cloud metadata (AWS/GCP/Azure/DigitalOcean), credential @ trick, open-redirect SSRF chain |
| `recon` | ~2,419 | Case variants (`NIKTO`, `SqlMap`), Docker/K8s API paths (`/api/v1/pods`), Spring actuator/swagger probes, backup file extensions (`.bak`, `.sql`, `.tar.gz`), GraphQL introspection |
| `header_injection` | ~830 | CRLF with %0d%0a, %0a-only line folding, unicode line separator (`%e2%80%a8`), whitespace padding, response splitting for cache poisoning |
| `nosql` | ~1,024 | MongoDB `[$ne]` array bracket encoding, `[$gt]`/`[$regex]` operators, `$where` JavaScript injection, JSON body injection (`{"$ne":null}`), alternate bracket encoding |
| `template_injection` | ~1,102 | Jinja2/Twig config access (`{{config}}`), `__globals__` chain, Spring EL (`${T(java.lang.Runtime)}`), Thymeleaf `__${...}__`, FreeMarker `<#assign>`, Velocity `#set`, Handlebars prototype pollution |
| `open_redirect` | ~769 | Protocol-relative URLs (`//evil.com`), credential @ trick (`https://legit.com@evil.com`), encoded scheme (`htt%70://`), relative escapes (`/%09//`), JavaScript: protocol variants |

### False Positive Candidates (`fp_candidates.ndjson`)

Legitimate HTTP traffic crafted to **trigger false positives** — requests that look like attacks due to keyword overlap, encoding, or ambiguous patterns.

| Detector Class | Count | Key FP Scenarios |
|---------------|------:|-----------------|
| `sqli` | ~2,925 | SQL tutorials/docs URLs, SELECT in blog post titles, database admin UI, ORM query strings, legitimate `order=DESC` params, column/table in JSON API bodies |
| `xss` | ~1,251 | JavaScript course content, security research blog, `onclick` in CSS class names (URL-encoded), `alert()` in testing docs, `document.cookie` in cookie policy pages |
| `path_traversal` | ~2,377 | `..` in CSS relative paths, npm package paths (`../src/utils`), changelog URLs, documentation breadcrumb paths |
| `command_injection` | ~606 | Shell tutorial pages (`/blog/bash-pipes`), DevOps docs, `&&` in boolean JS query, `$(document)` in jQuery docs, math expression `$()` |
| `ssrf` | ~1,076 | `localhost` in development docs, `127.0.0.1` in network config articles, `file://` in browser dev links, health-check endpoints |
| `recon` | ~2,211 | `/admin` dashboard for authenticated users, `.env` in tutorial URLs (`dotenv-package`), WordPress admin panel, `backup` in backup-restore UI, Swagger UI for API docs |
| `header_injection` | ~1,771 | URL-encoded newlines in user-agent display, legitimate Base64 with `%0a`, encoded pipe in search query |
| `nosql` | ~979 | E-commerce filter params (`?price[$lte]=100`), MongoDB blog content, `$ne` in math formula, nested JSON filter body |
| `template_injection` | ~347 | Handlebars/Mustache template syntax in content, `{{` in email template editor, Python f-string in code snippet URLs |
| `open_redirect` | ~1,457 | Protocol-relative CDN URLs (`//cdn.example.com`), legitimate `@` in email params (`?to=user@example.com`), URL in `next=` params pointing to same domain |

---

## How to Use This Dataset

### Manual spot-check
```bash
# View a few evasion attacks targeting SQLi
grep '"sqli"' tests/security/regex_dataset/evasion_attacks.ndjson | head -5 | python3 -m json.tool

# View FP candidates for recon detector
grep '"recon"' tests/security/regex_dataset/fp_candidates.ndjson | head -5 | python3 -m json.tool
```

### Integration test (Rust)
Feed records through `aegis-security` request parsing and apply each detector:

```rust
// Pseudocode
for record in evasion_attacks {
    let result = detector.check(&build_request(&record));
    if result.is_clean() {
        // True miss — evasion succeeded, WAF bypassed
        report_miss(&record);
    }
}

for record in fp_candidates {
    let result = detector.check(&build_request(&record));
    if result.is_blocked() {
        // False positive — legitimate traffic blocked
        report_fp(&record);
    }
}
```

### Python eval script (reference)
```python
import json, pathlib

evasion = [json.loads(l) for l in pathlib.Path("evasion_attacks.ndjson").read_text().splitlines()]
fp_cands = [json.loads(l) for l in pathlib.Path("fp_candidates.ndjson").read_text().splitlines()]

# Group evasion misses by class
from collections import Counter
classes = Counter(r["detector_class"] for r in evasion)
```

---

## Generation Strategy

### Evasion attacks
Each generator targets a specific detector module and applies one or more bypass techniques:

1. **Encoding tricks** — URL-encode, double-encode, hex-encode, unicode-escape critical characters that anchor the regex match.
2. **Whitespace injection** — insert spaces, tabs, SQL comments (`/**/`), or line breaks between keywords.
3. **Alternative syntax** — use equivalent constructs (`CHAR()` instead of string literals, `$IFS` instead of space, brace expansion instead of space-separated args).
4. **Vector shift** — move the payload from the expected field (query string) into headers, cookies, or POST body where the detector may not scan.
5. **Case/encoding variants** — mixed-case keywords that pass case-sensitive patterns, or full-width unicode equivalents.

### False positive candidates
Each generator picks legitimate contexts where the same patterns appear naturally:

1. **Educational content** — URLs for tutorials, blog posts, and documentation about the very attacks the WAF detects.
2. **Legitimate application semantics** — `order=DESC` in sort params, `select` in UI component names, `$` in jQuery/math expressions.
3. **DevOps/admin UIs** — authenticated admin panels, Swagger/OpenAPI docs, monitoring dashboards.
4. **Parameter naming coincidence** — query params like `?format=`, `?template=`, `?redirect=` that overlap with attack keywords.

### Expansion to 15,000 per class
The raw generators produce ~14–292 unique templates per class. To reach exactly 15,000 per class, records are sampled with replacement using a **per-class deterministic seed** derived from SHA-256(`{SEED}-{label}-{class}`), then shuffled within the class. After all classes are assembled the full list is shuffled globally and IDs are re-stamped sequentially (`ev-000001` … `ev-150000` / `fp-000001` … `fp-150000`). Each class is guaranteed to contribute exactly 15,000 records — no class is over- or under-represented.

---

## Relation to Existing Test Data

| Dataset | Location | Purpose |
|---------|----------|---------|
| `attacks_v4.ndjson` | `tests/security/dataset/` | Real-world attack samples for full pipeline testing |
| `evasion_attacks.ndjson` | `tests/security/regex_dataset/` | Adversarial evasion — regex bypass only |
| `fp_candidates.ndjson` | `tests/security/regex_dataset/` | FP stress-test — legitimate traffic that resembles attacks |

---

## Limitations

- Records are **synthetic** — generated from pattern templates, not replayed real traffic.
- The expansion step replicates records to reach 15,000; diversity is limited by the raw generator counts (~600–2,500 unique templates per class).
- Evasion success depends on the exact regex flags (case sensitivity, multiline) in `crates/aegis-security` — some techniques may already be caught by the multi-variant decoder pipeline (S1).
- FP candidates are intentionally constructed to overlap with attack patterns; real FP rates from production traffic may differ.
