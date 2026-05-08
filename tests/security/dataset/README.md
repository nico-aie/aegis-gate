# Aegis-Gate Security Test Dataset

**Version:** 1.0  
**Created:** 2026-05-08  
**Contract:** `EN_waf_interop_contract_v2.3`

## Overview

A reusable, categorized test dataset for end-to-end security validation of Aegis-Gate. Designed to be driven by the in-browser test runner (`run_security_tests.js`) or adapted for any HTTP test framework.

## Files

| File | Purpose |
|---|---|
| `attacks.json` | 57 attack payloads across 8 detector classes with metadata (id, label, method, path, query, headers, body, expected class) |
| `clean_baselines.json` | 33 legitimate traffic cases that MUST NOT be blocked (false-positive corpus) |
| `contract_tests.json` | Control-plane, header, audit-log, and challenge-engine compliance test cases keyed to specific contract sections |
| `README.md` | This file |

## Attack Classes Covered

| Class | Cases | Contract Ref | Acceptable Actions |
|---|---|---|---|
| SQLi | 10 | §3.1 High-confidence injection | block, challenge |
| XSS | 10 | §3.1 High-confidence injection | block, challenge |
| Path Traversal | 8 | §3.1 High-confidence injection | block, challenge |
| SSRF | 8 | §3.1 High-confidence injection | block, challenge |
| Header Injection | 5 | §3.1 High-confidence injection | block, challenge |
| Command Injection | 6 | §3.1 High-confidence injection | block, challenge |
| Recon | 10 | §3.1 Reconnaissance/scanning | block, rate_limit, challenge |
| Body Abuse | 3 | §3.1 Volumetric | block, rate_limit, challenge |

## Clean Baseline Categories

| Category | Cases | Notes |
|---|---|---|
| Static assets | 5 | Root, favicon, JS, CSS, images |
| API endpoints | 6 | GET/POST JSON/form API calls |
| Benign keywords | 9 | Contains security keywords in safe context |
| Browser headers | 4 | Realistic UA headers from Chrome/Firefox/Mobile/curl |

## Contract Test Sections

| Section | Test Cases |
|---|---|
| §2.1–2.3 GET /capabilities | 3 |
| §2.4 POST /reset_state | 4 |
| §2.5 POST /set_profile (all/features/policies) | 6 |
| §2.6 POST /flush_cache | 2 |
| §5 Header compliance (6 headers × 3 response types) | 6 |
| §6 Audit log fields + correlation | 5 |
| Challenge engine PoW verification | 4 |

## Running the Tests

### Via browser (Cowork mode — preferred)

The dataset is consumed by `tests/security/run_security_tests.js` — a self-contained JS test runner designed to be pasted into `mcp__Claude_in_Chrome__javascript_tool` on the data-plane tab (`http://127.0.0.1:8080`).

### Pre-conditions

1. WAF running: `make redis-up && make run-dev` (or `make bench-dev`)
2. Chrome tab open on `http://127.0.0.1:8080`
3. Chrome tab open on `http://127.0.0.1:9443` (admin, logged in)
4. WAF in `enforce` mode (default): verify via `GET /__waf_control/capabilities`

### Interpreting results

Each test case returns a result object:

```json
{
  "id": "sqli-001",
  "label": "Classic UNION SELECT",
  "pass": true,
  "status": 403,
  "action": "block",
  "rule_id": "detector:sqli",
  "risk_score": "25",
  "mode": "enforce",
  "request_id": "550e8400-...",
  "notes": ""
}
```

- `pass: false` → File a finding
- Any `clean_*` case with status 403/429 → CRITICAL false positive

## Extending the Dataset

Add new cases to `attacks.json` under the appropriate class, or create a new class object. Each case MUST have:
- Unique `id` (class-prefix + 3-digit number, e.g. `sqli-011`)
- `label`, `method`, `path`, `notes`
- One of `query`, `body`, or `headers` containing the attack payload

Keep cases **deterministic**: same input must always produce same WAF decision.
