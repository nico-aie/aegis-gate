# Aegis-Gate WAF — Detector Evaluation Report

| | |
|---|---|
| **Date** | 2026-05-22 17:56 |
| **WAF endpoint** | `https://waf.hk-aegis-gate.com:443` |
| **Dataset** | `tests/security/regex_dataset/` |
| **Sample per class** | 100 |
| **Local detector** | ✅ ran |
| **Live WAF** | ✅ ran |
| **Total elapsed** | 12.5s |

> **Class-name mapping**: dataset field `detector_class="nosql"` maps to
> Rust detector id `"nosql_injection"` (confirmed from `nosql_injection.rs`).

---
## Executive Summary

### Evasion Attacks

| Mode | Hit | Miss | Valid | Hit Rate | Target | Grade |
|---|---:|---:|---:|---:|---:|---|
| Local detector (regex port) | 874 | 126 | 1,000 | **87.4%** | ≥70% | 🟡 OK |
| Live WAF `https://waf.hk-aegis-gate.com` | 9 | 926 | 935 | **1.0%** | ≥90% | 🔴 POOR |

### FP Candidates

| Mode | FP | TN | Valid | FPR | Target | Grade |
|---|---:|---:|---:|---:|---:|---|
| Local detector (regex port) | 262 | 738 | 1,000 | **26.2%** | ≤5% | 🔴 HIGH |
| Live WAF `https://waf.hk-aegis-gate.com` | 0 | 988 | 988 | **0.0%** | ≤1% | 🟢 GOOD |

---
## Evasion Attack Detection — Per Detector Class

> **Local hit** = Python port of Rust regex catches the payload.  
> **WAF hit**   = live WAF returns 4xx.  
> Classes sorted by WAF hit rate ascending (worst first).

| Detector Class | Total | Loc-Hit | Loc-Miss | Loc-Rate | WAF-Hit | WAF-Miss | WAF-Rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| `open_redirect` | 100 | 67 | 33 | **67.0%** | 0 | 100 | **0.0%** |
| `template_injection` | 100 | 84 | 16 | **84.0%** | 0 | 100 | **0.0%** |
| `path_traversal` | 100 | 96 | 4 | **96.0%** | 0 | 100 | **0.0%** |
| `sqli` | 100 | 91 | 9 | **91.0%** | 0 | 99 | **0.0%** |
| `recon` | 100 | 86 | 14 | **86.0%** | 0 | 100 | **0.0%** |
| `nosql_injection` | 100 | 96 | 4 | **96.0%** | 0 | 100 | **0.0%** |
| `ssrf` | 100 | 86 | 14 | **86.0%** | 0 | 100 | **0.0%** |
| `xss` | 100 | 96 | 4 | **96.0%** | 0 | 100 | **0.0%** |
| `command_injection` | 100 | 72 | 28 | **72.0%** | 4 | 96 | **4.0%** |
| `header_injection` | 100 | 100 | 0 | **100.0%** | 5 | 31 | **13.9%** |

### Top Evasion Techniques (most misses)

**`open_redirect`**

| Technique | Loc-Hit | Loc-Miss | WAF-Hit | WAF-Miss |
|---|---:|---:|---:|---:|
| `protocol_relative` | 42 | 0 | 0 | 42 |
| `encoded_scheme` | 7 | 17 | 0 | 24 |
| `at_credential_trick` | 18 | 5 | 0 | 23 |
| `relative_escape` | 0 | 11 | 0 | 11 |

**`template_injection`**

| Technique | Loc-Hit | Loc-Miss | WAF-Hit | WAF-Miss |
|---|---:|---:|---:|---:|
| `spring_spel_thymeleaf` | 26 | 13 | 0 | 39 |
| `jinja2_twig` | 32 | 3 | 0 | 35 |
| `freemarker_velocity` | 16 | 0 | 0 | 16 |
| `handlebars_mustache` | 10 | 0 | 0 | 10 |

**`path_traversal`**

| Technique | Loc-Hit | Loc-Miss | WAF-Hit | WAF-Miss |
|---|---:|---:|---:|---:|
| `triple_dot_slash` | 26 | 0 | 0 | 26 |
| `path_segment` | 24 | 0 | 0 | 24 |
| `proc_dev_path` | 21 | 0 | 0 | 21 |
| `null_byte_extension` | 10 | 0 | 0 | 10 |
| `unc_path` | 3 | 4 | 0 | 7 |
| `overlong_utf8` | 5 | 0 | 0 | 5 |

**`recon`**

| Technique | Loc-Hit | Loc-Miss | WAF-Hit | WAF-Miss |
|---|---:|---:|---:|---:|
| `backup_file_probe` | 31 | 2 | 0 | 33 |
| `actuator_swagger` | 15 | 0 | 0 | 15 |
| `container_api` | 11 | 1 | 0 | 12 |
| `administrator_case` | 7 | 0 | 0 | 7 |
| `graphql_introspection` | 0 | 7 | 0 | 7 |
| `wp_admin_case` | 6 | 0 | 0 | 6 |

**`nosql_injection`**

| Technique | Loc-Hit | Loc-Miss | WAF-Hit | WAF-Miss |
|---|---:|---:|---:|---:|
| `json_body_operator` | 25 | 0 | 0 | 25 |
| `json_regex` | 8 | 0 | 0 | 8 |
| `regex_operator` | 8 | 0 | 0 | 8 |
| `partial_encode` | 7 | 0 | 0 | 7 |
| `where_func` | 6 | 0 | 0 | 6 |
| `json_gt` | 6 | 0 | 0 | 6 |

---
## False Positive Rate — Per Detector Class

| Detector Class | Total | Loc-FP | Loc-TN | Loc-FPR | WAF-FP | WAF-TN | WAF-FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ssrf` | 100 | 3 | 97 | **3.0%** | 0 | 100 | **0.0%** |
| `nosql_injection` | 100 | 2 | 98 | **2.0%** | 0 | 100 | **0.0%** |
| `xss` | 100 | 83 | 17 | **83.0%** | 0 | 100 | **0.0%** |
| `recon` | 100 | 56 | 44 | **56.0%** | 0 | 96 | **0.0%** |
| `command_injection` | 100 | 35 | 65 | **35.0%** | 0 | 100 | **0.0%** |
| `header_injection` | 100 | 22 | 78 | **22.0%** | 0 | 100 | **0.0%** |
| `open_redirect` | 100 | 24 | 76 | **24.0%** | 0 | 100 | **0.0%** |
| `template_injection` | 100 | 20 | 80 | **20.0%** | 0 | 93 | **0.0%** |
| `path_traversal` | 100 | 8 | 92 | **8.0%** | 0 | 100 | **0.0%** |
| `sqli` | 100 | 9 | 91 | **9.0%** | 0 | 99 | **0.0%** |

---
## Detector Source Reference

Patterns ported exactly from `crates/aegis-security/src/detectors/`.

| Class | Rust File | Score | Scan Surface |
|---|---|---:|---|
| `sqli` | `sqli.rs` | 70 | URI variants, body variants, headers: cookie / referer / x-forwarded-for / user-agent |
| `xss` | `xss.rs` | 70 | URI (url+entity decode), body, headers: cookie / referer / user-agent |
| `path_traversal` | `path_traversal.rs` | 70 | URI variants, body variants |
| `command_injection` | `command_injection.rs` | 70 | URI variants, body variants, headers: UA / referer / x-api-version / x-forwarded-for / x-real-ip / auth / cookie / x-requested-with. Log4Shell → score 90 |
| `ssrf` | `ssrf.rs` | 70 | query (decoded), path (decoded), body (decoded), headers: x-original-url / x-rewrite-url. NOT full URI (self-trip risk) |
| `recon` | `recon.rs` | 25 | path_and_query (RECON_PATHS score 25), user-agent (RECON_UA score 50) |
| `header_injection` | `header_injection.rs` | 70 | query raw+decoded (CRLF), all header values (CRLF), XFH poisoning, URL-override headers, method-override headers |
| `nosql_injection` | `nosql_injection.rs` | 70 | URI raw+decoded, body raw+decoded. **Dataset field = 'nosql'** |
| `template_injection` | `template_injection.rs` | 70 | URI raw+decoded, body raw+decoded |
| `open_redirect` | `open_redirect.rs` | 50 | Query-string redirect params only (next/url/redirect/return/goto/…). Evasion shapes always flag; bare https:// does NOT flag with empty allowlist |

---
*Generated by `tests/ml-model/eval_hit_waf_test_set.py` — 2026-05-22 17:56*
