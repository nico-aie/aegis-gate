---
id: 2026-05-17-audit-path-missing-query-string
date: 2026-05-17T00:00Z
severity: HIGH
area: data-plane · audit
component: crates/aegis-proxy/src/accept.rs (per-request `path` capture)
interop_contract: v2.3 §6 ("Request path bao gồm query string")
status: open
test_mode: source-review
---

# F-HIGH-001 · Audit-log `path` field strips query string — uses `.path()` instead of `.path_and_query()`

## Summary

The per-request capture site builds the audit-log `path` field from
`req.uri().path()`, which discards the query string. §6 of the v2.3
contract specifies the `path` field as "Request path bao gồm query
string" (path INCLUDING query). The OC harness relies on this for
correlation, replay, and false-positive analysis of payloads delivered
via `?q=...`.

This bug is silent: the WAF still blocks SQLi/XSS/SSRF probes
delivered via query parameters correctly (the detectors see the full
URI), but the audit-log entry that records the decision loses the
query. Post-run inspection of the chain cannot reconstruct what the
attacker sent.

## Observed code path

`crates/aegis-proxy/src/accept.rs:1089`:

```rust
let path = req.uri().path().to_string();
```

This value flows into `handle_data_request` and ultimately into the
audit-log emit at `admin_dispatch.rs:~1064`, where it is written
as the `path` field of each JSONL entry.

The control-endpoint check just below (line 1097) also uses this
truncated `path`, but that's fine because `/__waf_control/...` never
carries a meaningful query.

## Repro

```sh
HOST="http://127.0.0.1:8080"
curl -sk "$HOST/search?q=1%27%20OR%20%271%27%3D%271" >/dev/null
tail -1 ./waf_audit.log | jq .path
# → "/search"          (BUG — should be "/search?q=1' OR '1'='1")
```

## Impact

- §6 contract field "Request path including query string" violated
  on every request that uses a query string. The OC harness will
  see correct headers + correct action but a truncated path in the
  chain, breaking any correlation that pivots on path.
- Forensic value of the audit log drops significantly — every SQLi
  / XSS / SSRF probe loses its payload at the audit layer (the
  detector hits are still in `fields.detectors`, but the request
  payload itself is gone).
- Dashboards / SIEM consumers that filter by path-with-query break.

## Suggested fix

`crates/aegis-proxy/src/accept.rs:1089`:

```diff
-let path = req.uri().path().to_string();
+let path = req
+    .uri()
+    .path_and_query()
+    .map(|p| p.as_str().to_string())
+    .unwrap_or_else(|| req.uri().path().to_string());
```

The fallback to `.path()` handles the (impossible-in-practice for
HTTP/1.1+) case where `path_and_query()` is `None`.

If the `/__waf_control/` startswith check at line 1097 needs to use
the bare path (to avoid `/__waf_control/foo?bar=baz` mismatching),
introduce a separate `path_only` local for that check and keep
`path` (with query) for the audit emit.

```rust
let path_and_query = req
    .uri()
    .path_and_query()
    .map(|p| p.as_str().to_string())
    .unwrap_or_else(|| "/".to_string());
let path_only = req.uri().path().to_string();
// ...
if path_only.starts_with("/__waf_control/") { ... }
// audit uses path_and_query
```

## Verification

After the fix, the repro above should print:

```
"/search?q=1' OR '1'='1"
```

Add a regression case in `tests/contract/`:

```sh
curl -sk "$HOST/x?y=z" >/dev/null
tail -1 ./waf_audit.log | jq -e '.path == "/x?y=z"'
```

## Severity rationale

HIGH. Contract violation on every query-bearing request (which is
most of them). Not CRITICAL because detectors still fire correctly
and headers still ship — the chain is degraded, not absent.
