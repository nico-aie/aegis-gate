---
id: 2026-05-03-high-by-detector-chart-mis-bucketed
date: 2026-05-03T17:38Z
severity: HIGH
area: admin-api
component: /api/attacks/by-detector + Attack distribution donut
status: fixed
test_mode: full-qc
---

# `/api/attacks/by-detector` buckets by combination string, not by class

## Summary
`/api/attacks/by-detector` returns one row per *unique combination
of detector tags* on a request, instead of one row per detector
class. After 60 attack probes (10 each of sqli / xss / ptrav /
recon, plus 30 legit GETs that the broken SSRF detector also
caught), the API emits eight rows:

```json
[
  {"name":"ssrf",                                    "count":52},
  {"name":"path_traversal",                          "count":10},
  {"name":"path_traversal,path_traversal,ssrf",      "count":10},
  {"name":"sqli",                                    "count":10},
  {"name":"sqli,ssrf",                               "count":10},
  {"name":"ssrf,recon_path",                         "count":10},
  {"name":"xss",                                     "count":10},
  {"name":"xss,ssrf",                                "count":10}
]
```

The dashboard renders this verbatim in the Overview "Attack
distribution" donut, so the legend reads `ssrf · 59`, `sqli ·
12`, `sqli,ssrf · 12`, `ssrf,recon_path · 12`. A SOC operator
reading that donut cannot answer "how many SQLi attacks did I
see today?" — `sqli` is in two buckets, `xss` in two, etc.

There are also two secondary issues visible in the same response:

1. **`path_traversal` is listed twice** in the row
   `path_traversal,path_traversal,ssrf`. The detector tag list
   isn't deduped before the combo string is built.
2. **`window_seconds` is hard-clamped at 900.** Both
   `?window=300` and `?window=3600` come back with
   `"window_seconds": 900`. Either the parameter is silently
   ignored or there's a server-side max that isn't documented.

## Repro
```bash
# Drive a few probes
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "http://127.0.0.1:8080/?q=<script>alert(1)</script>"
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "http://127.0.0.1:8080/files?p=../../../../etc/passwd"
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "http://127.0.0.1:8080/.env"
done

# Inspect via the admin (signed-in cookies in $JAR)
curl -s -b $JAR "http://127.0.0.1:9443/api/attacks/by-detector?window=3600" | jq .
# -> .detectors[] each with a comma-joined "name" and a window_seconds
#    pinned at 900 regardless of the requested window.
```

Also the Overview "Attack distribution" donut shows the same
broken legend.

## Expected
- One row per detector class (sqli, xss, path_traversal,
  ssrf, recon_path, …), counts summed across all combinations.
- Detector tag list inside each event de-duplicated before
  any aggregation.
- `?window=` honoured (or, if there's a server-side cap,
  documented and the response should report the *requested*
  window plus a clamp note).

## Actual
- One row per *combination* of tags, with multiple rows per
  detector class.
- Tag list contains duplicates (`path_traversal,path_traversal`).
- `window_seconds` always 900.

## Suggested fix
In whatever layer renders `/api/attacks/by-detector` (probably
`crates/aegis-control/src/api/attacks.rs`):

1. When iterating audit events, expand `event.detectors[]` into
   one row per tag, then aggregate, instead of joining with `,`
   and using the joined string as the bucket key.
2. De-dup `event.detectors[]` either at write-time in the data
   plane (preferable — it'd fix the duplicate `path_traversal`
   in `X-WAF-Rule-Id` too) or at read-time before aggregation.
3. Either honour `?window=` up to a reasonable cap (e.g. 24h)
   or echo `requested_window_seconds` separately from the
   clamped `window_seconds` so callers can tell.

## Severity rationale
HIGH. The Attack-distribution donut on Overview is a primary
Phase 1 SOC visualisation; today it lies. Not CRITICAL because
the underlying audit data is correct (`/api/audit/since` shows
correct per-event tags), so the fix is one aggregation function;
the data isn't lost.
