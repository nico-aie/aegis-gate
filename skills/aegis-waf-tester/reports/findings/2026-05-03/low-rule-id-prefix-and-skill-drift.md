---
id: 2026-05-03-low-rule-id-prefix-and-skill-drift
date: 2026-05-03T17:45Z
severity: LOW
area: docs
component: aegis-waf-tester / SKILL.md
status: fixed
test_mode: full-qc
---

# `X-WAF-Rule-Id` carries a `detector:` prefix the skill says shouldn't be there

## Summary
The skill's Phase 2 section asserts the by-detector chart's names
are "NOT prefixed with 'detector:'". The implementation prefixes
every detector-class hit with `detector:` in the
`X-WAF-Rule-Id` response header AND in `/api/audit/since`'s
`fields.rule_id`:

```
sqli union     status=403 rule=detector:sqli,ssrf
xss script     status=403 rule=detector:xss,ssrf
ptrav          status=403 rule=detector:path_traversal,path_traversal,ssrf
ssrf imds      status=403 rule=detector:ssrf,ssrf
recon env      status=403 rule=detector:ssrf,recon_path
```

The prefix is consistent with how the Top Attackers and Audit
Trail pages render `RULE` cells (e.g. `detector:ssrf`) and how
the dashboard's blacklist hits are tagged (`blacklist`,
`blacklist:qa-test`). So the prefix is *intended* — what's
out of date is the skill's expectation.

Filing as LOW so the skill stays accurate. Two small edits:

1. Update the by-detector phase to expect `detector:` prefix
   on `rule_id` fields.
2. Update the security-regression `probe()` helper's `rule`
   capture so its assertion doesn't reject the prefix.

## Repro
```bash
$ curl -sI -H "X-Forwarded-For: 8.8.8.8" \
    "http://127.0.0.1:8080/?q=<script>alert(1)</script>" | grep -i x-waf-rule-id
x-waf-rule-id: detector:xss,ssrf
```

## Expected
Per the skill: `rule_id` matches its detector class ("`sqli` /
`xss` / `path_traversal` / `ssrf` / `recon`"), no prefix.

## Actual
`rule_id` is prefixed with `detector:` for class hits and
`blacklist` / `blacklist:<id>` for access-list hits.

## Suggested fix
In `skills/aegis-waf-tester/SKILL.md`, Phase 7 `probe()`:

```diff
-  rule=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 8.8.8.8" "$DATA$path" \
-         | grep -i '^x-waf-rule-id:' | awk '{print $2}' | tr -d '\r')
+  rule=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 8.8.8.8" "$DATA$path" \
+         | grep -i '^x-waf-rule-id:' | awk '{print $2}' \
+         | sed 's/^detector://' | tr -d '\r')
```

And in Phase 2:
> the by-detector chart shows real classes (sqli / xss /
> path_traversal / recon), **rendered with `detector:` prefix**
> (e.g. `detector:sqli`), and not truncated.

(Once the by-detector mis-bucketing finding lands, this stops
mattering for the chart — but the skill should still match what
the API actually returns.)

## Severity rationale
LOW. Skill drift, not a server bug. Catches future regressions
because operators will run the skill against the wrong
expectation and file false-positive findings.
