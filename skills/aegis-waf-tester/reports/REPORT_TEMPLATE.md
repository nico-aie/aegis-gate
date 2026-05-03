---
id: <YYYY-MM-DD>-<short-slug>
date: <YYYY-MM-DDTHH:MMZ>
severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
area: dashboard | data-plane | admin-api | docs | perf | security
component: <e.g. live-feed, blacklist, websocket-bridge>
status: open
build_sha: <git rev-parse HEAD>
test_mode: smoke | functional | full-qc
---

# <Short, descriptive title>

## Summary

One paragraph. What's broken (or surprising), where, and why it
matters to a SOC operator.

## Repro

Numbered, copy-pasteable steps. Include exact commands. Include
the env so the dev can reproduce on their box.

```bash
# 1. boot a clean dev WAF
make run-dev

# 2. drive this exact request
curl -i -H "X-Forwarded-For: 8.8.8.8" http://127.0.0.1:8080/

# 3. observe ...
```

## Expected

What a SOC operator would expect. Tie back to docs / spec /
common sense.

## Actual

What happened. Paste exact output. Trim long output to the
relevant lines.

```text
HTTP/1.1 502 Bad Gateway
x-waf-rule-id: <unexpected>
```

## Evidence

- Screenshot: `<relative path>` (drop into the same folder as
  this finding).
- Log excerpt: `<relative path>`
- Audit chain entries: `<inline JSON or path>`
- Browser console errors: `<inline>`
- Metrics scrape: `<inline diff>`

## Suggested fix

One paragraph. The dev does the implementation; you point at
the likely surface. Include a file path + line range when you
can.

> Example: "Suspect data_plane.rs:212 — the blacklist matcher
> hits `peer_ip` but the connection is terminated by a trusted
> proxy so `peer_ip` is the proxy. Consider running the matcher
> after XFF resolution (which already happens at line 198)."

## Severity rationale

Why this severity? "Blocks login → CRITICAL" / "UI label wrong
but functionality intact → LOW". Be specific.

## Notes for the dev

Anything else: related bugs, why this might be intentional, edge
cases the fix should also cover.

## Done-when

What signal closes this finding? (e.g. "the regression test in
tests/api/foo.sh passes against `make run-dev`").
