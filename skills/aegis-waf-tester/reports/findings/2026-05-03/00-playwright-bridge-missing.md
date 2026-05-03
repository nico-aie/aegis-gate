---
id: 2026-05-03-playwright-bridge-missing
date: 2026-05-03T16:05Z
severity: INFO
area: docs
component: aegis-waf-tester-skill
status: open
build_sha: cb95934
test_mode: smoke
---

# Playwright MCP bridge extension not installed — fall-back to curl-only coverage

## Summary

The first Playwright call (`browser_navigate`) returned `Extension
connection timeout. Make sure the "Playwright MCP Bridge" extension
is installed.` This is a user-side prerequisite, not a WAF bug.
Per `SKILL.md` § anti-patterns ("don't fake browser results"),
the rest of the smoke pass uses curl-only coverage and notes the
gap explicitly.

## Repro

1. Boot WAF: `make run-dev`.
2. Inside Claude Desktop with the `ecc:playwright` plugin
   enabled, ask Claude to navigate the dashboard.
3. Observe: extension-timeout error.

## Expected

Playwright MCP server connects to the local Chrome via the
bridge extension and `browser_navigate` succeeds.

## Actual

```
Error: Extension connection timeout. Make sure the
"Playwright MCP Bridge" extension is installed.
See https://github.com/microsoft/playwright-mcp/blob/main/packages/extension/README.md
```

## Suggested fix

Operator-side, not WAF-side:

1. Install the bridge extension per the linked README.
2. Restart Claude Desktop.
3. Re-run the skill.

## Severity rationale

INFO — not a product bug. But worth tracking because the Skill
is meaningfully degraded without the browser tooling (it covers
~70% of the SOC-UX checklist via curl, but the truly visual
items in `checklists/ux-soc.md` need the browser).

## Done-when

Operator confirms Playwright bridge is wired; next skill run
exercises a real browser.
