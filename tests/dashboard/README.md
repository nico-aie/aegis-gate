# `tests/dashboard/` — Round-1 acceptance harness

Closes track **DD-T8** of `plans/dashboard-redesign.md` by gating the
Aegis WAF Console redesign against the Hackathon WAF-FE v2.3 §2
contract. Pure `curl`/`jq` shell — no Playwright, no Node runtime —
because every requirement that matters is observable on the wire.

## Running

Boot a release `aegis-bin` against any config that exposes the admin
plane (the dev config in `config/waf.dev.yaml` is fine):

```sh
target/release/waf run --config config/waf.dev.yaml &
AEGIS_ADMIN=http://localhost:9443 \
AEGIS_DATA=http://localhost:8080 \
    bash tests/dashboard/round1-acceptance.sh
```

Exit code is `0` only when all eight checks pass.

## What it asserts

| # | Check | Bound | Source of truth |
|---|---|---|---|
| 0 | Shell mounts React 18 root (`id="root"`) | structural | `crates/aegis-control/assets/dashboard/index.html` |
| 0 | CSP for `/dashboard/*` is `script-src 'self'` (no eval, no CDN) | structural | `crates/aegis-control/src/dashboard/security.rs` |
| 0 | `app.js` bundle ≤ 256 KB | bundle budget | `crates/aegis-control/tests/dashboard_polish.rs::app_js_under_per_bundle_budget` |
| 1 | Real-time monitor latency ≤ 5 s | WAF-FE §2 #1 | `/dashboard/sse` round-trip after a probed data-plane request |
| 2 | Hot-reload ≤ 10 s with visible UI indicator | WAF-FE §2 #5 | POST `/api/rules` then poll `/api/config/version` until version advances |
| 3 | Find-audit event ≤ 30 s | WAF-FE §2 #7 | `/api/audit/since?rule_id=…` query latency |
| 4 | CSRF gate enforced on all 4 rule CRUD verbs | security invariant | POST/PUT/DELETE/toggle without cookie → 401/403 |
| 5 | Create-rule UI ≤ 5 clicks | WAF-FE §2 #6 | NewRuleModal markers in compiled bundle |

Each check prints `PASS:` or `FAIL:` with the measured value and
contract bound. The summary line at the end totals the two counts.

## Why this is a shell script and not Playwright

- The two timing requirements (#1, #2) are wire-observable. Adding
  a headless browser only makes them noisier.
- The "≤ 5 clicks" requirement (#5) is a design property — the
  modal exposes the three actionables (button, fields, save), and
  asserting the markers are in the compiled bundle is what
  prevents future regressions.
- Pure `curl`/`jq` keeps the harness usable from the same image
  that runs `tests/cluster/`, no extra dependencies.

## Next runs

The script is meant to be re-run after every dashboard change. A
green pass is what closes DD-T8; the result lands in
`tests/results/run-NN-…/README.md` alongside the existing perf and
cluster harnesses.
