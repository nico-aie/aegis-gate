# Hackathon Round-1 Stress Test — Preparation

> **Status:** Prep. Harness scaffolded; awaiting benchmark team's
> finalized upstream + traffic mix.

## 0 · Brief from the benchmark team

- **Target app:** matches `Hackathon_Doc/openapi.public.yaml`
  (login + OTP → sid cookie, then 26 financial / gaming
  endpoints).
- **Traffic shape:** mixed benign + hacker-class. Hacker
  requests probe SQLi / XSS / path traversal / IDOR /
  brute force / SSRF / mass assignment.
- **Duration:** 15 minutes.
- **Headline metrics:**
  1. **p99 latency** on the allow path (legit user).
  2. **Detected** count — the WAF saw the attack
     (`x-waf-action ∈ {block, challenge, rate_limit}`).
  3. **Prevented** count — the WAF actually stopped the
     attack reaching the upstream (status 403 / 429 / 401
     depending on detector).

## 1 · What this prep delivers

| Deliverable | Path | Status |
|---|---|---|
| Plan + runbook | `plans/hackathon-stress-test.md` | this doc |
| Mock upstream (matches OpenAPI) | `tests/hackathon/upstream/server.py` | scaffold |
| k6 mixed-traffic script | `tests/hackathon/k6/mixed-15min.js` | scaffold |
| WAF benchmark config | `tests/hackathon/configs/bench.yaml` | scaffold |
| 15-min orchestrator | `tests/hackathon/run.sh` | scaffold |
| Post-run summary | `tests/hackathon/summary.sh` | scaffold |

## 2 · Mock upstream — design

`tests/hackathon/upstream/server.py` (Python 3.10+, no deps)
serves every path in `openapi.public.yaml`. Each endpoint:

- Validates `sid` cookie (fixed map: `sid-alice` → alice, …).
- Returns canned JSON shaped per the OpenAPI schema.
- Adds 1–5 ms of synthetic latency (uniform jitter) to
  emulate a real DB lookup.
- Logs nothing on the hot path — perf hygiene.

Why Python: the previous Python `BaseHTTPServer` topped out
at ~2 k RPS as a single thread under 200 VUs, **but** with
`socketserver.ThreadingMixIn` + a fast in-memory store
the canned-response variant comfortably sustains 8–10 k RPS
on a laptop, which is enough headroom that the p99 we
measure is the WAF's, not the upstream's. If the benchmark
team's real upstream is faster (Go / Rust / Node), great —
the rest of the harness is upstream-agnostic.

> **Knob:** `UPSTREAM_BIN` env var lets the run script swap
> the mock for the team's real upstream binary.

## 3 · Traffic mix — design

`tests/hackathon/k6/mixed-15min.js` runs three scenarios in
parallel for 15 minutes:

| Scenario | VUs | Behaviour | Expected |
|---|---|---|---|
| `legit_users` | 80 | login → otp → browse → bet → withdraw | 200 / 201 |
| `crawlers` | 20 | static + sitemap + public stats | 200 |
| `attackers` | 30 | one attack per iteration, picked from the corpus | block / challenge / rate_limit |

Attack corpus (selected probes, full list inline in the JS):

- **SQLi** in `/login` body, `/api/transactions?id=`, `/game/{id}`
- **XSS** in `/api/feedback` body, `/api/profile` body
- **Path traversal** in `/static/{path}`, `/public/{file}`
- **IDOR** — log in as alice, attempt `/api/transactions?user=bob`
- **Brute force** — 50 fast hits on `/login` with rotating bad creds
- **SSRF** — `/api/feedback` body with a `url` field pointing at
  `http://169.254.169.254/latest/meta-data` and `file://etc/passwd`
- **Mass assignment** — `/api/profile` PATCH with `{"role":"admin"}`
- **Header injection / smuggling** probes on `/login`

k6 records two custom metrics:

- `legit_p99_ms` — only counts `legit_users` iterations
- `attacks_detected` — counts iterations where the WAF
  responded with `x-waf-action ∈ {block, challenge,
  rate_limit}`

Both are exported to `summary-export` for the post-run
report.

## 4 · WAF config — design

`tests/hackathon/configs/bench.yaml` derives from
`config/dev.yaml` with three changes:

- `risk.thresholds.block_at: 80` (so the legit scenarios
  that share a single source IP don't trip risk-strikes)
- `rate_limit.buckets[0].limit: 100000`,
  `window: "1s"` (loose enough that 100 VUs from one IP
  isn't itself a DoS signal)
- `audit.sinks` includes both jsonl + interop minimal
  (so the post-run summary can correlate)

> **Note:** when the benchmark team specifies their own
> source IP / VU count, we'll re-tune `block_at` and the
> bucket limit to match. The pure-WAF perf doesn't depend
> on these.

## 5 · 15-min orchestrator

`tests/hackathon/run.sh`:

1. Sanity check: cargo build --release -p aegis-bin succeeded.
2. Boot upstream (`UPSTREAM_BIN` or the bundled mock).
3. Boot WAF (`AEGIS_BIN` or `target/release/waf`) on the
   benchmark config.
4. Wait for `/healthz/ready = 200`.
5. Capture **before** stats: `/api/stats`,
   `/api/attacks/distribution`, audit log line count.
6. Run k6 for `DURATION=15m`.
7. Capture **after** stats.
8. Stop WAF, stop upstream.
9. Run `summary.sh` → human-readable report.

The whole thing is 16 minutes wall-clock (1 min for boot +
15 min run + a few seconds for shutdown + summary).

## 6 · Summary report

`tests/hackathon/summary.sh` reads:

- k6's `summary-export` JSON
- `/api/stats` before vs after
- `/api/attacks/distribution` after
- `waf_audit.log` line count delta

And produces a single Markdown file:

```
# Round-1 stress test — <timestamp>

## Headline
- Legit p99 latency: ___ ms (target ≤ ___ ms)
- Detected attacks: ___ / ___ (___%)
- Prevented attacks: ___ / ___ (___%)
- WAF binary CPU avg: ___% (sampled every 10s via top)

## Per-detector breakdown
| Detector | Hits |
|---|---|
| sqli | ___ |
| xss | ___ |
| path_traversal | ___ |
| ...

## p99 by scenario
| Scenario | p99 ms |
| legit_users | ___ |
| crawlers | ___ |
| attackers | ___ (expected high — they're being blocked)

## Anomalies
(any scenario that breached its threshold gets called out)
```

## 7 · Run command

```sh
# Default: 15 min, mock upstream, dev-bench config
bash tests/hackathon/run.sh

# Custom: real team upstream + custom duration
UPSTREAM_BIN=/path/to/team-upstream \
  DURATION=15m \
  bash tests/hackathon/run.sh
```

Output lands in `tests/hackathon/results/run-<ts>/` with:

- `summary.md` — the headline report
- `k6.json` — raw k6 export
- `waf-stats-before.json`, `waf-stats-after.json`
- `audit-delta.jsonl` — new audit lines during the run
- `server.log`, `upstream.log` — for post-mortem

## 8 · Open questions for the benchmark team

1. **Source IP shape:** do attacker requests come from a
   different source than legit users? Today the harness
   assumes both come from `127.0.0.1` (laptop). If the
   real benchmark fan-outs from many IPs, the harness will
   need to rotate `X-Forwarded-For` / use a fan-out runner.
2. **Attack labelling:** does the team count "detected" by
   the WAF's response header, or by their own ground-truth
   labels of "this iteration was an attack"? The harness
   exports both — we'll align with whichever they use.
3. **Latency target:** dedicated host targets are p99 ≤ 5 ms
   (we hold this on a clean baseline). Under attack-mix
   load with 130 VUs the realistic laptop target is
   p99 ≤ 50 ms. What's the team's bar?
4. **Allowlist for legit traffic:** can we use mTLS-bypass
   for the `legit_users` scenario so risk-strikes never
   downgrade a legit account? If yes, the harness uses the
   MTLS-T7 SAN allowlist we just shipped; if no, we fall
   back to broad rate-limit headroom.
