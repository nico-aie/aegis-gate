# Pre-prod feature run — <UTC-date> — <your-name>

**Build / commit:** <git rev-parse HEAD on the deployed nodes>
**Env:** pre-prod cluster · LB 185.23.199.194:56208 · nodes :56243/:56244/:56245
**Upstreams:** 10.20.0.72 (/ws:9992, /grpc:9993, catch-all /:9991 http+ws)
**Browser / MCP:** Chrome <version> · <MCP server name + version>
**Mode:** UI/UX + feature + contract conformance

## Results matrix

| Case | Pass / Fail / Blocked | Severity | Notes |
|---|---|---|---|
| CL-01 |  | High |  |
| CL-02 |  | Critical |  |
| CL-03 |  | High |  |
| CL-04 |  | Critical |  |
| CL-05 |  | High |  |
| CL-06 |  | High |  |
| CL-07 |  | High |  |
| WS-01 |  | Critical |  |
| WS-02 |  | High |  |
| WS-03 |  | High |  |
| WS-04 |  | High/INFO |  |
| WS-05 |  | Medium |  |
| WS-06 |  | High |  |
| MT-01 |  | High |  |
| MT-02 |  | High |  |
| MT-03 |  | High |  |
| MT-04 |  | High |  |
| MT-05 |  | Medium |  |
| MT-06 |  | Medium |  |
| MT-07 |  | High |  |
| CP-01 |  | High |  |
| CP-02 |  | High |  |
| CP-03 |  | Medium |  |
| CP-04 |  | Critical |  |
| CP-05 |  | Medium |  |
| CP-06 |  | High |  |
| CP-07 |  | Medium |  |
| CP-08 |  | Critical |  |

## Contract header spot-checks (§5)

| Probe | X-WAF-Request-Id | Action | Mode | Rule-Id | Risk | Cache | audit match |
|---|---|---|---|---|---|---|---|
| clean `/` |  |  |  |  |  |  |  |
| sqli probe |  |  |  |  |  |  |  |
| blacklisted IP |  |  |  |  |  |  |  |
| WS handshake |  |  |  |  |  |  |  |

## Known limitations confirmed (expected INFO)

- [ ] BUG-WS-2 — AI over-blocks WS frames in enforce; log_only / AI-off workaround OK.
- [ ] BUG-WS-3 — plaintext WS block sends bare TCP close (TLS sends 1008).
- [ ] Copilot off on node(s) without `--features llm` shows clean disabled state.

## Findings

> One block per finding, using the severity ladder in the master plan.
> CRITICAL/HIGH first. Reference the case id + screenshots.

### <severity> — <case id> — <one-line title>
- **Repro:** …
- **Expected:** …
- **Actual:** …
- **Screenshot(s):** …
- **Suggested fix / owner:** …

## End-of-run summary

```
Pre-prod feature run · <date> · <duration>
Cases: <pass>/<total> pass · <fail> fail · <blocked> blocked
Findings: <C> CRITICAL · <H> HIGH · <M> MEDIUM · <L> LOW · <I> INFO
Top blocker: <one line>
Release verdict: ship / hold (<reason>)
```
