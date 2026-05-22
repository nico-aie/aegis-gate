# Post run-08 — Three short tracks (closed)

> **Status:** Closed — AF-T1, HP-T1, TLS-T1 all shipped before
> the dashboard redesign track. Reference only.
>
> See [`README.md`](../README.md) for the track status board.

After run-08 closed the Round-2 self-gate, three small items
remained before pivoting to the dashboard redesign track. None
overlap; all three landed in one working session.

| ID | Track | Effort | Why |
|---|---|---|---|
| **AF-T1** | Action-class fidelity in `stamp_interop_response` | ~1 hr | DR-T6 surfaced: `challenge` body + 429 status currently maps to `rate_limit`. Plumbing the real decision through tightens contract attribution and unlocks the `challenge_unsolvable` lifecycle test. |
| **HP-T1** | Upstream HTTPS connection pool | ~3 hr | UP-T1 covers HTTP only; `upstream/tls.rs` still does per-request connect for HTTPS upstreams. Wire the pooled `Client` to a rustls connector — production-relevant, doesn't move the contract gate. |
| **TLS-T1** | Clean-host TLS handshake re-measure | ~30 min | Run-05 noise warning (`tls_handshake_ms` p95 9.08 ms vs run-04's 2.12 ms). One fresh measurement clears the question. |

**Out of scope** for this plan, per latest direction:

- Linux NUMA re-measure — long-term, needs different hardware.
- B6-T1 production Dockerfile — long-term packaging work.
- Multi-process workers (`SO_REUSEPORT`) — speculative without
  profiling evidence; revisit only if a future bottleneck
  proves the multi-thread runtime can't saturate cores.

**After these three close, the next track is the dashboard
redesign** — that gets its own plan when we start.

## AF-T1 — Action-class fidelity

**Approach.** Change `handle_data_request` to return both the
response and a `DecisionTag { action, rule_id }`. The
`stamp_interop_response` post-processor reads the tag instead
of inferring from HTTP status. Every existing `return` in the
function gains a partner tag.

**Mapping.**

| Branch | `Action` | `rule_id` |
|---|---|---|
| Strike-block | `Block` | `Some("risk-strikes")` |
| Per-IP rate limit | `RateLimit` | `Some("ip-rate-limit")` |
| Detector block | `Block` | `Some("detector:<tags>")` |
| Risk-score block | `Block` | `Some("risk-score")` |
| Risk-score challenge | `Challenge` | `Some("risk-challenge")` |
| Allow → upstream 2xx/3xx | `Allow` | `None` |
| Allow → upstream 502 (connect/handshake/send) | `Block` (current) → keep, but flag for follow-up; really should be `CircuitBreaker` if breaker is open, else `Timeout` | matches `forward::ForwardError` variant |
| Allow → upstream 503 | `CircuitBreaker` | `None` |
| Allow → upstream 504 | `Timeout` | `None` |
| Allow → 404 no-route | `Block` | `Some("no-route")` |

**Tests.** Three new shell checks added to DR-T1 (or a new
DR-T6 follow-up):

- A challenge-eligible client (high risk) gets `X-WAF-Action: challenge` not `rate_limit`.
- A rate-limited client gets `X-WAF-Action: rate_limit`.
- A normal client gets `X-WAF-Action: allow`.

## HP-T1 — Upstream HTTPS pool

**Approach.** Today `forward()` uses `Client<HttpConnector, ...>`
which only speaks plaintext to upstreams. For HTTPS upstreams,
swap in `Client<HttpsConnector<HttpConnector>, ...>`.

The connector cache becomes keyed on `(PoolKey, scheme)` so
HTTP and HTTPS members of different pools share neither idle
conn pool nor TLS session cache.

**Risks.**

| Severity | Risk | Mitigation |
|---|---|---|
| MEDIUM | `hyper-rustls` crate isn't on the dep list yet | Add it; the existing rustls features cover the cipher set |
| MEDIUM | Per-host TLS session cache vs upstream rotation | hyper-rustls provides session resumption out of the box |
| LOW | HTTPS connector exposes a different connect-error shape | Map to `ForwardError::Connect` same as HTTP |

**Tests.** Two new unit tests in `forward.rs`:

- `https_upstream_uses_pooled_tls` — two requests to an HTTPS
  upstream → 1 TCP + 1 TLS handshake.
- `mixed_http_and_https_pools_dont_share_clients` — pools
  pointing at HTTP vs HTTPS get distinct cached `Client`s.

## TLS-T1 — Clean-host TLS re-measure

**Approach.** Reboot-fresh re-run of `tests/load/tls-baseline.js`
against `config/prod.yaml`. Compare:

- run-04: handshake p95 2.12 ms (good baseline)
- run-05: handshake p95 9.08 ms (suspicious)
- TLS-T1: ?

If TLS-T1 lands near run-04, the run-05 number was host noise
and we close the carry-over. If it lands near run-05, we have a
real regression to chase.

Output goes into `tests/results/run-09-2026-04-30-tls-recheck/`.

## Done definition

- AF-T1: workspace tests pass with the new return type;
  DR-T1..T5 still all green; one new test asserts `challenge`
  reports as `challenge` not `rate_limit`.
- HP-T1: workspace tests pass; two new pool tests for HTTPS;
  live smoke against an HTTPS upstream succeeds.
- TLS-T1: run-09 README captures the fresh number + verdict
  on the run-05 noise warning.
- `Implement-Progress.md` updated with each track's outcome.
- Open queue cleared down to "dashboard redesign" only.
