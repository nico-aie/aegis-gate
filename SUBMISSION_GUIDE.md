# Aegis-Gate — WAF Hackathon Submission Guide (v2.5)

> Companion guide per §3 of the candidate briefing. Describes the
> operational workflow of every Round-1 feature so the OC can
> understand design intent, configuration surface, and expected
> behaviour under the v2.5 interop contract.
>
> **Scope:** Round-1 features only. Internal source code is not
> disclosed; this is a black-box workflow guide.

## Deployment shape

Three-host benchmarker topology (per committee 2026-05 brief):

```
[Benchmarker (OC)] ──► [Team WAF host] ──► [Upstream target-app (OC)]
                       (data plane :8080/:8443 public)
                       (admin :9443 + /__waf_control/* loopback-only)
```

- **Data plane** — `0.0.0.0:8080` (plain), `0.0.0.0:8443` (TLS).
  Reachable from the benchmarker host over the network.
- **Admin / dashboard** — `0.0.0.0:9443` in dev, `127.0.0.1:9443`
  in `prod-balanced.yaml`. Hosts the SOC dashboard + admin API.
- **`/__waf_control/*`** — loopback-only on both mounts via a
  peer-IP gate. Benchmarker reaches it via SSH tunnel from
  loopback; `X-Benchmark-Secret: waf-hackathon-2026-ctrl` is the
  shared secret.
- **`/challenge/verify`** — public on the data plane (separate
  from `/__waf_control/*`) so the external benchmarker can POST
  PoW solutions without a tunnel.

Boot procedure for the judging host:

```sh
make build && make stage   # produces ./waf + ./waf.yaml
./waf run                  # reads ./waf.yaml (= prod-balanced.yaml)
```

## Feature workflows

### + Policy/Feature: Blacklist (IP / CIDR / pattern)
- **Description:** Denies access from client identifiers known to
  be malicious or unwanted. Aegis-Gate keys blacklist entries by
  IP, CIDR, and request-attribute pattern.
- **How it works:**
  1. On every request the WAF resolves the client IP (TCP peer
     for audit logging; XFF-resolved IP for risk scoring with an
     empty default trusted-proxy list — distinct source IPs are
     treated as distinct clients).
  2. The resolved IP and selected attributes are matched against
     the blacklist tables loaded from `config/*.yaml` or hot-
     edited via the admin API.
  3. On match the WAF returns `403`, stamps `X-WAF-Action: block`
     with `X-WAF-Rule-Id: blacklist.<entry-id>`, and writes a
     `block` line to `./waf_audit.log`.

### + Policy/Feature: Whitelist (bypass)
- **Description:** Trusted identifiers skip the security pipeline
  (or selected stages thereof).
- **How it works:**
  1. On the same boundary as the blacklist check, the WAF
     consults a whitelist with optional `bypass: all|detectors|
     rate_limit|risk` scopes.
  2. Matching requests short-circuit to the upstream forwarder
     with `X-WAF-Action: allow`, `X-WAF-Rule-Id:
     whitelist.<entry-id>`.
  3. Hot-reload + the same audit trail as blacklist.

### + Policy/Feature: OWASP detectors (rules_engine)
- **Description:** Layered detection for the OWASP Top-10 plus
  Log4Shell, NoSQL injection, template injection, header
  injection, recon scanners. All toggleable per policy via
  `/__waf_control/set_profile`.
- **How it works:**
  1. The request body / headers / URL pass through the
     `SharedDetectorMask`, a per-tier bitmask of which detectors
     are armed (`base` + per-tier override).
  2. Each armed detector returns a score (0..100) and an
     optional `rule_id`. Scores feed the per-request risk
     aggregate.
  3. When the aggregate crosses `block_at`, the WAF returns
     `403` (`X-WAF-Action: block`, the highest-tier rule_id).
     When it crosses `challenge_at`, the WAF returns the PoW
     challenge (see Challenge below).
  4. Detector activation can be flipped at runtime via
     `POST /__waf_control/set_profile` with
     `scope: features|policies` — no restart, no warm-up.

### + Policy/Feature: Rate limit (per_ip)
- **Description:** Token-bucket rate limit per resolved client
  IP with configurable `rps`, `burst`, and route filter.
- **How it works:**
  1. After detector evaluation the request hits
     `IpRateLimiter::consume_with_key(RiskKey { ip, … })`.
  2. If the bucket has no token, the WAF returns `429` with
     `Retry-After`, `X-WAF-Action: rate_limit`,
     `X-WAF-Rule-Id: rate_limit.per_ip`.
  3. Composite-key buckets (IP + session + device-FP) also exist
     for finer granularity; the IP-only bucket is the floor.

### + Policy/Feature: Risk score + strike block (risk_engine)
- **Description:** Tracks per-client risk over a sliding window;
  repeat offenders move from challenge → block automatically.
- **How it works:**
  1. Every detector hit increments the risk score on the
     `RiskKey { ip, device_fp?, session? }` bucket. Three strikes
     within the window puts the bucket in "strike-block" for the
     configured cool-down.
  2. While in strike-block, every request is dropped with
     `X-WAF-Action: block`, `X-WAF-Rule-Id: ip-strikes`.
  3. `POST /__waf_control/reset_state` clears all risk + rate-
     limit + challenge state synchronously (audit log preserved).

### + Policy/Feature: Challenge (proof-of-work)
- **Description:** Self-built PoW challenge per v2.5 §4 Format A.
  No third-party CAPTCHA. Issued when risk crosses
  `challenge_at` but not `block_at`.
- **How it works:**
  1. The WAF returns HTTP `429` with JSON body containing
     `challenge_token` (opaque, packs nonce + difficulty +
     expiry + MAC), `difficulty`, `submit_url:
     /challenge/verify`, `submit_method: POST`.
  2. The benchmarker computes a nonce `n` such that
     `blake3(nonce_internal || ":" || n)` has ≥ `difficulty`
     leading zero bits, then POSTs
     `{"challenge_token": "<echo>", "nonce": "<n>"}` to
     `/challenge/verify` on the data plane.
  3. The WAF verifies MAC, expiry, work, and single-use nonce
     (state-backed). On success → `200 {"ok": true}`. The risk
     bucket is cleared so the original request can proceed.

### + Policy/Feature: DDoS gate (per-TCP-peer-IP)
- **Description:** Coarse pre-pipeline shed under sustained
  spike load. Intentionally keyed on TCP peer IP only — NOT
  composite key — so traffic floods cost O(1) per peer.
- **How it works:**
  1. A background spike detector promotes DDoS mode based on
     `req/s` and `unique-IPs/s` thresholds.
  2. Under spike, every request from a peer over the per-IP
     spike-budget is shed at the accept layer before detectors
     run.
  3. Toggleable via `set_profile` (scope `features`,
     feature_id `ddos`).

### + Policy/Feature: AI detector (anomaly classifier)
- **Description:** ONNX-backed anomaly classifier that scores
  requests on character / token distribution. Adds an
  intelligence-axis score independent of regex detectors.
- **How it works:**
  1. Behind a feature flag (`detectors.ai.enabled`). At runtime
     it computes a single score per request and adds it to the
     risk aggregate.
  2. Like all detectors it can be flipped via `set_profile`,
     and per-tier overrides are honoured.

## Control plane endpoints (§2)

All `/__waf_control/*` endpoints require
`X-Benchmark-Secret: waf-hackathon-2026-ctrl` and are loopback-
gated. Reach them via SSH from the benchmarker host.

| Endpoint | Method | Purpose |
|---|---|---|
| `/__waf_control/healthz` | GET | Startup health probe (no auth) |
| `/__waf_control/capabilities` | GET | Discover features + active state |
| `/__waf_control/reset_state` | POST | Clear runtime risk / rate-limit / challenge state |
| `/__waf_control/set_profile` | POST | Toggle `enforce` / `log_only` per scope |
| `/__waf_control/flush_cache` | POST | Flush cache (no-op when absent) |
| `/challenge/verify` | POST | **Public** — PoW solution submission |

## Audit log (§6)

- Path: `./waf_audit.log` (per `interop.audit_path` in `waf.yaml`).
- Format: JSONL, one entry per request decision.
- Fields: `request_id`, `ts_ms`, `ip` (TCP peer, not XFF),
  `method`, `path` (with query string), `action`, `risk_score`,
  `mode`, optional `rule_id`, `tier`.
- Append-only; `reset_state` does NOT truncate.
- `request_id` matches the `X-WAF-Request-Id` response header.

## Observability headers (§5)

Every response (allow / block / challenge / rate_limit / timeout
/ circuit_breaker) carries all six required headers:

`X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`,
`X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`.

Plus the bonus `X-WAF-Overhead-Latency` for operator dashboards.

## Mode toggle (§5.3)

`set_profile { scope: "all", mode: "log_only" }` flips the WAF
into log-only mode globally:
- Detectors still evaluate and `X-WAF-Action` reports the
  intended decision.
- Requests are NOT blocked — they continue upstream.
- The audit log records the intended action with
  `mode: "log_only"`.

## Smoke tests before judging

```sh
# Capabilities (control plane)
curl -k -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" \
     https://127.0.0.1:9443/__waf_control/capabilities

# Issue + solve a challenge (public path)
# 1. Trigger challenge via repeated SQLi-shaped requests
# 2. Read JSON body for challenge_token + difficulty
# 3. Find nonce n where blake3(internal_nonce:n) has D zero bits
# 4. POST {challenge_token, nonce} to /challenge/verify

# Flip to log-only and verify pass-through
curl -k -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" \
     -d '{"scope":"all","mode":"log_only"}' \
     https://127.0.0.1:9443/__waf_control/set_profile

# Verify audit log shape
tail -1 ./waf_audit.log | jq .
```

## Repository pointers

- `crates/aegis-proxy/` — data plane + admin dispatch.
- `crates/aegis-security/` — detectors + risk + rate limit + PoW.
- `crates/aegis-control/` — admin API, dashboard, interop runtime.
- `crates/aegis-core/` — config, audit bus, primitives.
- `config/profiles/prod-balanced.yaml` — judging-ready config.
- `deploy/STAGING-BENCHMARK.md` — staging topology + tunnel walk-through.
