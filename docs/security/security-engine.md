# How the Security Engine Works

> **Audience.** Anyone — operator, QC tester, or engineer onboarding —
> who wants the whole picture in one read: how a request becomes
> allowed / blocked / scored, where every gate sits, what the risk
> number means, and where to look when something doesn't behave the
> way you expected.
>
> **Status.** Implemented (`crates/aegis-security/`). For source-of-truth
> tests of each gate see [`docs/FEATURES.md`](../FEATURES.md). For the
> system-wide architecture context see [`Architecture.md`](../../Architecture.md)
> §4 (Request Lifecycle) and §5 (Security Pipeline).

> **2026-05-19 — composite-key migration.** Where this page says
> "per-IP" for the Strike-Block gate, Cumulative IP risk score,
> or Rate Limit, read it as **"per-`RiskKey { ip, device_fp?, session? }`
> bucket"**. Two browsers on the same NAT'd IP each carry their own
> bucket. **DDoS Gate stays per-IP by design** — volumetric protection
> must fire fast regardless of session. The "Cumulative IP risk
> thresholds" *card name* on the dashboard is preserved for operator
> memory; the underlying counter is per-bucket.

---

## TL;DR — one paragraph

Every request is **routed first** (host + path + method), then runs
through a **fixed pipeline** of gates. Each gate either short-circuits
the request (block / 403, redirect to challenge, return 429) or adds
a **score** to the request's running risk total. After all gates run,
the WAF compares the total to the route's **tier risk threshold** —
above the line it blocks, otherwise it forwards to the upstream pool.
Independently, every detector hit also accrues to a **per-bucket strike
score** that decays exponentially — a client that's been bad recently
can be blocked at the gate even if today's individual request is
clean.

---

## The picture

```
┌─────────────┐      ┌─────────────────────────────────────────────────────────┐
│  client     │─────▶│  Listener (HTTP/HTTPS/H2/H3 · TLS termination + SNI)    │
└─────────────┘      └─────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                     ┌─────────────────────────────────────────────────────────┐
                     │  Route table  (host + path + method, first-match-wins)  │
                     │  → resolves the route's tier + upstream pool            │
                     └─────────────────────────────────────────────────────────┘
                                         │
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  ACCESS GATE — short-circuits before detectors                     │
            │   (1) Blacklist (IP / CIDR / ASN / country)        → 403           │
            │   (2) Whitelist + bypass-scope                     → may bypass    │
            │   (3) Trusted-proxies XFF rewrite                                  │
            │   (4) Per-IP strike gate (cumulative score ≥ thr)  → 403           │
            │   (5) Rate limit (sliding window / token bucket)   → 429           │
            │   (6) DDoS mode (cluster-wide spike detector)      → 429 / chal    │
            └────────────────────────────────────────────────────────────────────┘
                                         │   request still alive
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  DETECTOR CHAIN — every detector enabled in the mask runs          │
            │   sqli · xss · path_traversal · ssrf · header_injection ·          │
            │   body_abuse · recon · brute_force · command_injection ·            │
            │   template_injection · nosql_injection · open_redirect ·            │
            │   ai (optional)                                                    │
            │                                                                    │
            │   Each detector is a pure function over the request.               │
            │   A hit emits a Signal { tag, score: 50–60 }.                      │
            │   The request contributes max(signal.score) to the per-IP risk     │
            │   total — single multi-detector hit doesn't pile up score (M003).  │
            └────────────────────────────────────────────────────────────────────┘
                                         │   detectors done
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  RULE ENGINE — operator-authored DSL rules                         │
            │   priority-ordered · scope-filtered (global / tier / route)        │
            │   actions: Allow · Block · Challenge · RaiseRisk(delta) ·          │
            │            RateLimit · LogOnly · Transform                         │
            │   First terminal action wins.                                      │
            └────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  RISK + TIER GATE                                                  │
            │   composite_score = Σ(detector signals) + Σ(rule risk_delta)       │
            │                   + reputation_delta + bot_class_weight            │
            │                                                                    │
            │   if composite_score ≥ tier.risk_threshold → BLOCK (403)           │
            │   else                                     → forward to upstream   │
            │                                                                    │
            │   ALSO: cumulative IP risk score += per-request composite_score    │
            │         (per-IP, decays exp. half-life risk.decay_half_life=5m)    │
            │         if score ≥ risk.thresholds.block_at  → access-gate block   │
            │         if score ≥ risk.thresholds.challenge_at → challenge ladder │
            │         (edited live from Settings → "Cumulative IP risk           │
            │          thresholds")                                              │
            └────────────────────────────────────────────────────────────────────┘
                                         │   allowed
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  Forward to upstream pool (member picked by LB)                    │
            │  Upstream responds                                                 │
            └────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  RESPONSE FILTER  (security headers, stack-trace scrub, DLP out)   │
            └────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
            ┌────────────────────────────────────────────────────────────────────┐
            │  AUDIT + METRICS                                                   │
            │   one hash-chained NDJSON event · one Prometheus histogram bucket  │
            └────────────────────────────────────────────────────────────────────┘
```

---

## How a request becomes a decision

### Stage 1 — Listener + TLS

`:8080` (plain HTTP) and `:8443` (TLS 1.2+) both serve the data plane.
HTTPS picks the right cert by **SNI** (servable `tls.certificates: []`
list with per-cert host pins). HTTP/2 negotiates via ALPN; HTTP/3 (QUIC)
is opt-in behind `--features http3`. Nothing is gated yet — the request
hasn't been parsed.

### Stage 2 — Route resolution

The route table is **first-match-wins, top to bottom**:

```yaml
routes:
  - id: payments
    host: api.example.com
    path: /v1/charges
    methods: [POST]
    tier_override: critical
    upstream: payments-pool

  - id: catch-all          # last entry — required
    path: /
    upstream: stub-pool
```

Match order: exact host > regex host > wildcard host > catch-all.
A request that matches the `payments` row inherits **tier = critical**
and **upstream = payments-pool**. Reference: [`routing-ingress.md`](../data-plane/routing-ingress.md),
[`upstream-pools.md`](../data-plane/upstream-pools.md).

### Stage 3 — Access gate

Six sub-checks, in order. Any short-circuits skip the detector chain:

1. **Blacklist** — exact IP, CIDR, ASN, or country. Terminal block (403).
   Surfaced on the **Access Lists** page; entries are audit-mutated.
2. **Whitelist** — same shape, but with a `bypass:` scope. `bypass: ["all"]`
   skips the entire pipeline; `bypass: ["sqli","xss"]` skips listed
   detectors only.
3. **Trusted-proxy XFF rewrite** — when the TCP peer is in
   `trusted_proxies`, the source IP becomes the leftmost `X-Forwarded-For`
   value. Without this, all traffic from a CDN looks like one IP.
4. **Per-IP strike gate** — covered below in [Risk model](#risk-model).
5. **Rate limit** — sliding window + token bucket. Scopes: IP, session,
   device, route, global. Hit → **429 Too Many Requests** with a
   Retry-After header. Reference: [`rate-limiting.md`](rate-limiting.md).
6. **DDoS mode** — cluster-wide RPS exceeds `spike_multiplier` ×
   rolling baseline → tighter thresholds + mandatory challenges on new
   sessions. Reference: [`ddos-protection.md`](ddos-protection.md).

### Stage 4 — Detector chain

Every detector enabled in the **detector mask** (Detectors page) runs
on the request. Each detector is a pure function `RequestView →
Vec<Signal>`. A hit emits one or more `Signal { tag, score, field }`
entries — `score` is typically 50-60 per hit. Detectors do **not**
block on their own; they accumulate signals.

| Detector | Tag emitted | Inspects |
|---|---|---|
| SQL injection | `sqli` | URL, body, headers |
| XSS | `xss` | URL, body, headers |
| Path traversal | `path_traversal` | URL, body |
| SSRF | `ssrf` | URL, body, fetch-style headers |
| Header injection | `header_injection`, `url_override_bypass` | Headers (CRLF, smuggling, XFH poisoning, X-Original-URL / X-Rewrite-URL admin-path bypass added 2026-05-09 GAP-011) |
| Body abuse | `body_abuse`, `xxe`, `mass_assignment`, `proto_pollution` | Body (size, nesting, JSON / XML / form) — `proto_pollution` sub-tag (score 45) added 2026-05-08 (GAP-010) |
| Recon | `recon_path`, `recon_tool` | URL patterns + path entropy (`/.env`, `/wp-admin/…`, Docker REST) — framework recon (Spring actuator danger paths / Laravel Ignition / Swagger / GraphQL / K8s API / Kibana / Jenkins / CGI / Prometheus federation) added 2026-05-08 (GAP-001) |
| Brute force | `brute_force` | Login endpoints (failure counter via `velocity.rs`) |
| Command injection | `command_injection` | URL, body, allowlisted headers — `$()`, backticks, `\|cmd`, `;cmd`, `/bin/sh`, reverse-shell shapes, Log4Shell `${jndi:...}` (score 60) |
| Template injection | `template_injection` | URL, body — Jinja2 / Twig / SpEL / Freemarker / Velocity / Handlebars |
| NoSQL injection | `nosql_injection` | URL, body — MongoDB operator injection (`[$ne]`, `[$where]`, `"$gt":`) |
| Open redirect | `open_redirect` | Query string — suspicious external URLs in redirect-style params (`?next=`, `?redirect_uri=`); allowlist via `cfg.detectors.open_redirect.allowed_domains` |
| Canary | `canary` | URL path — operator-curated honeypot paths (`risk.canary_paths`, editable on the Settings page). Score 100. Default OFF. |
| Velocity sequence | `velocity_*` | Cross-endpoint flow (login→withdrawal < 5 s, …) |
| Behaviour signals | `behavior_*` | Missing UA / Referer on mutations / zero-depth first-touch |
| AI (optional) | `ai` | URL + body, run through ONNX classifier — **short-circuit, see below** |

Per-detector deep-dives in [`detectors/`](detectors/).

The **detector mask** is the runtime gate. Flipping a class off (Detectors
page → Edit row → Save) stops the WAF from running it on the next
request. Audit-mutated, hot-swap, no restart.

#### AI short-circuit (Base detectors win)

The AI classifier is **deferred** to the end of the chain and runs
**only when no Base-mask (signature) detector fired on this request**.
The dispatcher (`run_all_filtered_timed` in
`crates/aegis-security/src/detectors/mod.rs`) collects the signature
detectors first; if any of them emitted a signal, it skips the AI
detector entirely. Rationale:

- **Fewer false positives.** A deterministic signature hit (sqli, xss,
  …) is already high-confidence and carries its own calibrated score;
  layering a probabilistic AI verdict on top only adds noise and the
  risk of double-counting. The signature detectors are the
  authoritative signal when they fire.
- **Lower cost.** ONNX inference is the most expensive step in the
  chain; skipping it on the (common) requests that a cheap regex
  already flagged keeps the hot path fast.

So AI is a **fallback for the long tail** — novel or obfuscated
payloads that slip past every signature detector. When it does run and
returns `attack`, it contributes score 60 as the sole detector signal.
Toggling AI off (kill-switch or `set_profile`) removes it from the
chain regardless of the short-circuit.

### Stage 5 — Rule engine

Operator-authored rules, evaluated in **priority order**, scope-filtered
by `(global → tier → route → session)`. Compiled into an `ArcSwap<Vec<CompiledRule>>`
so hot-reload is atomic. Each rule produces one of:

- `Allow` — short-circuit allow (rare; usually used to whitelist a
  specific UA pattern in a blocked tier).
- `Block` — terminal 403.
- `Challenge(level)` — JS / PoW / CAPTCHA escalation.
- `RaiseRisk(delta)` — adds to the running score.
- `RateLimit` — per-rule custom limiter.
- `LogOnly` / `Transform` — non-terminal.

**First terminal action wins**. Edit rules from the Rule Manager page;
the editor + 1 h dry-run is described in [`rule-engine.md`](rule-engine.md).

### Stage 6 — Risk + tier gate (the decision)

After every other stage has contributed, the WAF computes:

```
composite_score = Σ(detector signals)
                + Σ(rule risk_delta from RaiseRisk)
                + reputation_delta (ASN / threat-intel)
                + bot_class_weight
                + behavioral_anomaly_delta

if composite_score ≥ matched_route.tier.risk_threshold:
    block (403)            ← decisive
else:
    forward to upstream
```

The **tier risk threshold** comes from the resolved route's tier:

| Tier | Default threshold |
|---|---|
| `critical` | 50 — blocks on a single sqli or xss |
| `high` | 70 — blocks on a single hit by default |
| `medium` | 80 — needs more signal to block |
| `low` (default for unmarked routes) | 90 — most permissive |

Edit the thresholds from the **Detectors page → Edit tier** modal
(audit-mutated). Reference: [`tiered-protection.md`](tiered-protection.md).

### Stage 7 — Forward + response filter

Allowed requests go through the upstream pool's load balancer (round-robin /
least-conn / weighted / p2c / consistent-hash) and connect over the
configured scheme (`http` / `https` / `h2c` / `grpc` / `auto` / `tcp`).
The response runs through the **response filter**: security headers,
stack-trace scrub, internal-IP mask, DLP outbound. Reference:
[`response-filtering.md`](response-filtering.md).

### Stage 8 — Audit + metrics

Every decision lands as one **hash-chained NDJSON** entry under
`/tmp/aegis-dev-audit.jsonl` (configurable via `cfg.audit.sinks`).
Verify integrity any time with `waf audit verify --from <path>`.
Each request also adds one bucket to the per-stage Prometheus histogram
(`waf_request_duration_ms`, `waf_detector_evaluation_duration_ms{class=…}`,
`waf_detector_hits_total{class=…}`).

---

## Risk model

There are **two** numbers that look similar but answer different
questions. This is the most-asked confusion on the Investigation page,
so the distinction matters.

### Per-request score (this request only, composite)

Sum of every signal that fired on **this single request**. Compared
against the matched route's tier `risk_threshold` (critical 50 / high
70 / medium 80 / low 90 by default) to decide block vs allow.

**Where to edit:** the dashboard **Detectors page → Edit tier** modal
(audit-mutated `PUT /api/tiers/{name}`). YAML equivalent in
`cfg.tiers.<name>.risk_threshold`. **Not** the Settings page — that
card edits the cumulative IP score described below.

Visible in:

- The Live Feed row's `risk` field
- The request inspector drawer ("Risk score (this request)")
- The audit chain entry under `fields.risk_score`

Reset to 0 at the start of every request — independent of any other
request.

### Cumulative risk score (per-bucket, sticky)

A second number tracked **per source IP**, persisted in the state
backend (`StateBackend::add_risk` → Redis). Every detector hit AND
every explicit `RaiseRisk` rule contributes to this. **Decays
exponentially** with `risk.decay_half_life` (default 5 min) — so a
clean stretch of requests claws score back down. Two thresholds gate
the challenge ladder, both editable live:

| Threshold | YAML key | Default | Meaning |
|---|---|---|---|
| **Allow ceiling** | `risk.thresholds.challenge_at − 1` | 39 | score ≤ this → request goes through normally |
| **Challenge floor** | `risk.thresholds.challenge_at` | 40 | score ≥ this → JS / CAPTCHA / PoW challenge before allow |
| **Block floor** | `risk.thresholds.block_at` | 80 | score ≥ this → reject **all** requests from this IP at the access gate, before any detector runs, until decay drops the score back below `block_at` |
| **Score cap** | `risk.thresholds.max` | 100 | score saturates here so a single mega-burst can't permanently doom an IP |

**Where to edit:**

- **Global defaults** — Dashboard → **Traffic Gates → #3 Cumulative
  IP risk thresholds** card. The two sliders set `challenge_at` and
  `block_at`; saves go through the audit-mutated
  `PUT /api/risk/thresholds` endpoint, hot-swap to the live tracker.
  YAML equivalent in `cfg.risk.thresholds`.

- **Per-tier `challenges_enabled` toggle** — Dashboard →
  **Detectors & Tiers → Edit tier** modal. Defaults to `false`:
  challenges are opt-in per tier. With `false`, the cumulative
  challenge rung escalates straight to block on this tier (no
  PoW emitted). Useful for admin / payment / machine-API tiers.
  Audit-mutated `PUT /api/tiers/<name>` with the
  `challenges_enabled` field.

- **Per-tier `cumulative_challenge_at` / `cumulative_block_at`
  overrides** — API-only. The wire shape accepts per-tier values
  (`PUT /api/tiers/<name>`), but the dashboard does not surface
  inputs because per-tier cumulative tuning is a niche need. By
  default, every tier inherits the global thresholds.

**A separate `strikes.block_at`** counter (config: `risk.strikes.block_at`,
default 50) tracks **lifetime malicious-event count per IP** and never
decays. When it reaches the limit, the IP is permanently blocked until
an operator runs `PUT /api/risk/{ip}/reset`. This is the "you've been
bad enough times that decay won't save you" gate, distinct from the
score-based gate above.

Visible in:

- The Investigation page's "Recent requests" table — column **Risk score**
  (renamed 2026-05-19 from "IP risk" after the composite-key migration —
  the score is per-`RiskKey { ip, device_fp?, session? }` bucket now,
  not per-IP).
- Top Attackers page → **Composite RiskKey view** (one row per
  bucket, with surgical reset).
- `/api/risk` API surface — `RiskSnapshot` carries `device_fp` +
  `session` axes (omitted via `skip_serializing_if = None` for
  plain-HTTP / anonymous rows).
- Per-bucket detail panel in the request inspector.

A request can show **`Risk score = 100` and `action = ALLOW`** when:
- The bucket got hammered earlier (detectors fired, score climbed).
- The current request happens to not match any detector.
- Per-request score = 0; route's tier threshold not crossed.
- Score-gate `block_at` also not crossed (or already cleared by decay).

That's expected behaviour, not a bug. To **block on cumulative
score alone** (i.e. "if this bucket has been bad, refuse it
regardless of what this single request looks like"), lower
`risk.thresholds.block_at` from the Traffic Gates card. The
false-positive risk on shared egress is **dramatically reduced**
as of 2026-05-19: legit user B on a NAT'd IP now has a separate
bucket from attacker A on the same IP because TLS fingerprint +
session cookie split them apart. The remaining trade-off is
narrower (two legit users behind the same shared egress with
the same browser shape AND no session cookie, e.g. anonymous
public endpoints).

### What contributes to score

Per-detector signal scores (read straight from the detector code —
**not editable from the dashboard UI by design**; see
[`operator/risk-tuning.md`](../operator/risk-tuning.md) for the
rationale + the operator knobs that achieve the same effect
safely without touching the calibrated score ladder):

| Contributor | Where it adds | Default delta | Source |
|---|---|---:|---|
| SQL injection | per-request + per-IP | **70** | `detectors/sqli.rs` |
| XSS | per-request + per-IP | **70** | `detectors/xss.rs` |
| Path traversal | per-request + per-IP | **70** | `detectors/path_traversal.rs` |
| SSRF | per-request + per-IP | **70** | `detectors/ssrf.rs` |
| Header injection — CRLF / smuggling | per-request + per-IP | **70** (XFH poisoning **50**) | `detectors/header_injection.rs` |
| Recon (probe / scanner-UA) | per-request + per-IP | **25 / 50** | `detectors/recon.rs` |
| Body abuse (size → depth → proto-pollution → mass-assign → XXE) | per-request + per-IP | **30 / 35 / 50 / 60 / 90** | `detectors/body_abuse.rs` |
| Brute force | per-request + per-IP | **50** (default; YAML-configurable) | `detectors/brute_force.rs` |
| Command injection | per-request + per-IP | **70** (Log4Shell **90**) | `detectors/command_injection.rs` |
| Template injection (SSTI) | per-request + per-IP | **70** | `detectors/template_injection.rs` |
| NoSQL injection | per-request + per-IP | **70** | `detectors/nosql_injection.rs` |
| Open redirect | per-request + per-IP | **50** | `detectors/open_redirect.rs` |
| **AI / ML classifier** | per-request + per-IP | **60** | `detectors/ai/mod.rs` — runs only when no Base detector matched |

Identity / behaviour weights (configurable in `cfg.risk.weights`,
default **10 each**):

| Contributor | Where it adds | YAML key | Default |
|---|---|---|---:|
| ASN reputation (hosting / VPN / Tor exit) | per-request + per-IP | `risk.weights.bad_asn` | 10 |
| TLS / HTTP fingerprint reputation (bad JA4) | per-request + per-IP | `risk.weights.bad_ja4` | 10 |
| Failed authentication | per-IP only | `risk.weights.failed_auth` | 10 |
| Generic detector-hit modifier | per-request + per-IP | `risk.weights.detector_hit` | 10 |
| Unknown bot class | per-request + per-IP | `risk.weights.bot_unknown` | 10 |
| Repeat offender (history bonus) | per-IP only | `risk.weights.repeat_offender` | 10 |
| Rule engine `RaiseRisk(delta)` | per-request + per-IP | rule-defined | n/a |
| Canary route touch | per-request + per-IP | `risk.canary_routes` | `max_score` (immediate cap) |

Concrete worked examples (single-request, multi-detector combo, lifecycle
across decay, AI tiebreaker): [`risk-scoring.md`](risk-scoring.md#worked-example-sqli-probe-lifecycle).

---

## Decision precedence — who wins when stages disagree

If multiple stages have an opinion on the same request:

1. **Compliance clamp** wins over operator config. PCI / HIPAA / SOC2 /
   GDPR modes pin specific detectors **on**; the Detectors page mask
   surface refuses to disable a clamped class.
2. **Whitelist `bypass: all`** skips everything below it. Everything
   else stays in force.
3. **Blacklist** terminates the request before detectors run. No
   per-request score is computed.
4. **Strike-gate auto-block** (cumulative IP score over threshold) also
   terminates before detectors. Decays naturally.
5. **Rule engine** can short-circuit with `Allow` (rare) or `Block`.
   `Allow` is final — detectors do not run; risk is not raised.
6. **Detectors + per-request score** vs **tier threshold** is the
   default decision path.
7. **Challenge** is a non-terminal escalation — the client is asked to
   solve a JS / CAPTCHA / PoW. Solved → request continues. Failed →
   block.

`Allow` shows in the audit chain as `action: "allow"`; blocks land as
`action: "block"` with a `rule_id` field naming the gate that fired.

---

## Worked examples

### Example 1 — A simple SQLi hit

```
GET /search?q=1' OR '1'='1
Host: localhost:8080
```

1. **Listener** parses the request.
2. **Route table** matches `catch-all` (no host pin, prefix `/`).
   Tier = `low` (threshold 90). Upstream = `stub-pool`.
3. **Access gate**: source IP not blacklisted, not rate-limited.
   Strike score = 0. Pass.
4. **Detector chain** runs all enabled detectors. The sqli detector's
   Aho-Corasick catches `OR '1'='1` plus the `'` opener — emits
   `Signal { tag: "sqli", score: 70 }`.
5. **Rule engine** has no operator rule matching this URL. No-op.
6. **Per-request tier gate** (Option B, 2026-05-20): the request's
   summed detector score (`70`) is compared to the matched tier's
   `risk_threshold`. For `low` that's **90 — 70 < 90, so the WAF does
   NOT block per-request** (the request forwards upstream, reported
   `allow` with `X-WAF-Risk-Score: 70`). The SAME request against a
   route pinned `critical` (50) or `high` (70) **would** block, since
   `70 ≥ 50` / `70 ≥ 70`. RCE-class hits (Log4Shell, XXE = 90) block
   on every tier including `low`.
7. **Audit + metrics**: `action: "allow"` (or "block" on a
   critical/high-tier route), `fields.detectors: ["sqli"]`,
   `fields.risk_score: 70`.
8. **Cumulative IP risk score** climbs by `max(signal)` = 70 (the
   cumulative gate uses max per SEC-M003, not the per-request sum).
   Two more hits in 5 min
   → score saturates at `risk.thresholds.max` (100 in prod) → crosses
   `risk.thresholds.block_at` (default **80** in prod, deliberately
   pushed to 99999 in `config/dev.yaml` so shared-loopback dev traffic
   doesn't self-block) → **auto-blocked at the access gate** for
   subsequent requests, even benign ones, until exponential decay
   (`risk.decay_half_life`, default 5 min) drops the score back below.

### Example 2 — Allowed despite high IP risk

Same client as Example 1, but on the next request:

```
GET /index.html
Host: localhost:8080
```

1. Listener / Route same.
2. **Access gate** — IP strike score is 240. Strike threshold may have
   been raised (dev profile sets it loose). If under threshold, request
   continues.
3. **Detector chain** — `/index.html` has no attack pattern. Zero
   signals. Per-request score = 0.
4. **Tier gate**: 0 < 90 → allow.
5. **Audit chain**: `action: "allow"`, `fields.risk_score: 0` (per-request),
   but the audit event's top-level `risk_score` (the IP cumulative) shows
   240.

This is the row the user sees on the Investigation page that says
**`ALLOW · IP risk 240`** — looks contradictory, isn't.

### Example 3 — Blacklisted IP

```
curl -H 'X-Forwarded-For: 8.8.8.8' http://localhost:8080/anything
```

1. Listener / Route same.
2. **Access gate**: trusted-proxies XFF rewrite kicks in (loopback is
   trusted). Source becomes `8.8.8.8`.
3. Blacklist contains `8.8.8.8`. **Terminal 403**.
4. Detectors do not run.
5. Audit chain: `class: "access"`, `action: "block"`,
   `rule_id: "blacklist:ip:8.8.8.8"`.

---

## Where each gate is configured

| Gate | YAML key | Dashboard surface |
|---|---|---|
| TLS certs | `tls.certificates: []` | (read-only — Health & SLOs cert freshness) |
| Routes | `routes: []` | Routing & Upstreams (audit-mutated CRUD) |
| Tier definitions | `tiers: []` (defaults seed at boot) | Detectors page → Edit tier |
| Detector mask | `detectors.<class>.enabled` | Detectors page (per-class on/off) |
| AI detector | `cfg.ai.{enabled, model_path, confidence_threshold}` | Detectors page → AI row Enable/Disable |
| Custom rules | `rules: []` (or external file via `rules_path`) | Rule Manager |
| Blacklist / whitelist | `blacklist: []`, `whitelist: []` | Access Lists |
| Rate limit | `rate_limit.{ip, session, route, global}` | (read-only — Settings) |
| DDoS thresholds | `ddos.{spike_multiplier, ...}` | (read-only) |
| Risk weights | `risk.weights.{bad_asn, bad_ja4, ...}` | (read-only — YAML restart) |
| Tier `risk_threshold` (per-request gate) | `tiers.<name>.risk_threshold` | Detectors page → Edit tier (audit-mutated) |
| Cumulative IP score thresholds | `risk.thresholds.{challenge_at, block_at, max}` | Settings page → "Cumulative IP risk thresholds" card (audit-mutated) |
| IP strike count limit | `risk.strikes.block_at` | (read-only — YAML restart; reset per IP via `PUT /api/risk/{ip}/reset`) |
| Risk decay | `risk.decay_half_life`, `risk.trust_recovery.per_hour` | (read-only — YAML restart) |
| Compliance clamp | `compliance.modes: [pci|hipaa|soc2|gdpr|fips]` | Compliance page (read-only) |
| Mode (enforce / log_only) | `mode: enforce` | Settings → Mode toggle |
| Audit sinks | `audit.sinks: [jsonl, syslog, cef, leef, ocsf, splunk_hec, kafka]` | (read-only) |

"Read-only" means edit YAML and restart for now; the live runtime
gate is in place, the dashboard editor isn't built yet.

---

## How to verify each gate works

Every row above maps to an entry in [`docs/FEATURES.md`](../FEATURES.md)
with a concrete curl + expected outcome. Use that doc as the QC walk.

For deeper per-feature reading:

| Topic | Doc |
|---|---|
| Tier semantics + failure modes | [`tiered-protection.md`](tiered-protection.md) |
| Rule DSL + AST + actions | [`rule-engine.md`](rule-engine.md) |
| Risk model + scoring + decay | [`risk-scoring.md`](risk-scoring.md) |
| Per-detector behaviour | [`detectors/`](detectors/) |
| AI detector internals + perf | [`detectors/ai-detector.md`](detectors/ai-detector.md) |
| Rate limiting + token buckets | [`rate-limiting.md`](rate-limiting.md) |
| DDoS auto-block + cluster sets | [`ddos-protection.md`](ddos-protection.md) |
| Threat intel feeds + indicators | [`threat-intelligence.md`](threat-intelligence.md) |
| GeoIP / ASN reputation | [`geoip-filtering.md`](geoip-filtering.md), [`ip-reputation.md`](ip-reputation.md) |
| TLS / HTTP fingerprint | [`device-fingerprinting.md`](device-fingerprinting.md) |
| Bot classifier + good-bot verify | [`bot-management.md`](bot-management.md) |
| Behavioural / velocity | [`behavioral-analysis.md`](behavioral-analysis.md), [`transaction-velocity.md`](transaction-velocity.md) |
| Challenge ladder (JS / CAPTCHA / PoW) | [`challenge-engine.md`](challenge-engine.md) |
| API guard (OpenAPI + GraphQL) | [`api-security.md`](api-security.md) |
| DLP inbound + outbound | [`dlp.md`](dlp.md), [`response-filtering.md`](response-filtering.md) |
| Content scan via ICAP | [`content-scanning.md`](content-scanning.md) |
| Origin-facing auth (JWT / Forward / mTLS) | [`external-auth.md`](external-auth.md) |
