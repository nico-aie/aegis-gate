# Egress & Internal-Traffic Observability (EG track)

> **Status:** EG-2 response-path detectors shipped 2026-07-05
> (`feat/eg2-egress-observability`). All three are **default-OFF**,
> **log/score only** — they never block a response. EG-3 ("Internal
> Flows" dashboard page) aggregates existing internal-flow signals.
> Design of record: [`../../plans/future/round-2-improvement/DESIGN-EG1-egress-response-inspection-2026-07.md`](../../plans/future/round-2-improvement/DESIGN-EG1-egress-response-inspection-2026-07.md).

## Purpose

Detect suspicious activity *leaving* the environment, not just attacks
entering it — the outbound complement to the request-side detector chain.
Where [Response Filtering](response-filtering.md) *mitigates* (scrubs /
redacts / masks, silently, default-ON), the EG-2 detectors **observe,
score, and attribute** the same classes of leak so an operator can *see*
them and the per-IP risk model can react.

## The honest boundary (read this first)

Aegis is an inline reverse proxy. It sees **inbound edge traffic and the
responses to it — nothing else.**

| Traffic class | Visibility | Covered by |
|---|---|---|
| Responses origin → client **through the WAF** | Full (headers + body, terminated here) | **EG-2** (below) |
| The WAF's **own** internal flows (fleet channel, Redis/etcd, upstream dials, config plane) | Full (we originate them) | **EG-3** (Internal Flows page) |
| **Origin-initiated egress** — direct sockets from backends, DNS tunneling, lateral movement between services that never traverse the WAF | **None. Physically out of path.** | **Out of scope** |

Claiming more than rows 1–2 would be dishonest. For origin-initiated egress,
deploy an egress gateway / NDR alongside Aegis. **Integration point:** the
audit-bus SIEM sinks already ship multiple formats; an external NDR can
correlate on `request_id` / `client_ip` to stitch response-path observations
into a broader egress picture. Aegis does **not** attempt to build that
collector.

## EG-2 — response-path detectors

All three live off the detector chain (they need the response status / body /
size, which only the response-side sites see), mirroring `enumeration` /
`behavior_analyzer`. Each is a `ProxyContext` field, `Some` only when its
toggle is on. They **observe before** the `redact_dlp` rewrite so they see the
raw data the scrubber would replace with `[REDACTED]`.

### T4 — error-page information leaks (`detectors::egress_leak`)

On **5xx** responses with a `text/html` / `application/json` / `text/*` body
(first 64 KiB), detects language/runtime **stack traces**, framework **debug
banners** (Flask/Werkzeug, Rails, ASP.NET, Django, Spring, PHP…), and
**internal IPs** (RFC-1918 / loopback / link-local, v4+v6). Reuses the exact
[`response_filter`](response-filtering.md) scrub patterns via the
`has_stack_trace` / `has_internal_ip` oracles, so the observe and redact halves
can never drift. Emits one `Detection`-class audit row per leak kind and a
per-IP risk delta.

- **Config:** `detectors.egress_error_leak.enabled` (default `false`).

### T5 — egress-volume anomalies (`detectors::egress_volume`)

Per-IP sliding-window **bytes-out** (size from `Content-Length`; no body
access — streaming / unknown-size responses only track, never fire). Fires
**once per window** when the window volume crosses the threshold **AND** the
client's risk is already elevated — the false-positive guard so a legitimate
large download from a clean client never scores; only a high-volume transfer
to an *already-suspicious* client (the exfil shape) does. Feeds the risk model.

- **Config:** `detectors.egress_volume.enabled` (default `false`).
- Defaults: 50 MiB / 60 s window, risk gate 30.

### T2/T3 — sensitive-data in responses (`detectors::egress_sensitive`)

Content-type-gated (json/html/csv/text), size-capped (64 KiB), **1-in-N
sampled** (always-on for risky clients) `dlp::scan()` over the **v1 scope**:
- **Secret markers** (T2): AWS keys/secrets, GitHub / Stripe / Slack tokens,
  PEM private keys, JWTs, `.env`-style secret assignments — a single
  occurrence is signal.
- **Card PANs** (T3): Luhn-validated, scored only above a **density
  threshold** (one card is normal business; a *sweep* is the exfil shape).

Bulk-PII shapes (SSN / IBAN / email / phone) are **deferred** to a later
version pending an FP corpus (owner decision, design §6.2).

- **Config:** `detectors.egress_sensitive.enabled` (default `false`).

### Relationship to Response Filtering

The [Response Filtering](response-filtering.md) card *removes/mitigates*
(default-ON, silent); the EG-2 detectors *observe/score/attribute*
(default-OFF until FP-tuned). They read the same patterns but serve different
goals. The shipped `redact_dlp` rung is left **full-body and unchanged**; only
the EG-2 read is capped + sampled (design `max_scan_bytes` decision), so
enabling EG-2 never changes the scrubber's behavior.

## EG-3 — Internal Flows dashboard page

Aggregates existing internal-flow signals (no new collectors) — fleet-channel
health/latency, state-backend (Redis/etcd) round-trip + error rate, upstream
dial outcomes by zone, and config-plane propagation lag. See the **Internal
Flows** dashboard page.
