# Response Filtering

> **Status:** Core three-rung filter shipped 2026-05-11 (PR #7) —
> `Pipeline::on_body_frame` is wired into the data plane at
> `crates/aegis-proxy/src/data_plane.rs`. The richer roadmap below
> (FPE, OpenAPI validation, ICAP, streaming, security-header
> injection, header strip) is **forward-looking** and not on the
> hot path today. See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status)
> for the implementation matrix.

## Purpose

Attackers learn from responses as much as from requests. Verbose
errors leak schemas; a 500 with a stack trace reveals framework
versions; a chatty JSON endpoint exposes PII. Response filtering
is the **outbound half** of the WAF — scrubbing, masking, and
verifying backend responses before they reach the client.

## What ships today (2026-05-11)

`crates/aegis-security/src/pipeline.rs::Pipeline::on_body_frame`
runs three rungs over every upstream response body. Each rung is
independently toggleable via [`ResponseFilterConfig`](#configuration);
defaults are **all on** (safe-by-default).

> **Streamed responses bypass these rungs.** A response that streams
> through (SSE / `text/event-stream`, see
> [`../data-plane/sse-streaming.md`](../data-plane/sse-streaming.md)) is
> header-inspected only — its body can't be re-read, so the
> `on_body_frame` pipeline (and the response cache) are skipped. Each such
> response is audited with `response_inspection_skipped: true, reason:
> "streaming"`. Set `streaming.enabled: false` to force buffering (and
> thus body inspection) for every response.

### Rung 1 — Stack-trace scrubbing

`response_filter::scrub_stack_traces` matches per-framework stack
patterns and replaces the matched run with `[REDACTED]`. Today's
coverage:

| Framework | Pattern |
|---|---|
| Node.js / V8 | `at Function (file:line:col)` chains |
| JVM (Java / Kotlin / Scala) | `at Class.method(File.java:NN)` chains |
| Python | `Traceback (most recent call last):` blocks |
| Rust | `note: run with RUST_BACKTRACE=1`, `stack backtrace:` |
| PHP | `Stack trace:` blocks |
| .NET / C# | `at Namespace.Class.Method() in File:line` |
| Ruby | `(eval):N` / `from file.rb:NN:in` |
| Go | `goroutine N [running]:` blocks |

### Rung 2 — Internal IP masking

`response_filter::mask_internal_ips` masks the RFC 1918, loopback,
and link-local ranges → `[INTERNAL]`:

- IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `127.0.0.0/8`, `169.254.0.0/16`.
- IPv6: `::1` (loopback), `fc00::/7` (ULA), `fe80::/10`
  (link-local), `::ffff:<ipv4>` (IPv4-mapped IPv6). Added
  2026-05-18 (F-CRITICAL-013 §5.7). Public IPv6 addresses
  pass through untouched — the leading-anchor regex
  `(?:^|[^0-9a-fA-F:])` distinguishes a bare `::1` from the
  `::1` tail of e.g. `2001:db8::1`.

### Rung 3 — DLP redaction

`dlp::redact` redacts the following with `[REDACTED]`:

| Class | How matched |
|---|---|
| Credit cards | Regex + Luhn validation (zero false-positives on common-shape numbers) |
| US SSN | `NNN-NN-NNNN` with valid-area-code filter |
| IBAN | Country-code + check-digit regex |
| Email | RFC-5321 conservative match |
| AWS access keys | `AKIA[0-9A-Z]{16}` |
| GitHub tokens | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixes |
| Stripe keys | `sk_live_*`, `pk_live_*`, `sk_test_*` |
| Slack tokens | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-` |

## Hot-path behaviour

```text
upstream response → on_body_frame(frame, rctx, route)
                  ├─ all rungs off?              → PassThrough (short-circuit)
                  ├─ binary body (utf-8 fail)?   → PassThrough
                  ├─ scrub_stack_traces (Cow)   ─┐
                  ├─ mask_internal_ips    (Cow)  ├─ no change? → PassThrough
                  └─ dlp::redact          (Cow) ─┘
                                                 └─ changed?   → Rewrite(new_bytes)
```

Clean responses (the vast majority) pay **one `Cow::Borrowed` check
per rung** and **zero allocations**. Only modified payloads cost a
single `Bytes::from(String)` and a `Content-Length` rewrite.

Today the forwarder buffers the entire upstream body into one
`Full<Bytes>` frame (`crates/aegis-proxy/src/upstream/forward.rs:469-505`),
so this is a single `on_body_frame` call. The per-frame interface
is in place for the streaming-body work in the next phase.

## Configuration

`ResponseFilterConfig` lives on the `Pipeline` instance, held in
an `arc_swap::ArcSwap` so a future audit-mutated PUT can flip
rungs without a restart:

```rust
pub struct ResponseFilterConfig {
    pub scrub_stack_traces: bool, // default: true
    pub mask_internal_ips:  bool, // default: true
    pub redact_dlp:         bool, // default: true
}
```

When all three are off, `on_body_frame` short-circuits to
`PassThrough` so the per-frame cost goes to zero.

`Pipeline::set_filter_config` and `Pipeline::filter_snapshot` are
the dashboard-side APIs that the runtime toggle will call.
Wire-up of a `/api/response-filter` PUT + Security Engine tile in
the dashboard is **not in PR #7** — that's the next slice of
work.

## What does NOT ship yet

The richer v2 design (kept for reference and roadmapping):

| Feature | Status | Tracked |
|---|---|---|
| Per-content-type gate (`text/*`, `application/json` only) | Not wired — binary bodies short-circuit via UTF-8 decode fail today | Phase 2 |
| Streaming chunk processor (gigabyte responses) | Not wired — forwarder buffers whole body | Streaming phase |
| Field-name DLP match (case-insensitive JSON allow-list) | **Helper shipped** 2026-05-18 (`response_filter::mask_json_fields` — recurses into nested objects + arrays, case-insensitive on field names). Pipeline integration to call it from `on_response_complete` is the next slice of work — see F-CRITICAL-013 §5.7 sub-fix 3. | Phase 2 |
| Format-preserving encryption (FPE) tokenization | Not wired | Future |
| Masked redaction (`****-****-****-1234`) | Not wired — full-replace only | Phase 2 |
| OpenAPI / GraphQL schema validation | Not wired | API security phase |
| ICAP RESPMOD content scan | Not wired | Phase C |
| Information-leak header strip (`Server`, `X-Powered-By`, …) | **Shipped** via `response_filter::should_strip_header` + the expanded `STRIP_HEADERS_EXACT` (server, x-powered-by, x-aspnet-version, x-aspnetmvc-version, x-runtime, x-version, x-generator, x-php-version, x-rails-env) + `STRIP_HEADERS_PREFIX` (x-debug, x-internal, x-trace). Wired into `inject_security_headers`. Added 2026-05-18 (F-CRITICAL-013 §5.7). |
| Security header injection (HSTS, CSP, X-Frame-Options) | Not wired | Phase 2 |
| Templated block pages (per-tier / per-status) | Not wired | Phase 2 |

Each of these has a clear seam in the current code; the trait
shape (`on_response_start` + `on_body_frame` + `OutboundAction`)
was chosen so they can land incrementally without breaking the
PR #7 wire-up.

## Implementation

- `crates/aegis-security/src/response_filter.rs` — stack-trace
  scrubber + internal-IP masker (rungs 1 + 2).
- `crates/aegis-security/src/dlp/mod.rs` — DLP scanner (rung 3).
- `crates/aegis-security/src/pipeline.rs::Pipeline::on_body_frame` —
  the three-rung orchestrator with `Cow<str>` zero-alloc hot path.
- `crates/aegis-proxy/src/data_plane.rs` — call site in the
  `forward_allow_to_upstream` `Ok(resp)` arm; rebuilds the
  response with the new bytes + corrected `Content-Length` when
  `OutboundAction::Rewrite` fires, or returns 502 on
  `OutboundAction::Abort`.

## Tests

- `crates/aegis-security/src/response_filter.rs` — unit tests for
  Python / Node / Java / Go stack scrubs + IP masking.
- `crates/aegis-security/src/dlp/mod.rs` — unit tests covering
  Luhn validation, SSN format, IBAN check-digits, token shapes.
- `crates/aegis-security/src/pipeline.rs` — tier classification +
  the response-filter integration tests run via the workspace
  suite (3,300+ tests pass on the PR #7 commit).
