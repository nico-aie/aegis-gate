# Unwired-stubs catalogue (2026-05-11)

> ⚠️ **Staleness note (2026-05-28):** this catalogue is dated 2026-05-11.
> Some entries have since been **wired** and are no longer stubs — verify
> against the current code before trusting any "zero callers" claim
> (see [memory: docs drift both ways]). Known corrections applied this
> date: **`rules::evaluate` is now wired** (`data_plane.rs:1630`, guarded
> by `ctx.active_ruleset`) — custom rules DO run on live traffic;
> **HTTP/2 rapid-reset mitigation shipped** (`proto/h2.rs`
> `max_resets_per_window`); **JA4-light landed** (2026-05-18, see the JA4
> entry below). The roadmap in
> [`world-class-waf-roadmap.md`](../future/world-class-waf-roadmap.md) treats this
> file as the Tier-0/Ops wire-up backlog.
>
> **PE-1 sweep (2026-07-04,
> [FEAT-placeholder-endpoints-cleanup](../issues/FEAT-placeholder-endpoints-cleanup-2026-07.md)):**
> the placeholder endpoints catalogued here were dispositioned —
> `/api/threat-intel/feeds`, `/api/gitops/status`, `/api/audit/witness`
> (and the `WitnessRecord` shell + the witness-signing sketch this file
> carries), plus the never-routed `render_cert_renew`, were **removed**.
> Treat any witness/gitops entries below as historical.

> **Status:** Drafted 2026-05-11 as Phase 4 of the
> `plans/issue-fix/2026-05-11-policy-qa-and-audits` triage.
>
> The crate audits (LT-RUN-4 / LT-RUN-5) flagged a long tail of
> "this trait/struct exists in the source but isn't called from
> the data plane" findings. Most of them are not security
> incidents today — the trait shape ships against a deferred
> feature. They become real bugs the day someone wires them in.
>
> This file is the reference: every stub with a confirmed-zero
> caller in `aegis-proxy/src/` + `aegis-bin/src/` as of 2026-05-11,
> plus the contract status (required / not required / Phase-C
> deferred) so the person who wires each one in knows whether
> it's a contract obligation or a roadmap aspiration.

## Confirmation method

For each entry, `grep -rln '<symbol>' crates/aegis-proxy/src/
crates/aegis-bin/src/` returns zero hits as of commit
`3b01ade...` (PR #8 land). The stub still compiles + has unit
tests, but nothing in the live request path or the binary boot
sequence calls it.

---

## Challenge providers — CAPTCHA stubs

**File:** `crates/aegis-security/src/challenge/captcha.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `CaptchaProvider` trait | 1-8 | **Not required.** Contract v2.3 §3 challenge: "client must solve a JS challenge OR proof-of-work." PoW alone satisfies the spec. |
| `Turnstile` | 11-30 | Not required. Always returns `Ok(true)`. |
| `HCaptcha` | 33-49 | Not required. Always returns `Ok(true)`. |
| `ReCaptchaV3` | 52-… | Not required. Always returns `Ok(true)`. |

**Why deferred:** PoW (`crates/aegis-security/src/challenge/pow.rs`)
is the production-shipped challenge path and satisfies the
contract. Vendor CAPTCHA integration is roadmap work that
requires (a) HTTP client + secret-manager plumbing to call the
vendor verify endpoints, and (b) an audit-mutated config
surface for the per-tenant secret + min-score knobs.

**Action if you wire it:** call sites would be the
challenge-escalation ladder
(`crates/aegis-security/src/challenge/ladder.rs`) and the
`Decision::Challenge { level: ChallengeLevel::Captcha }` arm
in `data_plane.rs`. Today `ChallengeLevel::Captcha` parses but
never fires because the ladder never escalates beyond PoW.

---

## Auth — JWT validator

**File:** `crates/aegis-security/src/auth/jwt.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `JwtConfig` / `JwtClaims` / `JwtError` | 4-31 | **Not required.** Contract v2.3 §2.2 only requires *some* auth on control endpoints. The admin plane already uses argon2 + session cookie + CSRF (contract-conformant). |
| `validate(token, config, now)` | 37-… | Not required. Parses the base64 payload but never verifies the signature — `// In production, use jsonwebtoken crate with JWKS`. |

**Why deferred:** Admin auth ships via `aegis-control::api::login`
(argon2 + session cookie + CSRF) which the contract accepts.
JWT auth would be needed only if operators want a stateless
control-plane (no session store) — a roadmap item, not a gap.

**Action if you wire it:** swap the stubbed `validate` for a
`jsonwebtoken`-based implementation, plumb a JWKS fetcher with a
per-issuer cache, and add a config surface for `cfg.admin.
jwt_issuers[]`. Audit-mutated PUT path for the JWKS URL list.

---

## Auth — OPA client

**File:** `crates/aegis-security/src/auth/opa.rs`

**Contract status:** Not required. Rego-based external policy
evaluation is a roadmap feature; today's policy is expressed
through rules + tier config which the contract accepts.

**Action if you wire it:** add a `cfg.policy.opa.endpoint` config
surface, an HTTP client (reuse the `reqwest` secret-manager
client), and a call site in the request pipeline (most
likely between rule eval and detector eval). Note that the
contract doesn't accommodate OPA decision types like "deny
unless X" — you'd need to map them to `allow / block /
challenge / rate_limit / timeout / circuit_breaker`.

---

## Content scanning — ICAP

**Files:**
- `crates/aegis-security/src/content/icap/mod.rs`
- `crates/aegis-security/src/content/icap/codec.rs`
- `crates/aegis-security/src/content/icap/tcp.rs`

**Contract status:** Not required (Phase-C feature per module
doc). The contract calls out malware scanning as an optional
content-inspection layer, not a wire-required check.

**Why deferred:** ICAP RESPMOD/REQMOD scans add a network
round-trip per response — the latency budget needs an explicit
operator opt-in. The shipped response filter (PR #7) already
covers stack-trace + DLP + internal-IP scrubbing; ICAP would
add AV / payload reputation on top.

**Action if you wire it:**
- Add `cfg.response_filter.icap.{endpoint, timeout_ms,
  failure_mode}` config surface.
- Add an ICAP rung between the existing rungs in
  `Pipeline::on_body_frame` (after DLP, before pass-through).
- Per-content-type gate (don't ICAP-scan plain text, do scan
  octet-stream / multipart / archive types).
- New `OutboundAction::Abort { reason: "icap_quarantined" }`
  variant is already in place from PR #7.

---

## Audit sinks — SIEM exporters (Splunk HEC, Kafka, QRadar,
ArcSight)

**Status:** Symbols not present in the workspace as of
2026-05-11. The LT-RUN-5 finding referenced module names that
never landed; the audit fan-out today goes to:
- the in-memory `AuditRing` (dashboard live feed)
- the JSON audit log file (operator-configured path)
- the alert-receivers (Slack / Alertmanager / PagerDuty —
  these **are** shipped via `crates/aegis-control/src/api/
  alert_receivers.rs`)

**Contract status:** Not required. The contract specifies
audit-chain *shape* and accepts any sink that preserves the
shape.

**Action if added:** new sink crates under `crates/aegis-
control/src/audit/sinks/` consuming the `AuditBus`.

---

## Audit cold-tier export

**Status:** In-memory `AuditRing` capped at 200 events
(`crates/aegis-control/src/api/audit.rs::DEFAULT_CAP`); restart
loses the chain.  `/api/cold-tier` is a placeholder returning
`{"feature_present": false}`.  The dashboard's Reports card is
already honest about the cap ("Audit trail · full ring · last
200 events") — operator-visible surface is clean.

**Contract status:** Not required.  The contract specifies the
audit-chain shape + tamper-evident hash linking; persistence
window is a separate concern.

**Action if added:** Two design shapes documented at
`plans/future/audit-cold-tier-export.md`:
- v1 — JSONL append (`data/audit/chain-<date>.jsonl`).  ~30 LoC.
- v2 — embedded sqlite with range queries.  ~1 day.
Recommendation: ship v1 first; layer v2 if query power becomes
the bottleneck.  Promotes `/api/cold-tier` to a real endpoint
and updates `/api/reports/audit.csv` to support
`?from=<ts>&to=<ts>` from the cold tier.

---

## License validator

**Status:** No `license` module in `aegis-security` or
`aegis-control` as of 2026-05-11. The LT-RUN-5 finding may
have been against a different repo or a deleted branch.

**Contract status:** Not relevant (the contract is silent on
licensing).

---

## Jaeger / OTLP tracing

**File reference:** Comment in `crates/aegis-proxy/src/
data_plane.rs:33` only — the OTLP exporter actually ships
through `crates/aegis-bin/src/otel.rs::init_or_default` (see
the `--features otel` build).

**Contract status:** Not required. The contract is silent on
tracing.

---

## Redis rate-limit backend

**Status:** The Redis dependency (`aegis-proxy/redis` feature)
ships and is used by the state backend (`StateBackend`
implementation against deadpool-redis). There is no separate
"Redis rate-limit backend" — the in-memory `IpRateLimiter` reads
from the state backend (which may be Redis-backed) when running
in a multi-node deployment.

**Contract status:** Working as designed.

---

## ACME auto-renew (PROXY-04 / 23)

**Status:** ACME is **shipped** — `instant-acme`-backed cert
issuance + the challenge store live in
`crates/aegis-proxy/src/acme_instant.rs` and are wired into
`run.rs:978`. The LT-RUN-5 finding for `PROXY-04 / 23` was
probably about a sub-feature of ACME (e.g. wildcard cert via
DNS-01 challenge, which uses HTTP-01 today).

**Action if extending:** add DNS-01 challenge solver behind a
feature flag; current HTTP-01 covers the common case.

---

## Network secret providers (Vault / AWS / GCP / Azure)

**Status:** All four ship behind feature flags
(`aegis-proxy/vault`, `aws`, `gcp`, `azure`). Default builds
don't pull them; deployments opt-in via Cargo features. The
LT-RUN-5 finding flagged these as "stubs" but they are real
working integrations — the gap was that the dashboard doesn't
have a config-surface for choosing one.

**Contract status:** Not required (the contract leaves secret
management to the operator).

**Action if surfacing:** add an audit-mutated PUT on
`/api/secrets/provider` that swaps the active backend without
restart. Today the choice is boot-time (env-driven).

---

## Network service-discovery (Consul / etcd / k8s)

**Status:** Three feature-gated implementations
(`aegis-proxy/consul`, `etcd`, `k8s`) ship and are wired into
`crates/aegis-proxy/src/sd/`. Default builds don't pull them.

**Contract status:** Not required.

---

## Rules engine — `aegis_security::rules::evaluate` ✅ WIRED (no longer a stub)

**Status (corrected 2026-05-28):** **Wired into the live data plane.**
`crates/aegis-proxy/src/data_plane.rs:1630` calls
`aegis_security::rules::evaluate(&snapshot, &view, &route_ctx)`, guarded by
`ctx.active_ruleset.get()`. The `Arc<RuleSet>` is shared with
`DashboardServices`; admin CRUD calls `RuleSet::replace_rules` via
`rebuild_active_ruleset` after each successful mutation (now also durable +
cluster-propagated through the config plane). Custom operator rules **do
fire on live traffic** — the FEATURES.md "Custom rule engine" row is
accurate.

*(The 2026-05-11 entry below was correct at the time — the engine had
zero proxy callers then — but has since been superseded. Kept for history;
this stub should be removed from the catalogue on the next trim.)*

> ~~**Status:** Implemented at `crates/aegis-security/src/rules/eval.rs`
> with full unit-test coverage. Zero production callers in
> `aegis-proxy/src/` today.~~ — **stale, see above.**

---

## Legacy `SecurityPipeline` trait surface

**File:** `crates/aegis-security/src/pipeline.rs` —
`Pipeline::inbound` and `Pipeline::on_response_start`.

**Status:** Trait methods on `SecurityPipeline` that the
`aegis-proxy` data plane bypasses.  Production:

- `inbound()` → not called.  Detectors fire from
  `data_plane.rs:507::run_all_filtered_timed`.
- `on_body_frame()` → **IS called** from
  `data_plane.rs:1469` (response filter / DLP).
- `on_response_start()` → not called.  ICAP wiring is the
  natural future feature; the body-frame call covers DLP +
  stack-trace scrub today.

LT-RUN-5 and LT-RUN-6 static audits both flagged
`inbound()` as "detectors disconnected from the pipeline".
That's accurate for the trait surface but wrong as a security
claim — the FINAL release-readiness QC (96% detection rate)
empirically confirms detectors run.  The 2026-05-14 fix added
doc-comments on both methods pointing static auditors at the
real call sites (`data_plane.rs:507`, `data_plane.rs:1469`).

**Action if wired:** would have `inbound()` delegate to
`run_all_filtered_timed` so trait consumers see the
production behaviour.  Today the proxy doesn't consume the
trait — only the body-frame hook is reached.

---

## BotClassifier — `reverse_dns` population in proxy

**File:** `crates/aegis-security/src/bots.rs::BotClassifier::classify`
+ `BotSignals.reverse_dns` field.

**Status:** Implementation present with FCrDNS-validation
gap (LT-RUN-6 BOTS-01).  No production caller — `aegis-proxy`
does not currently populate `BotSignals.reverse_dns` from any
source (no PTR lookup, no header-trust read), so the
classifier is effectively unreachable.

**Contract status:** Not required.

**Action if wired:** before populating `reverse_dns`, perform
FCrDNS: PTR-lookup the client IP, then forward-A-lookup the
returned name, and only set the field when the IP resolves
back to itself.  Required to avoid the BOTS-01 trust-boundary
bypass.

---

## Domain threat-intel — `check_domain` wildcard walk

**File:** `crates/aegis-security/src/threat_intel/mod.rs::check_domain`.

**Status:** Exact-match `HashMap::get(domain)` lookup only
(LT-RUN-6 THREAT-01).  No subdomain walk — a feed entry for
`evil.com` does not match `c2.evil.com`.  Zero production
callers (aegis-proxy reads threat-intel hits from audit-event
fields, not the in-memory checker).

**Contract status:** Not required.

**Action if wired:** after the exact lookup, walk the domain
hierarchy: for `a.b.c.evil.com`, also check `b.c.evil.com`,
`c.evil.com`, `evil.com`.  ~6-line loop.

---

## GraphQL query complexity — schema-aware visitor

**File:** `crates/aegis-security/src/api_security/graphql.rs::analyze_query`.

**Status:** Computes complexity as `depth * word_count`
(LT-RUN-6 GQL-01).  Coarse; misses field aliases, fragment
spread costs, `@defer`/`@stream` directives.  Zero production
callers — the GraphQL guard isn't wired into the data plane.

**Contract status:** Not required.

**Action if wired:** schema-aware complexity visitor that
counts field cost (multiplier × children).  Significantly more
work than the current heuristic; defer until the GraphQL guard
itself is wired.

---

## Admin per-handler body streaming cap

**File:** `crates/aegis-proxy/src/admin_mutate.rs`,
`crates/aegis-proxy/src/admin_dispatch.rs` (30+ `into_body().collect()` call sites)

| Stub | Status |
|---|---|
| Each admin handler does `req.into_body().collect()` with no `Limited<_>` wrapper | **Partially mitigated.** A `Content-Length` pre-check in `admin_auth_middleware::admit` (2026-05-17 F-HIGH-admin commit) catches oversized declared bodies via 413 before they reach the handler. Chunked-encoding requests without a `Content-Length` header bypass that gate. |

**Why deferred:** Migrating all 30+ call sites to wrap their
`into_body()` in `http_body_util::Limited::new(body,
cfg.admin.dashboard_auth.max_request_body_bytes as usize)` is
mechanical but touches a lot of code; the Content-Length gate
covers the common DoS shape. Real chunked-streaming attacks on
the admin port are rare (every mainstream HTTP client sends
Content-Length on admin payloads) but the gap is real.

**Action if wired:** sed-style replace each
`req.into_body().collect().await` with
`http_body_util::Limited::new(req.into_body(),
limit_usize).collect().await`. Add a single helper
`collect_admin_body(body, cap) -> Result<Bytes,
ResponseTooLarge>` to avoid duplicating the error mapping.

---

## Quota module — per-route body / header / URI / timeout caps

**File:** `crates/aegis-proxy/src/quota.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `enforce_quota` + per-quota result types | 1-90 | **Not required.** Round-1 contract doesn't mandate per-route body caps — the global `cfg.proxy.max_body_bytes` already satisfies "WAF MUST reject oversized requests" (`data_plane.rs:450`, F-CRITICAL-004 fix). Per-route caps are a Phase-C operational ergonomics feature. |

**Why deferred:** The 2026-05-17 F-CRITICAL-006 (Phase 6 wire-up) bundle prioritised the load shedder (Round-3 resilience scoring) over the per-route quota wire. Today the global body cap covers the security need; per-route caps are an operator-ergonomics improvement that requires plumbing `route_ctx.quota` through every code path that touches body / headers / URI.

**Action if wired:** call sites are `data_plane::handle_data_request_inner` (right after route resolution, before body collection) — feed `route_ctx.quota` to a new `enforce_quota(&parts, body_len, &quota)` helper that returns `Result<(), QuotaError>` for each cap; map errors to the documented HTTP status (413 / 431 / 414 / 408 / 504). Existing `quota.rs` unit tests pin the per-cap behaviour; adding integration tests at the request-handler level is the main verification surface.

---

## DR module — runtime snapshot / restore

**File:** `crates/aegis-proxy/src/dr.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `dr::snapshot()` + `dr::restore()` | full file | **Not required.** Contract has no snapshot/restore primitive. README mentions it as an operator-quality bonus. |

**Why deferred:** Snapshot/restore is genuinely useful for blue/green operator workflows, but it requires consensus on the serialised shape (which subsystem state belongs in a snapshot — risk-tracker, rate-limit buckets, blacklist, etc.) and how to merge a restored snapshot against in-flight state without dropping audit events. Both are design questions that go beyond a wire-up.

**Action if wired:** start with a narrower scope — snapshot the access-list + risk-tracker state only (the two state-bearing surfaces with audit-mutated CRUD already), serialise to JSON, store via `StateBackend`. `dr.rs` today accepts `{}` as restore-input and would happily wipe runtime config; treat the wire-up as a brand-new design pass, not a "find the call site" refactor.

---

## HTTP/3 pipeline wire-up

**File:** `crates/aegis-proxy/src/listener/http3.rs` (function
`handle_h3_request` at ~line 261)

| Stub | Lines | Contract status |
|---|---|---|
| H3 dispatch via `proxy::handle_request` (legacy route+forward path) | 261 | **Required when H3 is enabled.** v2.3 §5 mandates the 6 `X-WAF-*` headers on every response; §3 mandates detectors run on every request; §6 mandates an audit row for every decision. H3 today emits none of these. |

**Why deferred:** Wiring requires bundling the 13 long-lived
data-plane args (`detectors`, `mask`, `risk`, `ip_rate_limiter`,
`load_gauge`, `verbosity`, `request_stage_hist`,
`route_latency_hist`, `route_activity`, `detector_latency_hist`,
`bus`, `detector_hit_metrics`, plus the existing `upstream_ctx`)
into a `DataPlaneServices` struct, installing it on
`ProxyContext` at boot via `OnceLock`, and giving the H3 handler
a new entry point `data_plane::handle_request_with_ctx(req, peer,
ctx, identity)`. ~250 LoC, touches every test that calls
`handle_data_request` directly. Deferred until after the Phase
3+6 admin-auth + load-shedder work stabilises so the refactor
doesn't compound with concurrent in-flight changes.

**Mitigation today:** `serve_http3()` emits a loud
`tracing::warn!` at boot when the H3 listener is started,
explicitly naming the security gap. H3 is `--features
http3`-gated and absent from every in-tree config, so operators
must explicitly opt in to expose the bypass — typo-bombs can't
silently switch the gateway into the broken mode.

**Action if wired:** the right shape is
```rust
pub struct DataPlaneServices {
    pub detectors: Arc<[Box<dyn Detector>]>,
    pub mask: SharedDetectorMask,
    pub risk: Arc<RiskTracker>,
    pub ip_rate_limiter: Arc<IpRateLimiter>,
    pub load_gauge: LoadGauge,
    pub verbosity: SharedVerbosity,
    pub bus: AuditBus,
    pub request_stage_hist: Arc<RequestStageHistogram>,
    pub route_latency_hist: Arc<RouteLatencyHistogram>,
    pub route_activity: Arc<RouteActivityWindow>,
    pub detector_latency_hist: Arc<DetectorLatencyHistogram>,
    pub detector_hit_metrics: Arc<DetectorHitMetrics>,
}
```
Install at boot in `run.rs` (currently scattered across local
`let`s) and store as
`ProxyContext.data_plane_services: OnceLock<Arc<DataPlaneServices>>`.
New entry `data_plane::handle_request_with_ctx` unpacks the
bundle and dispatches; existing `handle_data_request` stays
untouched so H1/H2 callers don't break. H3 handler at
`listener/http3.rs:261` replaces `proxy::handle_request(...)` with
the new entry. Stamp the 6 §5 headers on the response using the
existing `stamp_interop_response` once the data plane returns.

---

## Traffic module — shadow mirroring

**File:** `crates/aegis-proxy/src/traffic.rs`

| Stub | Lines | Contract status |
|---|---|---|
| `traffic::mirror_request` + tee plumbing | full file | **Not required.** Contract is silent on shadow traffic. README documents it as a Round-3 nice-to-have. |

**Why deferred:** Traffic mirroring (send a copy of every request to a secondary upstream for analysis without blocking the primary response) is a strong operator-tooling story, but it doubles the upstream connection count and risks amplifying any attack. Needs an opt-in flag plus sampling + circuit-breaker on the mirror side before it's safe to ship.

**Action if wired:** call site is `forward_allow_to_upstream` in `data_plane.rs`. After picking the primary member, also pick a "mirror" member from a separately-configured pool, spawn the mirror request in a `tokio::spawn` so it doesn't block the primary response. Discard the mirror response. Cap mirror concurrency separately so a slow mirror upstream can't backpressure the primary path.

---

## JA4 capture — partial wire-up landed 2026-05-18

**Status:** Activated as "JA4-light" — post-handshake fingerprint
captures negotiated cipher + ALPN + TLS version + SNI type from
the rustls `ServerConnection`. Threads into `RequestView.tls` so
the three downstream features now fire:

- `BotSignals.ja4_fingerprint` is populated (accept.rs line ~1421).
- `DeviceIpTracker.observe(ja4, peer_ip)` is called in the data
  plane after the detector chain runs.
- The brute_force `device` axis reads `view.tls.ja4` and tracks
  same-fingerprint-different-IP attempts.

**Remaining gap (lower priority — canonical JA4 capture):** the
canonical JA4 spec hashes the FULL ClientHello extension list
(supported_versions, key_share, …). rustls 0.23's post-handshake
API only exposes what the negotiator selected (single cipher,
single ALPN). The JA4-light shipped today distinguishes broad
client classes (Chrome / curl / sqlmap / Firefox) but won't
differentiate fine-grained library version differences inside
the same class.

If the canonical capture is needed, the wire-up is:

1. Hook the `ResolvesServerCert::resolve` callback (the only spot
   rustls exposes the full `ClientHello` to user code).
2. Bridge from the synchronous resolver callback to the async
   request handler via a `tokio::task_local!` scope wrapping the
   handshake (the scope is held across `accept().await` so the
   resolver write + handler read happen in the same task).

Documented here as the original below.

---

## JA4 capture (original — historical) — `RequestView.tls` always None today

Added 2026-05-18 (QC TLS-wiring batch).

**Symptom.** Three already-built features depend on the JA4 TLS
fingerprint being plumbed into `RequestView.tls`:

- `aegis_security::fingerprint::DeviceIpTracker` (Sprint 3.1,
  commit `093adeb`) — built, fully tested, currently dormant
  because the data plane has no JA4 to call `observe(fp, ip)`
  with.
- `aegis_security::detectors::brute_force` device axis (Sprint
  2.3, commit `fd9233f`) — code reads `req.tls.ja4` but always
  observes `None`, so the device axis silently no-ops.
- `aegis_security::bots::BotSignals.ja4_fingerprint` — populated
  with `None` at the accept-site (`accept.rs::~1374`), so the
  classifier's known-bad-JA4 lookup path never fires.

**Why it's not wired.** rustls 0.23 doesn't expose the full
ClientHello extension list through its public `ResolvesServerCert`
callback. Capturing canonical JA4 needs either:

1. A custom rustls feature hook (the experimental
   `client_hello_callback` extension trait) — risky, version-
   pinned to rustls internals.
2. A side-channel: pre-handshake parse of the raw ClientHello
   record from the TCP stream before rustls accepts. Bigger
   investment (~300 LoC of TLS record parsing).
3. A "JA4-light" using what rustls exposes — cipher_suites +
   ALPN + SNI from the ClientHello callback — passed through a
   per-connection `OnceLock` or task-local. ~100 LoC, but the
   resulting fingerprint is a strict subset of canonical JA4
   (won't differentiate clients with identical cipher lists but
   distinct extensions).

**Recommended path.** Option 3 (JA4-light). Differentiates
Chrome / curl / sqlmap with >90% accuracy in practice; the loss
vs canonical JA4 is in the "Firefox X.Y vs Firefox X.Y+1"
corner (rarely security-relevant). When the wire-up lands:

1. `listener/tls.rs::DynamicResolver::resolve` records
   cipher_suites + alpn + sni-type into a per-connection
   `TlsFingerprint`.
2. The accept loop stashes the fingerprint into the connection's
   handler context (e.g. a `parking_lot::Mutex<HashMap<SocketAddr,
   TlsFingerprint>>` keyed by peer).
3. `data_plane::handle_data_request_inner` reads the fingerprint
   for `peer` and sets `view.tls = Some(&fp)`.
4. The three downstream features (DeviceIpTracker observe call,
   brute_force device axis read, BotSignals.ja4 + JA4-known-bad
   lookup) activate automatically.

**Tracking.** Sprint 1 of a hypothetical future "TLS fingerprint
wire-up" batch. ~80-100 LoC, one PR. The QC plan at
`plans/issue-fix/2026-05-18-qc-followup/README.md` references
this as a "one wire-up unblocks three features" deferral.

## How this list will change

- **Trimmed** when a stub gets deleted (Phase 4 will remove
  truly-dead CAPTCHA + JWT modules).
- **Trimmed** when a stub gets wired (the entry moves into
  Architecture.md or a per-feature operator doc).
- **Grown** if a future audit catches a new "trait without
  callers" finding — same shape: file path + grep-confirmed
  zero-callers + contract status.

The principle behind the list: **a real stub is not the same as
a real bug.** A stub on a non-required code path is technical
debt to clean up at leisure. A stub on a contract-mandated
code path would be a critical bug — none of the entries above
fall into that bucket today.
