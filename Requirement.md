# WAF — Requirements

## 1. Problem Statement

Build a production-grade Web Application Firewall / Security Gateway in
Rust that acts as a full reverse proxy in front of arbitrary web
backends. Every HTTP/HTTPS request from the internet passes through the
WAF before reaching the backend, and every response from the backend
passes through the WAF before returning to the client.

**Scope.** Attackers do not only target `/login`. They scan `/admin`,
`/api/*`, static assets, and everything in between. The WAF therefore
protects **all** routes transparently, not a curated subset.

**Transparency.** Backend applications must not require code changes,
header awareness, or protocol awareness to benefit from the WAF.

**Deployment target.** Enterprise environments (fintech, healthcare,
public sector) with high availability, multi-tenancy, compliance, and
observability demands comparable to F5 BIG-IP ASM, Imperva, Akamai Kona,
and Cloudflare Enterprise.

---

## 2. High-Level Architecture

```
                 ┌──────────────────────────────┐
Internet ─────►  │   WAF / Security Gateway     │  ─────► Backend Pools
                 │   (reverse proxy + pipeline) │
                 └──────────────────────────────┘
                              ▲
                              │ control plane (dashboard, admin API,
                              │ metrics, health, audit)
                              │
                          Operators
```

The WAF runs as a cluster of stateless data-plane nodes sharing
distributed state (rate limits, risk scores, block lists, challenge
nonces). A separate control-plane listener carries the dashboard, admin
API, Prometheus scrape, and health probes.

---

## 3. Core Requirements

- **Language:** Rust, single static binary (`./waf run`).
- **No runtime dependencies** beyond the OS and the configured state
  backend.
- **Full bidirectional HTTP/HTTPS reverse proxy** with inbound and
  outbound inspection on every request.
- **Performance targets:**
  - p99 WAF-overhead latency ≤ 5 ms under nominal load
  - ≥ 5 000 requests/second per node, horizontally scalable
- **Horizontal scaling** via shared state backend — any node can serve
  any request, no sticky routing required for correctness.
- **Hot reload** of config, rules, secrets, and TLS certificates
  without dropping connections.
- **Dual-listener model:** public data-plane listener (`:443`) is
  never reachable from the admin plane, and vice versa.

---

## 4. Routing & Multi-Host

The WAF serves many sites from one binary via a declarative route
table (nginx `server {}` / Kubernetes `Ingress` style).

- Route shape: `{ id, host, path, match_type, methods, upstream_ref,
  tier_override, transforms, auth, quotas, tenant_id }`
- **Host matching:** exact (`api.example.com`), wildcard suffix
  (`*.example.com`), regex (opt-in), SNI-cross-checked when TLS is
  terminated.
- **Path matching:** exact, prefix, regex, or glob. Longest-match wins;
  ties broken by declaration order.
- **Method filter** per route (default: all).
- **Tier override:** a route can pin or raise its tier (e.g. `/admin/*`
  → CRITICAL).
- A catch-all route is required; the loader rejects configs that
  cannot match every request.
- Route metadata (name, description, owner) is surfaced in the
  dashboard.

---

## 5. Upstream Pools & Load Balancing

Each route points at a **named pool** of backend members.

- Pool shape: `{ name, members: [{addr, weight, zone}], lb, health,
  circuit_breaker, tls }`
- **LB algorithms:** round-robin, weighted round-robin, least-connections,
  consistent-hash (keyed by client IP, cookie, header, or JWT claim),
  power-of-two-choices.
- **Active health checks:** periodic HTTP probe (path, method, expected
  status, interval, timeout). Unhealthy members leave rotation.
- **Passive health checks:** N consecutive upstream 5xx / connect errors
  mark a member unhealthy for T seconds.
- **Per-member circuit breaker** with `closed → open → half-open`
  state machine and configurable error-rate threshold.
- **Per-pool keepalive connection pool** sized independently.
- **Graceful member drain:** removed members finish in-flight before
  being dropped.
- **Outlier detection** (bonus): p99 latency deviation triggers
  ejection.
- **Slow-start** (bonus): newly-healthy members ramp traffic gradually.

---

## 6. Traffic Management

- **Weighted splits** between pools for canary releases
  (e.g. `v1: 95%, v2: 5%`), with optional sticky assignment per
  client so a user lands on the same side for the session.
- **Header / cookie steering** — route to pool B when a specific
  header or cookie is present (A/B tests, dogfood).
- **Retries** with a per-pool budget: max attempts, per-try timeout,
  retryable status set, and a cluster-wide budget ratio to prevent
  retry storms.
- **Shadow mirroring:** fire-and-forget copy of the request to a
  second pool for replay or perf testing; response discarded, latency
  never charged to the user.
- **Automatic rollback** (bonus) on canary error-rate regression.

---

## 7. TLS Termination & Certificate Management

- **`rustls`-based termination** with a dynamic `ResolvesServerCert`
  that selects the right cert per SNI hostname.
- **Hot reload** of certificates from disk (file watcher) without
  dropping established connections.
- **TLS 1.3** enabled by default; TLS 1.2 allowed via config; TLS < 1.2
  refused under PCI or FIPS modes.
- **Strong cipher suite defaults**; weak suites refused at config load.
- **ACME auto-issue and renewal** (Let's Encrypt) via HTTP-01 or
  TLS-ALPN-01.
- **OCSP stapling** with background refresh.
- **mTLS to upstream** — per-pool client certificate + CA bundle.
- **FIPS mode:** only `aws-lc-rs` FIPS-validated provider loaded.
- **HSM / PKCS#11** (bonus) — private keys never leave the HSM.

---

## 8. Protocol Support

- **HTTP/1.1** baseline with configurable header/body/URI limits.
- **HTTP/2** on both listener and upstream side, including HPACK caps
  and a rapid-reset (CVE-2023-44487) mitigator.
- **WebSocket upgrade passthrough** — the security pipeline inspects
  the upgrade request, then the connection is tunneled transparently
  with idle + lifetime timeouts.
- **gRPC passthrough** (HTTP/2 + trailers) with per-method routing.
  No protobuf inspection.
- **HTTP/3** (QUIC) listener — optional, feature-gated.
- **gRPC-Web** (bonus) bridging to plain gRPC.

---

## 9. Tiered Protection Policy

Routes fall into one of four tiers, resolved **after** route matching
and subject to per-tenant overrides.

| Tier | Typical routes | Policy | Failure mode |
|---|---|---|---|
| **CRITICAL** | `/login`, `/otp`, `/deposit`, `/withdrawal`, `/payments/*` | Per-user rate limit, device FP, behavioral + transaction velocity, challenge, positive API schema | **Fail-close** |
| **HIGH** | `/api/*`, `/user/*`, `/game/*` | DDoS, rate limit (IP + session), OWASP detection, smart caching, bot filter | Fail-open |
| **MEDIUM** | `/static/*`, `/assets/*`, `/public/*` | Basic rate limit, path-traversal detection, aggressive caching | Fail-open |
| **CATCH-ALL** | `/**` | Baseline SQLi / XSS detection, rate limit, known-bad IP blocking, full logging | Fail-open |

- **Fail-close (CRITICAL):** any subsystem error, timeout, or panic
  blocks the request with 503. Better to refuse a login than allow one
  through an unchecked pipeline.
- **Fail-open (other tiers):** a failing layer is skipped, logged, and
  the request continues. A broken anomaly detector must not knock a
  static-asset endpoint offline.
- Per-route `failure_mode` override is allowed for non-CRITICAL routes
  that want stricter behavior.

**Global rules applied to every request regardless of tier:** inbound +
outbound inspection, audit logging, risk score calculation, global
blacklist enforcement, response header hardening.

---

## 10. Security Pipeline

### 10.1 Rule engine

- Conditions on IP, path, host, method, header, query, cookie, body,
  JWT claim, bot class, threat-feed label, tenant id, device fingerprint,
  and schema-violation events.
- **Match types:** exact, regex, wildcard, CIDR, AND / OR / NOT.
- **Actions:** allow, block, challenge (by level), rate-limit,
  raise-risk, transform, log-only.
- **Priority-based evaluation**; first matching terminal action wins.
- **Scope:** global, tier, route, tenant, IP, session, device.
- **Rule files hot-reload** via a filesystem watcher; the full rule
  set is swapped atomically through an `ArcSwap<Vec<Rule>>`.
- **Rule linter** enforces id uniqueness, depth limits, and priority
  sanity; failing the linter at load time refuses the change.

### 10.2 Rate limiting

- **Sliding window** and **token bucket** algorithms.
- **Scope** per rule: IP, session, device, tenant, route, global.
- **Backed by the state backend** so a cluster-wide limit holds across
  all nodes. A Lua script provides an atomic sliding-window check on
  Redis.
- **Local fallback** when the state backend is unreachable, reconciled
  on recovery via `max(local, remote)` so counters never drop.

### 10.3 DDoS protection

- **Per-IP burst detection** with a short sliding window; exceeding the
  threshold auto-blocks the IP for a configurable TTL.
- **Global rate-spike detection:** when cluster-wide RPS exceeds
  `rolling_avg * spike_multiplier`, DDoS mode tightens thresholds and
  forces challenges on new sessions.
- **Cluster-wide block list** in the state backend — blocking on one
  node blocks everywhere.
- **Per-tenant scope:** a flood against tenant A does not affect
  tenant B.

### 10.4 Attack detection (OWASP Top 5+)

- SQL injection, XSS, path traversal, SSRF, HTTP header injection,
  brute force / credential stuffing, reconnaissance scanners, request
  body abuse (oversized, deeply-nested).
- Detector output feeds both the rule engine (as conditions) and the
  risk engine (as signals).

### 10.5 Risk scoring and challenge

- Composite identity `RiskKey = (ip, device_fp, session, tenant_id)`.
- Score contributions from detectors, IP reputation, bot class,
  behavioral anomalies, transaction velocity, and threat-intel feeds.
- Score decays over time; canary-route hits set the score to max
  instantly.
- **Decision thresholds:**
  - `< 30` → allow
  - `30 – 70` → challenge
  - `> 70` → block
- **Challenge escalation ladder:** `None → JS → PoW → CAPTCHA → Block`,
  driven by `(risk, human_confidence, bot_class, tier)`.
- **Challenge tokens** are HMAC-signed, single-use via a nonce stored
  in the state backend, and non-downgradable within their TTL.
- **CAPTCHA providers:** Cloudflare Turnstile, hCaptcha, Google
  reCAPTCHA v3 — pluggable via a `CaptchaProvider` trait.
- **Human-confidence score** persists across sessions and decays; a
  returning legitimate user sees fewer challenges.

### 10.6 Device fingerprinting

- **JA4** (primary) and **JA3** (legacy) from the TLS `ClientHello`.
- **HTTP/2 fingerprint** from the `SETTINGS` frame + pseudo-header
  order.
- **UA entropy + header-order** for non-TLS paths.
- **Composite device id** via `blake3` over the above.
- **Clustered device store** so a fingerprint seen on one node is
  recognized elsewhere within replication latency.
- Fingerprints are per-deployment-salted hashes; privacy by default.

### 10.7 IP reputation

- Per-tenant **blacklist**, **whitelist**, and **trusted-proxy** CIDR
  lists, hot-reloadable.
- **ASN classification** (MaxMind GeoLite2-ASN or commercial) with
  configurable risk deltas per category (`residential`, `hosting`,
  `vpn`, `tor`, `bogon`).
- **XFF validation** against `trusted_proxies` — the WAF walks the
  chain from the right and ignores XFF entirely when the TCP peer is
  not trusted.
- **Threat-intel feed integration** (§23).

### 10.8 Response filtering

- Stack-trace scrubbing (Python, JVM, Node, Rust, PHP, .NET, Rails, Go).
- Internal IP masking (RFC 1918, link-local, loopback, ULA).
- Information-leak header stripping (`Server`, `X-Powered-By`, …).
- **Security header injection** (`X-Content-Type-Options`,
  `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`,
  `Permissions-Policy`, `Content-Security-Policy`).
- **DLP bridge** (§24).
- **Streaming** frame processor so large responses never balloon
  memory.

---

## 11. External Authentication (data plane)

Distinct from control-plane auth (§21).

- **ForwardAuth** — subrequest to a configured auth service; copy
  whitelisted response headers onto the forwarded request. Failure
  mode honors the route tier.
- **JWT validation** against a JWKS endpoint with a `moka`-backed
  cache and stale-on-error. Claims are exposed to the rule engine and
  projected as headers.
- **OIDC relying party** for browser traffic (session cookie via
  PASETO v4 local tokens).
- **HTTP Basic** against a secret-provider-backed password file.
- **IP allow / deny** per route reusing the reputation primitives.
- **OPA / Rego callout** (bonus).

---

## 12. Request / Response Transformations

- Add / set / remove request and response headers per route, with
  variable expansion (`$host`, `$client_ip`, `$request_id`, `$jwt.sub`,
  `$cookie.<name>`, `$header.<name>`).
- URL **rewrite** (regex), **prefix strip**, **prefix add**, and
  **redirect** (301/302/307/308) with target templating.
- **CORS** handler with preflight, origin allow-list (including
  wildcard subdomain), credentials flag, and exposed-header list. The
  WAF answers preflight directly unless the route opts out.
- Response-body rewrite hooks reuse the streaming redactor from §10.8.

---

## 13. Per-Route Quotas & Buffering

- `client_max_body_size`, request header total size, URI length.
- Read / write timeouts, upstream connect / request timeouts,
  absolute request duration ceiling.
- **Buffering vs streaming** mode per route — streaming opts out of
  body-dependent detectors, used for large uploads.
- **Tier defaults** with per-route and per-tenant overrides.
- Distinct HTTP status per quota (`413`, `431`, `408`, `504`, `503`)
  and an audit event naming the specific quota.

---

## 14. Session Affinity

- **Cookie-injected sticky session** — the WAF sets an HMAC-signed
  cookie naming the chosen pool member; subsequent requests with that
  cookie route to the same member if still healthy.
- **Consistent-hash fallback** (by client IP, cookie, header, or JWT
  claim) when the cookie is absent.
- **Failure handling:** ejected or draining members fall back to the
  pool's primary LB strategy and re-issue the cookie.

---

## 15. Observability

### 15.1 Prometheus

- `/metrics` endpoint on the control-plane listener.
- Counters, gauges, and histograms for: requests by tenant / route /
  tier / decision / status, detector hits, rule hits, risk-score
  buckets, upstream latency + circuit state, challenge issue / pass /
  fail counts, state-backend op latency, audit sink throughput and
  drops, config reload outcomes, retry + shadow counts.

### 15.2 Distributed tracing

- **W3C Trace Context** — accept and propagate `traceparent` /
  `tracestate` headers; generate a root span when absent.
- Server span `waf.request` with child spans for rule-engine, each
  detector, upstream, and challenge.
- **OTLP exporter** over gRPC or HTTP/protobuf (feature-gated).

### 15.3 Access logs

- Configurable format: nginx `combined`, JSON (ECS-compatible), or a
  user-supplied template with `$var` placeholders.
- Written to stdout, rotating file, or a dedicated audit sink.

### 15.4 Health endpoints

- `/healthz/live` — process alive.
- `/healthz/ready` — ready to serve (state backend reachable, certs
  loaded, ≥ 1 healthy upstream member per pool).
- `/healthz/startup` — first config load complete.

---

## 16. Audit Logging

- **Stable JSON schema** with a `schema_version` field; breaking
  changes require a bump.
- **Tamper-evident hash chain:** `hash = SHA-256(prev_hash ||
  canonical_json)` over detection and admin classes, periodically
  signed and exported to an external **witness** (S3 Object Lock, an
  append-only log service, or a blockchain anchor). A CLI
  (`waf audit verify`) walks the chain and reports any break.
- **SIEM sinks:** JSON Lines, Syslog RFC 5424, CEF, LEEF, OCSF,
  Splunk HEC, Elastic ECS, Kafka. Each sink is a dedicated tokio task
  with a bounded channel, on-disk spool, and priority drop policy
  (lowest severity first, admin + critical never dropped without
  paging).
- **Separate admin change log** with its own hash chain, recording
  actor, target, diff, reason, and approver.
- **Retention** per event class with compliance floors (e.g. PCI ≥ 90 d).

---

## 17. Zero-Downtime Operations

- **Graceful drain on `SIGTERM`:** stop accepting new connections,
  finish in-flight within a bounded TTL, then exit. The health probe
  goes `not-ready` immediately so L4 LBs bleed traffic away.
- **Worker model** via `SO_REUSEPORT` so N workers share the listener
  with kernel-level load balancing.
- **Hot binary reload:** new process inherits the listening socket via
  FD passing (SCM_RIGHTS). Old process drains; new process accepts;
  rollback on readiness-probe failure.
- **Dry-run validation** — every config reload (file, Git pull, admin
  API) performs a **full compile + lint + compliance check** before
  the atomic swap. Malformed updates are rejected; the running config
  is preserved.
- **TLS cert hot reload** via `ArcSwap<CertStore>`; in-flight
  handshakes finish on the old cert while new ones pick up the new
  cert.

---

## 18. Service Discovery (optional)

Upstream pool membership may be populated dynamically from an
external source so scaling events don't require a config edit.

- **File watcher** (JSON / YAML list).
- **DNS SRV** records (via `hickory-resolver`).
- **Consul** (long-poll `/v1/health/service`).
- **etcd v3** (prefix watch).
- **Kubernetes Endpoints** API (informer, feature-gated).

Safety limits: minimum-member floor, maximum churn-per-interval cap.
Added members enter `probing` before joining the LB ring; removed
members drain.

---

## 19. High Availability & Clustering

A single-node WAF is unacceptable in production.

- **Stateless data plane.** Any node can serve any request; no
  sticky client-to-node affinity required for correctness.
- **Shared distributed state** for rate-limit counters, risk scores
  per `(ip, device_fp, session, tenant)`, auto-block list with TTL,
  challenge-token revocation / nonce set, device fingerprints, and
  session metadata.
- **Pluggable state backend:** `in_memory` (single-node dev), `redis`
  / `redis_cluster` (default prod), embedded `raft` (via `openraft`),
  and `foca` SWIM gossip for advisory soft state.
- **Cluster membership** via gossip or a control-plane registry;
  nodes exchange health and load hints.
- **Multi-region active-active** with eventually-consistent replication
  and configurable per-zone read/write preference.
- **Split-brain safety:** counters reconcile via `max(local, remote)`
  so a healed partition never lowers a limit; block lists are strictly
  additive.
- **Leader tasks** (threat-intel fetch, ACME issuance, Git sync, hash
  chain witness export) elect a leader via a lease key in the state
  backend.
- **Rolling restart:** at least one healthy node per zone remains
  serving during upgrades.

---

## 20. Compliance

The WAF is deployable into environments governed by common compliance
regimes without architectural surgery. Modes **stack**; the strictest
setting from any active mode wins, and conflicting config is refused
at load time.

- **FIPS 140-2 / 140-3:** only `aws-lc-rs` FIPS-validated primitives;
  TLS / HMAC / PRNG restricted to the FIPS allowlist; non-FIPS
  algorithms refused at config load.
- **PCI-DSS v4.0:** PAN masking in logs and responses; TLS 1.2+ only
  on PCI-scope listeners; ≥ 90-day audit retention; no CVV / CVC
  storage anywhere.
- **SOC 2:** tamper-evident audit log (hash-chained), administrative
  change trail, access review exports, SLI / SLO monitoring.
- **GDPR:** PII redaction before logs leave the node, data-residency
  pinning, right-to-erasure admin endpoint, retention ceilings.
- **HIPAA:** PHI-safe log mode suppressing request bodies and flagged
  headers on PHI routes; BAA-relevant dedication flags.

A **compliance-mode profile** flips all of the above into their
strictest setting with a single config switch.

---

## 21. Administrative Access Control (RBAC + SSO)

The dashboard and admin API are privileged surfaces gated by
enterprise identity controls.

- **Separation** of data-plane and admin-plane listeners on distinct
  addresses; admin-plane behind **mTLS + OIDC**.
- **Roles:** `viewer`, `operator`, `admin`, `auditor`,
  `break_glass`. Per-endpoint role requirements enforced server-side
  via `require_role!`.
- **OIDC SSO** (Okta, Azure AD, Google Workspace, Keycloak) with
  group-claim → role mapping. Local users only as a break-glass
  fallback.
- **MFA** enforced for `operator`+ when the IdP supports it.
- **API tokens** for automation with scoped permissions, IP allowlist,
  and TTL; stored as `argon2` hashes.
- **Admin IP allowlist** enforced in addition to auth.
- **Session timeout** + absolute session lifetime.
- **Change approval:** mutations to CRITICAL-scope config require a
  second admin to approve before activation.
- **Admin change audit log** records actor, target, diff, reason, and
  approver, hash-chained separately from the detection log.
- **SCIM** provisioning and **WebAuthn** enforcement (bonus).

---

## 22. Secrets Management

Sensitive material (TLS private keys, HMAC challenge secrets, JWT
signing keys, upstream client certs, database passwords, cloud
credentials) **must not** live in plaintext YAML.

- **Reference syntax** in config: `${secret:<provider>:<path>[#field]}`
  placeholders resolved at load time.
- **Providers:** environment variables, file (with mode enforcement),
  HashiCorp Vault (KV v2 + dynamic creds), AWS Secrets Manager, GCP
  Secret Manager, Azure Key Vault, PKCS#11 HSM.
- **Rotation without restart** — the config watcher re-resolves
  secrets on provider change notifications; affected subsystems
  (TLS, HMAC, upstream mTLS) reload atomically.
- **Memory hygiene:** secret material is held in `zeroize`-ing
  containers and wiped on drop.
- **No secrets in logs**, ever. `/api/config` returns the
  `${secret:...}` reference string, never the value.

---

## 23. Multi-Tenancy

A single WAF fleet may serve many independent customers or business
units.

- **Tenant** is a first-class config entity: id, name, owner, quotas,
  allowed hosts, tier overrides, rule namespace, audit sinks, data
  residency.
- **Isolation boundaries:** routing (allowed-hosts match), state
  keyspace (every key prefixed by `tenant_id`), audit + metrics
  (labeled and projected through the token claim), rules
  (namespaced), secrets (tenant-scoped provider mounts).
- **Per-tenant quotas:** requests/sec, concurrent connections, log
  volume, risk-store entries, rule count, route count, body size.
  Exceeding quota load-sheds that tenant only.
- **Per-tenant dashboards** with data isolation — a tenant's `viewer`
  cannot see another tenant's traffic.
- **Per-tenant compliance profile** — one tenant can run in FIPS mode
  while another does not.
- **Security floors:** cluster admins set minimum CRITICAL controls,
  TLS version, retention, and required detectors that a tenant cannot
  weaken.
- **Noisy-neighbor protection** via the adaptive load shedder (§28).

---

## 24. Threat Intelligence

- **IOC feed ingestion:** IP, CIDR, domain, URL, JA3/JA4, ASN, file
  hash.
- **Formats:** plain-text, CSV, JSON, **STIX 2.1** over **TAXII 2.1**,
  MISP.
- **Multiple concurrent feeds** with per-feed confidence and severity
  scoring.
- **Automatic refresh** with exponential backoff; TTL-respected
  eviction.
- **Feed provenance** on every decision — audit events carry
  `feed_id` + `confidence` so analysts can trace the chain
  `block → rule → indicator → feed → source`.
- **Confidence → action** mapping configurable (`block` / `raise_risk` /
  `watch`).
- **Local override list** wins over imported feeds.
- **Bidirectional sharing** (bonus): publish observed attacker IPs
  upstream.

---

## 25. Data Loss Prevention

- **Pattern library:** credit-card numbers (Luhn validated), SSN,
  IBAN (mod-97), US phone / email / DOB, AWS / GCP / Azure / Stripe /
  GitHub / Slack / Twilio keys, private keys (PEM headers), JWT
  tokens, HIPAA identifiers (opt-in).
- **Custom patterns** via regex with a named `value` capture.
- **Actions per match:** redact, shape-preserving mask
  (`****-****-****-1234`), format-preserving encryption (AES-FF1
  tokenization), HMAC-hash, or block.
- **Inbound and outbound scanning.**
- **Audit redaction:** every audit event runs through DLP before
  emission.
- **Per-tenant, per-route policies.** Shared pipeline with response
  filtering (§10.8).
- **FPE key rotation** is versioned so existing tokens stay
  decryptable until retired.

---

## 26. API Security (Positive Security)

- **OpenAPI 3 schema enforcement:** path, method, parameters,
  headers, body must match the schema. Modes: `enforce`, `monitor`,
  `learn`.
- **Validation errors** include a JSON-pointer path for audit
  precision; client-facing error detail is minimized to prevent
  enumeration.
- **GraphQL protection:** depth limit, node-count limit, complexity
  cost budget, introspection toggle, persisted-query allowlist.
- **Mass-assignment protection:** reject unknown fields on strict
  schemas.
- **Request signing:** HMAC verification for machine-to-machine APIs
  (AWS SigV4-style or custom).
- **API-key management:** per-consumer keys with rate limits and
  scopes.
- **Positive + negative defense in depth:** positive enforcement runs
  before detectors; schema-accepted requests still face detectors.
- **Learn mode** records observed traffic into a synthesized spec for
  operator review and promotion.

---

## 27. Advanced Bot Management

- **Classification tiers:** `human`, `good_bot`, `likely_bot`,
  `known_bad`, `unknown`.
- **Good-bot verification** for Googlebot, Bingbot, LinkedInBot, etc.,
  via forward-confirmed reverse-DNS with cached results.
- **Signal set:** JA4 / JA3 / h2 fingerprint, header order, UA
  entropy, reverse-DNS, threat-intel labels, behavioral patterns,
  failed-challenge history, ASN + IP reputation.
- **Pluggable classifier:** shipped rule set plus optional
  model-backed classifier (feature-gated).
- **Actions:** map class to block / challenge / allow-rate-limited /
  tier-default.
- **Behavioral biometrics and device attestation** (bonus) — mouse /
  keystroke rhythm, iOS App Attest, Android Play Integrity.

---

## 28. Content & Upload Security

- **Magic-byte** file-type detection (not `Content-Type`).
- **Allowlist** of acceptable types per route.
- **Max file size** and **max total multipart size** enforcement.
- **Archive-bomb** protection (depth + ratio limits).
- **Antivirus scan** via **ICAP** (RFC 3507) to an external engine
  (ClamAV, Trend, Sophos, commercial AV). Both REQMOD (inbound) and
  RESPMOD (outbound) supported.
- **Clean-hash cache** to avoid re-scanning identical known-good
  payloads.
- **Scan timeout** applies the route's failure mode (fail-closed for
  CRITICAL by default).
- **Sandbox detonation** and **EXIF / steganography scrubbing** (bonus).

---

## 29. Adaptive Load Shedding

Under extreme load the WAF **must degrade gracefully** rather than
collapse.

- **Per-pool adaptive concurrency** using a Gradient2-style algorithm
  (`L(t+1) = L(t) * (RTT_min / RTT_now)`) — no static ceiling to tune.
- **Priority classes:** CATCH-ALL dropped first, then MEDIUM, then
  HIGH; CRITICAL is never shed by the adaptive layer (only by
  actual security decisions).
- **CPU-aware backstop** from `/proc/stat` or cgroups `cpu.stat`.
- **Per-tenant `concurrency_soft` / `concurrency_hard`** so a burst
  from one tenant never starves another.
- **Coordination with DDoS mode** — thresholds tighten further when
  global DDoS mode is active.
- **Load-shed response:** immediate `503` with `Retry-After` and a
  WAF request id, no pipeline cost, no upstream contact.

---

## 30. Disaster Recovery & Backup

- **Config snapshot / restore:** full effective config (routes, rules,
  tenants, secret references) exported as a versioned archive.
- **State snapshots** of the state backend (Redis RDB + AOF, Raft log
  + snapshot) replicated across AZs and archived to S3 hourly.
- **Audit log backup** via at-least-once delivery to SIEM + S3 Object
  Lock + witness anchor.
- **RPO targets:** ≤ 5 minutes for security state; 0 for config (Git).
- **RTO targets:** ≤ 30 minutes for a region failover; ≤ 4 hours for
  a cold-start region rebuild.
- **Restore validation:** restored config is dry-run validated before
  activation.
- **Quarterly restore drills** with audit evidence.

---

## 31. Data Residency & Retention

- **Region pinning** per tenant — audit sinks, state-backend writes,
  and metric exports honor the pin. `strict` mode refuses
  non-compliant sinks; `preferred` mode warns.
- **Retention policies** per event class: access logs 30 d default,
  security events 365 d default (90 d PCI floor), admin change log
  7 y (SOC 2 floor), challenge state hours, fingerprints 24 h.
- **Right-to-erasure** (GDPR Art. 17): admin API purges identified
  records from operational state; audit-log entries are pseudonymized
  in place so the hash chain stays valid. Dual-control required.
- **Data export** (GDPR Art. 20) streams subject records as JSONL.
- **Pseudonymization after N days:** salted-hashed client IP / UA /
  JWT sub.
- **Encryption at rest** for local spool files and snapshots.

---

## 32. Change Management & GitOps

- **Declarative config is the single source of truth** in a Git repo.
- **Signed commits only** — the loader verifies GPG or SSH signatures
  against an `allowed_signers` file at every pull.
- **CI lint pipeline** runs the same validator the runtime uses, so a
  passing CI guarantees a passing runtime.
- **Admin-approval floors:** merges to `rules/core/` or `tenants/`
  require at least 2 approvers, one `admin`.
- **Runtime pull:** the cluster leader polls (or receives a webhook);
  new commits run the dry-run validator before `ArcSwap` swap.
- **Direct API / dashboard edits** (break-glass) are allowed but
  **automatically round-trip** as a branch + PR against the repo. A
  banner warns until the PR is merged; the next Git pull will revert
  an unmerged emergency change.
- **Audit export** of all changes with actor, time, diff, approver.

---

## 33. SLO / SLI & Alerting

- **SLIs:** availability (non-5xx / total), latency overhead
  (p50/p95/p99), upstream availability, admin API availability, audit
  delivery rate, config freshness, cert freshness. Latency SLIs
  measure **WAF overhead**, not end-to-end, so a slow backend does
  not poison the WAF SLO.
- **SLOs:** data-plane availability 99.99% / 30 d, latency p99
  overhead ≤ 5 ms in 99% of 1-min windows, audit delivery 99.999%,
  cert freshness ≥ 7 days remaining.
- **Multi-window, multi-burn-rate alerts** (Google SRE pattern):
  fast (1 h / 2% budget), slow (6 h / 5%), trickle (3 d / 10%).
- **Alert routing:** Alertmanager compatible plus direct webhook
  (Slack, PagerDuty, ServiceNow, Jira) receivers.
- **Runbooks** referenced on every alert with symptom, mitigation,
  root-cause probes, and escalation path.

---

## 34. Deliverables Checklist

- [ ] `./waf run` starts from a single static binary
- [ ] Hot reload of config, rules, secrets, and certificates
- [ ] Multi-host routing with SNI-checked host matching
- [ ] At least two upstream pools demonstrating LB + health checks
- [ ] Canary split between two pools with sticky assignment
- [ ] TLS termination with hot-reloaded certificates
- [ ] HTTP/2, WebSocket upgrade, and gRPC passthrough verified
- [ ] ForwardAuth + JWT validation integration tests passing
- [ ] `/metrics` endpoint scraped by Prometheus successfully
- [ ] `traceparent` propagation to upstream verified
- [ ] Graceful drain under load (no dropped in-flight requests)
- [ ] Hot binary reload keeps connections alive across upgrade
- [ ] Dry-run validator blocks an intentionally malformed rule
- [ ] Two-node cluster sharing rate-limit + risk state via Redis
- [ ] FIPS-mode config profile boots successfully
- [ ] Audit-log hash chain verified tamper-evident
- [ ] Secrets resolved from Vault; rotation works without restart
- [ ] Admin listener gated by OIDC + RBAC; `viewer` cannot mutate
- [ ] Two tenants isolated: tenant A cannot see tenant B's data
- [ ] Syslog / CEF / OCSF forwarder delivering to a test SIEM
- [ ] STIX / TAXII feed imported; blocks show feed provenance
- [ ] Turnstile CAPTCHA fallback working in challenge escalation
- [ ] OpenAPI schema enforcement blocking a malformed request
- [ ] DLP pattern masking a synthetic credit card in a response
- [ ] ICAP antivirus integration on an upload route
- [ ] Load shedding kicks in under overload; CRITICAL traffic unaffected
- [ ] Config snapshot → restore round-trip succeeds
- [ ] `/healthz/*` endpoints return correct states at each lifecycle phase
- [ ] SLO burn alert fires via Alertmanager on synthetic regression
- [ ] Red-team attack simulation (SQLi / XSS / SSRF / brute force) blocked
- [ ] Load test sustains ≥ 5 000 RPS with p99 overhead ≤ 5 ms
