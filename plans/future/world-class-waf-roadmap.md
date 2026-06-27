# World-class WAF roadmap (north star)

> **Status:** Drafted 2026-05-28. **This is the ordering document for
> `future/`** — it grades Aegis-Gate against the 2025–2026 WAAP leaders
> (Cloudflare, Akamai, Imperva; also F5, Fastly, Radware), names the real
> gaps, and sequences them. The other files in `future/` are the
> per-feature specs; this file says *which to do next and why*.
>
> Built from two inputs: (1) a market scan of the Gartner WAAP Magic
> Quadrant + the leaders' 2025 product announcements (sources at the
> bottom), and (2) a **code-verified** audit of what Aegis actually ships
> on `develop` as of this date — not what the docs claim. Per the standing
> caution that repo docs drift both ways, so every "have / don't have"
> below was grep-checked against `crates/`.

---

## 1. Method + honest baseline

**What Aegis-Gate already does well** (verified in code, not just docs):

- **Data plane**: HTTP/1.1, HTTP/2 (+ rapid-reset cap in `proto/h2.rs`),
  WebSocket bridge, TCP CONNECT; routing, upstream pools with
  LB / circuit-breaker / health-probe; per-route quotas. **gRPC is only
  *partial*** — inbound h2-over-TLS + outbound h2 for `scheme: grpc|h2c` pools
  work, but gRPC responses misclassify as `Buffered` so `grpc-status` trailers
  are dropped, and the request body is buffered (client-streaming/bidi can't
  work). h2c is **upstream-only** (the plaintext *listener* is h1-only). See the
  correctness fix in [`grpc-aware-proxying.md`](./grpc-aware-proxying.md).
- **Detectors** (`aegis-security/src/detectors/`): sqli, xss, path
  traversal, ssrf, command injection, nosql injection, open redirect,
  header injection, template injection, body abuse, recon/scanner,
  brute_force, canary, behavior_signals, velocity_sequence, + AI detector
  (`--features ai`). Runtime mask toggle + per-tier overrides.
- **Rules + risk**: custom rule DSL **wired live** (`data_plane.rs:1630`
  `rules::evaluate`), per-request risk sum, cumulative IP strikes + decay,
  strike gate, risk reset.
- **Access control**: IP / CIDR / ASN / country block + whitelist with
  per-detector bypass scopes; PoW challenge.
- **Bot signals**: JA4-light + JA3 + H2 fingerprint, behavioural anomaly,
  an observational bot classifier (`bots.rs`).
- **Control plane**: argon2id + session + CSRF + TOTP + mTLS admin + IP
  allowlist; full audit-mutated CRUD; **cluster config plane** (versioned,
  CAS, per-node ACK, leader failover — just shipped).
- **Observability / ops**: Prometheus, hash-chained audit + witness, SIEM
  sinks (jsonl/syslog/cef/leef/ocsf/splunk_hec/kafka), OTel, Grafana, HA +
  Redis-shared state, snapshot/restore, GDPR erasure, cloud secrets,
  service discovery.

This is already a strong **negative-security** WAF. The gaps below are the
things 2025–2026 **WAAP leaders** ship that Aegis does **not** (or ships
only as un-wired scaffolding).

**The world-class bar (2025–2026).** Gartner's top recommendation for
buyers is **API protection** (discovery of 1st- + 3rd-party APIs, anomaly
+ vuln detection, granular policy). The four capability pillars every
leader now markets: **WAF + API security + bot management + DDoS**, plus
three fast-moving additions — **AI/LLM firewall** (prompt-injection /
jailbreak / output inspection), **client-side protection** (Page Shield /
PCI DSS 4.0.1), and **ML-learned positive security / anomaly detection**.

---

## 2. Gap analysis (code-verified)

| Capability | Leaders ship | Aegis today | Gap |
|---|---|---|---|
| **API security — positive model** | OpenAPI ingest, schema enforcement, API discovery, BOLA/BFLA | `api_security/` module (api_keys, hmac_sign, graphql) **built but NOT wired into the pipeline**; body_abuse + mass-assignment heuristics only | **Large** — Gartner #1 priority |
| **AI/LLM firewall** | Prompt-injection, jailbreak, toxicity, output/egress inspection, embedding-based intent | **Nothing** (the `ai` feature is the WAF's own detector model, not AI-endpoint protection) | **Large / net-new** |
| **Client-side protection** | Page Shield: script inventory, CSP collection, integrity/tamper alerts (PCI DSS 4.0.1 §6.4.3 + §11.6.1) | **Nothing** | **Medium-large / net-new, compliance-forced** |
| **Bot management — enforcement + ML score** | Verified-bot dir, ML good/bad/human score, hard challenges | Classifier is **observational**; `reverse_dns`/FCrDNS not populated; no per-class enforcement | **Medium** (scaffolding exists) |
| **Account takeover / credential stuffing** | Breached-credential feed, login protection, impossible-travel | brute_force + velocity_sequence only | **Medium / net-new** |
| **ML positive-security learning** | Auto-baseline normal traffic → positive model + zero-day anomaly | AI detector + behavioural anomaly, but no auto-learned per-route baseline | **Large** |
| **Managed ruleset / virtual patching** | Curated managed rules (CRS-class) + CVE virtual patches, auto-updated | Custom rules + TAXII threat-intel; no managed signature feed | **Medium-large** |
| DDoS L7 | Adaptive auto-mitigation | Rate limiting + DDoS mode + h2 rapid-reset cap | **Small** (adaptive tuning only) |

Everything else on the leaders' checklists (TLS, mTLS, HA, audit/SIEM,
secrets, SD, GDPR, snapshot) Aegis already has.

---

## 3. The ordered roadmap

Sequenced by **(market priority × compliance urgency × leverage from
existing code) ÷ effort**. Effort: **S** ≤ ~3 d, **M** ~1–2 wk, **L** ~3 wk+.

> **Execution order across both streams** (these capability tiers **and** the
> operational/infra backlog in §"Operational / correctness backlog" below) is
> arranged into dependency-ordered waves in
> [`../implementation-sequence.md`](../implementation-sequence.md) — read it for
> *what-blocks-what* and the recommended interleave.

### Tier 0 — Hygiene (do first, clears the runway) · S

- **Fix the 2 pre-existing red tests** before stacking features on them:
  `aegis-bin state_select::in_memory_selects_in_memory_backend` (reaper
  `tokio::spawn` outside a runtime, `state/in_memory.rs:40`) and the 2
  `dashboard_polish` JS-bundle-budget tests (app.js > 444 KB).
- **HTTP/3 pipeline wire-up** *(security, only if H3 ships)* — `serve_http3`
  bypasses detectors + the 6 `X-WAF-*` headers + audit. It's `--features
  http3`-gated and off by default, so it's not a live exposure, but wire it
  (or keep it gated) **before** anyone enables H3. See
  [`unwired-stubs-catalog.md`](../archive/unwired-stubs-catalog.md) → "HTTP/3".

### Tier 1 — API security · Gartner #1 priority · partial head start

The single highest-value direction. `api_security/` already has the
building blocks; they just aren't on the request path.

- **1A · Wire the existing API guards** *(S, wire-up)* — put `api_keys` +
  `hmac_sign` + the GraphQL guard (`api_security/graphql.rs`: depth /
  complexity / introspection caps) onto the data path, behind a per-route
  `api_security` policy. Code anchors: `api_security/mod.rs` (zero proxy
  callers today), call site alongside `rules::evaluate` in `data_plane.rs`.
- **1B · OpenAPI/JSON-schema positive enforcement** *(M, net-new)* — ingest
  an OpenAPI/JSON-schema per route; validate request (and optionally
  response) shape; reject off-schema params. This is the "positive security
  model" leaders sell. Surfaces in the console as a per-route schema upload.
- **1C · API discovery** *(L, net-new)* — passively learn endpoints + param
  shapes from live traffic; surface an API inventory + flag shadow/zombie
  endpoints. Feeds 1B (suggest a schema) and 1D.
- **1D · BOLA / BFLA detection** *(L, net-new)* — object- and
  function-level authorization anomaly detection (OWASP API Top-10 #1/#5).
  Hardest; do last in the tier, after discovery gives the data.
- Improve **GraphQL complexity** from the current `depth × word_count`
  heuristic to a schema-aware cost visitor once 1A lands
  (`unwired-stubs-catalog.md` → "GraphQL query complexity").

### Tier 2 — AI/LLM firewall · net-new differentiator · M

Every leader shipped a "Firewall for AI" in 2024–2025. Reuses the existing
`ai` detector infra + `dlp/` module, so the lift is below the market-novelty.

- **2A · Prompt-injection / jailbreak detection** *(M)* — request-side
  detection of system-prompt-override / jailbreak / instruction-injection.
  Start heuristic + signature; escalate to embedding-based intent scoring
  via the existing `--features ai` model path.
- **2B · LLM response inspection** *(M)* — output-side: system-prompt leak,
  PII/secret egress (reuse `dlp/`), toxicity. Rides the existing
  `on_body_frame` response-filter hook.
- **2C · AI-endpoint abuse controls** *(S)* — token/cost-aware rate limiting
  for model endpoints (per-key, per-route), built on the rate limiter.

### Tier 3 — Client-side protection (Page Shield) · compliance-forced · M-L

PCI DSS 4.0.1 §6.4.3 (script authorization + integrity) and §11.6.1
(payment-page tamper detection) are **mandatory since 2025-03-31**. Net-new
surface; pairs with [`compliance-profiles.md`](../archive/compliance-profiles.md)
(PCI mode).

- **3A · CSP report collection** *(M)* — inject `Content-Security-Policy-
  Report-Only` + `report-to`, collect violation reports at a new admin
  endpoint, build a per-page script inventory.
- **3B · Script-integrity monitoring** *(M)* — optional lightweight
  monitor script; baseline approved scripts per page; alert on drift /
  new third-party origins (Magecart / formjacking signal).
- **3C · Wire PCI mode** *(S)* — make `compliance.modes: [pci]` actually
  pin §6.4.3/§11.6.1 controls (today modes are doc tags only).

### Tier 4 — Advanced bot management + ATO defense · scaffolding exists · M

- **4A · Bot-classifier enforcement** *(S, plan exists)* — implement
  [`bot-classifier-enforcement.md`](../archive/bot-classifier-enforcement.md):
  FCrDNS `reverse_dns` → `verified`, JS-pass → `human`, per-class
  `action_mapping`. Also closes the `bots.rs` `reverse_dns`-never-populated
  gap (`unwired-stubs-catalog.md` → "BotClassifier").
- **4B · ML bot score** *(M)* — good/bad/human score from the multi-signal
  set (JA4 + H2 fp + behavioural + ASN + rDNS), surfaced per request.
- **4C · Credential-stuffing / ATO** *(M, net-new)* — login-endpoint
  protection: breached-credential check (k-anonymity range API),
  impossible-travel, per-account velocity. Builds on brute_force +
  velocity_sequence + the risk tracker.
- Supporting: [`rule-non-block-actions.md`](../archive/rule-non-block-actions.md)
  (challenge / tarpit / mirror) gives 4A/4C richer responses than block/log;
  [`risk-composite-key-data-plane.md`](../archive/risk-composite-key-data-plane.md)
  finishes the JA4 device-FP axis (S, partial).

### Tier 5 — ML positive-security learning · L

- **5A · Traffic baselining** *(L)* — auto-learn per-route param profiles
  (type / length / charset / enum) → anomaly flags → *suggested* rules an
  operator can promote. The "learning mode → positive model" leaders ship.
- **5B · Adaptive L7 DDoS** *(M)* — auto-tune rate limits + challenge
  aggressiveness from live load (extends DDoS mode).

### Tier 6 — Managed ruleset / virtual patching · M-L

- **6A · Managed ruleset** *(M-L)* — port/adapt an OWASP CRS-class signature
  set into the rule DSL with a signed auto-update channel (reuse the GitOps
  poll driver + TAXII plumbing).
- **6B · CVE virtual-patch feed** *(M)* — curated CVE→rule feed for
  emergency virtual patching.

### Operational / correctness backlog (interleave by capacity)

These aren't "world-class gaps" but are real operator value; slot between
tiers:

- [`alerts-refactor.md`](../archive/alerts-refactor.md) — non-SLO event classes +
  rich chat payload + dedup (high operator value; ~2 d Phase 1).
- [`audit-log-disk-growth.md`](../archive/audit-log-disk-growth.md) — boot disk
  guard + between-run rotation (the 6 GB/min soak finding).
- [`audit-cold-tier-export.md`](../archive/audit-cold-tier-export.md) — persist
  beyond the 200-event ring (v1 JSONL ~30 LoC). **Superseded by the analytics
  track below** for anything past the minimal JSONL dump.
- [`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md) —
  **enterprise analytics + reporting**: turn the ephemeral 15-min in-memory
  attack ring into a durable, historical, queryable warm store (ClickHouse) +
  Analytics Query API + time-range dashboards + scheduled/compliance reports +
  cold Parquet tier. Cloudflare / AWS-WAF / GCP-Cloud-Armor parity. Start at
  P0+P1 (schema + warm writer + query API). **M → L**, phased.
- [`smart-caching.md`](./smart-caching.md) — **per-upstream**, path-scoped
  opt-in response cache; serves repeats without an upstream round-trip, never
  caches CRITICAL tier, with Cache-Deception-Armor + poisoning-safe keys
  (2026-06-06 redesign; supersedes the archived per-tier draft).
- [`config-single-source-of-truth.md`](./config-single-source-of-truth.md) —
  correctness/infra: end the YAML-file vs `config:waf:doc` **dual authority** on
  the live data plane (a stray file save or unrelated API edit silently clobbers
  other keys). Demote the file to **bootstrap + publisher**, make the versioned
  doc the single source of truth, with an explicit Tier-1 (bootstrap-only) /
  Tier-2 (dynamic) / Tier-3 (partial) config split. **Prerequisite** to both
  `config-auto-restore` and `config-etcd-source-of-truth` (one writer first,
  then swap the store). P0 (seed boot file → doc v0) is a standalone win. Carries
  a **long-term arc** (§10): structural `BootstrapConfig`/`DynamicConfig` type
  split → etcd → a config control plane (canary rollout, GitOps reconcile,
  multi-region). **S–M near-term, L+ long-term**, phased.
- [`config-auto-restore.md`](./config-auto-restore.md) — durability: auto
  re-publish last-known-good config after a Redis data-loss wipe (the
  detect+alert half shipped 2026-06-18; auto-restore blocked on a fleet
  split-brain decision).
- [`config-etcd-source-of-truth.md`](../archive/config-etcd-source-of-truth.md) —
  ✅ **SHIPPED 2026-06-25 (PR #86, archived)**: config **and** control
  **source of truth** (`config:waf:doc` + `control:waf:*`) on **etcd** for
  first-class Txn/Watch/Lease + Raft durability, behind the default-off
  `etcd_config` feature (`config_plane.store: shared_state | etcd`, +
  `waf migrate-config-plane` cutover). Ephemeral hot path (`g:*`, cache, leases)
  stays on Redis — a trait split, not a StateBackend port. Default still
  Redis-only. Next config step = **H3** control plane.
- [`grpc-aware-proxying.md`](./grpc-aware-proxying.md) — protocol correctness:
  make gRPC a correct proxy target. Today gRPC responses misclassify as
  `Buffered` and `collect()` drops the `grpc-status`/`grpc-message` trailers →
  **every call looks like an internal error**; client-streaming/bidi deadlock on
  the buffered request body; `proto/grpc.rs` (`is_grpc`, trailer-preserving
  body) is built but dead. **P1 — force the streaming path for gRPC + verify
  trailers survive — is a standalone S correctness win** (fixes unary +
  server-streaming + `grpc-status`, makes `tests/protocols/05-grpc.sh` real).
  **P2 — stream the request body** (the `Full<Bytes>` `PooledClient` is
  client-type surgery) unblocks client/bidi and is a larger, flagged change;
  P3–P6 (wire-up, method-aware policy, stream-level LB/h2c-in, protobuf+gRPC
  health) are deferred. **S near-term (P1), M+ full arc**, phased.
- [`passive-upstream-health.md`](./passive-upstream-health.md) — correctness:
  mark members down from real forward failures (not just active probes), feed
  the LB. Requires a fail-open `LbStrategy::pick` change first.
- [`zone-aware-load-balancing.md`](./zone-aware-load-balancing.md) — locality
  routing: prefer healthy upstream members in the proxy node's own zone with
  safe cross-zone spillover, cutting inter-AZ latency + egress. The per-member
  `zone` field is already plumbed as metadata but no LB logic reads it; needs a
  node self-zone identity first, and shares the `LbStrategy::pick` touchpoint +
  fail-open concern with `passive-upstream-health`. **M**, phased.
- Wire-up backlog (`unwired-stubs-catalog.md`): ICAP content scanning,
  per-route quota enforcement, traffic mirroring, `dr.rs` runtime
  snapshot, JWT validator, OPA client, vendor CAPTCHA, threat-intel
  subdomain walk, canonical JA4. Each is built-but-dormant; wire on demand.

---

## 4. Recommended next move

**Tier 1A (wire the API-security guards)** is the highest-leverage start:
it's an **S** wire-up of code that already exists + ships **Gartner's #1
buyer priority**, and it lays the call-site for 1B–1D. Pair it with the
**Tier 0** test hygiene so the branch is green going in.

If the goal is a **visible differentiator** over a marketing window,
**Tier 2 (AI/LLM firewall)** is the splashier pick and reuses the `ai` +
`dlp` modules — net-new capability for moderate effort.

If a **PCI deadline** is in play for any tenant, **Tier 3** jumps the queue
(it's a hard compliance gate, not a nice-to-have).

---

## 5. Sources (2025–2026 market scan)

- Gartner — *Magic Quadrant / Market Guide for Cloud Web Application & API
  Protection (WAAP)*; leaders Akamai, Cloudflare, Imperva; buyer guidance
  prioritizes API discovery + protection.
  <https://www.gartner.com/en/documents/6353679>
- SDxCentral — *Gartner Names Akamai, Cloudflare, Imperva Cloud WAAP
  Leaders* (capability summary: API discovery, Page Shield client-side,
  bot mitigation).
  <https://www.sdxcentral.com/analysis/gartner-names-akamai-cloudflare-imperva-cloud-waap-leaders/>
- Cloudflare — *Firewall for AI* (prompt-injection / LLM protection).
  <https://blog.cloudflare.com/firewall-for-ai/> ·
  <https://developers.cloudflare.com/waf/detections/firewall-for-ai/>
- Akamai — *Firewall for AI* (input/output guardrails, jailbreak/toxicity).
  <https://www.akamai.com/products/firewall-for-ai>
- Impart Security — *LLM Firewall: unifying AI, API & web app security*
  (embedding-based attack analysis).
  <https://www.impart.ai/blog/introducing-llm-firewall-unifying-security-for-ai-api-web-apps>
- Indusface — *9 Must-Have WAF Features for SaaS Security 2025*
  (client-side protection, granular bot scoring).
  <https://www.indusface.com/blog/waf-features-for-saas-security/>
- Imperva — *Web Application Firewall* product page (RASP + ML positive
  security + API security framing).
  <https://www.imperva.com/products/web-application-firewall-waf/>
