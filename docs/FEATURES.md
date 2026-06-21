# Aegis-Gate — Feature Test Playbook

Single source of truth for **what the WAF does** and **how to verify each
feature works**. One row per feature. One concrete click path or curl per
verification. Pass criteria are explicit so a tester (engineering or
otherwise) can work through this top to bottom and produce a report.

> **Want to understand the *why* behind these tests?** Read
> [`security/security-engine.md`](security/security-engine.md) first.
> That's the narrative walkthrough — request → routing → access gate
> → detector chain → risk + tier gate → decision. This file is the
> verification grid that complements it.

**Audience**: QC, operators, anyone bringing the system up for the first
time and wanting to know everything's wired.

**How to use**: spin up `make run-dev`, log into the dashboard at
`https://127.0.0.1:9443/` (`admin` / `aegis-test-1234`), then go through
the sections below. Each row has Verify / Expected — when both line up,
that feature is good.

**Last refreshed**: 2026-05-04 — features inventoried against the live
binary. When something here drifts from reality, file an issue or fix
the doc.

---

## Quick legend

- ✅ **Live & verifiable** — works in `make run-dev` today, has a concrete how-to-test recipe.
- 🟡 **Live but YAML-only** — feature is implemented, but admin UI for it isn't. Test by editing the config and restarting.
- 🟦 **Optional / feature-gated** — only when you build with the right `--features` and supply the operator artifact (model, GeoIP DB, …).

Each Verify column gives you the smallest steps that prove the feature
works. Many of them have deeper docs linked from the row.

---

## 0 · One-shot smoke test (≈ 60 seconds)

Run these four commands. If all four pass, the system is wired well
enough to start the rest of the playbook.

| # | Command | Expected |
|---|---|---|
| 1 | `make setup && make run-dev` | Boots without panic. Last log line includes `data-plane listening on 0.0.0.0:8080` and `admin-plane listening on 127.0.0.1:9443`. |
| 2 | `curl -fsS http://127.0.0.1:9443/healthz/ready` | Returns 200 with `"status":"ok"`. |
| 3 | `curl -i http://127.0.0.1:8080/` | Returns either 200 or 502 (502 = upstream stub not running, that's fine). What matters: it's reachable and Aegis returned a response. |
| 4 | Open `https://127.0.0.1:9443/` in a browser, accept the self-signed cert, log in with `admin` / `aegis-test-1234` | Dashboard loads. Sidebar shows 17+ pages. Top-right shows your username + a sun/moon theme toggle. |

If any of those four fail, fix that before going further — nothing
below will work.

---

## 1 · Data plane (the proxy)

| Feature | Verify | Expected |
|---|---|---|
| ✅ HTTP/1.1 listener | `curl -i http://127.0.0.1:8080/` | Response with `HTTP/1.1` status line. |
| ✅ HTTPS listener (TLS 1.2+) | `curl -ki https://127.0.0.1:8443/` | Response with `HTTP/1.1` (or `HTTP/2`) status line, TLS handshake succeeds with the dev cert. |
| ✅ HTTP/2 ALPN | `curl --http2 -ki https://127.0.0.1:8443/` | `HTTP/2` status line. |
| ✅ Routing — exact host match | Add a route on **Routing & Upstreams** page with Host = `vnexpress.net`, Path = `/news`, then `curl -H 'Host: vnexpress.net' http://127.0.0.1:8080/news` | The route resolves; status reflects what the upstream returned (or 502 if no member). Audit chain shows `route_id`. |
| ✅ Routing — wildcard host | Add route with Host = `*.localhost`, then `curl -H 'Host: foo.localhost' http://127.0.0.1:8080/` | Route matches; route table tie-breaks correctly (exact > wildcard > catch-all). |
| ✅ Routing — first-match-wins ordering | Add a more-specific route above the catch-all, drive traffic to its path | First match takes the request; subsequent routes are skipped. Confirm in audit chain. |
| ✅ Catch-all guard | Try to delete the only catch-all route from the dashboard | UI surfaces `409 last_catchall` — refused to brick traffic. |
| ✅ Per-protocol upstream schemes | Edit a pool's `connection.scheme` to one of `http / https / h2c / grpc / auto / tcp` | Routing forwards correctly per scheme. See `docs/operator/upstream-cookbook.md` for one recipe each. |
| ✅ Multi-vhost upstream (`host_header`) | Pool member with `host_header: "example.com"` and a public-TLS upstream IP | Upstream sees `Host: example.com`, TLS SNI is `example.com`, cert validates. |
| ✅ WebSocket bridge | `wscat -c ws://127.0.0.1:8080/some-ws` against a route whose pool is `scheme: http` or `https` | WS handshake completes (101 Switching Protocols); audit chain shows `ws-open` then `ws-close` events when the client disconnects. |
| ✅ TCP CONNECT tunneling | Route with `scheme: tcp` + a `tcp_destination_allowlist`. `curl -x http://127.0.0.1:8080 https://example.com` | Tunnel establishes; non-CONNECT methods on the same route get 502 `non_connect_to_tcp_route`. |
| ✅ Upstream load balancing | Pool with 2+ members and `lb: round_robin`. Drive 10+ requests | Member picker rotates. Watch `Routing & Upstreams` → expanded route → member traffic. |
| ✅ Upstream circuit breaker | Stop one of the upstream members, drive traffic | Breaker opens after `error_rate_threshold` is exceeded; `open_duration` later it half-opens and re-probes. |
| ✅ Upstream health probe | Pool with a `health.path` configured | Member is marked unhealthy if the probe fails > N times consecutively. |
| ✅ Per-route quotas | Route with a `quota.body_size` set, send a body that exceeds it | Returns 413 (Payload Too Large). |
| ✅ PROXY protocol (real client IP behind an L4 LB) | Listener `accept_proxy: strict` + `proxy.trusted_proxies` set; front with nginx `stream proxy_protocol on;`. Drive attacks as client A, benign as B (`tests/cluster/10-proxy-protocol-client-ip.sh`) | Per-IP risk climbs for A while B stays clean (buckets no longer collapse onto the LB IP); audit `ip` = real client, `proxy_via` = LB hop; `waf_proxy_protocol_events_total{result="parsed"}` increments. A header from an untrusted source closes the connection. See `config/REFERENCE.md#listeners`. |
| 🟦 HTTP/3 | Build with `--features http3`, configure QUIC bind | Browser fetch over h3 succeeds. |

---

## 2 · Security pipeline

### 2.1 Detectors

| Feature | Verify | Expected |
|---|---|---|
| ✅ SQLi detector | `curl 'http://127.0.0.1:8080/?q=1%27%20OR%20%271%27%3D%271'` | 403; audit chain shows `detectors: ["sqli"]`. |
| ✅ XSS detector | `curl 'http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E'` | 403; audit `detectors: ["xss"]`. |
| ✅ Path traversal detector | `curl 'http://127.0.0.1:8080/files?p=../../../../etc/passwd'` | 403; audit `detectors: ["path_traversal"]`. |
| ✅ SSRF detector | `curl 'http://127.0.0.1:8080/fetch?url=http://169.254.169.254/'` | 403; audit `detectors: ["ssrf"]`. |
| ✅ Header injection detector | `curl -H 'X-Custom: foo%0d%0aX-Injected: bar' http://127.0.0.1:8080/` | 403; audit `detectors: ["header_injection"]`. |
| ✅ Body abuse detector | POST with deeply nested JSON or a 10 MB body | 413 / 400; audit `detectors: ["body_abuse"]`. |
| ✅ Recon / scanner detector | `curl http://127.0.0.1:8080/.env` or `/.git/config` | 403; audit `detectors: ["recon"]`. |
| 🟦 AI detector (`--features ai`) | Build with the feature, set `cfg.ai.enabled: true`, drive an attack request | Detectors page shows `aegis_ai_predictions_total{verdict=attack}` ticking up; runtime toggle on/off works via the page's Enable/Disable button. |
| ✅ Detector mask runtime toggle | Detectors page → click on a class pill (e.g. `xss`) and Edit → flip off → Save | Saves with audit chain entry; same xss attack now passes through (status 200 / upstream response). Flip back on, attack blocks again. Hot-swap, no restart. |
| ✅ Per-tier mask overrides | Detectors page → `+ Edit` on a tier row → flip a class | Per-tier override appears under the base mask; routes pinned to that tier follow the override. |

### 2.2 Rules + risk

| Feature | Verify | Expected |
|---|---|---|
| ✅ Custom rule engine | Rule Manager → New rule → write DSL → Save & deploy | Rule lives, request matching the pattern triggers configured action + `risk_delta`. |
| ✅ Risk score (per-request) | Drive a request that triggers two detectors at once | Audit chain shows the summed score; if it crosses the route's tier `risk_threshold`, request is blocked. |
| ✅ IP cumulative strike | Hammer the WAF with 5+ attacks from `127.0.0.1`, then send a benign request | Investigation page → Recent requests: the benign request shows `IP risk` ≥ the cumulative score (decays linearly at `trust_recovery.per_hour`, default 30/hr, applied on read). |
| ✅ Strike gate (block on accumulated score) | Set `risk.thresholds.block_threshold` lower, drive enough attacks to cross it | Subsequent requests from the same IP are blocked by the strike gate even if they themselves carry no detector signal. |
| ✅ Risk reset (per IP) | Tracking → Risk → click `Reset` on an IP row | Audit chain entry; subsequent fetches show that IP back to score 0. |

### 2.3 Access lists

| Feature | Verify | Expected |
|---|---|---|
| ✅ Blacklist by IP | Access Lists → Blacklist → Add `kind: ip`, `value: 8.8.8.8` → Save. Then `curl -H 'X-Forwarded-For: 8.8.8.8' http://127.0.0.1:8080/` | Request is rejected at the gate before the detector chain runs. Audit `class: access`, action `block`. |
| ✅ Blacklist by CIDR | Same flow with `kind: cidr`, `value: 8.8.8.0/24` | All IPs in the range are blocked. |
| ✅ Blacklist by ASN | Same flow with `kind: asn`, `value: AS15169` | All IPs from that ASN are blocked (requires GeoIP ASN DB). |
| 🟦 Blacklist by country | Run `make geoip-link COUNTRY_DB=/path/to/GeoLite2-Country.mmdb`, restart, then add `kind: country`, `value: CN` | All IPs from that country are blocked. |
| ✅ Whitelist (with bypass scope) | Access Lists → Whitelist → Add `kind: ip`, `value: 10.0.0.1`, `bypass: ["sqli","xss"]` | Requests from that IP skip listed detectors but still run others. |
| ✅ Whitelist (full bypass) | Same flow with `bypass: ["all"]` | Requests bypass the entire pipeline (use sparingly — auditors will read the reason field). |
| ✅ Access-list audit chain | Every add/delete | Entry appears on Audit Trail with class `admin` or `access`. |

### 2.4 Tiered protection

| Feature | Verify | Expected |
|---|---|---|
| ✅ Tier definitions read | Detectors page → tier list (left pane) | Shows critical/high/medium/low with their pipeline + thresholds. |
| ✅ Tier editor (audit-mutated) | Click `Edit tier` → toggle pipeline checkboxes / change thresholds → Save | Audit chain entry; tier list updates. **Note**: pipeline list is descriptive metadata today (mask is the runtime gate). |
| ✅ Per-route `tier_override` | Routing & Upstreams → edit a route → Tier override dropdown → Save | Route gets pinned to that tier; the route's tier shows in the table. |

### 2.5 Bot management + behavioural

| Feature | Verify | Expected |
|---|---|---|
| ✅ JA4 / JA3 fingerprint | Drive HTTPS traffic with curl + with `chrome` (different TLS stacks) | Investigation → Recent requests detail drawer shows different fingerprints. |
| ✅ HTTP/2 fingerprint | HTTPS with `--http2` from different clients | h2 fingerprint surfaces in the request inspector. |
| ✅ Behavioural analysis | Drive 50+ random-looking requests from the same IP | Anomaly score climbs; shows on the IP detail panel. |
| 🟡 Challenge ladder (JS / CAPTCHA) | Implemented but rarely surfaces in dev. Can flip via cfg.challenge | Use an aggressive risk gate to provoke. |

---

## 3 · Control plane (admin / dashboard)

### 3.1 Auth + admin

| Feature | Verify | Expected |
|---|---|---|
| ✅ Argon2id password login | `https://127.0.0.1:9443/admin/login` with the dev creds | 200; session + CSRF cookies set. Wrong password → 401, rate-limited after N attempts. |
| ✅ CSRF double-submit | `curl -X PUT http://127.0.0.1:9443/api/detectors -d '{}'` (no CSRF) | 403 with `reason: "csrf_missing_cookie"`. |
| ✅ Session expiry redirect | Wait for the cookie to expire and try a mutation | Dashboard toasts "Session expired — redirecting to login…" and bounces you to `/admin/login`. |
| 🟡 TOTP enrollment | `waf admin enroll-totp --issuer Aegis --account you@x.com` | Generates a TOTP secret + recovery codes. Login flow includes TOTP step when `dashboard_auth.totp_required: true` in cfg. |
| ✅ Zero Trust — downstream mTLS | `zero_trust.downstream.mode: required` + `ca_bundle` + `apply_to: [admin]` | The listener accepts only requests presenting a client cert that chains to the bundle (and matches the SAN allowlist, if set). |
| ✅ Zero Trust — upstream mTLS | Zero Trust page (Beta): store the WAF identity, upload a backend CA, enable a pool's drawer | The WAF presents its shared client cert + verifies the backend; fail-closed on an unverifiable backend. Handshake failures surface on the page. See [`docs/security/zero-trust-mtls.md`](security/zero-trust-mtls.md). |
| ✅ IP allowlist on admin | `admin.allow_ips: [127.0.0.1/32]` in cfg | Other IPs get rejected at the gate before auth runs. |

### 3.2 Audit-mutated CRUD (the daily-driver paths)

For each, do the operation in the dashboard, then verify Audit Trail
(class chip = `admin + sys`) shows the entry, AND the live state
reflects without restart.

| Surface | Verify |
|---|---|
| ✅ Routes — add / edit / delete | Routing & Upstreams page modals. Last-catch-all delete refused with 409. |
| ✅ Upstream pools — add / edit / delete | Same page. Delete refused with 409 if any route still references the pool. |
| ✅ Inline pool create from Add Route | Type a backend address in the route modal's "Forward to" field → pool + route both saved in one shot. |
| ✅ Detector mask | Detectors page → Edit row → Save. |
| ✅ AI detector runtime on/off | Detectors page → AI row → Enable/Disable button. |
| ✅ Tier definitions | Detectors page → Edit tier → Save. |
| ✅ Custom rules | Rule Manager → New / Edit / Delete. |
| ✅ Access lists | Blacklist + Whitelist add / delete. |
| ✅ Mode (enforce / log_only) | Settings → Mode toggle. |
| ✅ Risk thresholds | Settings → Risk thresholds form. |
| ✅ Alert receivers (VipTalk / Slack-shape) | Settings → Alert channels. |
| ✅ Drain | Topbar drain button or `POST /admin/drain`. `/healthz/ready` returns 503 immediately after. |

### 3.3 Read-only surfaces

| Page | Verify |
|---|---|
| ✅ Overview | KPIs + per-pool upstream tile (with "1 of 1 members up" or similar — not "no members configured") + live attack-origins map (real lat/lon, not stacked at 0,0). |
| ✅ Live Feed | SSE-driven; rows scroll in real time as `make mock-load` fires. Proto pill on each row distinguishes `http` / `ws-open` / `ws-close` / `tcp-open`. |
| ✅ Investigation | Recent requests table newest first; click any row → request inspector. Detector breakdown + bot-mix donuts on the right. |
| ✅ Top Attackers | List of IPs with hits / categories / risk / country. Click → pivot into Investigation. |
| ✅ Threat Intel | Read-only view of feeds. Edit via YAML + restart for now. |
| ✅ Compliance | Read-only view of active modes + clamped detectors. Edit via YAML + restart. |
| ✅ Performance | Per-stage and per-route p50 / p95 / p99 from live Prometheus histogram. |
| ✅ Health & SLOs | SLO burn rate + alert receivers + cluster peers + cert freshness. |
| ✅ Audit Trail | Hash-chained event log. Defaults to `admin + sys` (config history). Class chip flips to `requests` or `all`. |
| ✅ Scaling | Tokio workers / blocking pool / I/O FDs / state-backend health. |
| ✅ Settings | Mode, risk thresholds, alert channels, admin password rotation pointer. |
| ✅ Reports | CSV export for audit trail (last 200 / 1000). Top-attackers + compliance-snapshot CSVs not wired yet. |
| ✅ Help & Guide | This playbook's companion in the SPA — Get started / How it works / Glossary / Workflows / FAQ. |

---

## 4 · Observability

| Feature | Verify | Expected |
|---|---|---|
| ✅ Prometheus `/metrics` | `curl http://127.0.0.1:9443/metrics \| head -50` | OpenMetrics; ~70+ series including `waf_requests_total`, `waf_detector_hits_total{class=…}`, `waf_request_duration_ms_bucket`, etc. |
| ✅ Audit chain durability | `tail /tmp/aegis-dev-audit.jsonl` | NDJSON, one event per line. Hash chain verifiable: `waf audit verify --from /tmp/aegis-dev-audit.jsonl`. |
| ✅ Audit chain witness | `waf audit verify` returns `chain ok` and the last witness signature | Tampering with any line breaks the chain — verifier reports the offending seq. |
| 🟦 OTel tracing (`--features otel`) | Build with otel + point at a Jaeger collector | Traces appear with `#[tracing::instrument]` spans per request. |
| ✅ SIEM forwarding | Configure `cfg.audit.sinks: [jsonl, syslog, cef, leef, ocsf, splunk_hec, kafka]` | Each sink format documented in `docs/observability/siem-log-forwarding.md`. |
| ✅ Three Grafana dashboards | `make obs-up` → http://localhost:3000 (admin/admin) | "Aegis WAF Overview", "Aegis Runtime", "Aegis Redis" dashboards pre-loaded. |

---

## 5 · Operations / day-2

| Feature | Verify | Expected |
|---|---|---|
| ✅ Hot config reload (file) | Edit `config/dev.yaml` (e.g. add a route under `routes:`), save | notify-watcher picks up the change; the proxy hot-swaps within ~100 ms. Verify in Audit Trail. |
| ✅ Cluster config plane (multi-node) | `state.backend: redis`; edit via the dashboard / admin API on any node | Console edits write `config:waf:doc` + converge on every node within ~3 s; survive restart + leader failover. See `docs/operations/cluster-config-distribution.md`. |
| ✅ HA mode (Redis-shared state) | `make redis-up` (auto), profile uses `state.backend: redis` | Two WAF replicas share rate-limit counters + leader leases; one acquires the ACME lease. |
| ✅ Distributed lock (lease) | Two replicas + a leader-only task (ACME renewal) | Only one replica drives the leader-only task; the other is idle until the leader's lease expires. |
| ✅ Graceful drain | Topbar drain button or `kill -TERM <pid>` | `/healthz/ready` returns 503; in-flight requests finish; LB stops sending new traffic. |
| ✅ Binary handover (`SIGUSR2`) | `kill -USR2 $(pgrep waf)` against a release binary on Linux | New binary starts, inherits listener FDs; old finishes in-flight, exits cleanly. (See `plans/binary-handover-fd-pass.md`.) |
| ✅ Snapshot + restore | `waf snapshot --output /tmp/snap.json` then `waf restore --from /tmp/snap.json` against a fresh instance | Config + rules restored. JSON envelope carries blake3 hash + schema version. |
| ⚠ Compliance modes (deferred) | `cfg.compliance.modes: [pci, hipaa, soc2, gdpr, fips]` | Modes are accepted as documentation tags and surface on the Compliance dashboard. Auto-pinning detector classes / per-regime enforcement is **deferred** — see `plans/future/compliance-profiles.md`. |
| ✅ Data residency / GDPR erasure | `POST /api/gdpr/erase {subject_id: "..."}` | Audit chain rewires to remove the subject's IP/identity from past events; chain stays valid. |
| 🟦 Cloud secrets (`--features vault`/`aws`/`gcp`/`azure`) | `${secret:vault:/path#field}` references in cfg | Resolved at boot from the live secret backend. |
| 🟦 Service discovery (`--features consul`/`etcd`/`k8s`) | Configure the watcher; backend members come from the live SD source | Pool members refresh as upstream endpoints change. |

---

## 6 · CLI

```sh
waf run       --config <path>     # boot the gateway
waf validate  --config <path>     # dry-run config validation (no listeners)
waf audit     verify --from <p>   # hash-chain integrity check
waf admin     set-password        # generate argon2id password hash
waf admin     enroll-totp         # TOTP secret + recovery codes
waf snapshot  --output <p>        # bundle config + rules + integrity envelope
waf restore   --from <p>          # restore from a snapshot (validates first)
```

Each subcommand should respond to `--help` with usage info.

---

## 7 · How to file findings

For each row above that doesn't pass:

1. **What you ran** — exact command / click path.
2. **What you expected** — quote the row's "Expected" column.
3. **What happened** — actual output. Include status code, response body, audit chain entry (or absence of one), and console error if any.
4. **Severity** — Critical (security regression / data loss) · High (workflow blocker) · Medium (cosmetic / wrong copy) · Low (suggestion).
5. **Reproducer** — minimum steps from a clean `make run-dev`.

Attach to the relevant track plan in `plans/` or open a new issue.

---

## Where to dig deeper

- Per-detector behaviour + corpus — `docs/security/detectors/<name>.md`
- Per-protocol upstream recipes — `docs/operator/upstream-cookbook.md`
- Operator runbook (config, monitor, incident) — `docs/operator/usage.md`, `docs/operator/soc-runbook.md`
- API contract for scripting — `docs/control-plane/api.openapi.yaml`
- Implementation status per doc — `plans/implementation-matrix.md`
- Architecture deep-dive — `Architecture.md`
- Manual scripts you can rip — `tests/manual/`
- Live dashboard help (companion to this doc) — Help & Guide page in the SPA
