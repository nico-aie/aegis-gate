# SOC Team Operations Runbook

This is the **operations cheat sheet for a SOC analyst** running
Aegis-Gate in front of a production application. It walks through
the full lifecycle — config → build → deploy → login → test →
monitor — with the exact commands a SOC team needs to keep on
hand. For deeper specs, each section links to its canonical doc.

> **Audience.** Security Operations Center (SOC) analysts and
> on-call engineers. Assumes Linux/macOS shell, basic Docker, and
> read access to the WAF host.

---

## 0. Quick reference card

| Need | Command / file |
|---|---|
| Config file | `config/waf.yaml` (production), `config/waf.dev.yaml` (dev) |
| Validate config without booting | `waf validate --config config/waf.yaml` |
| Build release binary | `cargo build -p aegis-bin --release --features redis` |
| Run gateway | `target/release/waf run --config config/waf.yaml` |
| Dashboard URL | `http://<admin-host>:9443/dashboard/` |
| Default dev login | user `admin` / pass `aegis-test-1234` (DEV ONLY) |
| Health probe | `curl http://<admin>:9443/healthz/ready` |
| Metrics endpoint | `curl http://<admin>:9443/metrics` |
| Audit log | `./waf_audit.log` (JSONL hash-chained) |
| Verify audit chain | `waf audit verify --from ./waf_audit.log` |
| Drain a node (graceful) | `curl -XPOST http://<admin>:9443/admin/drain` |
| Live event stream | `curl -N http://<admin>:9443/dashboard/sse` |
| Round-1 acceptance | `bash tests/dashboard/round1-acceptance.sh` |

---

## 1. Config

### Goal

Get a working `config/waf.yaml` before doing anything else. The
WAF refuses to boot if the config doesn't validate.

### Steps

1. **Pick a starting point.**

   | File | When to use |
   |---|---|
   | `config/waf.dev.yaml` | local development; loopback only; password `aegis-test-1234` |
   | `config/waf.yaml` | production template; secrets via `${secret:…}` resolvers |
   | `config/waf.cluster-{a,b}.yaml` | two-node HA fixture for benchmark / test |

2. **Edit safely.** Three rules:

   - **No raw secrets in YAML.** Use `${secret:vault:path#field}`,
     `${secret:aws:arn#field}`, `${secret:gcp:resource#field}`,
     `${secret:azure:vault:secret#field}`, `${secret:env:NAME}`,
     or `${secret:file:/path}`.
   - **Listen addresses come in pairs:** one data plane (`8080` / `8443`),
     one admin plane (`9443`). Bind admin to loopback or restrict
     via `admin.dashboard_auth.ip_allowlist`.
   - **Pick a state backend.** `state.backend: in_memory` for
     single node; `state.backend: redis` with `state.redis.url`
     for HA. Cluster-shared rate limits + leases require Redis.

3. **Validate.**

   ```sh
   target/release/waf validate --config config/waf.yaml
   ```

   Exit code 0 = config is loadable. The validator also runs a
   compliance check (FIPS / PCI / SOC2 / GDPR / HIPAA profile if
   set) and rejects malformed rules.

4. **Hot-reload after edit (no restart needed).**

   ```sh
   # Either: file watcher picks up the change automatically.
   # Or: explicit reload via the admin API (after login).
   curl -XPOST -H "x-csrf-token: $CSRF" -b cookies.txt \
        http://<admin>:9443/admin/reload
   ```

   The dashboard's status bar shows "Last config sync 14s" so you
   know reload took effect. SLA: ≤ 10 s (Hackathon WAF-FE §2 #5).

### Verify

```sh
# Config schema is documented field-by-field:
config/README.md
docs/control-plane/secrets-management.md   # secret resolvers
docs/operations/ha-clustering.md           # state.backend choices
```

### Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `validate` fails: "missing field admin.bind" | YAML key drift | Compare against `config/waf.yaml` template |
| Boot OK, but rules don't match | rule file path wrong | Check `security.rules.path` resolves; `waf validate` will warn |
| `${secret:…}` returns empty | resolver auth missing | Set `VAULT_ADDR` / `AWS_PROFILE` / etc. before `waf run` |

---

## 2. Build

### Goal

Produce a release binary with the right Cargo features for your
deployment.

### Steps

```sh
# Minimum production set (HA + alerts + GeoIP + threat intel + HTTP/3)
cargo build -p aegis-bin --release \
  --features "redis alerts geoip taxii http3"

# Full feature set (everything above + cloud secret managers + service discovery)
cargo build -p aegis-bin --release \
  --features "redis vault aws gcp azure consul etcd k8s alerts geoip taxii http3"

# CPU-pinned build for runtime-tuning experiments
cargo build -p aegis-bin --release --features "redis affinity"
```

Output: `target/release/waf`. Single static binary, no runtime
deps beyond libc + OpenSSL/aws-lc-rs.

### Verify

```sh
target/release/waf version
# Should print the build hash, e.g.:
#   waf 1.4.2-3a8f (rust 1.82, redis+alerts+geoip+taxii+http3)
```

### Build the dashboard bundle separately

The React 18 SPA is pre-compiled and embedded. If you change
`crates/aegis-control/assets/dashboard/src/*.jsx`, rebuild the
bundle then rebuild the binary:

```sh
bash crates/aegis-control/assets/dashboard/build.sh
cargo build -p aegis-bin --release --features redis
```

---

## 3. Deploy

### Goal

Get the binary running in front of your real backends, with TLS
and an admin plane gated by your operator IPs.

### Three modes

#### A. Single node (small footprint, no HA)

```sh
# Drop the binary on the host
scp target/release/waf user@host:/usr/local/bin/waf
scp config/waf.yaml    user@host:/etc/aegis/waf.yaml

# Boot under systemd (or supervisord / runit / launchd)
sudo systemctl edit --full --force aegis-gate
# ExecStart=/usr/local/bin/waf run --config /etc/aegis/waf.yaml

sudo systemctl enable --now aegis-gate
```

#### B. Two-node HA cluster (recommended)

Reference deploy lives at [`deploy/haproxy/`](../../deploy/haproxy/)
and [`config/waf.cluster-{a,b}.yaml`](../../config/).

```sh
# 1. Bring up Redis (shared state backend).
docker run -d --name aegis-redis -p 6379:6379 redis:7-alpine \
  redis-server --save "" --appendonly no

# 2. Boot two WAF nodes.
target/release/waf run --config config/waf.cluster-a.yaml &
target/release/waf run --config config/waf.cluster-b.yaml &

# 3. Front them with HAProxy.
haproxy -f deploy/haproxy/haproxy.cfg
```

Run-05 measured: 9.5 k RPS via VIP; 99.93 % hard-failover budget;
100 % graceful failover (zero 5xx) when nodes are drained via
`/admin/drain` before being killed.

Detail: [`docs/operations/ha-clustering.md`](../operations/ha-clustering.md)
and the `tests/cluster/06-mid-burst-failover.sh` reproducer.

#### C. Docker / Compose (dev + integration)

```sh
docker compose -f deploy/docker-compose.dev.yml up -d
# Brings up: etcd, Prometheus, Jaeger, Redis, httpbin
# Then point waf at this stack:
target/release/waf run --config config/waf.dev.yaml
```

Production Dockerfile (`B6-T1`) is the only remaining Phase B item;
when shipped it will be at `deploy/Dockerfile`.

### Verify

```sh
# Both data plane and admin plane should answer.
curl -sf -o /dev/null -w "%{http_code}\n" https://<data-host>:8443/   # 200/3xx/4xx — anything but conn-refused
curl -sf -o /dev/null -w "%{http_code}\n" http://<admin-host>:9443/healthz/ready

# In an HA cluster, every node should report healthy.
for n in waf-a waf-b waf-c; do
  curl -sf "http://$n:9443/healthz/ready" || echo "$n DOWN"
done
```

---

## 4. Login

### Goal

Get a SOC analyst into the **Aegis WAF Console** with their own
credentials.

### Flow (defense-in-depth)

The dashboard uses 7 layered auth controls. SOC analysts hit them
in this order:

1. **IP allowlist** — `admin.dashboard_auth.ip_allowlist`. Your
   subnet must be listed before TLS even handshakes.
2. **mTLS** (optional) — if `admin.dashboard_auth.mtls_required`,
   present a client cert signed by the operator CA.
3. **Password** — argon2id. Generated by:
   ```sh
   waf admin set-password
   # Outputs the PHC string. Paste into:
   #   admin.dashboard_auth.password_hash_ref: '$argon2id$...'
   ```
4. **TOTP** — `waf admin enroll-totp` generates a secret + 10
   recovery codes. Scan into Authenticator app. Required when
   `totp_enabled: true`.
5. **HMAC session cookie** — set automatically on success.
   `HttpOnly; Secure; SameSite=Strict`. Idle TTL 30 min, absolute
   TTL 8 h. Bound to client IP + UA hash.
6. **CSRF token** — `aegis_csrf` cookie + matching
   `x-csrf-token` header on every mutation.
7. **Rate limit + lockout** — per-IP and per-user. Lockout fires
   after the configured threshold. **All failures audited.**

### Steps (operator console)

```sh
# 1. From an allowlisted IP, browse the dashboard:
open http://<admin-host>:9443/dashboard/

# 2. Login form: username + password (+ TOTP if enabled).
# 3. Session + CSRF cookies are set automatically.
# 4. The dashboard is now navigable. Sidebar has 12 pages:
#    Overview / Live Feed / Attack Events / Analytics / Audit Log /
#    Rule Manager / Tier Config / Blacklist / Whitelist / Settings /
#    Tracking / Help & Guide
```

### Steps (programmatic / scripts)

```sh
# Login via curl + cookie jar.
curl --cookie-jar cookies.txt \
     -H "content-type: application/json" \
     -d '{"user":"<USER>","password":"<PASS>"}' \
     http://<admin>:9443/admin/login

# Pull the CSRF cookie out of the jar for subsequent mutations.
CSRF=$(awk '/aegis_csrf/ {print $7}' cookies.txt | tail -1)

# Now you can call any /api/* mutation:
curl --cookie cookies.txt \
     -H "x-csrf-token: $CSRF" \
     -H "content-type: application/json" \
     -XPUT -d '{"body":"...","enabled":false}' \
     http://<admin>:9443/api/rules/<rule_id>
```

### Verify

```sh
# Currently logged-in admins:
curl --cookie cookies.txt http://<admin>:9443/api/admin/sessions

# Admin audit chain (separate from the detection chain):
curl --cookie cookies.txt http://<admin>:9443/api/admin/audit
```

### Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Browser refuses connection | not on allowlist | Add your IP to `admin.dashboard_auth.ip_allowlist` |
| 401 on `/admin/login` | wrong pw / TOTP / locked out | Wait `lockout.window`; check audit log for `auth_lockout` |
| 403 on every mutation | missing CSRF | Pass `x-csrf-token` header matching `aegis_csrf` cookie |
| "session_expired" toast | idle > 30 min | Re-login |

Spec: [`docs/control-plane/dashboard-auth.md`](../control-plane/dashboard-auth.md).

---

## 5. Test

### Goal

Confirm the WAF is actually inspecting traffic and the dashboard
contract holds.

### Three checks (in order of confidence)

#### 5.1. Smoke check — does the WAF block known-bad traffic?

```sh
# SQLi probe — should be blocked.
curl -i "http://<data>:8080/?q=' UNION SELECT * FROM users--"
# Expect: 403 (or 429 in challenge tier)

# Path-traversal probe.
curl -i "http://<data>:8080/../../etc/passwd"
# Expect: 403

# Honeypot probe.
curl -i "http://<data>:8080/.env"
# Expect: 403

# Audit chain should log all three.
tail -f waf_audit.log | jq 'select(.action=="block")'
```

#### 5.2. Round-1 acceptance — full WAF-FE §2 contract

```sh
AEGIS_ADMIN=http://<admin>:9443 AEGIS_DATA=http://<data>:8080 \
  bash tests/dashboard/round1-acceptance.sh
```

Eight checks, exit 0 = all pass. Tests:
- shell mounts `id="root"`, CSP `script-src 'self'`, bundle ≤ 256 KB
- real-time SSE latency ≤ 5 s
- hot-reload latency ≤ 10 s
- audit query latency ≤ 30 s
- all 4 rule CRUD verbs CSRF-gated
- NewRuleModal markers present in bundle

#### 5.3. Cluster smoke — HA failover

```sh
bash tests/cluster/run-all.sh
```

Six scripts: shared rate-limit counter, leader failover, rehydrate
readiness, partition fallback, single-VIP baseline, mid-burst
failover. All must be green before promoting an HA deploy.

#### 5.4. (Optional) Performance — k6

```sh
docker compose -f deploy/docker-compose.test.yml up -d
docker exec aegis-k6 k6 run /scripts/baseline.js
```

Baseline numbers (run-04): 31.7 k RPS plain HTTP, 31.8 k RPS over
TLS, p95 ≤ 1.04 ms.

### Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Smoke probes return 200 | WAF in `log_only` mode | Check `/api/loadmode`; flip to `enforce` |
| Round-1 fails on real-time | SSE not subscribed | Check `/dashboard/sse` returns `text/event-stream` |
| Round-1 fails on hot-reload | mutation pipeline disabled | Check `services.mutate` is wired in `aegis-bin` |

---

## 6. Monitor

### Goal

Know when something needs SOC attention, and have the right pane
to look at when it does.

### 6.1. The Tracking page (one-stop dashboard)

`http://<admin>:9443/dashboard/#/tracking` — the canonical SOC pane.
Shows in real time:

- **SLO burn** — multi-burn-rate windows for each declared SLO.
  Red = paging burn; yellow = ticket burn; green = within budget.
- **Cluster peers** — every node's `node.id`, last heartbeat, role
  (leader/follower), version, draining flag.
- **Upstream pools** — each pool's healthy/unhealthy count + last
  ejected backend.
- **Cert freshness** — TTL per certificate; alerts when < 14 days.
- **GitOps sync** — last commit applied + verification state.
- **Active alerts** — anything firing in the last 1 h, with
  ack/silence buttons (audited).

### 6.2. Live Feed (real-time SOC view)

`http://<admin>:9443/dashboard/#/live` — subscribes to
`/dashboard/sse`. Every request the WAF evaluates streams into
this pane within ~1 s. Click any row to open the inspector
drawer with full headers, rule matches, risk-score breakdown,
and a "Block IP" button (audited via blacklist mutation).

Filters: by tier, by action, by attack class, by IP, by request_id.

### 6.3. Audit Log (forensics)

`http://<admin>:9443/dashboard/#/audit` — searches the SHA-256
hash chain.

```sh
# Verify chain integrity from the CLI:
waf audit verify --from ./waf_audit.log

# Stream new events while investigating:
tail -F waf_audit.log | jq

# Pull entries for a specific request_id:
curl --cookie cookies.txt \
  "http://<admin>:9443/api/audit/since?request_id=<id>&limit=200"
```

### 6.4. Prometheus metrics

```sh
curl http://<admin>:9443/metrics | grep -E '^(waf_|http_)' | head
```

Key series for SOC dashboards:

| Metric | Meaning |
|---|---|
| `waf_requests_total{action,tier}` | every request bucketed by decision |
| `waf_block_total{category}` | OWASP-class breakdown of blocks |
| `waf_challenge_total{type}` | JS / CAPTCHA / strict challenge counts |
| `waf_rate_limit_total` | rate-limit decisions |
| `waf_ddos_mode_active` | 1 when DDoS auto-mode armed |
| `waf_audit_chain_length` | monotonic — equals `/api/config/version` |
| `waf_slo_burn_rate{slo,window}` | per-window burn rate (vs budget) |
| `up{job="aegis"}` | scraper liveness |

Wire these into Prometheus; alerts can fire via:

- `slo.alerts.receivers[*]` in `waf.yaml` (VipTalk supported via
  the `alerts` Cargo feature; defaults to the project's
  dev/UAT bot) — see [`docs/observability/slo-sli-alerting.md`](../observability/slo-sli-alerting.md)
- An out-of-band Alertmanager pointed at `/metrics`

### 6.5. SIEM forwarding

The audit chain ships to whichever SIEM your shop uses. Configure
under `audit.sinks` — supported formats:

| Format | Where it lands |
|---|---|
| JSONL | local file, log shipper, S3 |
| RFC 5424 syslog | `udp://syslog.host:514` |
| CEF | ArcSight, QRadar |
| LEEF | QRadar |
| OCSF | Splunk SOC, Snowflake |
| Splunk HEC | direct HTTP push |
| ECS | Elastic Common Schema for Elastic / OpenSearch |
| Kafka | event streaming |

Spec: [`docs/observability/siem-export.md`](../observability/siem-export.md).
Eight sinks ship; configure as many as you want — every audit
event broadcasts to all configured sinks.

### 6.6. Drain a node before maintenance

```sh
# Mark the node draining — readiness flips to 503 with ?strict=1,
# load balancer rolls traffic off, in-flight requests complete.
curl -XPOST --cookie cookies.txt \
     -H "x-csrf-token: $CSRF" \
     "http://<admin>:9443/admin/drain"

# Wait until in-flight = 0 (~5 s typical):
curl "http://<admin>:9443/healthz/ready?strict=1"
# 503 = drained, safe to kill or upgrade

# After upgrade, restart — readiness returns 200 once rehydrate finishes.
```

Run-05 verified: graceful drain produces zero 5xx mid-failover.

---

## 7. Common SOC playbooks

### 7.1. "We're under attack — blocks are spiking"

1. Open the **Tracking** page → check `waf_block_total{category}`
   pane to see which OWASP class.
2. **Live Feed** → filter by `action=block` + the spiking
   category. Note the top 3 source IPs / ASNs.
3. Click any row → inspector drawer → **Block IP** button (or
   add the ASN to **Blacklist** for whole-AS blocks).
4. If volume justifies it, flip **Settings** → **DDoS auto-mode**
   to `armed` (already auto-engages above the configured threshold,
   but operators can force it).
5. Verify in **Audit Log** that the new blacklist entry is on the
   chain (hash visible in the row).

### 7.2. "False positives — a real customer is being blocked"

1. **Live Feed** → filter by their IP → find the blocked request.
2. Inspector → **Risk score breakdown** → identify the rule
   contributing the most.
3. **Rule Manager** → that rule → **Edit** → either disable, lower
   `risk_delta`, or change `action: challenge`.
4. **Save & deploy** → toast confirms "Applied in X.X s".
5. Add the customer's IP to **Whitelist** as a temporary measure
   (audited; expires by default in 24 h unless pinned).

### 7.3. "An alert fired in the middle of the night"

1. Read the alert payload — `slo`, `window`, `current_burn_rate`.
2. **Tracking** → SLO panel → which SLO is burning? Page-burn
   means we're spending error budget faster than allowed.
3. Cross-check with **Live Feed** + Prometheus to see if it's
   real customer impact or a synthetic spike.
4. If real: drain the affected node (§ 6.6), then investigate
   logs / upstream health.
5. Acknowledge the alert from the **Tracking** page (audited).

### 7.4. "We need to verify nothing was tampered with"

```sh
# 1. Cryptographically verify the audit chain from the on-disk file.
waf audit verify --from ./waf_audit.log
# Exit 0 = chain intact. Any tamper = non-zero with offending offset.

# 2. Compare against a witness export (independent verifier).
curl --cookie cookies.txt \
     "http://<admin>:9443/api/admin/witness/export?since=<ts>" \
     > witness.jsonl

# 3. Independent verifier compares ./waf_audit.log roots vs witness.
```

Witness export shape: [`docs/observability/audit-witness.md`](../observability/audit-witness.md).

---

## 8. Where to look next

| If you need | Read |
|---|---|
| Full YAML config reference | [`config/README.md`](../../config/README.md) |
| Rule DSL grammar + examples | [`docs/security/rule-engine.md`](../security/rule-engine.md) |
| Detector-by-detector spec | [`docs/security/detectors/`](../security/detectors/) |
| Compliance profiles (FIPS / PCI / SOC2 / GDPR / HIPAA) | [`docs/operations/compliance.md`](../operations/compliance.md) |
| SLO definition + multi-burn alerting | [`docs/observability/slo-sli-alerting.md`](../observability/slo-sli-alerting.md) |
| Disaster-recovery + snapshot/restore | [`docs/operations/dr-backup.md`](../operations/dr-backup.md) |
| GitOps loader (config-as-code) | [`docs/control-plane/gitops-change-management.md`](../control-plane/gitops-change-management.md) |
| Per-page UI reference | [`docs/control-plane/enterprise/`](../control-plane/enterprise/) |
| Architectural deep-dive | [`Architecture.md`](../../Architecture.md) |
| Hackathon WAF-FE §2 contract status | [`Requirement.md` § 36](../../Requirement.md#36-hackathon-waf-fe-2-contract-2026-04-30) |

---

## 9. Escalation

When an issue is beyond what this runbook covers:

1. Capture the audit-log snapshot:
   ```sh
   waf snapshot create --output incident-$(date +%s).json
   ```
2. Capture metrics + last 1 h Live Feed:
   ```sh
   curl -s http://<admin>:9443/metrics > metrics-$(date +%s).txt
   ```
3. Hand both files + the offending request_id(s) to engineering.
   The audit chain is hash-linked, so even if the live system is
   compromised the snapshot is independently verifiable.
