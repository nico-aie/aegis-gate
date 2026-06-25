# Single-Node Hackathon Deploy — Aegis-Gate (no cluster, best performance)

> **For an AI assistant deploying the `pre-prod` branch on ONE machine** for a hackathon
> benchmark. Optimized for **throughput + low latency + low false-positives + contract
> compliance** (WAF Interop Contract v2.5). **No cluster mode, no load balancer** — the
> WAF *is* the edge. Follow top to bottom; every value below is deliberate.
>
> Companion (do NOT use for this): `PRE-PROD-DEPLOY.md` (multi-node cluster),
> `deploy/ansible/` (fleet automation). This guide is standalone and intentionally simpler.

---

## 0. Decide the topology first (you said you're unsure about machines)

**Use ONE machine. The WAF binds the public port directly and is the TLS edge.** This is
the simplest, fastest, and most contract-correct setup:

- The WAF sees the **real client IP natively** (no LB → no SNAT, no PROXY-protocol, no
  `trusted_proxies` plumbing). Per-IP rate-limit / risk / geoip "just work".
- JA3/JA4/device_fp come from the client's own TLS handshake (WAF terminates TLS).
- No cluster convergence, no shared Redis, no LB tuning — all of which are extra latency
  and failure surface you don't need for a single endpoint.

**If you have several machines:** still deploy this single-node config on **one** of them
and point the benchmark at it. Do NOT split across machines with a load balancer unless
the benchmark explicitly needs >1 node's capacity — an L4 LB collapses the client IP
(breaks per-IP scoring) and L7/cluster add latency + convergence bugs. One strong node
beats a fragile fleet for a benchmark. (If you genuinely must scale out, that's cluster
mode — a different guide.)

> Rule of thumb: **one machine, WAF on the public port, no LB, no cluster.**

### What you actually run (minimal stack)

| component | needed? | note |
|---|---|---|
| **`./waf`** | ✅ required | the gateway itself |
| **your protected app** | ✅ required | the backend the WAF sits in front of (this is the `app-pool` upstream — it's *your* app, not "infra") |
| **Redis** | ⚪ used (swappable) | the config uses Redis on loopback (your round-1 setup; state survives a WAF restart). Swap to built-in `in_memory` for the leanest run (no Redis at all) — see §4a. Either way it's the *only* extra component. |
| SigNoz / otel-collector | ❌ skip | observability only; delete the `observability` block (§4) and you ship nothing external |
| nginx / load balancer | ❌ skip | the WAF is the edge |
| mock upstream | ❌ skip | that's a *test* backend; you point at your real app |

So: **WAF + your app** is the whole footprint. Add Redis if you want restart-durable state;
everything else in the multi-node guides is unnecessary here.

---

## 1. Prerequisites

```sh
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y build-essential cmake pkg-config \
  protobuf-compiler libssl-dev curl git
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env"

git clone -b pre-prod <REPO_URL> aegis-gate && cd aegis-gate
```

Hardware: any modern multi-core Linux box. The WAF auto-scales Tokio workers to cores.

---

## 2. Build — full feature set (AI + Copilot included)

```sh
cargo build -p aegis-bin --release --features "redis geoip alerts ai affinity otel llm"
```

**What each feature gives you:**

| feature | role | notes |
|---|---|---|
| `ai` | ONNX ML detector | the headline detector. **Needs the onnxruntime runtime at launch** (§3a) and a model file. Powerful, but **can false-positive on legit traffic** — tune it (high threshold, or `log_only`) so you don't block clean requests in the benchmark (§4 + §8). |
| `llm` | Copilot (LLM assist) | dashboard situational briefings. Reads `LLM_*` env at runtime (§3a). Egresses to the LLM **only on a console briefing request** (no background polling), so ~zero data-plane cost. |
| `redis` | Redis state backend | optional on one node (see §4a); compiled in so you can switch without rebuilding. |
| `geoip` | MaxMind country/ASN | fast mmdb lookups; adds an ASN/geo signal to risk (no-op if you skip the DBs). |
| `otel` | OpenTelemetry | traces/metrics; cheap if you lower `sample_ratio` (§5). |
| `affinity` | CPU pinning | steadier tail latency. |
| `alerts` | alerting plumbing | negligible cost. |
| `etcd_config` | etcd config plane (H2b) | **skip on a single node** — `config_plane.store: etcd` buys durable consensus that one box doesn't need, and it adds a `protoc` build dep + an etcd container. Single-node keeps `store: shared_state` (Redis/in_memory). Add it only if you'll later grow to a cluster (then see `CONFIG-PLANE-RUNBOOK.md` §11). |

> The deterministic detectors (`sqli`, `xss`, `path_traversal`, `command_injection`,
> `recon`, `jwt_inspection`, `header_injection`/smuggling, WebSocket frame inspection,
> risk engine, rate limit, DDoS) run alongside AI and never false-positive on clean
> traffic — AI is the one to watch for over-blocking.

Copy the contract's three required files into place (Contract §8 expects `./waf`,
`./waf.yaml`, `./waf_audit.log` in the CWD):

```sh
cp target/release/waf ./waf
# create ./waf.yaml from §4 below; ./waf_audit.log is created on first request
```

---

## 3. TLS certificate (the WAF terminates TLS) — pick a track

The committee usually hits a **real domain** (e.g. `aiagent.waf-exams.info`), so a browser-
trusted cert matters. Two tracks:

### Track A — self-signed (quick / local / IP-only smoke tests)
```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/selfsigned.key -out certs/selfsigned.crt \
  -subj "/CN=aegis-gate" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:<PUBLIC_IP>"
```
Then in `tls:` point at `certs/selfsigned.{crt,key}`. Fine if the harness uses `-k`.

### Track B — Let's Encrypt (real public domain) — **recommended for the live benchmark**
This is the proven round-1 setup. The WAF has an **in-process ACME manager** (HTTP-01).
Two important facts learned in production:

1. ACME needs a **public DNS A-record → this machine** and **port 80 reachable** (HTTP-01
   challenge). Add a `force_https` listener on `:80` (it serves the challenge + 308-redirects
   everything else to HTTPS) and the TLS data plane on `:443`.
2. **The ACME cert-store hot-swap is a deferred stub** — the manager issues the cert and
   writes the PEM to disk, but does **not** install it into the live `:443` store at runtime.
   So the pattern is: enable `acme` for **one** issuance → it writes the PEM to
   `cert_dir/<domain>/{cert,key}.pem` → then **pin that PEM statically** under
   `tls.certificates` and **disable `acme`** → restart so `:443` serves it. Re-enable `acme`
   for a one-shot renewal before expiry, then disable again. (Leaving `acme` enabled churns
   re-issuance on every leader-lease acquire and can burn LE's 5-certs/domain/week cap.)

The TLS block for Track B (matches §4's `:443`/`:80` listeners):
```yaml
tls:
  min_version: "1.2"
  hsts: { max_age: 31536000, include_subdomains: true, preload: false }
  certificates:
    # the LE-issued PEM, pinned on disk (issued via the acme block below, then acme disabled)
    - cert_path: "/var/lib/aegis/certs/<YOUR_DOMAIN>/cert.pem"
      key_ref:   "/var/lib/aegis/certs/<YOUR_DOMAIN>/key.pem"
      hosts:     ["<YOUR_DOMAIN>"]
    # keep a self-signed for loopback SNI so local smoke tests still handshake
    - cert_path: "certs/selfsigned.crt"
      key_ref:   "certs/selfsigned.key"
      hosts:     ["localhost", "127.0.0.1"]
  # ── ONE-SHOT ISSUANCE: uncomment, restart, wait for
  #    "acme: initial issuance succeeded", confirm the on-disk leaf, then RE-COMMENT + restart ──
  # acme:
  #   directory_url: "https://acme-v02.api.letsencrypt.org/directory"  # LE PROD (use staging first to dry-run)
  #   contacts: ["mailto:ops@<YOUR_DOMAIN>"]
  #   domains: ["<YOUR_DOMAIN>"]
  #   account_key_path: "/var/lib/aegis/acme/account-prod.json"
  #   cert_dir:         "/var/lib/aegis/certs"
  #   renew_before:     30d
  #   terms_of_service_agreed: true
  #   challenge:        http01
```
> Dry-run on LE **staging** (`https://acme-staging-v02.api.letsencrypt.org/directory`) first —
> it doesn't count against the prod rate limit — then flip to prod for the real cert.

---

## 3a. AI runtime + Copilot env (required because we kept `ai` + `llm`)

The `ai` feature links onnxruntime **dynamically** (`ort` `load-dynamic`), so the WAF needs
the matching `.so` at launch — **onnxruntime 1.24.2** (the version `ort` 2.0.0-rc.12 expects;
a mismatched `.so` hangs the boot). Also place the model file.

```sh
# onnxruntime 1.24.2 runtime
mkdir -p runtime/onnxruntime
curl -fsSL https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-linux-x64-1.24.2.tgz \
  | tar -xz -C /tmp
cp /tmp/onnxruntime-linux-x64-1.24.2/lib/libonnxruntime.so* runtime/onnxruntime/

# the model (ship/copy it here)
mkdir -p data/ai_model
# place your model at  data/ai_model/waf_model.onnx
# (optional) geoip DBs for the geoip signal:  data/geoip/GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb
```

Create `.env` (sourced before launch in §5) with the AI runtime path and the Copilot creds:

```sh
cat > .env <<'EOF'
# AI (ort load-dynamic) — MUST point at the 1.24.2 .so
ORT_DYLIB_PATH=/ABS/PATH/aegis-gate/runtime/onnxruntime/libonnxruntime.so
# Copilot (LLM) — CopilotService::from_env() needs ALL four to enable:
LLM_ENABLED=true
LLM_BASE_URL=<https://your-llm-endpoint/v1>
LLM_API_KEY=<your-llm-key>
LLM_MODEL=<your-model-name>
EOF
```
Use the **absolute** path for `ORT_DYLIB_PATH`. Verify the LLM endpoint is reachable from
the box first: `curl -sS --max-time 10 -o /dev/null -w "%{http_code}\n" <LLM_BASE_URL>`
(any HTTP code = reachable; `000` = blocked → Copilot will stay inert).

---

## 4. `./waf.yaml` — the single-node, performance-tuned, contract-compliant config

Create this file verbatim, then edit the **5 marked spots** (`<...>`). Every choice is
explained in §5/§6.

```yaml
# Aegis-Gate single-node hackathon config. Contract v2.5 §8: ./waf + ./waf.yaml + ./waf_audit.log.
# Values = proven round-1 tuning (~5k+ RPS on one box) adapted to the new build.
node:
  id: "waf-1"

listeners:
  data:
    - bind: "0.0.0.0:443"          # public TLS data plane (LE cert from §3 Track B; or :8443 self-signed)
      tls: true
    - bind: "127.0.0.1:8080"       # loopback plaintext — local k6/curl harness only, NOT public
  admin:
    bind: "127.0.0.1:9443"         # dashboard. Open to 0.0.0.0 + ip_allowlist if the committee needs
                                   # console access (round-1 did). /__waf_control stays loopback-gated
                                   # regardless of this bind.
  force_https:
    bind: "0.0.0.0:80"             # ACME HTTP-01 challenge + 308-redirect plain HTTP → HTTPS

# TLS — see §3 (Track B Let's Encrypt for a real domain; Track A self-signed for IP/local).
tls:
  min_version: "1.2"
  hsts: { max_age: 31536000, include_subdomains: true, preload: false }
  certificates:
    - cert_path: "/var/lib/aegis/certs/<YOUR_DOMAIN>/cert.pem"   # LE PEM (or certs/selfsigned.crt)
      key_ref:   "/var/lib/aegis/certs/<YOUR_DOMAIN>/key.pem"
      hosts:     ["<YOUR_DOMAIN>"]
    - cert_path: "certs/selfsigned.crt"
      key_ref:   "certs/selfsigned.key"
      hosts:     ["localhost", "127.0.0.1"]
  # acme: { ... }   # one-shot issuance — see §3 Track B, then disable + restart.

# NO `proxy:` block (WAF is the edge → real client IP). NO `cluster:` block (single node).

routes:
  - { id: catch-all, path: "/", match_type: prefix, upstream: app-pool, tier_override: high }

upstreams:
  app-pool:
    members: [{ addr: "<PROTECTED_APP_HOST:PORT>" }]   # <-- the committee's target app
    lb: round_robin
    connection: { scheme: auto, keep_alive: true }     # reuse upstream conns (perf)

# State — Redis on loopback (proven round-1 choice; survives WAF restart). Leanest alternative:
# `backend: in_memory` (no Redis) — see §4a. timeout 1s is safe; 100ms is fine on loopback.
state:
  backend: redis
  redis: { urls: ["redis://127.0.0.1:6379"], pool_size: 32, timeout: "1s" }

# Config plane (H2b) — leave at the default `shared_state`: the durable config doc
# rides the state backend above (Redis/in_memory). A single box gains nothing from
# `store: etcd` (that's for multi-node durable consensus) — omit the block entirely.
# config_plane: { store: shared_state }

# Risk scoring — proven weights + bands. Challenge 30–69 / Block ≥70 (Contract §5.5 scale).
risk:
  weights: { bad_asn: 15, bad_ja4: 10, failed_auth: 20, detector_hit: 25, bot_unknown: 10, repeat_offender: 15 }
  decay_half_life: "5m"
  thresholds: { enabled: true, challenge_at: 30, block_at: 70 }
  strikes:
    block_at: 1000000              # benchmark override: one detector FP must NOT permanently block
                                   # an IP for the rest of a phase. Real prod uses ~50.

# Per-tier per-request block score + challenge rung. catch-all is tier high (60).
tiers:
  critical: { risk_threshold: 50, challenges_enabled: true }
  high:     { risk_threshold: 60, challenges_enabled: true }
  medium:   { risk_threshold: 70, challenges_enabled: true }
  low:      { risk_threshold: 80, challenges_enabled: true }

# Deterministic detector suite (no FP on clean traffic).
detectors:
  sqli:              { enabled: true }
  xss:               { enabled: true }
  path_traversal:    { enabled: true }
  command_injection: { enabled: true }
  ssrf:              { enabled: true }
  header_injection:  { enabled: true }   # incl. request-smuggling hygiene
  body_abuse:        { enabled: true }
  recon:             { enabled: true }
  brute_force:       { enabled: true }
  # jwt_inspection + WebSocket frame inspection are ON by default in this build.

# AI ONNX detector — ON, with the SYNCHRONOUS SESSION POOL (the right perf config). Needs §3a.
# `sessions: N` = N independent sessions, each capped to 1 intra-op thread → N inference threads
# total (NOT the default many-thread intra-op pool that hogs cores). batch_enabled:false because
# the model is fast — batching added coordination overhead + shape-mismatch spam + a huge tail.
# 8-core box → 4 is a good start; bump if AI lags at high RPS, lower if CPU-starved.
#
# ⚠ FP CAVEAT (round-1 finding): the engine is "first-fire + aggregator" — an AI hit adds to the
# cumulative risk score even in log_only, so it can still push an IP over block_at via the risk
# path. If AI over-blocks legit traffic, raise the threshold; the ONLY way to fully remove its
# contribution is `enabled: false`.
ai:
  enabled: true
  model_path: "data/ai_model/waf_model.onnx"
  confidence_threshold: 0.90       # raise toward 0.95 if clean traffic gets blocked
  sessions: 4
  batch_enabled: false

# GeoIP (ASN/country signal for risk + bot classifier). Absolute paths recommended on systemd.
geoip:
  country_db: "data/geoip/GeoLite2-Country.mmdb"
  asn_db:     "data/geoip/GeoLite2-ASN.mmdb"

# Bot classifier (observational: labels human/verified/suspect/malicious from UA + ASN).
bots:
  enabled: true

# Load mode — single-instance ~5k RPS profile.
load_mode: { elevated_rps: 1500, critical_rps: 4000, sample_interval: 1s }

# Adaptive load shedder — sheds 503 by tier when in-flight concurrency exceeds the adaptive
# limit (Critical never shed). Sized for >=10k RPS: 20k ceiling, 2k floor.
load_shedder: { enabled: true, initial_limit: 20000, min_limit: 2000 }

# Per-IP rate gate. 1,000,000/min effectively disables it for a SINGLE-SOURCE benchmark (one IP
# trips any realistic limit instantly). Pin a real value for production.
rate_limit:
  buckets:
    - { id: global-ip, scope: global, key: ip, algo: sliding_window, limit: 1000000, window: "1m" }

# DDoS per-IP burst gate. 10000 reqs / 10s ≈ 1000 rps/IP before it trips.
ddos: { enabled: true, observe_only: false, per_ip_limit: 10000, per_ip_window_s: 10 }

rules: { paths: [], max_rule_count: 10000, strict_compile: false }

logging:
  verbosity: info                  # `warn` for a touch more throughput under heavy load

# WAF's own hash-chained audit (separate from the contract log). `path` is a DIRECTORY;
# files rotate daily as audit-YYYY-MM-DD.ndjson inside it.
audit:
  sinks:
    - jsonl: { path: "logs/audit" }
  chain: { enabled: true }
  retention: "7d"

# Contract control plane + audit log (§2 + §8).
interop:
  enabled: true
  audit_path: "./waf_audit.log"                 # §8 — benchmarker reads this from CWD
  control_secret: "<X_BENCHMARK_SECRET>"        # <-- the organizer's secret (X-Benchmark-Secret)

# Observability — Prometheus scrape endpoint (self-contained → NO external collector / no extra
# infra). `curl http://127.0.0.1:9100/metrics` or point any Prometheus at it. Copilot below.
observability:
  prometheus: { bind: "127.0.0.1:9100", enabled: true }
  copilot:                                       # Copilot (LLM) — creds come from .env (§3a)
    enabled: true
    provider: openai_compatible
    base_url: "<https://your-llm-endpoint/v1>"   # mirror LLM_BASE_URL
    model: "<your-model-name>"                   # mirror LLM_MODEL
    timeout_ms: 20000
    briefing_interval_secs: 0                     # 0 = no background polling (egress only on request)
    api_key_ref: "${secret:env:LLM_API_KEY}"

admin:
  bind: "127.0.0.1:9443"
  environment: staging
  dashboard_auth:
    # CHANGE THIS hash (round-1 password was "aegis-hackathon-2026"; generate your own argon2id).
    password_hash_ref: '$argon2id$v=19$m=19456,t=2,p=1$DfRgVNq6Cb+eN3BEMmExAQ$69SVZBNpMFjN4evfN8g+U5jnmP56Gwx3AGaZFr32ZzY'
    csrf_secret_ref:   "<RANDOM_32B_SECRET>"
    session_ttl_idle: "30m"
    session_ttl_absolute: "8h"
    # round-1 opened this to 0.0.0.0/0 so the committee could reach the console. Tighten if you can.
    ip_allowlist: ["127.0.0.1/32", "::1/128"]
    totp_enabled: false
    login_rate_limit: { per_ip: { limit: 100, window: "1m" } }
```

**Edit before running:** ① `app-pool` member (the protected app), ② `interop.control_secret`
(organizer's `X-Benchmark-Secret`), ③ `<YOUR_DOMAIN>` + cert paths in `tls` (§3), ④ Copilot
`base_url`/`model` (mirror `.env`), ⑤ `csrf_secret_ref` + the admin password hash.

Validate before launching:
```sh
./waf validate --config ./waf.yaml      # expect "config OK"
```

---

## 4a. Redis (the config above uses it) — or switch to in-memory

The config uses **Redis** (your round-1 setup; state survives a WAF restart). Run it locally
on loopback so the hop is tiny:
```sh
docker run -d --name aegis-redis -p 127.0.0.1:6379:6379 redis:7-alpine \
  redis-server --save 60 1 --appendonly yes
# or natively:  sudo apt-get install -y redis-server && sudo systemctl enable --now redis-server
```
This is the **only** extra component besides the WAF + your app — nothing else.

**Leaner alternative — no Redis at all.** For max throughput / fewer moving parts, use the
built-in in-memory backend instead (loses restart-durability; `reset_state` still works):
```yaml
state:
  backend: in_memory
```
Pick one. Either way you need no SigNoz, no otel-collector, no nginx, no mock.

---

## 5. Run (detached, survives your shell)

```sh
mkdir -p logs logs/audit
set -a; . ./.env; set +a          # export ORT_DYLIB_PATH + LLM_* (§3a) for the WAF process
AEGIS_INSECURE_COOKIES=1 \
RUST_LOG="info,hyper=warn,h2=warn,tower=warn,rustls=warn,tonic=warn,maxminddb=warn" \
setsid nohup ./waf run --config ./waf.yaml >> logs/waf.json 2>&1 < /dev/null & disown
```
- `set -a; . ./.env; set +a` → loads the AI runtime path + Copilot creds into the env.
  Confirm after boot: `grep -m1 'AI detector loaded' logs/waf.json` and
  `tr '\0' '\n' < /proc/$(pgrep -f 'waf run')/environ | grep -c '^LLM_ENABLED=true'`.
- `setsid nohup … & disown` → reparents to init (ppid 1), survives SSH logout.
- `AEGIS_INSECURE_COOKIES=1` lets the admin dashboard work over plain HTTP for testing.
- Logs go to `logs/waf.json`; the contract audit to `./waf_audit.log`; the hash-chain to
  `logs/audit/audit-<date>.ndjson`.

> **Privileged ports.** This config binds `:443` and `:80` (< 1024). The WAF runs unprivileged,
> so grant the binary the capability ONCE (no need to run as root):
> ```sh
> sudo setcap 'cap_net_bind_service=+ep' ./waf      # re-run after every rebuild (new binary)
> ```
> If you can't `setcap`, either run the WAF as root, or bind `:8443`/`:8080` instead and
> redirect 443→8443 / 80→8080 with iptables. For boot-persistence, a systemd unit with
> `AmbientCapabilities=CAP_NET_BIND_SERVICE` is the clean option.

### Performance knobs recap (why this config performs)
- **AI session pool** (`sessions: 4`, `batch_enabled: false`, 1 intra-op thread each) — the big
  one: bounded inference threads (NOT the default many-thread pool) + low tail, no batch spam.
- **Redis on loopback** (or `in_memory`) — state hop is a local socket; `in_memory` removes it
  entirely if you don't need restart-durability.
- **`load_shedder`** (20k/2k) — sheds 503 by tier under overload so the WAF stays up at >10k RPS.
- **`keep_alive: true`** upstream — connection reuse to the backend.
- **`affinity` build** — steadier tail latency; pin with `taskset`/cgroups on a shared box.
- **Prometheus scrape** (pull) instead of OTLP push — no exporter overhead on the hot path.
- **`logging.verbosity: warn`** under heavy load — fewer log writes.
- Tokio auto-scales workers to all cores.

---

## 6. Contract compliance (v2.5) — do not skip

1. **Three files in CWD:** `./waf`, `./waf.yaml`, `./waf_audit.log` (the last appears on
   first request). Confirm: `ls -la waf waf.yaml waf_audit.log`.
2. **Control plane is LOCAL-ONLY + secret-gated** (`/__waf_control/*`). It binds to
   loopback and only loopback callers reach it (Contract §2). The benchmarker must call it
   from the **same host** or via an **SSH tunnel** — NOT from a remote IP:
   ```sh
   # on the box (or: ssh -N -L 9443:127.0.0.1:9443 user@box ; then curl localhost:9443)
   curl -X POST -H "X-Benchmark-Secret: <SECRET>" http://127.0.0.1:9443/__waf_control/reset_state
   curl     -H "X-Benchmark-Secret: <SECRET>" http://127.0.0.1:9443/__waf_control/capabilities
   ```
   Works on `:8443` too. `reset_state` clears all runtime state between runs (audit logs
   preserved). `set_profile` toggles `enforce`/`log_only`. (Single node → no `cluster` flag needed.)
3. **Response headers** on EVERY response (allow/block/challenge/…): `X-WAF-Request-Id`,
   `X-WAF-Action`, `X-WAF-Mode`, `X-WAF-Risk-Score`, `X-WAF-Cache`, plus overhead/latency.
   The WAF emits these automatically — verify in §7.
4. **Risk-score scale** matches the contract (`challenge_at:30/block_at:70`) so the reported
   `X-WAF-Action` aligns with the `X-WAF-Risk-Score` the harness checks.

---

## 7. Verify (run all before declaring done)

```sh
# readiness (admin)
curl -s http://127.0.0.1:9443/healthz/ready -o /dev/null -w "ready %{http_code}\n"   # 200

# legit allowed, with the contract headers (public TLS :443; -k for self-signed)
curl -sk https://127.0.0.1:443/ -D - -o /dev/null | grep -i '^x-waf-'
# (or via the loopback plaintext harness port:  curl http://127.0.0.1:8080/ -D - ... )

# attacks blocked (403)
curl -sk -o /dev/null -w "sqli %{http_code}\n" "https://127.0.0.1:443/?q=1%27%20OR%20%271%27%3D%271"
curl -sk -o /dev/null -w "trav %{http_code}\n" "https://127.0.0.1:443/../../etc/passwd"

# control plane (loopback + secret)
curl -s -H "X-Benchmark-Secret: <SECRET>" http://127.0.0.1:9443/__waf_control/capabilities -o /dev/null -w "ctl %{http_code}\n"  # 200

# Prometheus metrics (self-contained, no collector)
curl -s http://127.0.0.1:9100/metrics | head -3

# protocols (if used): WSS over TLS, gRPC over TLS — both ride the :443 listener
#   wscat --no-check -c wss://127.0.0.1:443/ws
#   grpcurl -insecure 127.0.0.1:443 list
```
Expect: ready 200, legit 200 with `x-waf-*` headers, attacks 403, control 200, metrics output.

---

## 8. Gotchas (learned the hard way — save yourself the time)

- **Privileged ports `:443`/`:80`** need `sudo setcap 'cap_net_bind_service=+ep' ./waf`
  (re-run after every rebuild — it's a new inode) or run as root, else bind fails. See §5.
- **Data port is HTTPS, admin is HTTP.** Hit the WAF at `https://<domain or ip>:443` (TLS).
  The admin dashboard is plain HTTP at `http://<ip>:9443`. Mixing schemes looks like an outage.
- **AI (kept ON here) needs the runtime + tuning.** `onnxruntime 1.24.2` (matching `ort`
  2.0.0-rc.12) + `ORT_DYLIB_PATH` + the model (§3a); a version-mismatched `.so` **hangs the
  boot**. Use the **session pool** (`sessions`/`batch_enabled:false`) — the default many-thread
  intra-op pool starves the WAF's cores. AI can **false-positive on legit traffic**: it feeds
  the risk aggregator even in `log_only`, so to fully remove its contribution set
  `ai.enabled:false`; otherwise keep `confidence_threshold` high (0.90–0.95).
- **Control plane is loopback-only.** A remote `curl` to `/__waf_control/*` gets a generic
  404/401 (hidden off-host by design). Tunnel in (`ssh -N -L 9443:127.0.0.1:9443 …`) or run on
  the box. The `X-Benchmark-Secret` is necessary but not sufficient — the caller must be loopback.
- **`strikes.block_at` is set huge (1,000,000) on purpose** — so a single detector false-positive
  can't permanently block an IP for the rest of a benchmark phase. Don't "fix" it to a small number.
- **Don't put the WAF behind an L4 load balancer for a benchmark** — it SNATs the client IP,
  so per-IP rate-limit/risk collapse to one "client" and legit traffic gets blocked with the
  attacker. Single node = real client IP, no problem.
- **ACME hot-swap is a stub** — issue the LE cert once, then **pin the on-disk PEM** in
  `tls.certificates` and disable `acme`, and restart so `:443` serves it (§3 Track B).
- **`reset_state` between runs** — accumulated risk/rate-limit state will skew the next run.
  Reset (loopback + secret) before each. It preserves the audit logs.
- **Build masks failures sometimes** — confirm `target/release/waf` exists and run
  `./waf validate --config ./waf.yaml` (expect `config OK`) before launching.
- **Where the logs are:** app/tracing → `logs/waf.json`; contract audit → `./waf_audit.log`;
  hash-chain → `logs/audit/audit-<date>.ndjson` (the `path` is a directory); metrics →
  `http://127.0.0.1:9100/metrics`.

---

## 9. One-screen quickstart

```sh
git clone -b pre-prod <REPO_URL> aegis-gate && cd aegis-gate
cargo build -p aegis-bin --release --features "redis geoip alerts ai affinity otel llm"
cp target/release/waf ./waf
mkdir -p certs logs logs/audit runtime/onnxruntime data/ai_model data/geoip

# AI runtime (onnxruntime 1.24.2) + self-signed fallback cert
curl -fsSL https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-linux-x64-1.24.2.tgz \
  | tar -xz -C /tmp && cp /tmp/onnxruntime-linux-x64-1.24.2/lib/libonnxruntime.so* runtime/onnxruntime/
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout certs/selfsigned.key \
  -out certs/selfsigned.crt -subj "/CN=aegis-gate" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:<PUBLIC_IP>"
# place the model at data/ai_model/waf_model.onnx (+ optional geoip mmdb in data/geoip/)

# local Redis (state backend)
docker run -d --name aegis-redis -p 127.0.0.1:6379:6379 redis:7-alpine \
  redis-server --save 60 1 --appendonly yes

# write ./.env (§3a) and ./waf.yaml (§4 — for a real domain do §3 Track B ACME first), then:
./waf validate --config ./waf.yaml          # config OK
sudo setcap 'cap_net_bind_service=+ep' ./waf   # so the unprivileged user can bind :443/:80
set -a; . ./.env; set +a
AEGIS_INSECURE_COOKIES=1 RUST_LOG="info,hyper=warn,h2=warn,maxminddb=warn" \
  setsid nohup ./waf run --config ./waf.yaml >> logs/waf.json 2>&1 < /dev/null & disown
curl -s http://127.0.0.1:9443/healthz/ready -o /dev/null -w "ready %{http_code}\n"   # 200
```
```
