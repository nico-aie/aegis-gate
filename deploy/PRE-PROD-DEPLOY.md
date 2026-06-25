# Aegis-Gate — Pre-Prod Cluster Deployment Guide

> **What this is:** the practical, *as-built* runbook for the `pre-prod`
> topology — **one infra host** (Redis + **etcd** + multi-protocol mock + SigNoz)
> and **N WAF nodes** (native binary, the TLS edge) sharing the data-plane hot
> path via Redis and the **durable config plane via etcd** (H2b), balanced by
> **DNS round-robin**. It reflects exactly what we stood up and verified,
> including the committee interop contract (v2.3/2.5 §8) and the feature set
> `redis geoip alerts ai affinity otel llm etcd_config`.
>
> **Companion docs:** [`INFRA-HOST-STATUS.md`](./INFRA-HOST-STATUS.md) (what runs
> on the infra host) · [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md)
> (live config) · [`HACKATHON-FLEET.md`](./HACKATHON-FLEET.md) (the HAProxy/TPROXY
> variant — *not* used here; see "Why DNS round-robin" below).

---

## 0. Topology (as built)

```
                    ┌──────────────── infra host: 10.20.0.72 ───────────────┐
   clients          │  Redis :6379  (data-plane hot path · leases · rl/risk) │
     │  DNS A RR     │  etcd  :2379  (durable config plane: doc + control)    │
     ▼              │  mock  :9991/2/3/4  (http · ws · grpc · raw-tcp)        │
  waf-1  waf-2  …    │  SigNoz :4317 OTLP  ·  :8090 UI                         │
  (TLS edge)         └───────────────────────────────────────────────────────┘
  (each VM is the TLS edge: terminates TLS → JA3/JA4 + real client IP native)
     │  each node → Redis(:6379) hot path · etcd(:2379) config · OTLP(:4317) · mock(:999x)
     └── all nodes share one Redis + one etcd ⇒ one fleet (rate-limit · risk · config · block-list)
```

- **No in-path load balancer.** Clients reach WAF nodes directly via **DNS
  round-robin** (one A record per node IP). Each node terminates TLS, so JA3/JA4
  fingerprinting + real client IP work natively. Failover is DNS-TTL-bound.
- **Why DNS-RR and not HAProxy/TPROXY?** The infra host runs **rootless Docker
  with no sudo**, which cannot do TPROXY (needs real host caps, `ip_nonlocal_bind`,
  privileged `:443`, host networking). DNS-RR needs none of that and preserves
  client IP/JA3/JA4 better than a rootless LB could. If you later get a host with
  root + a dedicated NIC, `HACKATHON-FLEET.md` covers the HAProxy `mode tcp` +
  TPROXY upgrade.

**Infra host endpoints every node points at:**

| Purpose | Endpoint |
|---|---|
| Data-plane hot path (rate-limit · risk · leases · L2 cache) | `redis://10.20.0.72:6379` |
| Durable config plane (config doc + control plane) — H2b | `http://10.20.0.72:2379` (etcd) |
| OTLP traces (SigNoz collector) | `http://10.20.0.72:4317` |
| Upstream mock (http/ws/grpc/tcp) | `10.20.0.72:9991` / `9992` / `9993` / `9994` |
| SigNoz UI (operators) | `http://10.20.0.72:8090` |

---

## 1. Per-VM prerequisites (each WAF node)

```sh
# Build toolchain (Debian/Ubuntu). Mirrors deploy/Dockerfile's builder deps.
sudo apt-get update && sudo apt-get install -y \
    build-essential cmake pkg-config protobuf-compiler libssl-dev curl git

# Rust (user-local, no sudo needed — needs >= 1.91)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Network reachability to the infra host (must succeed):
redis-cli -h 10.20.0.72 -p 6379 ping        # -> PONG   (or: nc -z 10.20.0.72 6379)
nc -z 10.20.0.72 2379 && echo "etcd ok"     # H2b config plane (gRPC :2379)
curl -s http://10.20.0.72:9991/api/health   # -> {"status":"ok"}
nc -z 10.20.0.72 4317 && echo "otlp ok"
```

> **`protoc` is REQUIRED** (H2b): the `etcd_config` feature pulls the etcd
> gRPC stack, whose build runs `protoc` codegen. The `protobuf-compiler`
> package above covers it. No sudo? Drop a static `protoc` on PATH:
> `curl -fsSL -o /tmp/p.zip https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-linux-x86_64.zip`
> then `unzip` it and `install -m0755 bin/protoc ~/.cargo/bin/protoc`.

> **glibc note:** the `ai` (ONNX) feature can't link its *prebuilt* runtime on
> glibc < 2.38. This repo already pins `ort` to **`load-dynamic`** (in
> `Cargo.toml`), so the binary builds on any glibc and `dlopen`s a separate
> `libonnxruntime.so` only if you actually enable `ai` (off by default). See §5.

---

## 2. Build the WAF (native, run-copilot + etcd_config feature set)

```sh
cd ~/aegis-gate            # the cloned repo (this pre-prod branch)
source "$HOME/.cargo/env"
cargo build -p aegis-bin --release \
    --features "redis geoip alerts ai affinity otel llm etcd_config"
# ~10-20 min first build; seconds after. Result: target/release/waf
# NB: etcd_config needs protoc on PATH (see §1). A binary built WITHOUT it that
# boots config_plane.store: etcd fails loud at startup — no silent fallback.
```

These are the `make run-copilot` features (`redis geoip alerts ai affinity` +
`otel llm`) plus **`etcd_config`** (H2b — the durable etcd config plane).
`affinity` enables optional CPU pinning (config
`runtime.cpu_affinity`, off by default — only turn on for dedicated bare metal).

---

## 3. Lay out the committee contract files (§8)

The judge runs `./waf run` from the **project root** and expects three files
there. They are gitignored (per-deployment artifacts), so create them per node:

```sh
cp target/release/waf ./waf                 # 1) binary at ./waf
cp deploy/waf.contract.yaml ./waf.yaml      # 2) config in CWD (edit per node, §4)
# 3) ./waf_audit.log is created automatically on the first request
```

`./waf.yaml` ships with `interop.enabled: true`, `interop.audit_path:
"./waf_audit.log"`, and `interop.control_secret: "waf-hackathon-2026-ctrl"` — the
exact contract surface (control plane §2, audit §6, headers §5 are emitted by the
binary on every response).

---

## 4. Configure the node (`./waf.yaml`)

Start from `deploy/waf.contract.yaml` and change **per node**:

```yaml
node:
  id: "waf-2"                                  # MUST be unique per node
state:
  redis:
    urls: ["redis://10.20.0.72:6379"]          # the infra host (same on all nodes)
config_plane:                                   # H2b — durable config plane on etcd
  store: etcd                                   # shared_state (Redis) | etcd (as built)
  etcd:
    endpoints: ["http://10.20.0.72:2379"]      # the infra etcd (same on all nodes)
observability:
  otel:
    endpoint: "http://10.20.0.72:4317"         # SigNoz collector
upstreams:                                     # → infra mock (or your real upstreams)
  http-pool: { members: [{ addr: "10.20.0.72:9991" }] }
  ws-pool:   { members: [{ addr: "10.20.0.72:9992" }] }
  grpc-pool: { members: [{ addr: "10.20.0.72:9993" }] }
  tcp-pool:  { members: [{ addr: "10.20.0.72:9994" }] }
listeners:
  data:  [{ bind: "0.0.0.0:8080" }]            # plaintext (add :8443 TLS once you have a cert, §6)
  admin: { bind: "127.0.0.1:9443" }            # loopback — /__waf_control/* is loopback-gated
geoip:                                          # MaxMind enrichment (geoip feature)
  country_db: "data/geoip/GeoLite2-Country.mmdb"
  asn_db:     "data/geoip/GeoLite2-ASN.mmdb"
```

> **GeoIP:** the `geoip` feature is built (part of the run-copilot set), but it's
> a **no-op without the `geoip:` block + the `.mmdb` files**. The DBs are NOT
> committed (MaxMind license + 30-day refresh) — populate `data/geoip/` per node
> (see `data/geoip/README.md`). Confirm load: `maxminddb::decoder` lines at boot.

> **Rules that make it ONE fleet:** identical `state.redis.urls` **and**
> `config_plane.etcd.endpoints` on every node + a **unique `node.id`** each.
> Don't hand-edit detectors/rules/upstreams on each node — set them once on any
> node via the dashboard or `PUT /api/config`; the config plane converges to all
> nodes (etcd native Watch, no Redis pub/sub nudge) — see `CONFIG-PLANE-RUNBOOK.md`.

> **H2b — etcd config plane (as built).** The durable config doc + control plane
> live in **etcd** (`config_plane.store: etcd`); Redis still backs the data-plane
> hot path (rate-limit/risk/leases/L2) — it is **not** optional. To stand it up
> or migrate an existing Redis-backed plane, follow
> [`CONFIG-PLANE-RUNBOOK.md` §11](./CONFIG-PLANE-RUNBOOK.md): bring up etcd, run
> `waf migrate-config-plane --config ./waf.yaml` (require `verified: true`), then
> flip `store: etcd` and restart. The migration is a **copy** — Redis keeps the
> pre-cutover doc, so rollback is just setting `store: shared_state` again.

Validate before running:

```sh
./waf validate --config ./waf.yaml           # -> config OK
```

---

## 5. ONNX `ai` detector — ✅ ON (needs the version-matched onnxruntime)

**Status:** ON — `ai` compiled in (load-dynamic), model at
`data/ai_model/waf_model.onnx`, loads in <1s (`AI detector loaded … sessions=1`).

**⚠️ The one thing that matters: the onnxruntime `.so` version MUST match `ort`.**
`ort` 2.0.0-rc.12 expects **onnxruntime 1.24.2** (see `ort-sys/build/download/dist.txt`).
We first shipped **1.22.0** and boot **hung in `commit_from_file`** — that was a
**C-API version mismatch**, NOT glibc, threads, or cores (core-pinning to 8 did
*not* help; the correct `.so` fixed it instantly). Always match `dist.txt`.

**Fetch the right `.so` + set `ORT_DYLIB_PATH`** (per node; `runtime/` is gitignored):
```sh
mkdir -p runtime/onnxruntime
curl -fsSL https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-linux-x64-1.24.2.tgz \
  | tar -xz -C /tmp
cp /tmp/onnxruntime-linux-x64-1.24.2/lib/libonnxruntime.so* runtime/onnxruntime/
export ORT_DYLIB_PATH="$PWD/runtime/onnxruntime/libonnxruntime.so"   # we keep this in .env
```

**Config** (`waf.yaml` / `waf.contract.yaml`):
```yaml
ai: { enabled: true, model_path: "data/ai_model/waf_model.onnx", confidence_threshold: 0.95 }
```

> **Two boot facts:** (1) the ONNX session is built whenever `ai.model_path` is
> set + exists — *independent of* `enabled` (`run.rs:531`; `enabled` only flips
> the per-request toggle). (2) With `ai` enabled, **`ORT_DYLIB_PATH` must be set
> at launch or boot fails** to find onnxruntime — keep it in `.env` (sourced
> before `./waf run`) or a systemd `Environment=`. The new `POST /api/ai/reload`
> hot-swaps the model from `model_path` without a restart (admin-authed).

Signature detectors (sqli/xss/path-traversal/command-injection) + risk + DDoS are
on regardless — `ai` is an additive ML layer. Threshold kept HIGH (0.95): QA Run-2
saw ~75% FP at 0.85 on benign traffic.

---

## 6. Copilot (AI Operator Copilot — `llm`) — ✅ ON

Compiled in and **active** on the infra host. It activates when
`api_key_ref` resolves — the key lives in the gitignored **`.env`**
(`LLM_API_KEY=…`), which you must **load into the environment before `./waf run`**
(the raw `./waf run` does *not* auto-read `.env`; `make run-copilot` does):

```sh
set -a; . ./.env; set +a            # exports LLM_API_KEY for ${secret:env:LLM_API_KEY}
./waf run --config ./waf.yaml
```

It calls `observability.copilot` (`https://console.bizbrain.app/v1`, model
`Qwen3.6-35B-A3B`). Without the key the WAF logs `copilot api_key_ref failed to
resolve — copilot disabled` and runs normally. ⚠️ Active copilot = external LLM
egress — intended here. (If you `./waf run` without sourcing `.env`, that's the
**#1 reason copilot shows as disabled.**)

---

## 7. TLS — WAF terminates (edge); cert on every node

Each node terminates TLS (so JA3/JA4/device_fp work), so **the cert lives on the
node**, not on any LB. (If you front nodes with nginx `stream`, nginx forwards raw
TLS and holds **no cert** — §15.)

### 7a. Testing — self-signed (per node)
```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/selfsigned.key -out certs/selfsigned.crt \
  -subj "/CN=aegis-gate.local" \
  -addext "subjectAltName=DNS:localhost,DNS:aegis-gate.local,IP:127.0.0.1,IP:<NODE-IP>"
```
The committed `waf.contract.yaml` already has the matching TLS block:
```yaml
listeners:
  data:
    - { bind: "0.0.0.0:8080" }
    - { bind: "0.0.0.0:8443", tls: true }   # WAF terminates → device_fp
tls:
  min_version: "1.2"
  certificates:
    - cert_path: "certs/selfsigned.crt"
      key_ref:   "certs/selfsigned.key"
      hosts: ["localhost", "aegis-gate.local", "*.aegis-gate.local"]
```
Test: `curl -k https://<node>:8443/` → 200, and now the WAF computes JA4 →
`device_fp` populates (vs empty over plaintext). ⚠️ **The cert files must exist
before `./waf run`** or the `:8443` listener fails to bind.

### 7b. Production — one shared cert via DNS-01
In-WAF ACME runs on a **single node** (the `acme` task-lease holder) and is **not
fleet-aware** (the cert isn't distributed to the other nodes), so don't use it for a fleet.
Issue ONE wildcard / multi-SAN cert out-of-band with **DNS-01** (no per-node HTTP
challenge to route), deploy the SAME PEM to every node, ACME off:
```sh
certbot certonly --dns-<provider> -d yourdomain.com -d '*.yourdomain.com' ...
# push /etc/letsencrypt/live/yourdomain.com/{fullchain,privkey}.pem to each node
```
```yaml
tls:
  acme: { auto_renew: false }
  certificates:
    - { cert_path: "/etc/aegis/fullchain.pem", key_ref: "/etc/aegis/privkey.pem",
        hosts: ["yourdomain.com", "*.yourdomain.com"] }
```
Renew centrally → re-push → the WAF **hot-reloads** the cert (atomic swap, no
restart) on config apply.

---

## 8. Run

```sh
cd ~/aegis-gate
set -a; . ./.env; set +a                      # load LLM_API_KEY → activates copilot (§6)
AEGIS_INSECURE_COOKIES=1 ./waf run --config ./waf.yaml
#   AEGIS_INSECURE_COOKIES=1 allows the http admin/dashboard over loopback; drop it
#   once admin is TLS. The data plane is unaffected.
#   ORT_DYLIB_PATH is only needed if you enable the ai detector (§5) — leave the
#   config's ai.model_path UNSET otherwise, or boot will try (and here hang) to
#   load ORT.
```

The committed `deploy/waf.contract.yaml` is contract-correct as-is for a
copilot-on / ai-off node: copy it to `./waf.yaml`, set `node.id`, run.

For a long-lived service, wrap it in systemd / tmux / `nohup` per your ops norm.
⚠️ Do **not** stop it with `pkill -f "waf run --config ./waf.yaml"` from a shell
whose own command line contains that string — `pkill` will kill itself first.
Use the PID (`pgrep -f 'waf run' | head -1`).

---

## 9. DNS round-robin

Create one **A record per node IP** under your service hostname:

```
waf.example.com.  30  IN  A  <waf-1-ip>
waf.example.com.  30  IN  A  <waf-2-ip>
waf.example.com.  30  IN  A  <waf-3-ip>
```

Low TTL (30–60s) so failover/scale changes propagate quickly. Clients spread
across nodes; each sees the real client IP (it's the edge).

---

## 10. Verify the cluster

```sh
# Per-node readiness (admin is loopback — run on the node, or via your jump host):
curl -s http://127.0.0.1:9443/healthz/ready -o /dev/null -w "ready %{http_code}\n"

# Shared config version equal across nodes ⇒ same fleet / shared Redis:
#   (run on each node) compare the value
curl -s http://127.0.0.1:9443/api/config | jq .version

# Committee contract surface (run on the node, loopback):
SECRET=waf-hackathon-2026-ctrl
curl -s -H "X-Benchmark-Secret: $SECRET" http://127.0.0.1:9443/__waf_control/capabilities | jq .ok
curl -s -o /dev/null -w "no-secret -> %{http_code}\n" http://127.0.0.1:9443/__waf_control/capabilities  # 403

# Observability headers + decisions on the data plane:
curl -s -D - -o /dev/null http://127.0.0.1:8080/products | grep -i '^x-waf-'        # allow + 6 headers
curl -s -o /dev/null -w "SQLi -> %{http_code}\n" "http://127.0.0.1:8080/?q=1'%20OR%20'1'='1"  # 403 block
tail -1 ./waf_audit.log                                                              # JSONL contract entry

# Traces: open SigNoz http://10.20.0.72:8090 → Traces → serviceName=aegis-gate
#   (one service, spans tagged by node via resource attributes / node.id)
```

---

## 10a. Cross-node admin console — LB to any node

The cluster is **leaderless** and every node's console now renders the **whole
fleet**, not just its own slice — so you can put an LB in front of the admin
consoles and operators hit **any** node (round-robin / pick-any). No "must hit
the leader" anymore. Enable the cross-node sync (shared Redis required):

```yaml
cluster:
  fleet_events: { enabled: true }   # peers' live events → every node's SSE (≤5s)
  fleet_view:   { enabled: true }   # RPS / latency / top-attackers merged on read
  pubsub_nudge: true                # set_profile/reset_state converge in ms
```

With these on, `/api/stats` carries `fleet_nodes` and the dashboard banner shows
**"Fleet view (N nodes)"**; `/api/cluster` is a flat roster (`peers` + `our_node`,
no leader badge).

**Three things to get right when LB-ing the console plane** (cluster plan §5.5):

1. **Expose the admin listener.** It binds `127.0.0.1:9443` by default (that's why
   you port-forward today). To LB it, bind admin to a routable interface and keep
   it locked down — admin-auth is already on; add a network ACL / private subnet /
   mTLS. **Never expose `:9443` to the public internet.**
2. **Stream the SSE feed.** `/dashboard/sse` is a long-lived `text/event-stream`.
   The LB must do **streaming pass-through** — disable response buffering + a
   generous read timeout (nginx: `proxy_buffering off; proxy_read_timeout 1h;`).
   Otherwise events stall in the LB buffer and you blow the ≤5s SLA at the *LB*.
3. **Share the admin cookie-signing key.** Sessions live in the shared backend, so
   a login on any node validates on all — but every node must use the **same**
   `admin.dashboard_auth.csrf_secret`. Sticky affinity is then optional (it only
   trims SSE-reconnect churn; correctness doesn't need it).

Audit logs stay per-node (the live feed is a lossy monitor); for the complete
fleet trail merge every node's `waf_audit.log` with
[`collect-audit.sh`](./collect-audit.sh) (orders by `ts_ms`, joins by `request_id`)
or query SigNoz. See [`config/REFERENCE.md`](../config/REFERENCE.md) §`cluster` +
[`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).

---

## 11. Operate

- **Scale out:** new VM → §1–§4 with a fresh `node.id` + same Redis → run → add
  its IP to the DNS A-record set.
- **Drain (zero-drop):** `curl -X POST http://127.0.0.1:9443/admin/drain` →
  readiness flips 503 → remove the node's IP from DNS (or let clients re-resolve)
  → stop the process after in-flight drains.
- **Rolling upgrade:** drain → `git pull` + `cargo build --release …` → swap
  `./waf` → start → wait `/healthz/ready` 200 → next node. The config plane keeps
  policy consistent across mixed versions.
- **Reset between benchmark runs (contract §2.4):**
  `curl -X POST -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" http://127.0.0.1:9443/__waf_control/reset_state`
  (clears risk/rate-limit/challenge/cache state; **preserves** `./waf_audit.log`).

---

## 12. Gotchas (learned the hard way)

| Symptom | Cause | Fix |
|---|---|---|
| `undefined symbol: __isoc23_strtoll` at link | `ort` prebuilt needs glibc ≥2.38 | already fixed — `ort` uses `load-dynamic` in `Cargo.toml`; provide the `.so` (§5) only if enabling `ai` |
| `COPY .../waf: not found` in Docker build | Dockerfile masks cargo failure with `|| true` | check the real `cargo build` output; usually the glibc/ort link above |
| Nodes show different `/api/config` versions | a node can't reach Redis | check `state.redis.urls` + reachability to `10.20.0.72:6379` |
| `/__waf_control/*` returns 403 from another host | endpoints are loopback-gated | call from the node itself (127.0.0.1), not over the network |
| Traces missing in SigNoz | SigNoz onboarding not done / wrong endpoint | onboard once (admin org), confirm `otel.endpoint=http://10.20.0.72:4317` |
| Traces show but **no logs** in SigNoz | WAF doesn't push logs over OTLP — only stdout | run a per-node otel-collector with the `filelog` receiver (§13) |
| `copilot disabled` in logs | `LLM_API_KEY` not set / `.env` not sourced | `set -a; . ./.env; set +a` before `./waf run` (§6) |
| WAF hangs at boot after "fresh-bind" with `ai` | onnxruntime `.so` version ≠ what `ort` expects (C-API mismatch) | use the version in `ort-sys/build/download/dist.txt` (1.24.2 for rc.12), not an older one (§5) |
| Boot fails: can't find onnxruntime, with `ai` enabled | `ORT_DYLIB_PATH` unset (load-dynamic) | set it (we keep it in `.env`, sourced before `./waf run`) — or disable `ai` |
| collector crashes: `redaction … telemetry type is not supported` | otelcol-contrib 0.103 redaction has no logs support | keep `redaction` out of the logs pipeline (done in `collector.yaml`) |
| SigNoz logs flooded with TRACE/DEBUG | dependency crates log verbosely | set `RUST_LOG="info,hyper=warn,hyper_util=warn,h2=warn,tower=warn,rustls=warn"` (§13) |
| `pkill -f "waf run …"` kills nothing / kills itself | the pkill shell's own argv matches the pattern | kill by PID: `kill $(pgrep -f '\./waf run' | head -1)` |

---

## 13. Observability shipping — traces, logs, metrics (multi-node)

**Traces** go straight from each WAF to SigNoz (`observability.otel.endpoint`).
**Logs and metrics do NOT auto-export** — the WAF writes logs to stdout and
serves metrics on its admin `/metrics`. To get them into SigNoz you run an
**OTel Collector**, and because its `filelog`/`prometheus` receivers read
**local** files/ports, you need **one collector AGENT per WAF VM** (a single
central collector cannot tail a remote node's log or scrape its loopback admin).

```
per WAF VM:   WAF ──traces OTLP──────▶ local agent ─┐
              logs/waf.json ──filelog──▶ agent       │
              waf_audit.log ──filelog──▶ agent       ├─OTLP─▶ 10.20.0.72:4317 (central SigNoz)
              /metrics :9443 ──prom─────▶ agent ─────┘   tagged host.name=<node-id>
```

**Three log streams — know what goes where:**

| File | Contents | Shipped to SigNoz |
|---|---|---|
| `logs/waf.json` | WAF **app/tracing** logs (level/target/message) | ✅ `filelog` |
| `./waf_audit.log` | **Security audit** (contract §6: request_id, action, risk_score, mode) — tagged `log_type=waf_audit` in SigNoz | ✅ `filelog/audit` |
| `/tmp/aegis-audit.jsonl` | the `audit:` block's chain sink | ❌ **wired but unfed** — no file is produced (per-request decisions go to `waf_audit.log`, not this chain). Harmless; it's a redundant path. The contract audit is authoritative. |

> The two log files have **different schemas** (`waf.json` has `timestamp`+`level`;
> `waf_audit.log` has epoch-ms `ts_ms`, no level), so the collector uses **two
> filelog receivers**. The audit file mounts to a **separate path**
> (`/var/log/aegis-audit/`) because `/var/log/aegis` is a read-only mount.

**Set up per node:**
1. Write the WAF's JSON logs to a file: `./waf run … >> logs/waf.json 2>&1`.
2. Point the WAF's traces at the **local** agent (so the agent stamps host.name +
   can redact): `WAF_OBSERVABILITY__OTEL__ENDPOINT=http://127.0.0.1:4317`.
3. Run the agent (config: [`../otel/collector-agent.yaml`](../otel/collector-agent.yaml)):
   ```sh
   cd deploy/compose
   NODE_ID=waf-2 docker compose -f otel-agent.docker-compose.yml up -d
   ```
   It exports to `10.20.0.72:4317` and stamps `host.name=$NODE_ID` so SigNoz
   groups traces/logs/metrics per node. (Uses host networking — needs rootful
   Docker on the WAF VM; for rootless, see the comments in that compose.)

> **The node co-located with SigNoz** (the infra host) is the exception — it can
> reach SigNoz over the docker network, so it uses
> [`../otel/collector.yaml`](../otel/collector.yaml) +
> [`otel-collector.docker-compose.yml`](compose/otel-collector.docker-compose.yml)
> (exports to `signoz-otel-collector:4317`). Same `filelog` logs pipeline.

**Tame log volume** (the WAF logs dependency crates at TRACE/DEBUG, which floods
SigNoz). Run with:
```sh
export RUST_LOG="info,hyper=warn,hyper_util=warn,h2=warn,tower=warn,rustls=warn,tonic=warn,maxminddb=warn"
```
For even quieter logs, lower `logging.verbosity` or extend `RUST_LOG` with the
`aegis_proxy=info` target.

**Metrics caveat:** the `prometheus` receiver scrapes the WAF admin `/metrics`,
which is bound to `127.0.0.1:9443`. The agent reaches it only via **host
networking** (above). A central collector cannot scrape a remote node's loopback
admin — another reason for the per-node agent.

### 13a. Ship logs + traces from a REMOTE node (do-this checklist)

A remote node ships **nothing** to SigNoz until you do this ON that node — setting
the traces endpoint is **not enough for logs** (logs are local files; they need an
agent). Symptom if skipped: requests that round-robin to this node have **no logs
and no traces** in SigNoz (you only see the infra node's share).

**Robust path (works rootless or rootful) — traces direct + a logs-only agent:**
```sh
# On the remote node, in the repo:
# 1) TRACES — WAF exports straight to central SigNoz. In waf.yaml:
#      observability: { otel: { endpoint: "http://10.20.0.72:4317", sample_ratio: 1.0 } }
nc -z 10.20.0.72 4317 && echo otlp-reachable          # must succeed
# 2) write logs to a file (so the agent can tail them):
#      ./waf run --config ./waf.yaml >> logs/waf.json 2>&1   (waf_audit.log is ./waf_audit.log)
# 3) LOGS — run the agent (filelog → central SigNoz). NODE_ID must match the WAF node.id:
cd deploy/compose
NODE_ID=<this-node-id> docker compose -f otel-agent.docker-compose.yml up -d
```
> The agent compose uses `network_mode: host` so it can also scrape `:9443/metrics`.
> That needs **rootful Docker** on the node. **On rootless Docker**, host-net can't
> reach the host loopback — drop `network_mode: host` from `otel-agent.docker-compose.yml`,
> add `extra_hosts: ["host.docker.internal:host-gateway"]`, and the **filelog (logs)
> still ships fine**; only the loopback `/metrics` scrape is lost (traces still go
> direct from the WAF; logs via the agent).

**Unified `host.name` on traces too (optional):** instead of step 1, point the WAF
at the **local** agent — `WAF_OBSERVABILITY__OTEL__ENDPOINT=http://127.0.0.1:4317` —
so the agent stamps `host.name` on traces+logs+metrics. Requires the agent up first
+ host networking (rootful).

**Verify (from the infra host):**
```sh
# traces from this node arrive (drive traffic through the LB first):
docker exec signoz-clickhouse clickhouse-client -q "SELECT count() FROM signoz_traces.distributed_signoz_index_v3 WHERE timestamp > now()-INTERVAL 2 MINUTE AND serviceName='aegis-gate'"
# logs by node — expect this node's host.name with log_type=waf_audit:
docker exec signoz-clickhouse clickhouse-client -q "SELECT resources_string['host.name'], attributes_string['log_type'], count() FROM signoz_logs.distributed_logs_v2 WHERE timestamp > toUnixTimestamp64Nano(now64()-INTERVAL 2 MINUTE) GROUP BY 1,2"
```
In the SigNoz UI → **Logs**, filter `log_type = waf_audit` to see request decisions,
grouped by `host.name`.

---

## 14. Resource limits — match the real node spec (8 vCPU / 16 GB)

This infra host has 128 cores; to benchmark against the real **8 vCPU / 16 GB**
node spec, constrain the WAF. **Pin CPUs with `cpuset`, not just `cpus`:** a CFS
quota (`cpus`) throttles but the process still *sees* all 128 cores, so tokio
workers and ORT's intra-op pool still size to 128 (the ORT 128-thread pool is
what deadlocks `ai`). `cpuset` changes `sched_getaffinity` → the WAF sees 8 CPUs.

**Docker node** ([`waf-local.docker-compose.yml`](compose/waf-local.docker-compose.yml)):
```yaml
services:
  waf-local:
    cpuset: "0-7"        # pin to 8 cores (sizes tokio workers + ORT threads to 8)
    cpus: "8"            # CFS quota (defence in depth)
    mem_limit: "16g"
```

**Native binary** — pin + cap via systemd (or `taskset`/`nice`):
```ini
# /etc/systemd/system/aegis-waf.service  (excerpt)
[Service]
AllowedCPUs=0-7        # = cpuset; the WAF then sees 8 CPUs
MemoryMax=16G
ExecStart=/home/USER/aegis-gate/waf run --config /home/USER/aegis-gate/waf.yaml
```
or ad-hoc: `taskset -c 0-7 ./waf run --config ./waf.yaml`. Also set
`runtime.workers: 8` in `waf.yaml` to fix the tokio pool explicitly.

> **Note:** core count is **not** what blocked `ai` — that was an onnxruntime
> version mismatch (§5), fixed by the right `.so`. `cpuset` is purely about
> matching the real node spec; `ai` runs fine at 8 or 128 cores once the
> onnxruntime version matches `ort` (1.24.2).

---

## 15. Testing multiple nodes with an nginx LB (alternative to DNS-RR)

For a single test entry point in front of ≥2 WAF nodes, nginx works and — unlike
HAProxy+TPROXY — needs **no root/caps** (runs under rootless Docker). Two modes,
pick by whether you need client-IP forwarding:

| Mode | Config | TLS / JA3 | Client IP to WAF | Use when |
|---|---|---|---|---|
| **L4 `stream`** | [`../nginx/nginx-stream.conf`](../nginx/nginx-stream.conf) | ✅ WAF terminates (preserved) | ❌ nginx IP (SNAT) | keep protocols + JA3; don't need client IP |
| **L7 `http` + XFF** | [`../nginx/nginx-http.conf`](../nginx/nginx-http.conf) | ❌ nginx terminates | via `X-Forwarded-For` | want client IP forwarded (pending WAF XFF-resolution) |

The active LB config is **L4 `stream` over TLS** (`nginx-stream.conf` → nodes'
`:8443`/`:8444`): `curl -k https://10.20.0.72:8088/`. Verified 10 HTTPS requests →
**5 node1 / 5 node2**, WAF terminates TLS each side → JA3/JA4/device_fp work.

**Two-nodes-on-ONE-host (this test box)** needs distinct ports per node:

| | node1 | node2 |
|---|---|---|
| plaintext | :8080 | :8081 |
| **TLS** | **:8443** | **:8444** |
| admin | :9443 | :9444 |
| config | `waf.yaml` | `waf2.yaml` (same, ports+node.id+audit changed) |

```sh
set -a; . ./.env; set +a   # LLM_API_KEY + ORT_DYLIB_PATH
AEGIS_INSECURE_COOKIES=1 ./waf run --config ./waf.yaml  >> logs/waf.json  2>&1 &
AEGIS_INSECURE_COOKIES=1 ./waf run --config ./waf2.yaml >> logs/waf2.json 2>&1 &
cd deploy/compose && docker compose -f nginx-lb.docker-compose.yml up -d   # VIP :8088 → {8443,8444}
```
Verified: both nodes share the Redis cluster (leaderless — members `waf-infra-1`
+ `waf-infra-2` in `/api/cluster.peers`, shared per-task leases).

### 15a. Deploying nodes on OTHER machines (the real cluster)

On separate VMs there is **no port contention**, so **every node uses the SAME
ports** — `:8080`, `:8443`, `:9443` — and the **same `waf.yaml`** (just a unique
`node.id`). The `:8081/:8444/:9444/waf2.yaml` split above is *only* because two
nodes share this one host.

Per remote VM:
1. Build (§1–§2) + contract files (§3) + config (§4) with a **unique `node.id`**
   and `state.redis.urls=["redis://10.20.0.72:6379"]`.
2. **Cert (§7):** self-signed with that node's IP in the SAN (test), or the shared
   DNS-01 PEM (prod); enable the `:8443` TLS listener.
3. `ai` (§5): onnxruntime **1.24.2** + `ORT_DYLIB_PATH`; `geoip` (§4): copy the
   `.mmdb`s. Run `set -a; . ./.env; set +a; ./waf run --config ./waf.yaml`.
4. **Front the fleet** — nginx `stream` upstream points at each VM's `:8443`:
   ```nginx
   upstream waf_nodes {
       server 10.20.0.81:8443;   # waf VM 1
       server 10.20.0.82:8443;   # waf VM 2
       server 10.20.0.83:8443;   # waf VM 3
   }
   ```
   …or skip the LB and use **DNS round-robin** (A-records → each VM IP) so the WAF
   is the direct edge (real client IP + JA3/JA4 — recommended for prod).
5. Verify: node shows in Redis cluster members + `/healthz/ready` 200; per-protocol
   smoke through the VIP.

**Gotchas learned here:**
- **Round-robin looked "pinned to node1"** — `worker_processes auto` on a many-core
  host gives each worker its own RR counter; low-volume sequential requests scatter
  across fresh workers that all start at server #1. Fix: `worker_processes 1` (test)
  or an upstream `zone` for shared state. Under real concurrent load `auto` evens out.
- **X-Forwarded-For needs L7** — `stream` (L4) can't add headers. The L7 config sets
  `X-Forwarded-For $proxy_add_x_forwarded_for` (appends client-sent XFF), verified as
  `fwd_for="5.195.235.51, <nginx-src>"` toward the WAF.
- ⚠️ **The WAF currently IGNORES XFF** (default `trusted_proxies` empty / not plumbed),
  so it still keys on nginx's peer IP until **XFF-resolution lands + nginx's IP is in
  `trusted_proxies`**. The nginx side is ready; the WAF side is the pending piece.
- ⚠️ Rootless Docker SNATs published-port traffic too, so nginx sees the docker
  gateway as the source for host-originated curls — send a real client XFF to test
  the chain end-to-end.

> **This is a test harness, not the production topology.** Production stays
> **DNS round-robin** (no LB) so the WAF is the edge with real client IP + JA3/JA4
> (§0). Use the nginx LB to exercise multi-node fan-out + cluster behaviour.
