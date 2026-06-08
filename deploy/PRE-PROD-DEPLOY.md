# Aegis-Gate — Pre-Prod Cluster Deployment Guide

> **What this is:** the practical, *as-built* runbook for the `pre-prod`
> topology — **one infra host** (Redis + multi-protocol mock + SigNoz) and
> **N WAF nodes** (native binary, the TLS edge) sharing state via Redis,
> balanced by **DNS round-robin**. It reflects exactly what we stood up and
> verified, including the committee interop contract (v2.3/2.5 §8) and the
> `make run-copilot` feature set (`redis geoip alerts ai affinity otel llm`).
>
> **Companion docs:** [`INFRA-HOST-STATUS.md`](./INFRA-HOST-STATUS.md) (what runs
> on the infra host) · [`CONFIG-PLANE-RUNBOOK.md`](./CONFIG-PLANE-RUNBOOK.md)
> (live config) · [`HACKATHON-FLEET.md`](./HACKATHON-FLEET.md) (the HAProxy/TPROXY
> variant — *not* used here; see "Why DNS round-robin" below).

---

## 0. Topology (as built)

```
                    ┌──────────────── infra host: 10.20.0.72 ───────────────┐
   clients          │  Redis :6379  (shared state · config plane · leases)   │
     │  DNS A RR     │  mock  :9991/2/3/4  (http · ws · grpc · raw-tcp)       │
     ▼              │  SigNoz :4317 OTLP  ·  :8090 UI                         │
  waf-1  waf-2  …    └───────────────────────────────────────────────────────┘
  (each VM is the TLS edge: terminates TLS → JA3/JA4 + real client IP native)
     │   each node → Redis(:6379) state+config · OTLP(:4317) traces · mock(:999x) upstream
     └── all nodes share one Redis ⇒ one fleet (rate-limit · risk · config · block-list)
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
| Shared state / config plane / leases | `redis://10.20.0.72:6379` |
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
curl -s http://10.20.0.72:9991/api/health   # -> {"status":"ok"}
nc -z 10.20.0.72 4317 && echo "otlp ok"
```

> **glibc note:** the `ai` (ONNX) feature can't link its *prebuilt* runtime on
> glibc < 2.38. This repo already pins `ort` to **`load-dynamic`** (in
> `Cargo.toml`), so the binary builds on any glibc and `dlopen`s a separate
> `libonnxruntime.so` only if you actually enable `ai` (off by default). See §5.

---

## 2. Build the WAF (native, run-copilot feature set)

```sh
cd ~/aegis-gate            # the cloned repo (this pre-prod branch)
source "$HOME/.cargo/env"
cargo build -p aegis-bin --release \
    --features "redis geoip alerts ai affinity otel llm"
# ~10-20 min first build; seconds after. Result: target/release/waf
```

These are exactly the `make run-copilot` features (`FEATURES="redis geoip alerts
ai affinity"` + `otel llm`). `affinity` enables optional CPU pinning (config
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
```

> **Rules that make it ONE fleet:** identical `state.redis.urls` on every node +
> a **unique `node.id`** each. Don't hand-edit detectors/rules/upstreams on each
> node — set them once on any node via the dashboard or `PUT /api/config`; the
> config plane converges to all nodes in ~3s (see `CONFIG-PLANE-RUNBOOK.md`).

Validate before running:

```sh
./waf validate --config ./waf.yaml           # -> config OK
```

---

## 5. (Optional) Enable the ONNX `ai` detector

Off by default. To turn it on, the node needs a glibc-compatible
`libonnxruntime.so` (the `ai` feature is compiled in via `load-dynamic`):

```sh
mkdir -p runtime/onnxruntime
curl -fsSL https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-linux-x64-1.22.0.tgz \
  | tar -xz -C /tmp
cp /tmp/onnxruntime-linux-x64-1.22.0/lib/libonnxruntime.so* runtime/onnxruntime/
# then set ai.enabled:true in ./waf.yaml, provide your model, and:
export ORT_DYLIB_PATH="$PWD/runtime/onnxruntime/libonnxruntime.so"
```

(onnxruntime 1.22 matches `ort` 2.0.0-rc.12; that `.so` needs only GLIBC_2.27.)
If `ai.enabled:false` (default), `ORT_DYLIB_PATH` is **not** required.

---

## 6. Copilot (AI Operator Copilot — `llm`)

Compiled in. Inert until a key resolves. To activate:

```sh
export LLM_API_KEY="sk-..."                   # resolves ${secret:env:LLM_API_KEY}
```

It calls the endpoint in `observability.copilot` (`https://console.bizbrain.app/v1`,
model `Qwen3.6-35B-A3B`). Without the key the WAF logs `copilot disabled` and runs
normally. ⚠️ This makes external LLM egress — only enable where that's intended.

---

## 7. TLS (deferred → add per node when ready)

We run **plaintext `:8080`** for now (TLS deferred). When you provision certs,
since each node is the TLS edge, deploy **one shared cert to all nodes** and turn
off in-WAF ACME (it's leader-only / not fleet-aware):

```yaml
listeners:
  data:
    - { bind: "0.0.0.0:8443", tls: true }
    - { bind: "0.0.0.0:8080" }
tls:
  acme: { auto_renew: false }
  certificates:
    - { cert_path: "/etc/aegis/fullchain.pem", key_ref: "/etc/aegis/privkey.pem" }
```

Issue a wildcard/multi-SAN cert out-of-band (certbot/cert-manager on the infra
host or DNS-01), push the same PEM to every node, re-push on renewal.

---

## 8. Run

```sh
cd ~/aegis-gate
# ORT_DYLIB_PATH only if ai enabled; LLM_API_KEY only if copilot wanted.
AEGIS_INSECURE_COOKIES=1 ./waf run --config ./waf.yaml
#   AEGIS_INSECURE_COOKIES=1 allows the http admin/dashboard over loopback; drop it
#   once admin is TLS. The data plane is unaffected.
```

For a long-lived service, wrap it in systemd / tmux / `nohup` per your ops norm.

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
| `copilot disabled` in logs | `LLM_API_KEY` not set | export the key (§6) — harmless if you don't want copilot |
