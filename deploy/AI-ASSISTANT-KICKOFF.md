# Deploying Aegis-Gate with an AI assistant — kickoff

> Hand this file (or the prompt below) to an AI coding assistant to redeploy the
> system with minimal back-and-forth. It encodes the environment facts and the
> decisions already made, so the assistant doesn't have to re-discover them.

## 1. Paste this prompt to start

```
Deploy Aegis-Gate per deploy/PRE-PROD-DEPLOY.md and deploy/INFRA-HOST-STATUS.md.
READ BOTH FIRST. We use the pre-prod topology: one infra host + native WAF nodes,
DNS round-robin (NO HAProxy/TPROXY — this infra host is rootless Docker, no sudo).
Honor the committee interop contract (Hackathon_Doc/EN_waf_interop_contract_v2.5.md
§8: ./waf, ./waf.yaml, ./waf_audit.log). Build with the make run-copilot feature
set. My answers to the usual decisions are in deploy/AI-ASSISTANT-KICKOFF.md §3 —
use them, don't re-ask unless reality differs. Verify everything end-to-end and
show me the contract checks before declaring done.
```

## 2. Environment facts (verify, don't assume — they may change)

- **Infra host:** `10.20.0.72` (NIC `ens34`). Ubuntu 22.04, **glibc 2.35**.
- **Docker is rootless** (uid 1003, slirp4netns), **no passwordless sudo**.
  ⇒ no TPROXY, no privileged ports, no host networking. This is *why* we use
  DNS round-robin instead of HAProxy. If a future host has root + a spare NIC,
  `HACKATHON-FLEET.md` covers the HAProxy `mode tcp` + TPROXY upgrade.
- **Repo:** `~/aegis-gate`, deploy branch **`pre-prod`**.
- **Rust:** install rustup (user-local, no sudo) if `cargo` is missing.
- **SigNoz** lives **outside the repo** at `~/signoz` with a local
  `docker-compose.override.yaml` (UI remapped to `:8090`, off the busy `:8080`).
  Re-clone + re-apply the override if rebuilding it.

## 3. Pre-answered decisions (the questions the assistant will hit)

| Decision | Answer | Why |
|---|---|---|
| Load balancing / client-IP | **DNS round-robin, no LB** | rootless host can't TPROXY; DNS-RR keeps real client IP + JA3/JA4 |
| Redis topology | **Single instance (AOF)** | fine for this scale; HA later via Sentinel/Cluster |
| Observability | **Full SigNoz** (UI `:8090`, OTLP `:4317`) | OTel-native single pane |
| WAF runtime | **Native binary** (`cargo build --release`) | contract wants `./waf`; best perf |
| Build features | **`redis geoip alerts ai affinity otel llm`** | = `make run-copilot` set |
| `ai` / ONNX (`ort`) | **ON** (load-dynamic + onnxruntime 1.24.2) | glibc 2.35 can't link the prebuilt → load-dynamic; the `.so` version MUST equal `ort-sys/.../dist.txt` (**1.24.2** for rc.12 — 1.22.0 hung at boot, a C-API mismatch, NOT a deadlock/glibc/core issue). `ai.enabled`+`model_path` in `waf.yaml`; **`ORT_DYLIB_PATH` required at launch** (kept in `.env`). Guide §5 |
| Copilot (`llm`) | **ON** | key in gitignored `.env`; **`set -a; . ./.env; set +a` before `./waf run`** (bare run doesn't read `.env`). Endpoint `console.bizbrain.app`, model `Qwen3.6-35B-A3B` |
| Logs → SigNoz | **per-node otel-collector** (`filelog`) | WAF only exports traces; logs need `./waf run … >> logs/waf.json` + a collector tailing it. ONE agent per VM. Guide §13 |
| Resource limits | **cpuset+mem** to match 8 vCPU/16 GB | use `cpuset` (not just `cpus`) so the WAF sees 8 CPUs — caps tokio + ORT threads. Guide §14 |
| Log verbosity | **cap via `RUST_LOG`** | deps log at TRACE → floods SigNoz. `RUST_LOG="info,hyper=warn,hyper_util=warn,h2=warn,tower=warn,rustls=warn"` |
| TLS | **Deferred** (plaintext `:8080`) | add a shared cert per node when ready (guide §7) |
| Control-plane secret | `waf-hackathon-2026-ctrl` | contract §2.2 `X-Benchmark-Secret` |
| Cross-node console | **ON** — `cluster.{fleet_events,fleet_view}.enabled: true` + `pubsub_nudge: true` | leaderless; every node's dashboard shows the whole fleet (live events ≤5s + merged metrics), so the console can be hit on any node. PRE-PROD-DEPLOY §10a |

**Things the assistant MUST still ask you** (don't pre-answer — they're real-time
or sensitive): the actual **WAF node IPs/hostnames**, the **LLM_API_KEY** value,
the **TLS cert/domain** when you stop deferring, and confirmation before
**stopping/altering any unrelated service** on a shared host.

## 4. Definition of done (make the assistant prove these)

- Infra: `redis-cli -h 10.20.0.72 ping` → PONG; mock `/api/health` 200 on `:9991`;
  SigNoz UI 200 on `:8090`, OTLP `:4317` open + ingesting.
- Per WAF node: `./waf`, `./waf.yaml`, `./waf_audit.log` present; `/healthz/ready`
  200; legit → `allow` 200, SQLi → `block` 403 with all six `X-WAF-*` headers;
  `/__waf_control/capabilities` 200 with the secret / 403 without; `reset_state`
  + `set_profile` work; audit log is JSONL with the §6 fields; traces
  (`serviceName=aegis-gate`) visible in SigNoz.
- Cluster (leaderless): every node shows the same `/api/config` version (shared
  Redis); `/api/cluster` lists both nodes as flat `peers` + `our_node` (no
  `is_leader`); with fleet-view on, `/api/stats` carries `fleet_nodes` ≥ 2.

## 5. Gotchas the assistant should expect

- The Dockerfile's `cargo build … || true` **masks build failures** → they
  resurface as `COPY .../waf: not found`. Check the real cargo output.
- `__isoc23_strtoll` undefined at link = the glibc/ort issue → load-dynamic (§3).
- `/__waf_control/*` is **loopback-gated** — call it from the node (127.0.0.1).
- Don't commit artifacts: `./waf`, `./waf.yaml`, `./waf_audit.log`, `runtime/`,
  `target/` are gitignored on purpose.
