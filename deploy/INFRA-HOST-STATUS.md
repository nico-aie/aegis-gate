# Aegis-Gate infra host — deployment status (this machine)

**Host:** `10.20.0.72` (NIC `ens34`, /22) · Ubuntu 22.04.5 (glibc 2.35)
**Docker:** rootless (uid 1003, slirp4netns) · **no sudo**
**Topology:** DNS round-robin (no in-path LB) · **Date:** 2026-06-08

> To deploy **additional WAF nodes on other VMs (cluster mode)**, follow
> [`PRE-PROD-DEPLOY.md`](./PRE-PROD-DEPLOY.md). This file documents only what runs
> on **this** host.

> **Why no HAProxy/TPROXY here?** Rootless Docker (slirp4netns NAT) + no sudo
> can't do TPROXY (needs real host `CAP_NET_ADMIN`/`NET_RAW`, `ip_nonlocal_bind=1`,
> privileged `:443`, true host networking). We use **DNS round-robin**: each WAF
> node is the TLS edge, which *preserves* real client IP + JA3/JA4 natively — a
> better outcome than a rootless HAProxy (which would SNAT the client away).

## What's running

| Service | Bind (on `10.20.0.72`) | Status | Managed by |
|---|---|---|---|
| Redis (single, AOF) | `6379` | ✅ healthy | `deploy/compose/infra.docker-compose.yml` |
| Mock — HTTP/1.1+h2c | `9991` | ✅ | same |
| Mock — WebSocket | `9992` | ✅ | same |
| Mock — gRPC | `9993` | ✅ | same |
| Mock — raw TCP | `9994` | ✅ | same |
| SigNoz UI | `8090` *(remapped off busy :8080)* | ✅ | `~/signoz/deploy/docker/` + `docker-compose.override.yaml` |
| SigNoz OTLP gRPC / HTTP | `4317` / `4318` | ✅ ingesting | same |
| **WAF node `waf-infra-1`** (native binary) | data `:8080`, admin `127.0.0.1:9443` | ✅ | `./waf run` (see below) |

### Manage the infra containers

```sh
cd ~/aegis-gate/deploy/compose
docker compose -f infra.docker-compose.yml up -d        # Redis + mock
docker compose -f infra.docker-compose.yml down         # (-v wipes redis volume)

cd ~/signoz/deploy/docker                                # SigNoz — BOTH -f files
docker compose -f docker-compose.yaml -f docker-compose.override.yaml up -d
```

## WAF node on this host — committee binary contract (§8) ✅

Built natively with the **`make run-copilot` feature set** and run from the repo
root so the three contract artifacts live in the project folder:

```
./waf            # binary (gitignored)        — built from target/release/waf
./waf.yaml       # config in CWD (gitignored)  — copy of deploy/waf.contract.yaml
./waf_audit.log  # JSONL audit (gitignored)    — created on first request
```

Build + run (the `ort`/`ai` fix is committed — see below):

```sh
source ~/.cargo/env
cargo build -p aegis-bin --release --features "redis geoip alerts ai affinity otel llm"
cp target/release/waf ./waf
cp deploy/waf.contract.yaml ./waf.yaml        # then set node.id / IPs as needed
set -a; . ./.env; set +a                       # LLM_API_KEY (copilot) + ORT_DYLIB_PATH (ai)
export RUST_LOG="info,hyper=warn,hyper_util=warn,h2=warn,tower=warn,rustls=warn,tonic=warn"
AEGIS_INSECURE_COOKIES=1 ./waf run --config ./waf.yaml >> logs/waf.json 2>&1 &
# ai is ON (waf.yaml: ai.enabled + model_path). It needs onnxruntime 1.24.2 in
# runtime/onnxruntime/ + ORT_DYLIB_PATH (kept in .env). The earlier boot hang was
# a VERSION MISMATCH (1.22.0 vs required 1.24.2), not a deadlock — see §5 of the
# deploy guide. Loads in <1s.
```

**Verified against the contract:**
- §8 — `./waf`, `./waf.yaml`, `./waf_audit.log` all present.
- §5 — every response carries `X-WAF-Request-Id/Risk-Score/Action/Rule-Id/Cache/Mode`.
- §3/§4 — legit → `allow` 200; SQLi → `block` 403 (`X-WAF-Rule-Id: sqli`).
- §2 — `GET /__waf_control/capabilities` (with `X-Benchmark-Secret: waf-hackathon-2026-ctrl`) → 200; without → 403; `reset_state` (audit preserved) and `set_profile` (`all`→`log_only` flips enforcement while still reporting the intended action) work.
- §6 — `waf_audit.log` is JSONL with `request_id, ts_ms, ip(peer), method, path, action, risk_score, mode`; `request_id` matches the response header.
- Traces (`serviceName=aegis-gate`) land in SigNoz; **logs** ship via the
  otel-collector `filelog` pipeline (below); AI **hot-reload** API merged from
  develop (`POST /api/ai/reload`, no restart — `crates/*/src/ai_reload.rs`).
- **`ai` ONNX detector ON** — `AI detector loaded … sessions=1, enabled=true`
  from `data/ai_model/waf_model.onnx` (onnxruntime 1.24.2).

**Copilot** is **ON** — `llm` compiled in + `LLM_API_KEY` loaded from `.env`
(`set -a; . ./.env; set +a` before `./waf run`; the bare command does NOT read
`.env`). Endpoint `https://console.bizbrain.app/v1`, model `Qwen3.6-35B-A3B`.

**Logs → SigNoz:** WAF JSON logs go to `logs/waf.json`; an otel-collector tails
them (`filelog`) → SigNoz Logs. Started via
`deploy/compose/otel-collector.docker-compose.yml` (this host) /
`otel-agent.docker-compose.yml` (other VMs). See PRE-PROD-DEPLOY.md §13.

## ✅ Resolved: `ai`/`ort` vs glibc (committed fix)

`ort`'s **prebuilt** ONNX binary needs **glibc ≥ 2.38**; this host (2.35) and the
Dockerfile base (bookworm 2.36) both failed to link it (`undefined symbol
__isoc23_strtoll`, masked by the Dockerfile's `cargo build … || true` → later
`COPY waf: not found`). **Fix (in `Cargo.toml`):** the workspace `ort` dep now
uses **`load-dynamic`** (keeping `std, ndarray, tracing, api-24`) so the binary
`dlopen`s a glibc-compatible `libonnxruntime.so` at runtime instead of linking the
prebuilt. This makes the full `run-copilot` set build on **any** glibc.

**Then a second gotcha (now also resolved):** the `.so` version must match what
`ort` rc.12 expects — **onnxruntime 1.24.2** (`ort-sys/build/download/dist.txt`).
The first `.so` shipped was 1.22.0, and boot **hung in `commit_from_file`** — a
C-API version mismatch, *not* a thread/glibc/core issue (pinning to 8 cores did
not help). Swapping to **1.24.2** (needs only GLIBC_2.27) made `ai` load in <1s.
The `.so` lives in `runtime/onnxruntime/` (gitignored — re-fetch the **1.24.2**
build per host). With `ai` enabled, set `ORT_DYLIB_PATH` at launch (kept in `.env`).

## ⚠️ SigNoz onboarding (one-time, done)

Admin org created via API (`setupCompleted: true`); collector registered.
UI: **http://10.20.0.72:8090/**. Import `deploy/signoz/dashboards/waf-overview.json`.

## ⚠️ Network exposure

No firewall control + one flat lab NIC → `6379`, `999x`, `4317/4318`, `8090` are
reachable by anything on `10.20.0.0/22`. Restrict at the network layer; only WAF
nodes should reach Redis/OTLP, SigNoz UI is operators-only.
