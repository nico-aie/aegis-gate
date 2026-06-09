# Deploy a WAF node on ANOTHER machine — kickoff (local, not committed)

> Paste the prompt below to an AI assistant on the new node's machine, or follow
> the raw commands. Companion docs: `PRE-PROD-DEPLOY.md` (§15a), `INFRA-HOST-STATUS.md`,
> `AI-ASSISTANT-KICKOFF.md`. Infra host = **10.20.0.72** (Redis :6379, OTLP :4317,
> mock :9991-9994). On a separate machine use the STANDARD ports — :8080/:8443/:9443.

## 1) Paste-to-assistant prompt

```
Deploy ONE Aegis-Gate WAF node on this machine, joining an existing cluster.
READ deploy/PRE-PROD-DEPLOY.md (esp. §15a "deploying nodes on OTHER machines"),
deploy/INFRA-HOST-STATUS.md, and deploy/AI-ASSISTANT-KICKOFF.md FIRST.

Context / fixed facts (verify, don't assume):
- Repo: clone branch `pre-prod` from github.com:nico-aie/aegis-gate.
- Infra host = 10.20.0.72 — shared Redis :6379, SigNoz OTLP :4317, mock upstream
  :9991/9992/9993/9994. This new node must reach all of those.
- This is a SEPARATE machine, so use the STANDARD ports (no :8081/:8444 split):
  data :8080 (plaintext) + :8443 (TLS), admin 127.0.0.1:9443.
- Topology: nodes terminate TLS at the edge (JA3/JA4/device_fp). Cert lives on THIS
  node (nginx, if any, is L4 stream passthrough and holds no cert).

Do this:
1. Prereqs (§1): apt build deps + rustup. Confirm reachability:
   redis-cli -h 10.20.0.72 ping ; curl http://10.20.0.72:9991/api/health
2. Build (§2): cargo build -p aegis-bin --release \
   --features "redis geoip alerts ai affinity otel llm"   (ort is load-dynamic).
3. Contract files (§3): cp target/release/waf ./waf ; cp deploy/waf.contract.yaml ./waf.yaml
4. Edit ./waf.yaml (§4): set node.id to a UNIQUE value (e.g. waf-<hostname>);
   keep state.redis.urls=["redis://10.20.0.72:6379"],
   observability.otel.endpoint=http://10.20.0.72:4317, upstreams → 10.20.0.72:999x.
5. ai (§5): fetch onnxruntime 1.24.2 (NOT 1.22) into runtime/onnxruntime/ and set
   ORT_DYLIB_PATH; geoip (§4): place data/geoip/GeoLite2-*.mmdb.
6. TLS (§7): self-signed cert into certs/ with THIS node's IP in the SAN
   (or drop in the shared DNS-01 PEM). The :8443 listener fails to boot without it.
7. .env: LLM_API_KEY (copilot) + ORT_DYLIB_PATH. Run (MUST redirect logs to a file
   so the agent in step 8 can tail them):
   set -a; . ./.env; set +a
   AEGIS_INSECURE_COOKIES=1 RUST_LOG="info,hyper=warn,h2=warn,maxminddb=warn" \
     ./waf run --config ./waf.yaml >> logs/waf.json 2>&1 &
8. SHIP OBSERVABILITY (§13a) — REQUIRED, or this node is invisible in SigNoz:
   - Traces: waf.yaml observability.otel.endpoint=http://10.20.0.72:4317 (already in
     step 4); confirm `nc -z 10.20.0.72 4317`.
   - Logs: run the per-node agent (tails logs/waf.json + ./waf_audit.log → SigNoz):
       cd deploy/compose && NODE_ID=<node.id> docker compose -f otel-agent.docker-compose.yml up -d
     (host networking needs rootful Docker; on rootless, drop network_mode:host —
     logs still ship, only the /metrics scrape is lost. See §13a.)
9. Verify: /healthz/ready 200; legit → allow 200, SQLi → block 403 with X-WAF-*
   headers; ./waf_audit.log JSONL; node in Redis cluster members; AND in SigNoz both
   TRACES (serviceName=aegis-gate) and LOGS (log_type=waf_audit, host.name=<node.id>)
   from THIS node. Then on the infra host add this node's <ip>:8443 to the nginx
   stream upstream (or a DNS A-record).

Ask me for: this node's IP/hostname, the unique node.id, and the LLM_API_KEY.
Don't enable anything that egresses externally without confirming. Verify
end-to-end and show me the checks before declaring done.
```

## 2) Raw command sequence (manual)

```sh
git clone -b pre-prod git@github.com:nico-aie/aegis-gate.git && cd aegis-gate
sudo apt-get update && sudo apt-get install -y build-essential cmake pkg-config protobuf-compiler libssl-dev curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env

cargo build -p aegis-bin --release --features "redis geoip alerts ai affinity otel llm"
cp target/release/waf ./waf
cp deploy/waf.contract.yaml ./waf.yaml
sed -i 's/waf-infra-1/waf-<THIS-NODE>/' ./waf.yaml          # unique node.id

# ai runtime (match ort rc.12 -> onnxruntime 1.24.2) + geoip dbs
mkdir -p runtime/onnxruntime
curl -fsSL https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-linux-x64-1.24.2.tgz \
  | tar -xz -C /tmp && cp /tmp/onnxruntime-linux-x64-1.24.2/lib/libonnxruntime.so* runtime/onnxruntime/
# (copy data/geoip/GeoLite2-*.mmdb onto the box)

# TLS self-signed (put THIS node's IP in the SAN)
mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/selfsigned.key -out certs/selfsigned.crt -subj "/CN=aegis-gate.local" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:<THIS-NODE-IP>"

printf 'LLM_API_KEY=%s\nORT_DYLIB_PATH=%s/runtime/onnxruntime/libonnxruntime.so\n' "<key>" "$PWD" > .env
set -a; . ./.env; set +a
AEGIS_INSECURE_COOKIES=1 RUST_LOG="info,hyper=warn,h2=warn,maxminddb=warn" \
  ./waf run --config ./waf.yaml >> logs/waf.json 2>&1 &

curl -s  http://127.0.0.1:9443/healthz/ready -o /dev/null -w "ready %{http_code}\n"
curl -sk https://127.0.0.1:8443/ -o /dev/null -w "tls   %{http_code}\n"
curl -sk https://127.0.0.1:8443/ -D - -o /dev/null | grep -i '^x-waf-'   # contract headers

# SHIP OBSERVABILITY (else this node is invisible in SigNoz) — §13a
nc -z 10.20.0.72 4317 && echo otlp-reachable                 # traces target reachable
cd deploy/compose
NODE_ID=<node.id> docker compose -f otel-agent.docker-compose.yml up -d   # logs+metrics agent
# rootless node? edit otel-agent.docker-compose.yml: drop `network_mode: host`,
# add extra_hosts host.docker.internal:host-gateway — logs still ship.
```

## 3) On the INFRA host — add the node to the fleet entry point

```sh
# nginx stream LB: append to upstream waf_nodes in deploy/nginx/nginx-stream.conf
#   server <NEW-NODE-IP>:8443 max_fails=2 fail_timeout=5s;
# IMPORTANT: use --force-recreate, NOT `restart`/`-s reload` — a single-file bind
# mount doesn't follow the host file's inode swap on edit, so reload keeps the OLD
# config. Recreate re-binds the current file.
docker compose -f deploy/compose/nginx-lb.docker-compose.yml up -d --force-recreate
# …or add a DNS A-record  yourdomain.com -> <NEW-NODE-IP>  (DNS round-robin)
```

## Remember
- Separate machine → **standard ports** :8080/:8443/:9443 (the :8081/:8444 split is
  only for 2 nodes on one host).
- **Unique `node.id`** + the **same Redis** (`10.20.0.72:6379`) = one fleet.
- TLS cert lives **on the node** (self-signed for test, shared DNS-01 for prod);
  the LB never holds a cert in stream mode.
- `ai` needs onnxruntime **1.24.2** + `ORT_DYLIB_PATH`; `copilot` needs `LLM_API_KEY`.
