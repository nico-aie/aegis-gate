# `deploy/compose/` — local fleet dry-run

Stands up the whole [`HACKATHON-DEPLOY.md`](../HACKATHON-DEPLOY.md) topology on
**one machine** so you can exercise the cluster, every protocol, and the full
feature set before touching real VMs:

```
redis  ── shared state (rate-limit · risk · config plane · leases · metrics)
mock   ── multi-protocol upstream (http :9991 · ws :9992 · grpc :9993 · tcp :9994)
waf-a  ── data 18080/18443 · admin 19443     ┐ 2-node cluster, both → redis
waf-b  ── data 28080/28443 · admin 29443     ┘ (config plane converges across them)
```

## Run

```sh
cd deploy/compose
docker compose up --build      # FIRST build is a long Rust compile (~minutes)
# subsequent: docker compose up    (image cached as aegis-gate:compose)
docker compose down            # stop (add -v to wipe redis volume)
```

The WAF image is built once (on `waf-a`, with `CARGO_FEATURES="production otel"`)
and reused by `waf-b`. JA3/JA4 works because each node terminates TLS itself
(`:8443`). `host.docker.internal:4317` is the OTLP target — run `make signoz-up`
on the host first if you want traces (harmless if not).

## Verify

```sh
# Dashboard (login admin / aegis-test-1234) — either node:
open http://localhost:19443/      # waf-a     · http://localhost:29443/  waf-b

# HTTP through each node (WAF terminates TLS → JA3/JA4 captured):
curl -k https://localhost:18443/             # waf-a → mock http echo
curl -k https://localhost:28443/api/health   # waf-b → {"status":"ok"}
curl    http://localhost:18080/products       # plaintext path

# Cluster proof — shared config version + shared state across both nodes:
for p in 19443 29443; do
  curl -s http://localhost:$p/api/config | jq .version    # equal on both
done

# Config plane converges: edit on waf-a, read on waf-b
#   (dashboard → Detectors/Routing on :19443, then re-check :29443 ~3s later)

# WebSocket / gRPC / raw TCP (via the WAF):
wscat -c ws://localhost:18080/ws
grpcurl -plaintext -proto ../mock/echo.proto -d '{"message":"hi"}' localhost:18080 mock.Echo/Say
# (raw TCP: add a tcp listener/route, or hit the mock directly to confirm it echoes)
```

## Notes & differences from the real VM deploy

- **No Cloudflare / DNS round-robin here** — you hit `waf-a`/`waf-b` directly on
  their published ports. The real deploy uses Cloudflare DNS-only round-robin
  ([`../HACKATHON-DEPLOY.md`](../HACKATHON-DEPLOY.md)); the *cluster* behaviour
  (shared Redis + config plane) is identical.
- **Self-signed dev cert** (`config/certs/dev.*`, hence `curl -k`). Real deploy
  uses a DNS-01 wildcard.
- **admin `ip_allowlist`** is widened to RFC1918 so the dashboard is reachable
  through the docker gateway — never do that in production.
- **SigNoz** is intentionally not embedded (heavy). Use `make signoz-up`.
- **Copilot** is off (image built `production otel`, no `llm`). Add `llm` to
  `CARGO_FEATURES` + an `LLM_API_KEY` env if you want it.
- First build compiles the WAF in-container (linux). Slow once; cached after.
