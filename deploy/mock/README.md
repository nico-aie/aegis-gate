# `deploy/mock/` — multi-protocol mock upstream

One Go binary that serves every protocol Aegis-Gate forwards, so each
upstream path can be exercised end-to-end. Used by the fleet deploy guides
([`../HACKATHON-DEPLOY.md`](../HACKATHON-DEPLOY.md) §5,
[`../HACKATHON-FLEET.md`](../HACKATHON-FLEET.md) §5).

> This is the **coverage** mock (all protocols). For 5k-RPS HTTP throughput
> stress, use [`../../tests/hackathon/upstream/fast-upstream.go`](../../tests/hackathon/upstream/fast-upstream.go).

## Build & run

```sh
cd deploy/mock
go build -o aegis-mock .            # go.sum is committed; no `go mod tidy` needed
./aegis-mock --http :9991 --ws :9992 --grpc :9993 --tcp :9994
# or: make mock-build   (from the repo root)
```
Each flag is independent; pass `""` to disable a listener.

## What it serves

| Flag | Protocol | Behaviour |
|---|---|---|
| `--http` | HTTP/1.1 + h2c | `GET /` echoes `{path, method, proto, host}`; `/api/health`, `/products`, `/login` mirror the fast-upstream surface so detector/audit tests fire |
| `--ws` | WebSocket | echoes every frame; the text `bye` closes the connection |
| `--grpc` | gRPC (HTTP/2) | echoes **any** method (raw passthrough codec + unknown-service handler — no protoc needed) |
| `--tcp` | raw TCP | byte echo (for `scheme:tcp` upstreams) |

Every connection logs its protocol + peer so you can confirm the WAF routed it.

## Verify each path (directly, then through the WAF)

```sh
curl  http://localhost:9991/api/health                 # {"status":"ok"}
curl  http://localhost:9991/foo?x=1                     # echo JSON
wscat -c ws://localhost:9992/                           # type a line → echoed; "bye" closes
grpcurl -plaintext -proto echo.proto \
        -d '{"message":"hi"}' localhost:9993 mock.Echo/Say   # → {"message":"hi"}
printf 'ping\n' | nc -w1 localhost 9994                 # → ping
```

`echo.proto` exists only so `grpcurl` can call the gRPC echo **without
server reflection** — the server itself doesn't compile it (it echoes raw
bytes, and `EchoReq`/`EchoResp` share field 1 so the round-trip decodes).

## Wiring into the WAF

One route/pool per protocol (dashboard or profile):
`/` → http pool, `/ws` → ws pool (`scheme: auto`), `/grpc` → grpc pool
(`scheme: grpc`), and a `scheme: tcp` route for raw TCP.
