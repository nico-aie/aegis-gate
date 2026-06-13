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

> **Same-port HTTP + WebSocket.** The `--http` listener also upgrades
> WebSocket requests on the same port, so a single `--http :9999` serves
> **both** HTTP and WS. This matches the dev profile (one stub-pool at
> `127.0.0.1:9999`) and is what lets the WAF's `ws_inspect` actually run —
> an upstream that keeps the WS connection open and echoes frames means the
> WAF's ws bridge stays alive long enough to inspect them. A plain-HTTP
> upstream (`fast-upstream` / nginx with no WS handler) accepts the `101`
> then EOFs immediately, so the bridge exits before any frame is inspected
> and the client sees a bare `1006` close.

## Testing `ws_inspect` against the dev WAF

`ws_inspect` is **on by default** (no route block needed). The only missing
piece for WS attack tests is a WS-capable upstream at the dev pool port:

```sh
make mock-build            # build /tmp/aegis-mock
make upstream-down         # stop fast-upstream (HTTP-only, no WS handler)
/tmp/aegis-mock --http :9999   # HTTP + WS on the dev stub-pool port
# now run the WS attack suite — frames reach the inspector instead of 1006'ing
```

## What it serves

| Flag | Protocol | Behaviour |
|---|---|---|
| `--http` | HTTP/1.1 + h2c + WS | `GET /` echoes `{path, method, proto, host}`; `/api/health`, `/products`, `/login` mirror the fast-upstream surface so detector/audit tests fire; **WebSocket upgrades on the same port** are echoed (see note above) |
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
