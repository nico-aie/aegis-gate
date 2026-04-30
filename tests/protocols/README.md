# `tests/protocols/` — multi-protocol smoke

Five short shell tests that exercise every transport the WAF
supports and assert it negotiates / forwards each one cleanly.
Pure `curl` (with `openssl` and `grpcurl` as optional bonuses) —
no Node, no Docker required.

## What each script asserts

| File | Layer | Asserts |
|---|---|---|
| `01-http1.sh` | HTTP/1.1 plaintext | The plaintext data listener answers; response code is not 000 (connect-refused). |
| `02-http2.sh` | HTTP/2 over TLS | ALPN advertises `h2`; curl negotiates `--http2`; bonus `openssl s_client` ALPN probe. |
| `03-http3.sh` | HTTP/3 (QUIC) | curl `--http3-only` lands on the UDP listener and negotiates h3. Skips when curl lacks HTTP/3 OR the WAF was built without `--features http3`. |
| `04-websocket.sh` | WebSocket upgrade | Sends a real `Upgrade: websocket` handshake; the WAF must NOT respond 400 (which would mean it stripped the upgrade headers). 101 = forwarded; 502/504 = forwarded but no upstream. |
| `05-grpc.sh` | gRPC over h2 | Uses `grpcurl` if available, otherwise curl with `content-type: application/grpc`. Asserts h2 negotiation and that the WAF doesn't reject the gRPC content-type. |

## Running

Boot the WAF first:

```sh
make setup    # one-time
make run      # boot against config/prod.yaml
```

Then in another terminal:

```sh
# All five
bash tests/protocols/run-all.sh

# One at a time
bash tests/protocols/01-http1.sh
bash tests/protocols/02-http2.sh

# Override endpoints (e.g. against a remote staging WAF)
AEGIS_DATA_HTTP=http://staging:8080 \
AEGIS_DATA_HTTPS=https://staging:8443 \
AEGIS_DATA_H3=https://staging:8443 \
AEGIS_ADMIN=https://staging:9443 \
    bash tests/protocols/run-all.sh
```

## What "PASS" actually means

The data-plane upstreams in the dev config (`config/dev.yaml`,
ports 3001–3004) aren't running by default — every smoke is
expected to land at the WAF, get forwarded, and return a 502
because there's no backend listening. **That's a pass** — the
WAF accepted the protocol negotiation. A test fails only when:

- The WAF refused the connection at the TCP / QUIC layer (`code=000`)
- The WAF stripped a protocol-specific header (e.g. WebSocket
  Upgrade or gRPC content-type) and answered 400 itself

To get a green response code (200) instead of 502, run an
upstream that the WAF can forward to:

```sh
docker run -d --name aegis-httpbin -p 3002:80 kennethreitz/httpbin
```

Then re-run; HTTP/1.1 + HTTP/2 + WebSocket should now return 200
(or 101 for WS).

## Enabling HTTP/3

`03-http3.sh` skips by default because two preconditions need
to be in place:

1. **WAF build** — `cargo build -p aegis-bin --release --features "redis http3"`
2. **Config** — add a UDP listener; the existing TLS listener
   on `:8443` will auto-stamp `Alt-Svc: h3=":8443"; ma=86400` on
   responses so browsers retry over QUIC. Operators who want a
   dedicated UDP port set:
   ```yaml
   listeners:
     data:
       - bind: "0.0.0.0:8443"
         tls: true
         http3: true   # opt-in QUIC bind on the same port
   ```
3. **Curl with HTTP/3** — `brew install curl --HEAD --with-openssl-http3`
   on macOS, or use `quiche-client` / `nghttp3` instead.

## Enabling gRPC

`05-grpc.sh` works against any gRPC server reachable through the
WAF's upstream config. For a dev fixture, run a reflection-enabled
gRPC server:

```sh
docker run -d --name aegis-grpc -p 3002:50051 \
    fullstorydev/grpcurl-dev:latest
```

Then point an upstream at `127.0.0.1:50051` with `connection.tls:
false` (the `forward.rs` HTTP/2 ALPN advertises both `h2` and
`http/1.1`, so plaintext h2 to local upstreams works).

## Findings (current state — post CI-T10)

Running the suite against `config/prod.yaml` on macOS surfaces:

| Test | Result | Notes |
|---|---|---|
| 01 HTTP/1.1 | ✅ PASS | clean negotiation |
| 02 HTTP/2 | ✅ PASS | ALPN advertises `h2`; `hyper_util::server::conn::auto::Builder` serves real h2 (CI-T10 wire-up) |
| 03 HTTP/3 | ⏭ SKIP | macOS-shipped curl lacks HTTP/3. Build curl with `ngtcp2 + nghttp3` or use `quiche-client` to actually test the listener. |
| 04 WebSocket | ✅ PASS | Upgrade headers passed through; would land at WS upstream when one is running |
| 05 gRPC | ✅ PASS | gRPC over h2 reaches upstream (now that #02 works) |

**Historical context — CI-T10 (closed 2026-04-30):** prior to CI-T10
the data-plane TLS branch in `lib.rs` called `http1::Builder::new()`
directly, even though the TLS config advertised `[h2, http/1.1]`
ALPN. Result: ALPN was downgraded to h1-only at config time, and
curl always fell back to h1. The fix swapped the bare
`http1::Builder` for `hyper_util::server::conn::auto::Builder` and
restored the h2 ALPN advertisement. Closes a real client-compat
gap (gRPC clients and modern browsers expect h2 by default).

## When to add a new protocol script

If the WAF starts terminating a new protocol (HTTP/4? QUIC v2?)
add `06-<proto>.sh` here. The contract is:

- Skip cleanly when the dep isn't met (curl lacks support, WAF
  built without the feature, listener not bound).
- Fail loudly when the WAF actively rejects the protocol it's
  supposed to support.
- One file, one protocol, < 50 lines.
