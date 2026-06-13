# MT-04 · Upstream mTLS — WAF presents its identity to the backend

**Covers:** mTLS — upstream direction (`zero_trust.upstream_identity` +
per-pool `upstream_mtls`) · **Severity:** **High** ·
**Expected duration:** ~8 min · **Prereq:** MT-01 green.

> The pre-prod upstreams are the mock pools on **10.20.0.72**
> (`http-pool` :9991, `ws-pool` :9992, `grpc-pool` :9993). This case needs a
> pool whose backend actually requires client-auth (mTLS). If none of the
> mock pools enforce backend mTLS, verify the **config + telemetry plumbing**
> (steps 1–2) and mark the live-handshake step BLOCKED + INFO.

## Test

**Given** the upstream direction: the WAF dials a backend as a TLS **client**,
verifying the backend's server cert against an uploaded backend CA and
presenting the WAF's shared client identity. Config: a fleet
`upstream_identity` keypair + per-pool `upstream_mtls` (enable + backend CA).

**When** the operator enables `upstream_mtls` on a pool via the Zero Trust /
Routing UI and drives traffic through that route via the LB.

**Then** the WAF completes the backend mTLS handshake (request succeeds end
to end), and a backend that rejects the WAF identity surfaces in
`/api/zero-trust/upstream/failures` with an upstream-direction reason — not a generic 502.

## Paste-to-Claude (copy verbatim)

> Admin tab N1, Zero Trust + Routing & Upstreams pages.
>
> 1. Read the upstream config:
>    ```js
>    (async () => (await fetch('/api/zero-trust/upstream/config',{credentials:'include'})).json())()
>    ```
>    Report whether a fleet `upstream_identity` is configured and which
>    pools have `upstream_mtls` enabled. Confirm the UI shows the same
>    (upload-backend-CA vs download-WAF-cert controls are distinct).
> 2. For a pool with `upstream_mtls` enabled (or enable it on a test pool
>    pointing at a backend that wants client-auth), drive a request through
>    the LB to that route and confirm it succeeds end-to-end (200 from the
>    backend, not a TLS/identity 502).
> 3. Force a failure: point the pool at a backend whose cert won't verify
>    (or whose CA isn't trusted) and drive one request; then read
>    `/api/zero-trust/upstream/failures` and confirm an **upstream**-direction failure with
>    a clear reason appears (and is distinguishable from a downstream failure).

## Pass criteria

- [ ] `/api/zero-trust/upstream/config` reflects the configured identity +
      per-pool enablement; UI controls correctly separate "upload backend CA"
      (server-auth anchor) from "download WAF cert" (our client identity).
- [ ] A pool with `upstream_mtls` completes the backend handshake — traffic
      flows end-to-end through the LB.
- [ ] A verification failure surfaces in `/api/zero-trust/upstream/failures` as an
      **upstream**-direction error with a reason (not a bare 502).
- [ ] Enabling upstream mTLS on one pool does NOT affect unrelated pools
      (both default off, isolation guarantee).
- [ ] (If no client-auth backend) live step BLOCKED + INFO, config/telemetry verified.

## Findings template

- upstream_identity present? which pools enabled?
- End-to-end success on an mTLS pool?
- Failure telemetry reason + direction labelling.
