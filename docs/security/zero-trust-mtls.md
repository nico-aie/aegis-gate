# Zero Trust — mutual TLS, both directions

> **Status:** Implemented (2026-06). One `zero_trust` module + one **Zero Trust**
> console page (Beta) own *both* mutual-TLS directions. This supersedes the old
> fragmented `tls.client_auth` (downstream) feature and the old per-pool
> `tls: { client_cert, client_key, ca_bundle }` (upstream) shape — **there is no
> back-compat alias; migrate existing YAML.**
>
> Design + phasing history: [`../../plans/future/mTLS.md`](../../plans/future/mTLS.md).

## The two directions

mTLS confuses people because "the cert" is ambiguous. Aegis names the two
directions explicitly:

| Direction | WAF acts as | Verifies | Config |
|---|---|---|---|
| **Downstream** | server | the **client's** cert presented *to* the WAF | `zero_trust.downstream` |
| **Upstream** | client | the **backend's** server cert, and presents the WAF's own client cert | `zero_trust.upstream_identity` + per-pool `upstream_mtls` |

> **"Upload their cert" vs "download our cert".** Upstream direction: *upload the
> backend's CA* = the trust anchor the WAF verifies the **backend** against
> (server-auth). *Download the WAF cert* = **our** shared client identity the
> backend verifies **us** against (client-auth). Different keypairs, opposite ways.

Both default **off**. Enabling one never affects the other or any unrelated pool.

---

## Downstream — verify client certs presented to the WAF

```yaml
zero_trust:
  downstream:
    mode: required          # disabled | optional | required
    ca_bundle: config/certs/clients-ca.pem   # trust anchor for client certs
    allowed_sans: ["svc-a.internal"]         # optional SAN allowlist (empty = any)
    apply_to: [admin, data]                  # which listener planes enforce
```

- `mode != disabled` requires a `ca_bundle` and at least one `apply_to` plane
  (validation rejects an unenforceable policy).
- An empty `allowed_sans` admits any client cert that chains to `ca_bundle`;
  a non-empty list adds a SAN gate on top (`*.example.com` matches one label).

---

## Upstream — the WAF dials backends with mTLS

### 1. The shared fleet identity

Every node presents the **same** WAF client cert when dialing a backend pool that
opts in. One identity = one thing to protect, rotate, and hand to backend
operators; every backend that trusts the WAF's CA accepts any node with zero
per-node setup.

```yaml
zero_trust:
  upstream_identity:
    source: file            # file | state
    # source: file —
    cert_path: config/certs/waf-client.pem    # PUBLIC leaf (+chain), EKU clientAuth
    key_ref:   "${secret:env:WAF_UPSTREAM_KEY}"  # private key via a secret reference
    # source: state — declare only `source: state`; the PUBLIC cert + key_ref
    # come from the config plane (see "State mode" below).
```

### 2. Opt in per pool

```yaml
upstreams:
  payments-pool:
    members: [ ... ]
    connection:
      tls: true             # mTLS requires a TLS connection to the backend
    upstream_mtls:
      enabled: true         # absent/false ⇒ today's no-client-auth dial
      verify: true          # default; an unverifiable backend FAILS CLOSED
      trust: payments-ca    # a file path OR an uploaded bundle name; null ⇒ webpki roots
      # allowed_sans: [...]  # (reserved — enforcement lands in P5)
```

- `trust` resolves **lookup-first**: a bare name matching an uploaded bundle
  (`aegis:zt:upstream:trust:<name>`) is used as that bundle's PEM; a value with a
  `/` is read as a file path. Neither resolvable ⇒ the dial fails closed.
- Enabling `upstream_mtls` requires a configured `zero_trust.upstream_identity`
  and `connection.tls: true` — both checked at config load (and on the runtime
  `PUT /api/upstreams/pool/{id}` path).

---

## State mode (config plane) — `source: state`

Reference-only: the **PUBLIC** cert and backend-CA bundles live in the Redis
config plane (multi-node, atomic `cas_set` activation); **the private key never
does** — it stays a `key_ref` reference resolved at client-build time. There is
**no envelope encryption** (the repo ships no AEAD primitive; we deliberately
don't hand-roll crown-jewel crypto).

Config-plane keys:

| Key | Holds |
|---|---|
| `aegis:zt:upstream:identity` | `{ cert_pem (PUBLIC), key_ref }` — the shared fleet identity |
| `aegis:zt:upstream:trust:<name>` | `{ ca_pem (PUBLIC) }` — a backend-CA trust bundle |

At **boot** (async, before the sync pool build), each node materializes the
PUBLIC cert/CA PEM from the plane into its config snapshot. **Fail-closed:** a
`source: state` identity with no stored record / unreadable / corrupt aborts boot
rather than dialing without client auth.

> **Hot rotation is P5.** Today the identity/trust PUTs land at the **next boot**
> (or config-doc reload). Storing via the console or API persists immediately;
> presenting the new material fleet-wide is a restart away.

---

## Console — the Zero Trust page (Beta)

Left sidebar → **Zero Trust** (Policy group). Sections:

1. **WAF Client Identity** — subject / fingerprint / expiry (with an amber badge
   inside 30 days), **Download WAF cert** (PUBLIC PEM only), and a store/rotate
   upload (PUBLIC cert + a `key_ref` — the key is never uploaded).
2. **Backend-CA Trust Bundles** — upload / list / delete PUBLIC backend CAs.
   Delete is **ref-checked**: a bundle a pool still references can't be removed.
3. **Upstream mTLS by Pool** — a status pill per pool plus an **Edit drawer** to
   enable/disable and pick a trust bundle (round-trips the whole pool through
   `PUT /api/upstreams/pool/{id}`).
4. **Upstream Handshake Failures** — a per-pool, per-reason histogram.
5. **Downstream** — mode / CA-bundle / SAN-allowlist cards.

All cert mutation is **audited, CSRF-gated, and behind the
`admin.dashboard_auth.allow_ca_upload` capability flag** (off by default). The
upload UI only renders when the flag is on.

---

## API surface

```text
# downstream (WAF-as-server)
GET    /api/zero-trust/downstream                 mode / ca / sans / apply_to (+ live, NO key)
PUT    /api/zero-trust/downstream/{mode,ca-bundle,sans}
DELETE /api/zero-trust/downstream/sans/{san}
POST   /api/zero-trust/downstream/sans/{san}/test
GET    /api/zero-trust/downstream/{connections,failures,ca-summary}

# upstream (WAF-as-client)
GET    /api/zero-trust/upstream/identity          shared identity metadata (NO key)
PUT    /api/zero-trust/upstream/identity          store {cert_pem, key_ref}        (audited, gated)
GET    /api/zero-trust/upstream/config            per-pool mTLS state (live registry)
GET    /api/zero-trust/upstream/trust             list backend-CA bundles
POST   /api/zero-trust/upstream/trust/{bundle}    upload PUBLIC backend CA (PEM)   (audited, gated)
DELETE /api/zero-trust/upstream/trust/{bundle}    remove bundle (ref-checked)      (audited, gated)
GET    /api/zero-trust/upstream/failures          handshake-failure histogram
```

Per-pool `upstream_mtls` editing round-trips through the existing
`PUT /api/upstreams/pool/{id}` (it's a `PoolConfig` field). Bundle names are
`[A-Za-z0-9._-]`, ≤64 chars.

---

## Security model (the gate)

- **The WAF client key is a crown jewel** — whoever holds it can impersonate the
  fleet to every backend that trusts it. It is never logged, never returned by
  any read API or metric, and never uploaded; the download/`GET` paths emit
  PUBLIC PEM only. Tests assert no `GET` and no view JSON leaks the key (or the
  materialized `trust_pem`).
- **Fail closed, scoped** — `enabled + verify: true` against an unverifiable
  backend fails *that pool's* dials with a clear reason; it never falls back to
  trust-anything, and it can't disturb other pools.
- **Capability gate** — browser-driven cert mutation is off until an operator
  sets `allow_ca_upload: true`.

## Observability — handshake failures

`forward()` failures on an mTLS-enabled pool are recorded in a bounded,
process-global histogram (`upstream::mtls_failures`) keyed by `(pool, reason)`:
`untrusted_backend_cert | san_mismatch | cert_expired | client_identity_error |
handshake_failed`. Read via `GET /api/zero-trust/upstream/failures`; rendered on
the console. Expiry is surfaced as a badge on the identity + each trust bundle.

## Operator quick-start

1. Mint a WAF client cert+key out of band (your internal CA, EKU `clientAuth`,
   a clear SAN like `waf.internal`). `config/gen-cert.sh` has a dev helper.
2. Set `admin.dashboard_auth.allow_ca_upload: true` (to use the console) and a
   `zero_trust.upstream_identity` (`file`, or `state` + store via the console/API).
3. Upload each internal backend's CA as a trust bundle; hand backend operators
   the **Download WAF cert** PEM for their client-trust store.
4. Enable `upstream_mtls` per pool (drawer or YAML), pick the trust bundle, save.
5. Watch the **Upstream Handshake Failures** card after cut-over.

## Implementation anchors

- `aegis-core/src/config.rs` — `ZeroTrustConfig`, `UpstreamIdentityConfig`,
  `UpstreamMtlsConfig`, `CertSource`, `resolve_upstream_mtls`,
  `UpstreamIdentityRecord` / `UpstreamTrustRecord` + state keys, `validate_*`.
- `aegis-proxy/src/upstream/{identity,tls,forward,mtls_failures}.rs` —
  state materialization (`materialize_zero_trust_state`, fail-closed),
  `client_config_from_resolved`, fallible fail-closed `build_client`,
  the handshake-failure tracker.
- `aegis-proxy/src/admin_mutate.rs` — audited identity/trust PUT+DELETE,
  `validate_pool_trust_bundles` cross-ref.
- `aegis-control/src/api/{zero_trust,upstreams_config,mtls}.rs` — read views +
  upload validation; `PoolView.upstream_mtls` round-trip.
- `crates/aegis-control/assets/dashboard/src/pages.jsx` — `PageZeroTrust`.
