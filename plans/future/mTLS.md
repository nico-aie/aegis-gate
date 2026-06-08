# Upstream mTLS — WAF→backend client-cert auth + Zero Trust console (future plan)

> **Status (2026-06-08): Not started — design only.**
> Today the WAF can *terminate* mTLS from downstream clients
> (`tls.client_auth` → `WebPkiClientVerifier`, the `MTLS-T*` series) and can
> dial upstreams over TLS (`connection.tls` / `scheme: https`,
> `forward.rs::build_client`), but that upstream TLS is **server-auth only** —
> it uses `with_webpki_roots()` and `with_no_client_auth()`, so the WAF never
> presents a client cert to the backend. This plan adds the **missing
> direction**: the WAF authenticating *itself* to upstreams with a client cert
> (mutual TLS, WAF-as-client), configured **per upstream**, plus a **Zero Trust**
> console page to manage it. Complements — does not replace — the existing
> downstream `client_auth`. Config axis is *per-upstream* (slots into
> `PoolConfig`, exactly like `cache:` did in `smart-caching.md`).

## Goal

Let an operator turn on **mutual TLS to a specific upstream backend** from the
console: the WAF presents a client certificate when it dials that backend, and
the backend verifies it before accepting traffic. Two independent trust
directions are configured per upstream:

1. **WAF → backend (client auth).** The WAF holds **one client cert + key** (its
   own identity) and presents it on every upstream connection. The backend
   operator installs the WAF's cert (or the CA that signed it) in *their*
   client-trust store so they accept us. The console offers a **"download WAF
   cert"** button so they can grab exactly that public material.
2. **backend → WAF (server auth).** The backend presents *its* server cert,
   which the WAF must verify. For internal/self-signed backends the operator
   **uploads the backend's CA / server cert** ("their cert") on the console; we
   store it and add it to that upstream's trust anchors instead of falling back
   to public webpki roots.

> **Naming clarity (the #1 source of mTLS confusion).** "Upload their cert" =
> the **upstream's** trust material the WAF verifies *them* against (server-auth
> direction). "Download WAF cert" = **our** client identity the upstream
> verifies *us* against (client-auth direction). They are different keypairs
> going opposite ways. The page labels them explicitly.

This is a **per-upstream** capability, defaults **off**, and never weakens the
existing data path — an upstream with no mTLS block behaves exactly as today.

---

## 1. How the world does it (2025–2026 scan)

| Product | Config axis | WAF/proxy client identity | Backend trust (verify server) | Rotation story |
|---|---|---|---|---|
| **nginx (`proxy_ssl_*`)** | Per `location` / `upstream` | `proxy_ssl_certificate` + `proxy_ssl_certificate_key` (PEM on disk) | `proxy_ssl_trusted_certificate` + `proxy_ssl_verify on` + `proxy_ssl_verify_depth` | Reload after swapping files on disk; `proxy_ssl_session_reuse on` to amortise handshakes |
| **HAProxy** | Per `server` line | `ssl crt <client.pem>` (cert+key bundled) | `ca-file <ca.pem>` + `verify required` | Runtime API / reload; cert bundles on disk |
| **Envoy** | Per cluster (`UpstreamTlsContext`) | `tls_certificates` **or `tls_certificate_sds_secret_configs`** (SDS) | `validation_context` / `combined_validation_context` (trusted CA, optional SPIFFE matcher) | **SDS streams new certs in with zero downtime, keys never touch disk** — the gold standard |
| **SPIFFE / SPIRE (mesh)** | Per workload identity | **Short-lived X.509-SVID** (default ~1h), auto-rotated by the agent and pushed via SDS | Trust-domain bundle, SVID SAN matcher | **Auto-rotation built in** — issue short, renew before expiry, no operator action |
| **Cloudflare mTLS to origin** | Per hostname/origin | Cloudflare-managed client cert presented to origin | Origin trusts the Cloudflare client-CA | Managed by the platform |

**Cross-product consensus — the baseline a serious upstream-mTLS feature shares:**

1. **Client identity is per-destination-scope, configured where the destination
   is** — nginx `location`/`upstream`, HAProxy `server`, Envoy `cluster`. The
   universal axis is **per upstream**, which is exactly our `PoolConfig` home.
2. **Two separable knobs:** *present a client cert* (client-auth) and *verify the
   server cert against a trust anchor* (server-auth). Products let you set them
   independently; many real deployments turn on client-auth while keeping a
   custom CA for server verification because the backend is internal/self-signed.
3. **Trust by CA, not by pinned leaf.** Backends verify the WAF's cert by the CA
   that signed it; the WAF verifies the backend by a trusted CA bundle. This is
   what makes a single WAF client cert work for many backends and makes rotation
   cheap (re-sign under the same CA → nothing downstream changes).
4. **Session reuse to amortise the handshake** (nginx `proxy_ssl_session_reuse`,
   TLS resumption) — the asymmetric crypto + cert exchange is the expensive part;
   keep-alive + resumption keep it off the steady-state hot path.
5. **Rotation is a first-class operation, ideally hot.** Envoy/SPIRE set the bar:
   swap the cert on live connections without a restart and without writing the
   private key to disk. File-based proxies require a reload.

### Why a WAF's upstream-mTLS must be *more* careful than a generic proxy's

We are a security product holding a **private key that authenticates us to every
protected backend**. Two design constraints follow:

- **The WAF client key is a crown jewel.** Whoever holds it can impersonate the
  WAF to backends that trust it. It must never be logged, never returned by any
  read API, and ideally never sit in plaintext in a shared store. The
  *download* button exports **only public cert material**, never the private key.
- **Fail closed, but scoped.** Turning on `verify` for an upstream whose cert we
  can't validate must fail *that upstream's* dials (surfaced as a clear health
  error), not silently fall back to "trust anything" — a silent fallback would
  defeat the whole point. Conversely, mTLS is opt-in per pool so enabling it on
  one backend can never disturb the others.

---

## 2. The decision: one shared WAF client cert vs per-upstream client certs

**Recommendation — default to ONE WAF client identity (cert + key) shared across
all upstreams, signed by an internal CA; allow a per-upstream override only when
a backend lives in a different trust domain.**

### Why one shared client cert is the right default

- A client certificate identifies **who is connecting** (the WAF), not **where
  it connects to**. One identity for "the WAF fleet" is the natural model, and
  every backend that trusts our CA accepts it with zero per-backend setup.
- **Rotation stays trivial:** re-issue one cert under the same internal CA and
  every backend keeps trusting it (they pin the CA, not the leaf). This is the
  same "trust the CA, don't pin the leaf" rule that the scan's consensus #3 and
  our smart-caching plan's "config slot already paid for" rationale both lean on.
- One keypair to protect, one to rotate, one to download for backend operators.

### When a per-upstream client cert override earns its keep

Expose an optional per-pool override (`client_cert_ref`) for the cases the scan
shows are real:

- **Separate trust domains** — a backend run by another team/org with its own CA
  that won't trust our shared cert; it issues us a dedicated client cert.
- **Independent revocation** — you want to revoke the WAF's access to *one*
  backend without rotating the identity used everywhere else.
- **Per-backend authorization** — the backend authorizes by the client cert's
  SAN/SPIFFE ID and wants a distinct identity per caller.

### Server-trust (verifying the backend) is naturally per-upstream

Each backend presents a different server cert with a different CA/hostname, so
the **trust anchor for server verification is per upstream by nature** — this is
the "upload their cert" material, stored against the specific pool. (Public
internet backends keep using webpki roots; the upload only overrides for
internal/self-signed ones.)

**Net:** *client identity* defaults to one shared cert (per-upstream override
available); *server trust* is per-upstream. The console reflects exactly this —
a single global "WAF identity" section + a per-upstream "trust the backend"
section.

---

## 3. Proposed design

### 3.1 Config (per-upstream `upstream_mtls:` block + one global identity)

Global WAF client identity (under the existing `tls:` block, sibling to the
downstream `client_auth:`):

```yaml
tls:
  # ... existing server certs / client_auth (downstream) unchanged ...
  upstream_identity:                 # NEW — the WAF's client cert for dialing backends
    cert_path: config/certs/waf-client.pem      # leaf (+ chain), PUBLIC
    key_ref: "${secret:env:WAF_UPSTREAM_KEY}"   # private key via secret ref, NOT inline
    # OR, when managed from the console (stored in the Redis config plane):
    # source: state            # cert+key resolved from the StateBackend (see 3.3)
```

Per-upstream switch (slots into `PoolConfig`, exactly like `cache:`):

```yaml
upstreams:
  payments-pool:
    members: [ ... ]
    connection:
      tls: true                # or scheme: https — TLS to the backend (prereq)
    upstream_mtls:             # NEW — absent ⇒ no client cert presented (today's behaviour)
      enabled: true
      # client-auth direction (WAF → backend): default = shared tls.upstream_identity
      client_cert_ref: null            # set only to override with a per-upstream identity
      # server-auth direction (backend → WAF): how we verify THE BACKEND
      verify: true                     # default true when enabled — fail closed
      trust: backend-ca                # name of an uploaded trust bundle (3.3); null ⇒ webpki roots
      allowed_sans: ["payments.internal"]   # optional: require a SAN on the backend's server cert
```

- **Opt-in, per pool.** No `upstream_mtls` block (or `enabled: false`) ⇒ the
  data plane builds the client exactly as today (`with_no_client_auth`). Mirrors
  nginx `location` / Envoy cluster scoping.
- `verify: true` is the safe default *when mTLS is enabled* — an enabled-but-
  unverifiable backend fails its dials loudly rather than trusting anything.
- `trust` names a bundle uploaded via the console and stored in the config plane
  (3.3); `client_cert_ref` likewise when a per-upstream override is used.

### 3.2 The data-plane hook (where the client cert plugs in)

Today `forward.rs::build_client` (~228) does:

```text
HttpsConnectorBuilder::new().with_webpki_roots().https_or_http()...
```

`with_webpki_roots()` yields a `ClientConfig` with `with_no_client_auth()`. To
present a client cert and/or use a custom trust anchor we build the
`rustls::ClientConfig` explicitly and feed it via
`.with_tls_config(client_config)`:

```text
let roots = match pool.upstream_mtls.trust {
    Some(bundle) => load_bundle_from_state_or_disk(bundle),   // custom CA
    None         => webpki_roots(),                            // default
};
let builder = ClientConfig::builder().with_root_certificates(roots);
let client_config = match pool.upstream_mtls.client_cert {
    Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,  // mTLS
    None               => builder.with_no_client_auth(),               // server-auth only
};
// optional SAN allowlist → custom ServerCertVerifier wrapping webpki
```

Cert/key DER parsing already exists in `listener/tls_policy.rs` (the
`CertificateDer` / `PrivateKeyDer` helpers, ~360–386) — reuse it, don't
re-implement.

**`PoolKey` must gain a cert-identity field** (`forward.rs` ~320). The
per-process client cache is keyed by `PoolKey`; if the cert/trust material isn't
part of the key, a hot-reload that swaps a cert would hit a stale cached client
(the exact bug `HIGH-RU-02` fixed for `scheme`). Add a **fingerprint** of the
effective (client_cert, trust_bundle) so a rotation rebuilds the client. Never
put the private key bytes in the key — hash them.

### 3.3 Cert storage — the Redis config plane (console-managed certs)

The console-uploaded material persists through the existing **`StateBackend`**
(`crates/aegis-core/src/state.rs`, the `redis` backend in production), reusing
the **config plane's `cas_set`** activation pattern (the same mechanism config
versions already use). Proposed keys:

```text
aegis:mtls:upstream:identity            → { cert_pem, key_enc, fingerprint, not_after }   # global WAF client identity
aegis:mtls:upstream:trust:<bundle>      → { ca_pem, fingerprint, subjects[], not_after }  # an uploaded backend-trust bundle
aegis:mtls:upstream:client:<name>       → { cert_pem, key_enc, fingerprint, not_after }   # optional per-upstream override identity
```

Persistence + safety rules:

- **Public material (certs, CA bundles) is stored as-is.** It is non-secret by
  design and is exactly what the download button exports.
- **Private keys are the sensitive part.** The user's ask ("save the cert to
  Redis persistence") is fine for the public cert + the uploaded backend trust
  bundle. For the WAF's **private key**, store it **encrypted at rest** (envelope
  encryption with a boot secret / KMS-style key ref — mirrors how `key_ref` /
  `${secret:...}` already keeps API keys out of plaintext config) rather than
  raw PEM in Redis. If encryption-at-rest isn't acceptable, keep the key on disk
  / in the secret store and persist only the *reference* in Redis. **This is a
  gate item, not a nice-to-have** (see §6).
- **No read API ever returns a private key.** `GET` endpoints return metadata
  only (subject, fingerprint, `not_after`, SAN list) — the same shape
  `identity_tracker::parse_ca_bundle` already produces for the downstream CA
  summary.
- Activation uses `cas_set` so a multi-node fleet flips to the new cert
  atomically; nodes pick it up on the existing config-reload path and rebuild
  the affected upstream client (3.2).

### 3.4 Console — the "Zero Trust" page (the operator surface)

**New left-sidebar entry**, `app.jsx` `NAV` (~18). It belongs in the **Policy**
group next to `Routing & Upstreams` (same mental model — per-backend config):

```jsx
{ id: 'zero-trust', label: 'Zero Trust', icon: <window.I.Shield />, badge: 'NEW', tone: 'warn' },
```

(The `I` icon set in `widgets.jsx` (~5) has no `Lock`/`Key` glyph today —
either reuse `Shield`/`Server` or add a `Lock` SVG to the set first.)

Page layout (`pages.jsx`, a new `ZeroTrustPage`):

1. **WAF identity card (global, top).** Shows the current WAF client cert
   metadata (subject, fingerprint, expiry) + a **"Download WAF cert"** button
   that streams the **public** leaf (+ chain) as `waf-client.pem`. A
   **"Generate / rotate"** action (re-issues under the internal CA; see §3.6).
   Hand this file to backend operators to install in their client-trust store.
2. **Upstream list.** Reuses the `/api/upstreams/config` data the Routing page
   already loads — every pool, each row showing an mTLS status pill
   (`off` / `client-auth` / `mutual+verify`).
3. **Per-upstream drawer (on click).** A **toggle to enable mTLS** for that
   upstream. When on, reveal:
   - **"Upload backend cert/CA"** — a PEM paste-or-file control (reuse the
     existing CA-upload card pattern at `pages.jsx` ~5688: `FileReader` +
     `readAsText` + metadata preview), saved to
     `aegis:mtls:upstream:trust:<bundle>` (3.3). This is the **"their cert"**
     the WAF will verify the backend against.
   - `verify` toggle (default on) + optional `allowed_sans` field.
   - Optional **per-upstream client identity override** (advanced; default uses
     the shared WAF identity).
   - **Save** → audit-logged `PUT` (3.5) → `cas_set` activation → live.

Reuse, don't reinvent: the upload widget, the x509 preview
(`identity_tracker::parse_ca_bundle`), and the `/api/mtls/*` endpoint family all
already exist for the downstream-mTLS feature — this page adds the
`upstream`-direction siblings.

### 3.5 API surface (audit-mutated, mirrors `/api/mtls/*` + `/api/upstreams/config`)

```text
GET    /api/mtls/upstream/identity            → WAF client-cert metadata (NO key)
POST   /api/mtls/upstream/identity/rotate     → generate/re-issue WAF client cert (audited)
GET    /api/mtls/upstream/identity/download    → public leaf+chain PEM (download button)
GET    /api/mtls/upstream/config              → per-pool mTLS state (metadata only)
PUT    /api/mtls/upstream/config/{pool}       → enable/disable + verify/trust/sans (audited, cas_set)
POST   /api/mtls/upstream/trust/{bundle}      → upload a backend trust bundle (PEM in body, audited)
DELETE /api/mtls/upstream/trust/{bundle}      → remove a trust bundle (ref-checked like pool delete)
```

Gate writes behind the same `allow_ca_upload`-style capability flag the
downstream CA-upload card uses (`dashboard_services.rs` ~277) so cert mutation
from the browser is an explicit opt-in, not on by default.

### 3.6 WAF client cert provisioning (the "download" needs something to download)

Two supported flows, defaults to the simplest:

- **Operator-supplied (default, no new crypto code).** Operator generates the
  WAF client cert + key out of band (their internal CA), sets
  `tls.upstream_identity.{cert_path,key_ref}`, and the download button just
  serves that public cert. Extend `config/gen-cert.sh` with a
  `--client --eku clientAuth` mode to emit a dev/test client cert quickly.
- **Console-generated (Phase 3, optional).** A "Generate" action mints a
  keypair + CSR and self-signs (or signs under a configured internal CA),
  stores it per §3.3, and the download serves the resulting public cert. Needs
  `rcgen` (or shells `openssl`) and careful key handling per §6.

Set **EKU = `clientAuth`** (not `serverAuth`) on the WAF cert and a clear SAN
(e.g. `waf.internal`) so backends can authorize on it.

### 3.7 Handshake cost & resumption (keep it off the hot path)

mTLS adds the client cert exchange + an extra signature verify to the handshake.
Mitigations, all already partly in place:

- **Connection pooling / keep-alive is already per-pool**
  (`ConnectionPoolConfig`) — the handshake is paid once per pooled connection,
  not per request.
- **TLS session resumption** amortises re-handshakes (the nginx
  `proxy_ssl_session_reuse` analogue). rustls supports resumption; ensure the
  upstream client config keeps a session cache enabled.
- Keep `verify` doing CA-chain validation only by default; a SAN allowlist is an
  inexpensive extra string check.

### 3.8 Observability (reuse the mTLS surfaces that exist)

- Per-upstream mTLS state pill on the Zero Trust list **and** the Routing &
  Upstreams page (`off|client-auth|mutual+verify`).
- Surface handshake outcomes the way `/api/mtls/connections` + `/api/mtls/failures`
  already do for the downstream direction — add the upstream side so a failed
  client-cert handshake to a backend is visible (with reason:
  `untrusted_backend_cert|san_mismatch|cert_expired|no_client_cert`).
- **Expiry watch:** the WAF identity card and each trust bundle show `not_after`
  with a warning badge inside the renewal window — the single most common mTLS
  outage is a silently-expired cert.

---

## 4. Phasing

| Phase | Scope | Est. |
|---|---|---|
| **1** | Config types (`tls.upstream_identity`, `PoolConfig.upstream_mtls`) + validation; `build_client` builds an explicit `ClientConfig` with `with_client_auth_cert` + custom roots; `PoolKey` gains the cert fingerprint; file/secret-ref cert source. **No console yet** — YAML-configurable, server-auth + client-auth both working. | ~500 LoC · ~3 d |
| **2** | Read APIs + **Zero Trust page**: upstream list with mTLS pills, per-upstream drawer, backend-cert upload (reuse CA-upload card + `parse_ca_bundle`), **download WAF cert** (public). `verify`/`trust`/`allowed_sans` editing via audited `PUT` + `cas_set`. | ~550 LoC · ~3.5 d |
| **3** | Console-managed WAF identity stored in the Redis config plane (encrypted key at rest), **generate/rotate** action, per-upstream client-cert override, expiry-watch badges + upstream handshake failure surface. | ~450 LoC · ~3 d |
| **4** | Hot rotation without dropping live connections (rebuild client on `cas_set` activation), TLS session-resumption tuning, optional SPIFFE-SAN matcher for mesh interop. | ~350 LoC · ~2.5 d |
| — | Tests (handshake success/fail matrix, fail-closed on unverifiable backend, key-never-leaked assertions) + dashboard wiring | ~450 LoC · ~3 d |

Defaults **off**; operator opts in per pool. Phase 1 is shippable standalone
(YAML-only), the console lands in Phase 2.

---

## 5. Code anchors (verified 2026-06-08)

- `crates/aegis-core/src/config.rs` — `PoolConfig` (~1212) gains
  `upstream_mtls: Option<UpstreamMtlsConfig>` (the `cache:` field at ~1231 is the
  precedent for a per-pool optional block); `ConnectionPoolConfig` (~1351) +
  `UpstreamScheme` (~1419) are the TLS prereq; `TlsConfig` (~1986) gains
  `upstream_identity`; `ClientAuthConfig` (~2042) is the **downstream** inverse to
  mirror; `CertConfig` (~2208) + `key_ref`/`${secret:...}` (~3139, ~3226) are the
  cert-source precedent; `validate_tls_hardening` (~911) is where new validation
  slots in.
- `crates/aegis-proxy/src/upstream/forward.rs` — `build_client` (~228) is the
  hook: replace `with_webpki_roots()`/implicit `with_no_client_auth()` with an
  explicit `ClientConfig`; `PoolKey` (~320) + `From<&ConnectionPoolConfig>`
  (~328) must include the cert fingerprint (see `HIGH-RU-02` rationale in-file);
  `pooled_client` (~350) rebuilds on key change.
- `crates/aegis-proxy/src/listener/tls_policy.rs` — `CertificateDer` /
  `PrivateKeyDer` parsing helpers (~360–386) and the `with_no_client_auth()`
  call sites (~64, ~118) to reuse / mirror.
- `crates/aegis-control/src/identity_tracker.rs` — `parse_ca_bundle` (~401,
  x509-parser → subject + fingerprint + `not_after`) for upload preview;
  `/api/mtls/*` family (connections/failures/ca-summary) to add `upstream`
  siblings.
- `crates/aegis-control/src/api/upstreams_config.rs` — `GET/PUT
  /api/upstreams/config` (PoolView ~50+) is the pattern for the per-pool mTLS
  read/write + the ref-check on delete.
- `crates/aegis-core/src/state.rs` — `StateBackend` (~135): `get`/`set`/`del`
  (~136) + `cas_set` (~210) for persisting + atomically activating cert material
  in the Redis config plane.
- `crates/aegis-control/assets/dashboard/src/app.jsx` — `NAV` (~18) add the
  Zero Trust entry; `crates/aegis-control/assets/dashboard/src/pages.jsx` — the
  CA-upload card (~5688, `FileReader`/`readAsText`/PEM preview) is the upload
  widget to reuse; `dashboard_services.rs` `allow_ca_upload` (~277) is the
  capability-gate precedent.
- `config/gen-cert.sh` — extend with a `clientAuth`-EKU mode for dev/test WAF
  client certs.

---

## 6. Security review checklist (gate before enabling by default)

- [ ] **WAF private key never leaves the process in plaintext** — no log line, no
      read API, no metrics field ever contains it. A test asserts the download
      endpoint + every `GET` returns public PEM only.
- [ ] **Key at rest** — if stored in Redis, it is envelope-encrypted (boot
      secret / KMS ref), not raw PEM; or only a `${secret:...}` reference is
      persisted and the key stays in the secret store / on disk.
- [ ] **Fail closed when enabled** — `upstream_mtls.enabled + verify: true` with
      an unverifiable backend cert ⇒ that pool's dials fail with a clear reason,
      **never** a silent fallback to "trust any cert". Covered by a test that
      points `trust` at a CA that doesn't sign the backend and asserts the dial
      fails + is surfaced.
- [ ] **Scope isolation** — enabling mTLS on one pool provably does not change
      the client built for any other pool (PoolKey fingerprint test).
- [ ] **Hot-reload correctness** — rotating the cert via `cas_set` rebuilds the
      upstream client (no stale `PoolKey` cache hit); a restart is not required.
- [ ] **EKU correctness** — generated WAF certs carry `clientAuth` EKU, not
      `serverAuth`; a SAN is present for backend-side authorization.
- [ ] **Upload validation** — uploaded backend CA/cert is parsed + previewed
      (`parse_ca_bundle`); malformed/empty PEM is rejected before activation.
- [ ] **Audit coverage** — enable/disable, trust-bundle upload/delete, and
      identity rotate all emit audit events with actor + fingerprint.
- [ ] **Capability gate** — browser-driven cert mutation is behind the
      `allow_ca_upload`-style flag, off by default.

---

## 7. Roadmap slot + cross-refs

Belongs under the roadmap's **Security-capability** tier (zero-trust egress to
backends), adjacent to the existing downstream-mTLS (`MTLS-T*`) work. Pairs with:

- `tls.client_auth` (downstream mTLS) — this is the **mirror direction**
  (WAF-as-client vs WAF-as-server); the two together give end-to-end mutual auth
  through the WAF. Reuse its parsing, upload card, and `/api/mtls/*` surface.
- `plans/future/smart-caching.md` — the precedent for a **per-upstream optional
  `PoolConfig` block** activated through the same config plane; reuse its
  phasing/anchor style.
- `archive/cluster-config-sync-and-scaling.md` — the `cas_set` config-plane
  activation this feature persists cert state through (multi-node atomic flip).
- `config/gen-cert.sh` — extend for `clientAuth` dev certs.

## 8. Out of scope

- Full SPIFFE/SPIRE SDS integration with auto-rotating short-lived SVIDs (Phase 4
  adds a SAN matcher for interop; a real SDS data source is a later, separate
  effort).
- An in-product internal CA / PKI (issuing + CRL/OCSP) — Phase 3 can self-sign or
  sign under an *externally provided* CA, but running a full CA is out of scope.
- mTLS for non-HTTP upstream schemes (`tcp` raw forwarding is itself unimplemented).
- Hardware-backed key storage (HSM/PKCS#11) for the WAF identity key.

---

### Sources (2025–2026 scan)

- NGINX — securing HTTP traffic to upstreams (`proxy_ssl_certificate`,
  `proxy_ssl_certificate_key`, `proxy_ssl_trusted_certificate`,
  `proxy_ssl_verify`, `proxy_ssl_session_reuse`):
  <https://docs.nginx.com/nginx/admin-guide/security-controls/securing-http-traffic-upstream/>
- smallstep — mutual TLS on the client side with nginx (reverse proxy):
  <https://smallstep.com/hello-mtls/doc/client/nginx-proxy>
- Envoy — TLS / upstream `UpstreamTlsContext` + validation context:
  <https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl>
- Envoy — Secret Discovery Service (SDS), keys-never-touch-disk rotation:
  <https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret>
- SPIFFE — using Envoy with X.509-SVIDs + SPIRE auto-rotation:
  <https://spiffe.io/docs/latest/microservices/envoy/>
