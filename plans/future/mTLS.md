# Unified Zero Trust — downstream + upstream mTLS, rebuilt as one module + console page

> **Status (2026-06-09): Design only — not started.**
> **This plan supersedes the old "upstream-mTLS complements downstream" design.**
> Decision (2026-06-09, with Nico): **remove the existing fragmented downstream
> mTLS feature (the `MTLS-T*` series) and rebuild BOTH mutual-TLS directions as a
> single cohesive `zero_trust` module + one console page.**
>
> Four directional decisions are locked:
> 1. **Unified rebuild** — one module, one page, both directions (not reuse-and-extend).
> 2. **One shared fleet identity** — every node presents the *same* WAF client
>    cert+key, distributed via the Redis config plane (private key encrypted at
>    rest); per-upstream override allowed.
> 3. **Hard cut** — delete the old downstream mTLS module/routes/cards up front and
>    rebuild from scratch (no strangler period). Accepted risk: a window where
>    downstream client-cert verification is offline until the rebuild lands. The
>    crypto *primitives* (rustls `WebPkiClientVerifier` wiring, DER parsing) are
>    carried over rather than rewritten line-for-line — rewriting working rustls
>    glue adds risk with no benefit. "Hard cut" applies to the **feature surface,
>    module layout, config, API, and dashboard**, not the low-level library glue.
> 4. **Hard rename** — new top-level `zero_trust:` config block, **no** back-compat
>    alias for `tls.client_auth`. Existing YAML must be migrated on upgrade.

## What exists today (verified 2026-06-09)

**Downstream mTLS (WAF-as-server) — shipped, wired into the live handshake:**
- Config: `ClientAuthConfig` (`config.rs` ~2042) — `mode` (`disabled|optional|required`),
  `ca_bundle`, `allowed_sans`, `apply_to: [admin|data]`; `ClientAuthMode`,
  `ClientAuthScope`.
- Listener enforcement: `listener/tls.rs` (~534 LoC), `listener/client_trust.rs`
  (~338, the `WebPkiClientVerifier`), `listener/tls_policy.rs` (~664, incl. the
  `CertificateDer`/`PrivateKeyDer` parsing helpers ~360–386).
- Control APIs: `api/mtls.rs`, `api/mtls_ca_bundle.rs`, `api/mtls_mode.rs`,
  `identity_tracker.rs` (incl. `parse_ca_bundle` ~401 → subject/fingerprint/not_after).
- Routes (admin plane): `GET /api/mtls`, `/connections`, `/failures`, `/ca-summary`,
  `/ca-bundle/capability`, `/mode`; `PUT /api/mtls/{mode,ca-bundle,sans}`;
  `DELETE /api/mtls/sans/{san}`; `POST /api/mtls/sans/{san}/test`
  (`admin_get.rs` ~1027–1076, `admin_dispatch.rs` ~460–486, `admin_mutate.rs` ~922+).
- Dashboard: mode card + CA-bundle upload card + SANs card (`pages.jsx` ~5588/5688/5812),
  break-glass banner (`app.jsx` ~164, env `AEGIS_MTLS_BREAK_GLASS`), route-auth pills
  (`pages.jsx` ~4534), data hooks (`data.jsx` ~749–798).
- Audit events: `mtls_sans_set`, `mtls_sans_removed`, `mtls_ca_bundle_validated`.
- Tests: `crates/aegis-control/tests/dod.rs`.

**Upstream TLS (WAF-as-client) — server-auth only:** `forward.rs::build_client`
(~228) uses `with_webpki_roots()` ⇒ implicit `with_no_client_auth()`. The WAF
never presents a client cert and can't pin a custom backend CA. **This is the
missing direction.**

## Goal

One **Zero Trust** console page + one `zero_trust` backend module that own **both**
mutual-TLS directions:

1. **Downstream (WAF-as-server).** Verify client certs presented *to* the WAF
   (rebuilt cleanly from the old `MTLS-T*` feature). Two knobs: present-a-trust-
   anchor + optional SAN allowlist, scoped to admin/data listeners.
2. **Upstream (WAF-as-client).** The WAF presents **one shared fleet client cert**
   when dialing a backend (client-auth), and verifies the backend's server cert
   against an uploaded CA (server-auth). Per-upstream, defaults off.

> **Naming clarity (the #1 source of mTLS confusion).** Upstream direction:
> *"Upload their cert"* = the **upstream's** trust material the WAF verifies *them*
> against (server-auth). *"Download WAF cert"* = **our** shared client identity the
> upstream verifies *us* against (client-auth). Different keypairs, opposite ways.
> The page labels them explicitly.

---

## 1. How the world does upstream mTLS (2025–2026 scan)

| Product | Config axis | Proxy client identity | Backend trust (verify server) | Rotation |
|---|---|---|---|---|
| **nginx (`proxy_ssl_*`)** | Per `location`/`upstream` | `proxy_ssl_certificate` + `_key` (PEM on disk) | `proxy_ssl_trusted_certificate` + `proxy_ssl_verify on` + `_verify_depth` | Reload after file swap; `proxy_ssl_session_reuse on` to amortise handshakes |
| **HAProxy** | Per `server` line | `ssl crt <client.pem>` | `ca-file <ca.pem>` + `verify required` | Runtime API / reload |
| **Envoy** | Per cluster (`UpstreamTlsContext`) | `tls_certificates` **or SDS** | `validation_context` (CA, optional SPIFFE matcher) | **SDS streams certs in, keys never touch disk** — gold standard |
| **SPIFFE/SPIRE** | Per workload identity | **Short-lived X.509-SVID**, auto-rotated, pushed via SDS | Trust-domain bundle + SVID SAN matcher | **Auto-rotation built in** |
| **Cloudflare mTLS to origin** | Per hostname/origin | CF-managed client cert | Origin trusts CF client-CA | Platform-managed |

**Cross-product consensus the rebuild adopts:**

1. **Client identity is per-destination-scope, configured where the destination
   is.** Universal axis = **per upstream** → our `PoolConfig` home.
2. **Two separable knobs:** *present a client cert* and *verify the server against a
   trust anchor*, set independently (real deployments turn on client-auth while
   pinning a custom CA for an internal/self-signed backend).
3. **Trust by CA, not by pinned leaf** — makes one shared WAF client cert work for
   many backends and makes rotation cheap (re-sign under the same CA → nothing
   downstream changes).
4. **Session reuse amortises the handshake** (keep-alive + TLS resumption).
5. **Rotation is first-class, ideally hot** (Envoy/SPIRE swap on live connections,
   no restart, key never on disk).

### Why a WAF's upstream-mTLS must be *more* careful than a generic proxy's

We hold a **private key that authenticates us to every protected backend**:

- **The WAF client key is a crown jewel.** Whoever holds it can impersonate the WAF
  to backends that trust it. Never logged, never returned by any read API, ideally
  never plaintext at rest. The download button exports **only public cert material**.
- **Fail closed, but scoped.** `verify` on an upstream whose cert we can't validate
  must fail *that upstream's* dials (clear health error), **never** silently fall
  back to "trust anything". mTLS is opt-in per pool so enabling it on one backend
  can't disturb the others.

---

## 2. Fleet identity decision (locked: ONE shared identity)

**Every node presents the SAME WAF client cert + key**, signed by an internal CA,
distributed through the Redis config plane (private key envelope-encrypted at rest)
or, in file mode, the same file deployed to every node. A **per-upstream override**
(`client_cert_ref`) is allowed for the cases the scan shows are real.

Why shared is the right default for a multi-node fleet:

- A client cert identifies **who is connecting** (the WAF fleet), not **where**. One
  identity is the natural model; every backend that trusts our CA accepts any node
  with zero per-node setup.
- **Rotation stays trivial:** re-issue one cert under the same internal CA; every
  backend keeps trusting it (they pin the CA, not the leaf). One keypair to protect,
  rotate, and download for backend operators.
- **Multi-node convergence:** the cert lives in the config plane; `cas_set`
  activation flips the whole fleet atomically; each node rebuilds the affected
  upstream client on the existing config-reload path (§3.2/§3.3).

When a **per-upstream client cert override** earns its keep: separate trust domains
(a backend run by another org with its own CA), independent revocation (revoke the
WAF's access to *one* backend), or per-backend authorization by SAN/SPIFFE ID.

**Server-trust (verifying the backend) is per-upstream by nature** — each backend
has a different server cert/CA/hostname. Public-internet backends keep webpki roots;
the upload only overrides for internal/self-signed ones.

---

## 3. Proposed design

### 3.0 Hard-cut removal inventory (deleted up front, Phase 1)

- `crates/aegis-control/src/api/mtls.rs`, `mtls_ca_bundle.rs`, `mtls_mode.rs` →
  replaced by one `api/zero_trust/` module.
- Old route registrations: `admin_get.rs` (~1027–1076), `admin_dispatch.rs`
  (~460–486), `admin_mutate.rs` (`handle_mtls_*` ~922+); `api/mod.rs` (~21–23).
- Dashboard — **the 3 downstream-mTLS cards currently live ON the Settings page**
  (`PageSettings` ~6145 renders them at ~6252–6254): `MtlsModeCard` (~5595),
  `MtlsCaBundleCard` (~5696), `MtlsSansCard` (~5961). **Remove them from Settings**
  and relocate the rebuilt equivalents to the new `ZeroTrustPage` (§3.4 section 2).
  Also delete `data.jsx` hooks (~749–798, `useMtlsSansApi`/`mtlsSansPut`/`Delete`/`Test`).
- Config: `ClientAuthConfig`/`ClientAuthMode`/`ClientAuthScope` (`config.rs` ~2042)
  → re-expressed under `zero_trust.downstream` (renamed, no alias).
- Audit event names `mtls_sans_*`, `mtls_ca_bundle_validated` → `zero_trust_*`.
- **Kept (library glue, carried over):** `tls_policy.rs` DER parsing helpers,
  `client_trust.rs` `WebPkiClientVerifier` wiring, `identity_tracker::parse_ca_bundle`.
- **Settings-page touchpoints to refactor (NOT remove):**
  - Break-glass card (`SettingsBreakGlassCard` ~6492) + boot banner (`app.jsx` ~164,
    env `AEGIS_MTLS_BREAK_GLASS`, status field `mtls_break_glass_active`): keep the
    emergency-override feature; it now acts on `zero_trust.downstream` mode —
    reconcile env/field naming under the hard rename.
  - `SettingsCertsCard` (~6577) `'mtls'` cert-source tag: leave (server-cert inventory).
  - `ROUTE_AUTH_CHOICES` (~13048, `mtls`/`spiffe`) + route-auth pills (~4534/4558):
    keep — per-route client-identity requirement, part of downstream zero-trust.

### 3.1 Config — unified `zero_trust:` block (hard rename, no alias)

```yaml
zero_trust:
  downstream:                       # = old tls.client_auth, RENAMED (no alias)
    mode: required                  # disabled | optional | required
    ca_bundle: config/certs/clients-ca.pem   # or source: state (config plane)
    allowed_sans: ["svc-a.internal"]
    apply_to: [admin, data]
  upstream_identity:                # NEW — the ONE shared fleet WAF client cert
    source: state                   # state (config plane, key encrypted) | file
    # when source: file —
    # cert_path: config/certs/waf-client.pem   # leaf (+chain), PUBLIC
    # key_ref:  "${secret:env:WAF_UPSTREAM_KEY}"  # private key via secret ref

upstreams:
  payments-pool:
    members: [ ... ]
    connection:
      tls: true                     # TLS to backend (prereq)
    upstream_mtls:                  # NEW per-pool (slots into PoolConfig like cache:)
      enabled: true                 # absent/false ⇒ today's with_no_client_auth
      client_cert_ref: null         # null = shared upstream_identity; set to override
      verify: true                  # default true when enabled — FAIL CLOSED
      trust: backend-ca             # uploaded bundle name; null ⇒ webpki roots
      allowed_sans: ["payments.internal"]   # optional SAN check on backend server cert
```

- Opt-in per pool; no `upstream_mtls` ⇒ data plane builds the client exactly as today.
- `verify: true` is the safe default *when enabled* — unverifiable backend fails loudly.
- `trust` / `client_cert_ref` name console-uploaded material in the config plane (3.3).

### 3.2 Data-plane hook — and the threading gap the old doc missed

`forward.rs::build_client` (~228) builds from `&ConnectionPoolConfig`. Today:

```text
HttpsConnectorBuilder::new().with_webpki_roots().https_or_http()...   // ⇒ no_client_auth
```

Replace with an explicit `rustls::ClientConfig` fed via `.with_tls_config(cfg)`:

```text
let roots = match upstream_mtls.trust {
    Some(bundle) => load_bundle_from_state_or_disk(bundle),   // custom CA
    None         => webpki_roots(),
};
let b = ClientConfig::builder().with_root_certificates(roots);
let client_config = match upstream_mtls.client_cert {        // shared identity or override
    Some((chain, key)) => b.with_client_auth_cert(chain, key)?,   // mTLS
    None               => b.with_no_client_auth(),                // server-auth only
};
// optional SAN allowlist → custom ServerCertVerifier wrapping webpki
```

Reuse the DER parsing already in `tls_policy.rs` (~360–386).

**THE GAP (fix in Phase 2):** `build_client`/`pooled_client` only receive
`&ConnectionPoolConfig`, but `upstream_mtls` lives on the parent `PoolConfig`. The
cert/trust material must be threaded into the build path — fold a resolved
`upstream_mtls` (certs + fingerprint) into `ConnectionPoolConfig` where it's cloned
from `PoolConfig` (`registry.rs` ~197, `dns_refresh.rs` ~289).

**`PoolKey` must gain a cert-identity fingerprint** (`forward.rs` ~320). The
per-process client cache is keyed by `PoolKey`; without the cert in the key, a
hot-reload that swaps a cert hits a stale cached client — the exact bug `HIGH-RU-02`
fixed for `scheme`. Add a **fingerprint** of the effective (client_cert, trust)
material; **never** hash raw private-key bytes into the key.

### 3.3 Cert storage — Redis config plane (`StateBackend` + `cas_set`)

Console-uploaded material persists through `StateBackend`
(`crates/aegis-core/src/state.rs` ~135: `get`/`set`/`del` ~136, `cas_set` ~210),
reusing the config plane's activation pattern. Proposed keys:

```text
aegis:zt:downstream:ca                 → { ca_pem, fingerprint, subjects[], not_after }
aegis:zt:upstream:identity             → { cert_pem, key_enc, fingerprint, not_after }  # shared fleet identity
aegis:zt:upstream:trust:<bundle>       → { ca_pem, fingerprint, subjects[], not_after }
aegis:zt:upstream:client:<name>        → { cert_pem, key_enc, fingerprint, not_after }  # per-upstream override
```

Persistence + safety rules:

- **Public material (certs, CA bundles) stored as-is** — non-secret, exactly what
  the download button exports.
- **Private keys envelope-encrypted at rest** (boot secret / KMS-style key ref —
  mirrors how `key_ref`/`${secret:...}` keeps API keys out of plaintext). If
  encryption-at-rest isn't acceptable, persist only a `${secret:...}` *reference* and
  keep the key in the secret store / on disk. **Gate item, not nice-to-have (§6).**
- **No read API ever returns a private key.** `GET` returns metadata only (subject,
  fingerprint, `not_after`, SANs) — same shape `parse_ca_bundle` already produces.
- Activation via `cas_set` so the multi-node fleet flips atomically; nodes pick it
  up on the config-reload path and rebuild the affected upstream client (3.2).

### 3.4 Console — the unified "Zero Trust" page

New left-sidebar entry in the **Policy** group (`app.jsx` `NAV` ~36, next to
`Routing & Upstreams`):

```jsx
{ id: 'zero-trust', label: 'Zero Trust', icon: <window.I.Shield />, badge: 'NEW', tone: 'warn' },
```

(`widgets.jsx` `I` set has no `Lock`/`Key` glyph — reuse `Shield`/`Server` or add a
`Lock` SVG first.)

Page layout (`pages.jsx`, new `ZeroTrustPage`), three sections:

1. **WAF identity card (upstream client-auth, global, top).** Shows the shared fleet
   WAF client-cert metadata (subject, fingerprint, expiry) + **"Download WAF cert"**
   (streams the **public** leaf+chain as `waf-client.pem`) + **"Generate / rotate"**
   (re-issues under the internal CA; §3.6). Backend operators install this in their
   client-trust store.
2. **Downstream section (WAF-as-server).** Ported from the old 3 cards into one:
   mode (`disabled|optional|required`), client-CA upload (reuse the upload widget +
   `parse_ca_bundle` preview), SAN allowlist with synthetic admit-test, `apply_to`
   scope, identity-tracker live counts + handshake-failure histogram.
3. **Upstream list + per-upstream drawer.** Reuses `/api/upstreams/config`; each row
   an mTLS status pill (`off|client-auth|mutual+verify`). Drawer: **enable** toggle →
   **"Upload backend cert/CA"** (PEM paste/file, saved to `aegis:zt:upstream:trust:<bundle>`),
   `verify` toggle (default on) + `allowed_sans`, optional per-upstream client-cert
   override (advanced). **Save** → audited `PUT` → `cas_set` activation → live.

### 3.5 API surface (one `/api/zero-trust/*` family, audit-mutated)

```text
# downstream (WAF-as-server)
GET    /api/zero-trust/downstream                 → mode/ca/sans/apply_to + live (NO key)
PUT    /api/zero-trust/downstream/mode            → mode override (audited)
PUT    /api/zero-trust/downstream/ca-bundle       → upload client-trust CA (audited)
PUT    /api/zero-trust/downstream/sans            → SAN allowlist replace (audited)
DELETE /api/zero-trust/downstream/sans/{san}      → single SAN remove (audited)
POST   /api/zero-trust/downstream/sans/{san}/test → synthetic admit check
GET    /api/zero-trust/downstream/connections     → identity tracker counts
GET    /api/zero-trust/downstream/failures        → handshake-failure histogram

# upstream (WAF-as-client)
GET    /api/zero-trust/upstream/identity          → shared WAF client-cert metadata (NO key)
POST   /api/zero-trust/upstream/identity/rotate    → generate/re-issue (audited)
GET    /api/zero-trust/upstream/identity/download  → public leaf+chain PEM
GET    /api/zero-trust/upstream/config             → per-pool mTLS state (metadata only)
PUT    /api/zero-trust/upstream/config/{pool}      → enable/verify/trust/sans (audited, cas_set)
POST   /api/zero-trust/upstream/trust/{bundle}     → upload backend trust bundle (audited)
DELETE /api/zero-trust/upstream/trust/{bundle}     → remove bundle (ref-checked like pool delete)
```

Gate all browser-driven cert mutation behind the same `allow_ca_upload`-style
capability flag (`dashboard_services.rs` ~277), off by default.

### 3.6 WAF client cert provisioning (the download needs something to download)

- **Operator-supplied (default, no new crypto).** Operator mints the WAF client
  cert+key out of band (their internal CA), sets `zero_trust.upstream_identity`
  (`source: file`), download serves the public cert. Extend `config/gen-cert.sh`
  with a `--client --eku clientAuth` mode for dev/test.
- **Console-generated (Phase 4, optional).** "Generate" mints a keypair + CSR and
  self-signs (or signs under a configured internal CA), stores per §3.3, download
  serves the public cert. Needs `rcgen` (or shells `openssl`) + careful key handling.

Set **EKU = `clientAuth`** (not `serverAuth`) and a clear SAN (e.g. `waf.internal`)
so backends can authorize on it.

### 3.7 Handshake cost & resumption (keep it off the hot path)

- Connection pooling/keep-alive is already per-pool (`ConnectionPoolConfig`) — the
  handshake is paid once per pooled connection, not per request.
- TLS session resumption amortises re-handshakes (rustls supports it; keep the
  upstream client's session cache enabled).
- `verify` does CA-chain validation by default; a SAN allowlist is a cheap string check.

### 3.8 Observability

- Per-upstream mTLS pill on the Zero Trust list **and** the Routing & Upstreams page.
- Upstream handshake-failure surface mirroring the downstream tracker, with reason:
  `untrusted_backend_cert|san_mismatch|cert_expired|no_client_cert`.
- **Expiry watch:** WAF identity card + each trust bundle show `not_after` with a
  warning badge inside the renewal window — silent cert expiry is the #1 mTLS outage.

---

## 4. Phasing (hard cut — no strangler)

| Phase | Scope | Est. |
|---|---|---|
| **1 — Cut + unified config + downstream rebuild** | Delete old `api/mtls*.rs` + routes + the 3 Settings-page cards (`MtlsModeCard`/`MtlsCaBundleCard`/`MtlsSansCard`, pages.jsx ~6252–6254) + `data.jsx` hooks; introduce `zero_trust:` config (`downstream` renamed from `client_auth`, no alias) + the new `api/zero_trust` module re-exposing downstream over `/api/zero-trust/downstream/*`; keep the rustls verifier glue; reconcile break-glass env/field naming. Downstream parity restored. Branch: `feat/zero-trust-mtls`. | ~600 LoC · 4d |
| **2 — Upstream data plane (YAML-only)** | `zero_trust.upstream_identity` + `PoolConfig.upstream_mtls` + validation; `build_client` builds explicit `ClientConfig` (`with_client_auth_cert` + custom roots + SAN verifier); **thread material into `ConnectionPoolConfig`**; `PoolKey` cert fingerprint; fail-closed on unverifiable backend. | ~550 LoC · 3.5d |
| **3 — Unified Zero Trust page** | WAF identity card (metadata + public download + rotate stub) · downstream section (ported) · per-upstream list + drawer (backend-CA upload via `parse_ca_bundle`, verify/trust/sans). NAV entry. Audited `PUT` + `cas_set`. | ~650 LoC · 4d |
| **4 — Shared fleet identity in config plane** | Identity stored in Redis config plane, **private key envelope-encrypted**; generate/rotate; per-upstream client-cert override; expiry-watch badges; upstream handshake-failure surface. | ~500 LoC · 3.5d |
| **5 — Hardening** | Hot rotation on `cas_set` (rebuild client, no dropped conns); TLS session-resumption tuning; optional SPIFFE-SAN matcher. | ~350 LoC · 2.5d |
| — | Tests: handshake success/fail matrix (both directions), **fail-closed proof**, **key-never-leaked** assertion, `PoolKey` scope isolation, multi-node `cas_set` activation, downstream parity regression. | ~500 LoC · 3.5d |

Defaults **off**; operator opts in per pool. **~3,150 LoC · ~21 working days.**

### 4.1 Progress tracker (update as phases land)

Branch: **`feat/zero-trust-mtls`** (cut from `develop` 2026-06-09). No real upstream
traffic yet, so the temporary downstream-enforcement gap during the hard cut is safe.

> **Sequencing decision (2026-06-09):** renaming the *internal API module files*
> (`api/mtls*.rs` → `api/zero_trust`), the `/api/mtls/*` → `/api/zero-trust/*`
> *routes*, and relocating the dashboard cards was **moved from P1 to P3**, where the
> new unified page actually consumes them. Doing it in P1 would have stranded
> `accept.rs`/`admin_dispatch`/`dashboard_services` (which seed `mtls_mode_store` /
> `allowed_sans` from those modules) and forced a multi-hour red build across three
> crates. End state is unchanged (no aliases, single surface). P1's deliverable is the
> **config contract rename + everything compiling + downstream parity green.**

- [x] **P1** `zero_trust:` config block (`ZeroTrustConfig` + `downstream` = renamed
      `ClientAuthConfig`→`DownstreamMtlsConfig`/`Mode`/`Scope`, no alias); field moved
      from `TlsConfig` to top-level `WafConfig`; new `validate_zero_trust`.
- [x] **P1** All consumers rewired to `cfg.zero_trust.downstream`
      (run.rs/accept.rs ×3/reload.rs + control `api/mtls::from_config`); types
      renamed tree-wide; workspace compiles.
- [x] **P1** Downstream parity green: config 270, tls_policy 21, reload(client_auth) 5,
      control mtls 37 — all pass. Real profile `config/profiles/prod-strict.yaml`
      migrated + `validate` CLI OK.
- [ ] **P1→P3** Delete `api/mtls.rs`/`mtls_ca_bundle.rs`/`mtls_mode.rs`, rename routes
      (`admin_get`/`admin_dispatch`/`admin_mutate`/`api/mod`) to `/api/zero-trust/*`,
      remove the 3 `PageSettings` cards (pages.jsx 6252–6254) + defs + `data.jsx` hooks,
      reconcile `AEGIS_MTLS_BREAK_GLASS` env/`mtls_break_glass_active` field. **(moved to P3)**
- [x] **P2** `zero_trust.upstream_identity` (`UpstreamIdentityConfig`, source file|state) +
      `PoolConfig.upstream_mtls` (`UpstreamMtlsConfig`) + `validate_upstream_mtls`
      (enabled⇒identity+TLS; client_cert_ref/verify:false/allowed_sans/source:state rejected as P4/P5).
- [x] **P2** `build_client` builds explicit rustls `ClientConfig`
      (`client_config_from_resolved`: client-auth cert + custom-CA or webpki roots, `https_only`);
      threaded via `ConnectionPoolConfig.upstream_mtls` (`#[serde(skip)]`, resolved in
      `registry.build_pools` from `resolve_upstream_mtls`; identity stored on registry for `apply`;
      preserved across `dns_refresh`); `PoolKey` gains `mtls_fingerprint`; `build_client`/`pooled_client`
      now fallible ⇒ `forward` maps to `ForwardError::Handshake` (fail closed). Key bytes never in config.
- [x] **P2** Gates green: resolution (3) + validation (7) in aegis-core; PoolKey scope-isolation +
      build-fail-closed-on-missing-cert in forward; **wrong-CA live-handshake fail-closed** in upstream/tls.
      Scope cut: `verify:false` + `allowed_sans` enforcement + `source:state` deferred to P4/P5 (rejected now, not silently ignored).
- [x] **P3 slice 1 (backend)** `api/zero_trust` read views: `UpstreamIdentityView`
      (public cert metadata via parse_ca_bundle, never the key) + `UpstreamConfigView`
      (per-pool off|mutual+verify); `GET /api/zero-trust/upstream/{identity,config}`
      wired (same dispatch/auth as /api/mtls). Additive — old /api/mtls/* untouched. 4 tests.
- [x] **P3 slice 2 (frontend)** `PageZeroTrust` (NAV: Policy group): upstream section = WAF
      client-identity card (public cert metadata + Download WAF cert, public PEM only) +
      per-pool upstream-mTLS status table (reads /api/zero-trust/upstream/*); downstream section =
      mode/CA-bundle/SANs cards relocated off Settings (Settings keeps a breadcrumb). Bundle rebuilt.
- [x] **P3 hard cut** `/api/mtls/*` → `/api/zero-trust/downstream/*` renamed in lockstep (backend
      route matches + audit resource labels + frontend fetch URLs). control 1068 / proxy 754 / api_smoke 8 green.
- [ ] **P3 deferred (cosmetic polish, non-blocking)** — backend-CA *upload* + per-pool drawer editing
      (read-only today; needs audited PUT + cas_set, pairs with P4); rename audit ACTION names
      `mtls_*`→`zero_trust_*`; rename break-glass env `AEGIS_MTLS_BREAK_GLASS`/`mtls_break_glass_active`;
      consolidate `api/mtls*.rs` files into `api/zero_trust`. Decision (2026-06-09): P3 uploads/downloads
      PUBLIC material only; private-key upload + encryption-at-rest is P4 (key stays a YAML `key_ref` path).
      **Verification DONE (2026-06-09):** live headless-Chromium render against the running WAF
      (debug binary, in_memory config) — page renders, both sections present, relocated downstream
      cards work, NAV entry active; `/api/zero-trust/{upstream/identity,upstream/config,downstream,
      downstream/sans}` all return 200 with correct JSON (identity shows no key leak); no React/page
      errors (only pre-existing CSP-inline warnings + unrelated background-poll 403/503 in single-node dev).
- [~] **P4** Shared identity in config plane. **Decision (2026-06-09): REFERENCE-ONLY** (not
      envelope-encrypted) — repo has no AEAD primitive; `source:state` stores the PUBLIC cert +
      backend CAs in the config plane (cas_set, multi-node), private key stays a `${secret:...}`/path
      ref via `secrets/mod.rs::resolve_secret`. Satisfies §6 "key at rest" (reference path).
      Remaining backend: (a) lift the `source:state` validation guard + async state→PEM resolution
      threaded into the resolve/build path (build_pools is sync + has no StateBackend — materialize
      PEM in the async boot/apply step before build_pools); (b) audited `POST /api/zero-trust/upstream/
      trust/{bundle}` (upload PUBLIC backend CA → state) + state-backed CA loading in build_client;
      (c) per-pool `upstream_mtls` editing ALREADY round-trips via existing `PUT /api/upstreams/pool/{id}`
      (it's a PoolConfig field) — needs the global cross-ref validation added to that path + a frontend drawer.
      Frontend: drawer editing, backend-CA upload, expiry badges, upstream handshake-failure surface.
- [ ] **P5** Hot rotation on cas_set; session resumption; optional SPIFFE-SAN matcher.
- [ ] **Tests/gates** §6 checklist all green before default-on.

---

## 5. Code anchors (verified 2026-06-09)

- `crates/aegis-core/src/config.rs` — `PoolConfig` (~1212) gains
  `upstream_mtls: Option<UpstreamMtlsConfig>` (the `cache:` field ~1231 is the
  per-pool-optional precedent); `ConnectionPoolConfig` (~1351) +
  `UpstreamScheme` (~1419) are the TLS prereq; `ClientAuthConfig` (~2042) is what
  moves under `zero_trust.downstream`; `CertConfig` + `key_ref`/`${secret:...}` are
  the cert-source precedent; `validate_tls_hardening` (~911) is where validation slots.
- `crates/aegis-proxy/src/upstream/forward.rs` — `build_client` (~228) is the hook;
  `PoolKey` (~320) + `From<&ConnectionPoolConfig>` (~328) must include the cert
  fingerprint (see in-file `HIGH-RU-02`); `pooled_client` (~350) rebuilds on key change.
- `crates/aegis-proxy/src/upstream/{registry.rs ~197, dns_refresh.rs ~289}` — where
  `ConnectionPoolConfig` is cloned from `PoolConfig`; the threading point for §3.2.
- `crates/aegis-proxy/src/listener/{tls.rs ~534, client_trust.rs ~338, tls_policy.rs ~664}`
  — downstream handshake enforcement + DER parsing helpers (~360–386) to carry over.
- `crates/aegis-control/src/identity_tracker.rs` — `parse_ca_bundle` (~401) for upload
  preview (both directions).
- `crates/aegis-control/src/api/upstreams_config.rs` — `GET/PUT /api/upstreams/config`
  (PoolView) is the per-pool read/write + delete-ref-check pattern.
- `crates/aegis-core/src/state.rs` — `StateBackend` (~135): `get`/`set`/`del` (~136) +
  `cas_set` (~210) for persisting + atomically activating cert material fleet-wide.
- `crates/aegis-control/assets/dashboard/src/app.jsx` — `NAV` (~36, Policy group);
  `pages.jsx` — old cards (~5588/5688/5812) to delete + the upload widget
  (`FileReader`/`readAsText`/PEM preview ~5688) to reuse; `data.jsx` hooks (~749–798)
  to delete; `dashboard_services.rs` `allow_ca_upload` (~277) capability gate.
- `config/gen-cert.sh` — extend with a `clientAuth`-EKU mode for dev/test WAF certs.

---

## 6. Security review checklist (gate before enabling by default)

- [ ] **WAF private key never leaves the process in plaintext** — no log, read API,
      or metric. A test asserts download + every `GET` returns public PEM only.
- [ ] **Key at rest** — envelope-encrypted in Redis (boot secret/KMS ref) **or** only
      a `${secret:...}` reference persisted; never raw PEM in Redis.
- [ ] **Fail closed when enabled** — `upstream_mtls.enabled + verify: true` with an
      unverifiable backend ⇒ that pool's dials fail with a clear reason, never silent
      trust-all. Covered by a test pointing `trust` at a non-signing CA.
- [ ] **Downstream parity / no regression** — after the hard cut, a test proves
      client-cert termination still enforces (`optional`/`required`, SAN allowlist).
- [ ] **Scope isolation** — enabling mTLS on one pool provably doesn't change the
      client built for any other pool (`PoolKey` fingerprint test).
- [ ] **Hot-reload correctness** — rotating via `cas_set` rebuilds the upstream client
      (no stale `PoolKey` hit); no restart required; fleet converges.
- [ ] **EKU correctness** — generated WAF certs carry `clientAuth` EKU + a SAN.
- [ ] **Upload validation** — uploaded CA/cert parsed + previewed; malformed/empty
      PEM rejected before activation.
- [ ] **Audit coverage** — downstream mode/ca/sans edits, upstream enable/disable,
      trust upload/delete, identity rotate all emit audit events with actor + fingerprint.
- [ ] **Capability gate** — browser-driven cert mutation behind the
      `allow_ca_upload`-style flag, off by default.

---

## 7. Roadmap slot + cross-refs

Belongs under the roadmap's **Security-capability** tier (zero-trust ingress +
egress). Replaces the old downstream-mTLS (`MTLS-T*`) entries — they are folded into
this unified feature. Pairs with:

- `plans/future/smart-caching.md` — precedent for a per-upstream optional `PoolConfig`
  block activated through the same config plane; reuse its phasing/anchor style.
- `archive/cluster-config-sync-and-scaling.md` — the `cas_set` config-plane
  activation this feature persists cert state through (multi-node atomic flip).
- `config/gen-cert.sh` — extend for `clientAuth` dev certs.

## 8. Out of scope

- Full SPIFFE/SPIRE SDS with auto-rotating short-lived SVIDs (Phase 5 adds a SAN
  matcher for interop; a real SDS data source is a later, separate effort).
- An in-product internal CA / PKI (issuing + CRL/OCSP) — Phase 4 can self-sign or
  sign under an *externally provided* CA; running a full CA is out of scope.
- mTLS for non-HTTP upstream schemes (raw `tcp` forwarding is itself unimplemented).
- Hardware-backed key storage (HSM/PKCS#11) for the WAF identity key.

---

### Sources (2025–2026 scan)

- NGINX — securing HTTP traffic to upstreams (`proxy_ssl_*`):
  <https://docs.nginx.com/nginx/admin-guide/security-controls/securing-http-traffic-upstream/>
- smallstep — client-side mTLS with nginx reverse proxy:
  <https://smallstep.com/hello-mtls/doc/client/nginx-proxy>
- Envoy — upstream `UpstreamTlsContext` + validation context:
  <https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl>
- Envoy — Secret Discovery Service (SDS), keys-never-touch-disk rotation:
  <https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret>
- SPIFFE — Envoy with X.509-SVIDs + SPIRE auto-rotation:
  <https://spiffe.io/docs/latest/microservices/envoy/>
