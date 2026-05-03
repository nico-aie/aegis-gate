# mTLS support — `MTLS-T*`

> **Status:** **MTLS-T1 + T2 + T3 + T4 (route gate) + T5 +
> T6 + T7 ✅ shipped 2026-05-01 / 2026-05-02.** T4 has 3
> deferred sub-slices (`/admin/login` bypass,
> `AuditEvent.actor` field, identity-rate-limit). T7 (SAN
> allowlist) shipped via `plans/followups-rollback-and-sans.md`
> with live `AllowedSansStore`, GET/PUT/DELETE/test endpoints,
> identity-extraction gate, and Settings-page UI card. T8..T11
> (break-glass, CA upload, per-route editor) remain queued.
> Track ID prefix `MTLS-T<n>`. Adds server-side mutual-TLS to
> a WAF that today supports outbound mTLS only
> (`UpstreamTlsConfig`).

## 0 · Why

The data plane and admin plane today serve TLS via
`with_no_client_auth()` — the rustls handshake never asks the
client for a cert, so the existing `admin_auth::mtls`
SAN-allowlist module is dormant. Operators wanting zero-trust
ingress (cert-pinned admin access, SPIFFE-identified callers,
no-password ops) have no path. This track wires server-side
mTLS through the proxy + identity-extraction stage + per-route
authz + audit chain + UI management.

## 1 · Architecture

```
┌─────────────────────┐
Client ────────▶ │ TLS Termination     │  rustls + WebPkiClientVerifier
                │ (rustls)            │  ✦ MTLS-T2
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Identity Extractor  │  parse SAN / SPIFFE URI from
                │ (SAN / SPIFFE)      │  peer_certificates() leaf
                └─────────┬───────────┘  ✦ MTLS-T3
                          ↓
                ┌─────────────────────┐
                │ WAF Policy Engine   │  per-route auth_required +
                │ rules / authz       │  admin-login mTLS bypass
                └─────────┬───────────┘  ✦ MTLS-T4
                          ↓
                     Backend
```

Identity rides through the request handler the same way
`peer: SocketAddr` does today. `ClientIdentity` is an enum so
adding SPIFFE / JWT / OIDC later doesn't churn the policy
signature.

## 2 · Currently-shipped surface (what we keep)

| Surface | Status | File |
|---|---|---|
| Outbound — WAF → upstream mTLS | ✅ Implemented | `aegis-proxy::upstream::tls::UpstreamTlsConfig` |
| Outbound — etcd / consul / k8s SD client certs | ✅ Implemented | `sd::etcd` / `sd::consul` / `sd::k8s` env vars |
| Inbound — admin SAN-allowlist policy | ⚠️ Pure-function only | `aegis-control::admin_auth::mtls::verify_client_cert` (never called from a real handshake) |
| Inbound — server cert hot-reload | ✅ Implemented | `DynamicResolver::swap` + CC-T cfg-reload |
| Inbound — client-cert verification at handshake | ❌ **None** | `with_no_client_auth()` in `tls_policy.rs` + `tls.rs` + `proto/h2.rs` + `http3.rs` |

## 3 · Slices (smallest first)

Each slice builds on the previous and ships a working surface
on its own. You can stop after any slice.

### MTLS-T1 — Config schema (~30 min, no behaviour change)

**Goal:** introduce types so subsequent slices can land without
churn. Default-deserialised configs see no behaviour change.

```yaml
tls:
  certificates: [...]                # existing
  client_auth:                       # NEW, opt-in
    mode: required                   # disabled | optional | required
    ca_bundle: /etc/aegis/admin-ca.pem
    allowed_sans:                    # optional gate; empty = any signed
      - admin@aegis.local
    apply_to: [admin]                # admin | data; default [admin]
```

**Files**:
- `aegis-core/src/config.rs` — `ClientAuthConfig`, `ClientAuthMode`,
  `ClientAuthScope` types + validation hook.
- `aegis-core/src/identity.rs` (new) — `ClientIdentity` enum
  (`Anonymous`, `Mtls { san, fingerprint, chain_ok }`,
  `Spiffe { uri, td }`). Pure types, no parsers yet.

**Validation**:
- `mode != disabled` requires `ca_bundle` populated.
- `mode != disabled` requires `apply_to` non-empty.

**Tests**: deserialisation matrix (`disabled` default, all 3
modes, both scopes), validation rejection cases, `ClientIdentity`
exhaustiveness (matches all variants).

### MTLS-T2 — Rustls inbound wiring — ✅ shipped 2026-05-01

**Goal:** the listener actually requests + verifies client certs.

**Files**:
- `aegis-proxy/src/listener/tls_policy.rs` — new
  `build_hardened_server_config_with_client_auth(resolver,
  min_version, client_auth)` variant. Builds
  `WebPkiClientVerifier::builder(roots).allow_unauthenticated().build()`
  for `Optional`, `.build()` for `Required`. `Disabled` keeps the
  existing path.
- `aegis-proxy/src/listener/client_trust.rs` (new) —
  `ClientTrustStore` newtype around `Arc<ArcSwap<RootCertStore>>`
  (mirrors `CertStore`).
- `aegis-proxy/src/lib.rs::run` — boot path builds the trust
  store + verifier when `client_auth` is set; threads two
  `TlsAcceptor`s when `apply_to` differs across planes.

**Tests**: handshake passes with valid cert; `mode: required`
rejects missing cert; `mode: optional` accepts both with-cert
and without-cert; bad cert (untrusted CA) rejected in both.

### MTLS-T3 — Identity extraction — ✅ shipped 2026-05-01

**Goal:** populate `ClientIdentity` for every request.

**Files**:
- `aegis-proxy/src/listener/identity.rs` (new) —
  `extract_identity_from_handshake(tls_stream) -> ClientIdentity`.
  Parses leaf cert: URI-SAN starting with `spiffe://` →
  `Spiffe`, otherwise DNS / email / URI SAN → `Mtls`. SHA-256
  fingerprint of the leaf DER for audit.
- `aegis-proxy/src/proxy.rs` — `ProxyContext` carries
  `Arc<ClientIdentity>` per request (similar shape to peer addr).
- `aegis-proxy/src/lib.rs::accept_loop` — calls
  `extract_identity_from_handshake` after `acceptor.accept`,
  threads identity into the per-request handler.

**Tests**: SAN parser matrix (DNS, email, URI-SPIFFE,
multi-SAN cert), fingerprint stability, anonymous fallback when
`allow_unauthenticated` admits a no-cert connection.

### MTLS-T4 — Policy integration — ✅ partially shipped 2026-05-01

> Route-scoped `auth_required: Vec<String>` gate landed
> (rejects anonymous on `/secure/*`-style routes with
> 403 + `mtls_required`). Three sub-slices deferred:
> `/admin/login` mTLS bypass; `AuditEvent.actor` field
> (schema bump — bundle with MTLS-T11); identity-rate-limit
> fan-out (defer until concrete policy).

**Goal:** identity actually gates requests.

**Files**:
- `aegis-control/src/admin_auth/mtls.rs` — wire
  `verify_client_cert` into the `/admin/login` handler. mTLS
  with valid SAN bypasses password; still issues a session +
  CSRF cookie + audit event (`auth_method: mtls`).
- `aegis-core/src/config.rs` — `RouteConfig` gains
  `auth_required: Vec<String>` (default empty, accepts any).
- `aegis-proxy/src/proxy.rs::handle_request` — after route
  resolve, if `route.auth_required` non-empty, gate against
  `req.identity`. Reject with 403 + `actor.kind` audit.
- `aegis-control/src/audit/event.rs` — add
  `actor: ActorIdentity { kind, principal }`. Backfill
  existing audit emit-sites with `Anonymous`.

**Tests**: route with `auth_required: [mtls]` admits cert
client + rejects anonymous; admin-login with valid cert skips
password; admin-login with invalid SAN gets `RejectedSan` audit.

### MTLS-T5 — Hot-reload — ✅ shipped 2026-05-01

**Goal:** rotate CA bundle + SAN allowlist + mode without
restart.

**Files**:
- `aegis-proxy/src/config_source/reload.rs` — new
  `apply_cfg_change_to_client_auth(new_cfg, trust_store)`
  returns `ClientAuthReloadOutcome::{NoStore, Applied { mode },
  SkippedDisabled, Failed { reason }}`. Empty CA bundle in new
  cfg → **skip-not-clear** (mirrors TLS cert pattern, keeps
  live trust live).
- Both watchers (file + etcd) call helper after `tls_reloaded`.
  Emits `mtls_reloaded` / `mtls_reload_failed`.

**Tests**: rotate CA → live trust swaps; rotate to bad CA →
old trust stays + `mtls_reload_failed` event.

### MTLS-T6 — Console observability (Tier 1, ~3-4 h)

**Goal:** read-only management surface — operators see who's
connecting via mTLS without changing anything.

**Endpoints**:
- `GET /api/mtls` — current cfg snapshot.
- `GET /api/mtls/connections` — sliding-window
  `[{san, last_seen, request_count, decision_breakdown}]` from
  a new `IdentityTracker` (sibling to `RiskTracker`).
- `GET /api/mtls/failures` — handshake failure counter grouped
  by reason.
- `GET /api/mtls/ca-summary` — loaded CA subjects + fingerprints
  + expiry. **Never the raw PEM bytes.**

**Files**:
- `aegis-control/src/identity_tracker.rs` (new) — sliding
  window per-SAN tracker.
- `aegis-control/src/api/mtls.rs` (new) — read handlers.
- `aegis-control/src/metrics/mtls.rs` (new) — handshake-failure
  counter (already designed in `metrics/`).
- `assets/dashboard/src/pages.jsx::PageMtls` — three cards:
  identity table, failure histogram, CA bundle status.

**Tests**: handlers emit shape that matches OpenAPI (extends
`api.openapi.yaml` by ~4 paths). Live identity tracker
sliding-window correctness.

### MTLS-T7 — Console mutation, SAN allowlist (Tier 2, ~2 h)

`PUT /api/mtls/sans` (whole-list replace) +
`DELETE /api/mtls/sans/{san}` + `POST /api/mtls/sans/{san}/test`.
Audit-mutated via the same pipeline as alert receivers
(CC-T2.1.b). UI gains an "Allowed SANs" card on the mTLS page.

### MTLS-T8 — Console mutation, mode toggle (Tier 3, ~2 h)

`PUT /api/mtls/mode` with confirm gate UI:
- `disabled → optional` — single-click.
- `disabled → required` / `optional → required` — type-CONFIRM
  modal showing how many active sessions / SANs would lose
  access.
- `required → disabled` — also type-CONFIRM.

### MTLS-T9 — Break-glass + session/mTLS coexistence (~1 h, lands with T8)

**Boot-time `AEGIS_MTLS_BREAK_GLASS=1`** env var: downgrades
admin plane to `optional` for the boot session, log loudly to
stderr + audit chain every 60 s. **Boot-only** — runtime
override would defeat the purpose.

**Session/mTLS coexistence on the dashboard origin**: a session
cookie *without* a cert is admitted on the dashboard origin
specifically (transition window bounded by session TTL). Other
origins enforce strict `required`.

### MTLS-T10 — Console mutation, CA bundle upload (Tier 4, opt-in, ~3 h)

> **Status:** Phase 1 (parse + preview + audit) ✅ shipped at
> `24ab3f9`. Phase 2 (live hot-swap) ✅ shipped at the commit
> alongside this paragraph.

Gated behind a feature flag (`cfg.dashboard.allow_ca_upload`)
because some operators run trust anchors through GitOps and
don't want them mutable from a browser. `PUT /api/mtls/ca-bundle`
multipart-uploads PEM, validates parse + future expiry,
**previews affected SANs** before commit, audit chain captures
diff (subjects + fingerprints, never raw bytes).

**Phase 2 — hot-swap (`?apply=true`):**
- `PUT /api/mtls/ca-bundle?apply=true` swaps `RootCertStore` via
  `ClientTrustStore::swap_pem`; new `WebPkiClientVerifier`
  instances see the new roots immediately, in-flight handshakes
  complete on the old store.
- `TrustAnchorWriter` trait in `aegis-control::api::mtls_ca_bundle`
  is the boundary that lets the audit-mutated handler call into
  the live store without `aegis-control → aegis-proxy` circularity.
- Audit emits `mtls_ca_bundle_swapped` with before/after preview
  + diff (added/removed/kept counts), no raw bytes.
- 409 when no live trust store (proxy booted without inbound
  mTLS); 403 when feature flag is off; 400 on invalid PEM with
  the rustls reason surfaced.

### MTLS-T11 — Per-route `auth_required` editor (Tier 5, free with route editor, ~30 min)

Existing CC-T1.2 route editor gains a multi-select for
`auth_required`. Reuses `PUT /api/upstreams/config` mutation
path. Route table rebuild on hot-reload picks up the new field
automatically.

### MTLS-T12 — Tests + docs (~2 h, lands continuously across the track)

End-to-end tests:
- `tests/api/mtls-handshake.sh` — `mode: required` rejects
  no-cert, accepts valid cert.
- `tests/api/mtls-admin-login.sh` — cert bypasses password +
  audit captures `auth_method: mtls`.
- `tests/api/mtls-route-authz.sh` — `auth_required: [mtls]`
  rejects anonymous with 403.
- `tests/api/mtls-rotate-ca.sh` — rotate CA via UI, observe
  swap + new cert admitted.

Operator docs: `docs/security/mtls.md` covering deployment
story (issuing operator certs, rotating CAs, break-glass
recovery, SPIFFE migration path).

## 4 · Out of scope (queued for later)

- **CRL / OCSP revocation** — `WebPkiClientVerifier` doesn't do
  CRL. Custom verifier or external check. Separate track.
- **Full SPIRE workload-API integration** — SVID rotation,
  trust-bundle fetch, federation. SPIFFE-via-URI-SAN gives 80%
  of the value with 5% of the code; full SPIRE only when there's
  customer demand.
- **Mutual cert pinning by fingerprint** — beyond SAN-allowlist
  (some ops want to pin specific cert hashes). Trivial to add
  alongside `allowed_sans`.

## 5 · Operator footguns (designed-out)

- **`disabled → required` lockout**: confirm gate in T8 + boot
  break-glass in T9.
- **Browser-uploaded CA bundle injection**: T10 opt-in, audit
  the diff (no raw bytes).
- **Hot-reload of CA bundle that drops the operator's issuing
  CA**: T7 `POST /test` endpoint lets operators preview their
  own SAN admission before flipping mode.

## 6 · Tracks-in-flight order

`MTLS-T1` → `MTLS-T6` (read-only first, no mutation risk) →
`MTLS-T2` (rustls wiring lights up T6's data) → `MTLS-T3` →
`MTLS-T4` → `MTLS-T5` (hot-reload, mirrors CC-T pattern) →
`MTLS-T11` (routes free-rider) → `MTLS-T7` (SAN list) →
`MTLS-T9` (break-glass before next mutation slice) →
`MTLS-T8` (mode toggle) → `MTLS-T10` (CA upload, opt-in last) →
`MTLS-T12` (tests + docs land continuously).
