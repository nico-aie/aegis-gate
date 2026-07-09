# BUG — Zero Trust page: console-uploaded WAF client identity never reaches the upstream mTLS dial

- **Type:** Functional bug (upstream mTLS enforcement).
- **Severity:** High — enabling upstream mTLS silently presents **no client cert**
  or the **wrong (stale) on-disk cert**; the dashboard shows `configured: true`,
  masking the failure.
- **Status:** 🟡 open — plan approved 2026-07-09, awaiting implementation.
- **Branch:** `fix/zerotrust-page`.
- **Reporter:** liud (QC, 2026-07-09).
- **Decisions (confirmed):**
  - Console/UI upload is **authoritative** — overrides a boot-YAML `source: file`
    identity (effective source flips to `state`).
  - Must **converge across all cluster nodes** (fleet deploy).

---

## 1. Symptom (QC report)

An operator uploads the WAF client identity (public cert + private key) on the
Zero Trust page and enables mTLS for an upstream pool, but the WAF either presents
**no client cert** or the **wrong (stale) cert** when dialing the backend. The
dashboard says `configured: true`, so it *looks* saved and attached — but the
backend either downgrades to no-client-auth or gets an old on-disk cert, not the
one just uploaded.

## 2. Root cause (code-traced)

The upload **is** persisted (Redis config plane, key `aegis:zt:upstream:identity`),
and the `configured: true` pill is real — but it comes from a **display-only**
rotation-status field, decoupled from enforcement. The uploaded identity only
reaches the live dial path if the **booted/published YAML already declares
`zero_trust.upstream_identity.source: state`**. The console upload writes a
**record** to the state key but never publishes that **declaration** into the
config blob. One missing declaration gates two independent enforcement points,
both keyed on the config blob's declared `source`, never on "does a record exist":

| # | Gate | File:line | Effect when block absent / `source: file` |
|---|------|-----------|-------------------------------------------|
| G1 | `validate_upstream_mtls` — enabling a pool requires `zero_trust.upstream_identity` in the **active config blob** | `crates/aegis-core/src/config.rs:2697-2707` | pool-enable rejected ("none is set in the active config"); with a file block, enable succeeds but see G2 |
| G2 | `materialize_zero_trust_state` (`id_is_state` gate) folds the record's `cert_pem`/`key_pem` into cfg **only** when `source == state` | `crates/aegis-proxy/src/upstream/identity.rs:59-105` | record ignored → `resolve_upstream_mtls` gets no `cert_pem` → **no client cert** (block absent) or **stale on-disk cert** (`source: file`) |
| G2′ | `read_material` (rotation hot-apply) — same `id_is_state` gate | `crates/aegis-proxy/src/upstream/rotation.rs:123-146` | record ignored → never hot-applied |

Supporting facts:
- `handle_zt_upstream_identity_put` stores `UpstreamIdentityRecord{cert_pem,key_pem,key_ref}`
  via `cas_set`, then calls only `notify_identity_updated(cert_pem)` — a
  **display-only** `RotationStatus.identity_cert_pem`, not the pools
  (`crates/aegis-proxy/src/admin_mutate.rs:1627-1702`).
- The GET view prefers that rotation-status PEM, so the page shows `configured:true`
  regardless of whether enforcement ever received it
  (`crates/aegis-proxy/src/admin_get.rs:1292-1322`, `zero_trust/mod.rs:126-139`).
- `resolve_upstream_mtls` is source-agnostic — it uses whatever `cert_pem`/`key_pem`
  are in the materialized `UpstreamIdentityConfig` (`config.rs:3432-3441`).
  **Materialization is the only thing that must happen; there is no third gate.**
- The per-pool "Upload backend cert" control is a *different* concept (backend-CA
  **trust/verify** bundle, `POST /api/zero-trust/upstream/trust/pool-*`) and
  already works via the trust fold. This bug is the **client identity** the WAF
  *presents*.

## 3. Fix — publish the `source: state` declaration on upload (fleet-convergent)

**Core change (fixes G1, G2, G2′ through existing code paths, cluster-safe).**
Extend `handle_zt_upstream_identity_put` (`crates/aegis-proxy/src/admin_mutate.rs:1573`)
so that, after the record `cas_set` succeeds, it **also publishes**
`zero_trust.upstream_identity: { source: state }` into the active config-plane
blob — reusing the pool-upsert pattern:

1. `cas_set` the `UpstreamIdentityRecord` **first** (unchanged) so the material is
   present before any reload materializes it.
2. `let (store, base_blob, expected) = load_active_config_doc(services).await?`
   (already used by `handle_pool_upsert`, `admin_mutate.rs:503`).
3. If the loaded blob's `zero_trust.upstream_identity` is **absent or not
   `source: state`**, patch it to `{ source: state }` (new helper
   `patch_zero_trust_identity_source_state`, mirroring `patch_upstream_pool_set`
   at `admin_mutate.rs:219`; drop any `cert_path`/`key_ref` — materialize ignores
   them for `state`). If already `source: state`, **skip the activate**
   (idempotent; record write + `notify_identity_updated` suffice — rotation picks
   it up).
4. `load_config_str(&new_blob)` to validate, then
   `store.activate(expected, new_blob, &actor, "publish upstream identity (source: state)")`
   inside the existing `mutate.apply_async` audit envelope.

Why this is complete and convergent:
- **G1 passes** — active blob carries the identity block → `validate_upstream_mtls`
  accepts enabling a pool.
- **G2 passes** — `activate` triggers a reload; `materialize_zero_trust_state` runs
  with `source: state`, reads the shared record, folds `cert_pem`+`key_pem`.
- **G2′ / hot-apply** — `rotation::spawn` reads the live `ArcSwap<WafConfig>` every
  tick (`rotation.rs:250`); once the reload swaps in the `source: state` cfg,
  `read_material` reads the record and `registry.apply` rebuilds the pool client
  with the uploaded cert within ~5s — **no restart**.
- **Cluster convergence** — `store.activate` propagates the blob to every node via
  the config-plane convergence watcher, and the identity record is a single shared
  Redis key all nodes read → every node presents the uploaded identity.
- **Console wins over `source: file`** — step 3 overwrites a file declaration with
  `source: state`, so the uploaded material (not the on-disk cert) is presented.

**Ordering / failure-mode note:** keep the record write and the config activate in
one audited outcome. On an activate CAS conflict, return the existing conflict
response; the record is already stored, so a retry only re-publishes the
(idempotent) declaration.

## 4. Robustness fixes (in scope)

- **Rotation fingerprint ignores a rotated key.** `fingerprint`
  (`rotation.rs:184-204`) hashes `cert_pem` + `key_ref` only — **not** inline
  `key_pem`. A new private key with the same cert → same fingerprint → no re-apply
  → old key stays. **Fix:** fold `identity.key_pem` into the hash. (The per-process
  `PoolKey` fingerprint at `config.rs:3451-3461` already hashes the key PEM, so the
  client rebuilds correctly once rotation re-resolves — the miss is only the
  change-detector.)
- **Independent cert/key file fallback (mismatch guard).** `resolve_upstream_mtls`
  (`config.rs:3432-3441`) resolves cert and key **independently**, each with its
  own file fallback → a PEM cert could pair with a stale file key. Latent after the
  core fix (both come from one record), but add a guard: if the cert resolves from
  `CertSource::Pem` the key must too (fail closed with a clear error).

## 5. Files to change

- `crates/aegis-proxy/src/admin_mutate.rs` — `handle_zt_upstream_identity_put`
  (publish `source: state`); new `patch_zero_trust_identity_source_state` helper
  (model on `patch_upstream_pool_set:219`, reuse `load_active_config_doc`).
- `crates/aegis-proxy/src/upstream/rotation.rs` — add `key_pem` to `fingerprint`.
- `crates/aegis-core/src/config.rs` — cert/key source-consistency guard in
  `resolve_upstream_mtls`.
- (Frontend, optional polish) `crates/aegis-control/assets/dashboard/src/pages.jsx`
  — none required for correctness; the `identityReady` gate now aligns with real
  enforcement once the upload publishes. Consider dropping/soft-tuning the LOW-5
  "file-sourced identity — not yet in the active config plane" banner
  (`pages.jsx:7537-7552`), which the fix makes obsolete.

## 6. Verification (end-to-end, real handshake)

1. **Unit/integration (Rust).**
   - After `handle_zt_upstream_identity_put`, the active config blob declares
     `zero_trust.upstream_identity.source == state` and a subsequent
     `handle_pool_upsert` enabling `upstream_mtls` **passes** `validate_upstream_mtls`
     (previously rejected). Cover the `source: file`→`state` override case.
   - `rotation::fingerprint` changes when only `key_pem` changes.
   - `cargo test -p aegis-core -p aegis-proxy -p aegis-control` green.
2. **Live mTLS harness (`tests/mtls/`).** `docker-compose up` the nginx mutual-TLS
   upstream, run `configure-waf.sh`, then `test.sh`. With **no** `zero_trust` block
   in the WAF's boot YAML, uploading the identity via the console API + enabling the
   pool makes the WAF present the **uploaded** client cert (nginx accepts). Before
   the fix this fails (nginx 400 no-cert or wrong-cert). Verify hot-apply (<~5s, no
   restart) and key-only rotation.
3. **Cluster convergence smoke.** With ≥2 nodes on the shared config plane, upload
   on node A; confirm node B's `GET /api/zero-trust/upstream/config` +
   `/upstream/identity` reflect it and node B presents the same cert.

## 7. Out of scope / notes

- Per-pool **client** identity override (`upstream_mtls.client_cert_ref`) stays
  reserved/rejected (`config.rs:2690`) — single shared fleet identity only.
- Storing `key_pem` in the Redis config plane is the **existing** design
  (materialized at boot); unchanged here. Key-at-rest hardening (prefer `key_ref` +
  per-node secret) is a separate ticket — do not block this fix.
- Downstream (client→WAF) mTLS cards are hidden (`SHOW_DOWNSTREAM_MTLS=false`) and
  unaffected.

## Related

- `plans/issues/archived/UX-zero-trust-page-upstream-mtls-flow.md` — prior ZT UX
  pass (stepper, gates, `allow_ca_upload` messaging).
- `plans/issues/archived/UX-zero-trust-page-simplify-per-pool-cert-upload.md` —
  per-pool trust-bundle simplification (different cert concept).
- `docs/security/zero-trust-mtls.md` — feature spec; update the "applies when?" /
  source semantics when this ships.
