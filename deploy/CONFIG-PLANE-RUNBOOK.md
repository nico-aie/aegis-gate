# Aegis-Gate — Config Plane Deploy & Operate Runbook

Mechanical, step-by-step runbook for the **cluster config plane** and the
features that ride on it (folded console toggles, durable inline rules,
cluster-wide metrics, single-VIP load balancing). Written so an AI assistant
can drive it: every step has a copy-paste command and a deterministic
**Verify** check.

- New to deploying this WAF at all? Start with
  [`./STAGING-BENCHMARK.md`](./STAGING-BENCHMARK.md) (single Linux box) or
  [`./GUIDE.md`](./GUIDE.md) (production topology), then come back here.
- Design + semantics reference:
  [`../docs/operations/cluster-config-distribution.md`](../docs/operations/cluster-config-distribution.md).

---

## What the config plane gives you

A console edit on **any** node (detector toggle, tier threshold, rule CRUD,
upstream pool, AI on/off, response-filter rungs) is written to a shared,
versioned config document and **converges on every node within ~3 s**, and
**survives restart + leader failover**. Before this, a `PUT` mutated only the
serving node's RAM and was lost on restart.

| Capability | `state.backend: in_memory` (1 node) | `state.backend: redis` (N nodes) |
|---|---|---|
| Console edits persist across restart | ❌ (in-process only) | ✅ (`config:waf:doc`) |
| Edits propagate to other nodes | n/a | ✅ (~3 s watcher poll) |
| Durable inline rules (`rules.inline`) | ✅ (in doc) | ✅ + fleet-wide |
| Cluster-wide metrics (route-activity / list-hits) | ❌ (local rings) | ✅ |

---

## 0 · Prerequisites

```sh
# A release binary built with redis (multi-node) — the Makefile default
# already includes it; explicit form:
cargo build -p aegis-bin --release --features "redis geoip alerts ai affinity"
# → target/release/waf

# Tools this runbook uses
command -v curl jq docker   # jq optional but assumed in Verify blocks
```

Decide your topology:

- **Single node** → `state.backend: in_memory`. The config plane still works
  (edits persist in-process for the process lifetime; folds + `PUT /api/config`
  function). Cluster metrics aggregation stays off. Skip step 1.
- **Multi node** → `state.backend: redis`. Do every step.

---

## 1 · Shared state backend (multi-node only)

```sh
# Dev / throwaway ONLY — persistence OFF (see the durability note below).
docker run -d --name aegis-redis -p 6379:6379 redis:7-alpine \
  redis-server --save "" --appendonly no
```

**Verify:**

```sh
docker exec aegis-redis redis-cli PING        # → PONG
```

> ⚠️ **Durability — enable AOF persistence in production.** The shared config
> document (`config:waf:doc`) — every runtime-added pool, route, rule, and
> toggle — lives in this Redis. With persistence **off** (the dev command
> above), a Redis restart comes back **empty** and each node silently reverts
> to its on-disk boot config (`*.yaml`), **dropping all runtime-added
> pools/routes** — a protected backend's route can vanish with no outage on
> the surviving routes. Run production Redis with AOF:
>
> ```sh
> redis-server --appendonly yes --appendfsync everysec
> ```
>
> The WAF defends in depth regardless: it persists a local last-known-good
> version marker next to each node's boot config and, when it detects the
> store came back empty after a version had been applied, emits a
> `config_store_reverted_to_baseline` audit event and flips
> `/healthz/ready` → `checks.config_store_degraded: true` (status `degraded`,
> still HTTP 200 — the node keeps serving the baseline). Treat that flag as a
> page: re-apply config from a `waf` snapshot or the dashboard. But AOF is the
> primary fix — keep it on.

> Production: also enable TLS + AUTH on Redis and point `state.redis.urls` at
> the TLS endpoint. See [`./GUIDE.md`](./GUIDE.md) production checklist.

---

## 2 · Node config (the config-plane knobs)

Each node needs **(a)** a shared backend, **(b)** a stable `node.id`, and
**(c)** a boot config **file** so the node can seed version 0 of the shared
document on the first edit. `config/cluster-a.yaml` + `config/cluster-b.yaml`
are ready-made; the only fields that matter here:

```yaml
node:
  id: "waf-a"            # MUST be unique + stable per node (e.g. ${POD_NAME})

state:
  backend: redis         # `in_memory` for a single node
  redis:
    urls: ["redis://127.0.0.1:6379"]
    pool_size: 8
    timeout: "1s"
```

**Verify the file is loadable before boot** (catches typos + compliance
conflicts):

```sh
target/release/waf validate --config config/cluster-a.yaml   # → config OK
```

> **Why a file config matters:** a folded console edit (e.g. `PUT /api/detectors`)
> seeds `config:waf:doc` version 0 from this file the first time. On an
> etcd/static boot with no file and no prior baseline, folds return
> `400 "publish a baseline via PUT /api/config first"` (see step 6).

---

## 3 · Boot the nodes + confirm the plane is live

```sh
target/release/waf run --config config/cluster-a.yaml &   # data :8080 admin :9443
target/release/waf run --config config/cluster-b.yaml &   # data :8090 admin :9543
```

**Verify each node is ready** (`/healthz/*` is open — no auth):

```sh
curl -fsS http://127.0.0.1:9443/healthz/ready && echo " A ready"
curl -fsS http://127.0.0.1:9543/healthz/ready && echo " B ready"
```

The shared-store config watcher logs `shared-store config watcher started` at
boot on every node (in_memory: harmless no-op until something writes the doc).
The cluster roster (`/api/cluster`) + config-plane status (`/api/config`) need
admin auth — verified in step 4.

---

## 4 · Authenticate

Every `/api/*` endpoint needs admin auth (`/healthz/*` is open). Two methods,
each best at one job:

- **Bearer token — reads, any node.** A service-account token authenticates
  `GET`s on every node with no per-node login and no CSRF. Use it for all the
  verify/read steps below.
- **Login cookie + CSRF — writes.** Mutations (`PUT`/`POST`/`DELETE`) are
  CSRF-gated; a bearer-only write is rejected with `csrf_missing_cookie`. Log in
  to the node you're writing to, keep its cookie jar, and echo the `aegis_csrf`
  cookie as the `x-csrf-token` header.

**One-time: mint a read/write token and wire it into every node's config.**

```sh
target/release/waf admin service-account mint --name ops --scopes read,write
# Prints the token (save it) + a fragment. Paste the fragment under
# cfg.admin.dashboard_auth.service_accounts in EACH node's config (same
# token_hash on all nodes so one token works fleet-wide), then restart:
#
#   admin:
#     dashboard_auth:
#       service_accounts:
#         - name: "ops"
#           token_hash: "$argon2id$...."     # from the mint output
#           scopes: ["read", "write"]
export TOKEN="<token from the mint output>"
apiget() { curl -fsS -H "authorization: Bearer $TOKEN" "$@"; }   # reads, any node
```

**For writes, log in to the target node** (single-user admin name is `admin`;
password = what you hashed into `password_hash_ref`, see `waf admin set-password`):

```sh
login() {  # Usage: login <admin_base_url>
  curl -fsS -c /tmp/aegis-cookies.txt -X POST "$1/admin/login" \
    -H 'content-type: application/json' \
    -d '{"user":"admin","password":"'"$AEGIS_ADMIN_PASSWORD"'"}'   # add "totp_code":"…" if TOTP enabled
  CSRF=$(awk '$6=="aegis_csrf"{print $7}' /tmp/aegis-cookies.txt); export CSRF
}
login http://127.0.0.1:9443
admin() { curl -fsS -b /tmp/aegis-cookies.txt -H "x-csrf-token: $CSRF" "$@"; }  # writes
```

**Verify auth + cluster + config-plane status:**

```sh
apiget http://127.0.0.1:9443/api/cluster | jq '{our_node, is_leader, peers: [.peers[].id]}'
apiget http://127.0.0.1:9443/api/config | jq .   # → {version, applied:[], backend:true} pre-edit
echo "CSRF present: $([ -n "$CSRF" ] && echo yes || echo NO)"
```

---

## 5 · Make a console edit → watch it propagate fleet-wide

This is the core demonstration. Make an edit on **node A** and confirm **node
B** converges without touching B. We use a rule create — it's unconditional
(no feature gate), the body is simple, and it doubles as the durable-inline-
rules demo (step 6).

```sh
# Create a rule via node A.
admin -X POST http://127.0.0.1:9443/api/rules \
  -H 'content-type: application/json' \
  -d '{"id":"demo-1","body":"- id: demo-1\n  priority: 100\n  when: true\n  then: log_only\n","enabled":true}' | jq
# → { "ok": true, "id": "demo-1", "version": <n>, "note": "config activated; propagates ..." }
```

**Verify propagation (read node B, which you never edited):**

```sh
sleep 4    # one watcher poll (~3 s) + margin
# Drift view: active config-plane version + each node's applied version.
# Both nodes should converge to the same `version`.
apiget http://127.0.0.1:9543/api/config | jq '{version, applied}'
# → { "version": <n>, "applied": [ {"node":"waf-a","version":<n>}, {"node":"waf-b","version":<n>} ] }
# The rule is now live on B too (read B with the bearer token — no login to B):
apiget http://127.0.0.1:9543/api/rules | jq '[.rules[].id]'   # includes "demo-1"
```

Every folded surface propagates the same way — `PUT /api/ai/enabled`,
`PUT /api/response-filter`, `PUT /api/tiers/{name}`, `PUT /api/detectors`,
`PUT /api/upstreams/config` (+ `…/pool/{id}`). **Note:** the detector-mask and
response-filter PUT bodies are **full-state replaces**, not partial patches —
the dashboard always sends the complete shape (a body of `{"recon":false}`
deserialises with every *other* class defaulting to `false`, i.e. it disables
them all). Send the full mask, or use the dashboard, for targeted changes.

---

## 6 · New config: inline rules are durable (survive restart)

`rules.inline[]` is the new persistent rule list — rules now live in the
config document, so they survive a restart and propagate fleet-wide. Before
this they were ephemeral + node-local (lost on restart). Confirm the `demo-1`
rule from step 5 outlives a restart of the node that created it:

```sh
# Restart node A (kill + re-run), then read it back.
# (systemd: `systemctl restart aegis-gate`. Foreground: kill the PID, re-run.)
sleep 4   # node A re-applies config:waf:doc on boot (rules seed from the doc, not the file)
apiget http://127.0.0.1:9443/api/rules | jq '[.rules[].id]'   # still includes "demo-1"
```

Toggle / update / delete propagate the same way
(`POST /api/rules/{id}/toggle`, `PUT /api/rules/{id}`, `DELETE /api/rules/{id}`).

> The equivalent **static** form for a fork-and-commit workflow is to put the
> rules straight in the YAML:
> ```yaml
> rules:
>   inline:
>     - id: block-internal-ua
>       body: "- id: block-internal-ua\n  priority: 100\n  when: true\n  then: log_only\n"
>       enabled: true
> ```
> `rules.paths` is unchanged and feeds only the backup/snapshot tooling — it is
> **not** loaded into the live engine.

---

## 7 · Full-document activation + rollback

For a bulk change (or GitOps push of a whole `waf.yaml`), activate the full
document with optimistic concurrency:

```sh
# 1. Read the current version.
VER=$(apiget http://127.0.0.1:9443/api/config | jq -r '.version // 0')
# 2. Activate a new full config (blob = the entire WafConfig YAML).
admin -X PUT http://127.0.0.1:9443/api/config \
  -H 'content-type: application/json' \
  -d "$(jq -n --arg blob "$(cat config/cluster-a.yaml)" --argjson v "$VER" \
        '{expected_version:$v, blob:$blob, summary:"bulk update via runbook"}')" | jq
# → 200 {version: V+1}   OR   409 {current: X}  (someone else activated first → re-read + retry)
```

**Rollback** to an earlier known-good version (re-applies that version's content
as a **new** version — the chain only moves forward, so an audit trail is kept):

```sh
admin -X POST http://127.0.0.1:9443/api/config/rollback \
  -H 'content-type: application/json' -d '{"target_version": 1}' | jq
# → { "ok": true, "rolled_back_to": 1, "version": <new, e.g. 3> }
```

**Verify:** `GET /api/config` `.version` reflects the new (post-rollback)
version and every entry in `.applied[]` matches it within ~3 s.

---

## 8 · Cluster-wide metrics (Phase C — redis only)

With `state.backend: redis`, per-route activity and access-list hit counts are
flushed to shared counters and the dashboard endpoints return a **fleet-wide
sum** instead of one node's slice. No config knob — it activates automatically
when the backend isn't `in_memory`.

**Verify** (drive a little traffic through both nodes, then read either node):

```sh
# Drive traffic through BOTH nodes' data ports, then wait one flush cycle (~10 s).
for i in $(seq 1 10); do curl -s -o /dev/null http://127.0.0.1:8080/; done   # node A
for i in $(seq 1 40); do curl -s -o /dev/null http://127.0.0.1:8090/; done   # node B
sleep 12
# Either node now reports the CLUSTER-WIDE sum (≈50), not its local slice (10 or 40):
apiget http://127.0.0.1:9443/api/analytics/route-activity | jq -c '.routes[] | {route, last_60s_count}'
apiget http://127.0.0.1:9543/api/analytics/route-activity | jq -c '.routes[] | {route, last_60s_count}'
# Cluster-wide blacklist-entry hit counts (1 h window):
apiget 'http://127.0.0.1:9443/api/blacklist/hits?window=3600' | jq
```

Both nodes `INCRBY` into one key per `(time-bucket, id)`, so a single key holds
the fleet total — confirm directly:

```sh
redis-cli --scan --pattern 'waf:route:*'   # → waf:route:<bucket_ts>:catch-all
redis-cli GET waf:route:<bucket_ts>:catch-all   # → 50
```

Keys are TTL'd (`waf:route:*`, `waf:hits:bl:*`, `waf:hits:wl:*`); sustained
backend errors emit a `metrics_flush_failed` audit event while the local rings
keep serving.

---

## 9 · Single VIP in front of the fleet (Phase D — HAProxy)

The reference HAProxy LB ships ready to use. It health-checks the **admin**
port and balances the **data** port across nodes behind one VIP.

```sh
# Brings up the aegis-lb HAProxy container (compose `ha` profile).
docker compose -f deploy/docker-compose.dev.yml --profile ha up -d aegis-lb
```

**Verify the VIP serves + both backends get traffic:**

```sh
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9180/   # VIP (plaintext)
curl -fsS 'http://127.0.0.1:8404/;csv' | awk -F, '$1=="cluster_http"{print $2,$8}'  # per-backend stot
```

The full single-VIP RPS benchmark (k6 at the VIP, asserts both backends
served ≥ 15 %) is `tests/cluster/05-single-vip-baseline.sh`. On Kubernetes the
equivalent is the Helm chart's data-plane `Service.type: LoadBalancer` + ≥ 2
replicas — no HAProxy sidecar needed.

---

## 10 · Zero Trust upstream mTLS (shared fleet identity + trust bundles)

The WAF dials backends with **one shared client cert** (the fleet identity) and
verifies each backend against an uploaded **trust bundle**. The PUBLIC cert +
bundles distribute through the config plane; **the private key never does**
(reference-only — it stays a `key_ref`). Full feature:
[`../docs/security/zero-trust-mtls.md`](../docs/security/zero-trust-mtls.md).

Enable the capability on **every** node and point the identity at the plane:

```yaml
admin:
  dashboard_auth:
    allow_ca_upload: true          # gate for cert mutation (off by default)
zero_trust:
  upstream_identity:
    source: state                  # PUBLIC cert + key_ref come from the config plane
```

```sh
# Store the shared identity (PUBLIC cert + a key reference — never the key bytes).
curl -fsS -X PUT "$ADMIN/api/zero-trust/upstream/identity" -b "$JAR" -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/json' \
  -d "{\"cert_pem\": $(jq -Rs . < waf-client.pem), \"key_ref\": \"\${secret:env:WAF_UPSTREAM_KEY}\"}"

# Upload a backend CA as a named trust bundle (raw PEM body).
curl -fsS -X POST "$ADMIN/api/zero-trust/upstream/trust/payments-ca" -b "$JAR" -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/x-pem-file' --data-binary @payments-ca.pem

# Enable mTLS on a pool (round-trips the whole pool — fetch, patch upstream_mtls, PUT).
#   …or just use the Zero Trust page → Upstream mTLS by Pool → Edit drawer.
```

- **Fail-closed:** `source: state` with no stored identity (or a corrupt record)
  **aborts boot** — nodes refuse to dial backends without client auth. Store the
  identity *before* rolling `source: state`.
- **Hot rotation (no restart).** Activation is fleet-wide via `cas_set`, and every
  node's reconcile task (≈5 s) re-seeds + re-applies on a change — the new cert is
  presented within a tick, in-flight requests finish on the old client, **no
  dropped connections**. Watch `GET /api/zero-trust/upstream/rotation` (generation
  bumps) or the console's "live · rotated ×N" badge. (File-source identities still
  rotate by swapping the file + reload.)
- **Delete is ref-checked:** a trust bundle a pool still references returns `409`
  (`{error:"bundle_in_use", pools:[…]}`). Disable the pool's `upstream_mtls`
  first.
- Watch `GET /api/zero-trust/upstream/failures` (or the console card) after
  cut-over: `untrusted_backend_cert` ⇒ wrong/missing trust bundle;
  `cert_expired` ⇒ rotate; `client_identity_error` ⇒ identity cert/key unreadable.

---

## 11 · etcd config plane (optional — durable consensus store) — H2b

By default the durable config document (`config:waf:doc` + version snapshots +
the control plane `control:waf:*`) rides the **shared state backend** (Redis):
`config_plane.store: shared_state`. That couples config durability to correct
Redis AOF/RDB provisioning — a Redis restart without persistence returns an
**empty** config doc and the node reverts to its file baseline.

`config_plane.store: etcd` instead keeps **only the config + control plane** on
a dedicated etcd cluster (durable-by-design Raft, native Watch/Txn/Lease). The
hot-path ephemeral keyspace (rate-limit / risk / nonce / auto-block /
smart-cache L2) **never moves** — `state.backend: redis` stays mandatory. etcd
is *additive for config durability*, not a Redis replacement.

```yaml
config_plane:
  store: etcd                # default: shared_state
  etcd:
    endpoints: ["http://etcd-1:2379", "http://etcd-2:2379"]
```

**Build requirement.** etcd support is behind a default-off cargo feature
(distinct from the `etcd` *service-discovery* feature):

```sh
# protoc is required at build time (gRPC codegen): `brew install protobuf`
# or `apt-get install -y protobuf-compiler`.
cargo build -p aegis-bin --release --features "redis etcd_config"
```

A binary built **without** `etcd_config` that boots `store: etcd` **fails loud**
at startup (it does not silently fall back) — rebuild with the feature, or set
`store: shared_state`.

### Cutover (Redis → etcd), zero data loss

The migration is a **copy**, not a move — Redis keeps its keys, so rollback is
just flipping the knob back.

```sh
# 1. Stage the etcd endpoints in each node's config (still store: shared_state):
#      config_plane:
#        store: shared_state          # not flipped yet
#        etcd:
#          endpoints: ["http://etcd-1:2379"]
#
# 2. Copy the live config + control plane into etcd and VERIFY (idempotent,
#    safe to re-run). Reads the Redis source from state.backend, the etcd
#    dest from config_plane.etcd.endpoints:
target/release/waf migrate-config-plane --config config/cluster-a.yaml
#    → report: source active version : N
#              active doc copied     : true
#              version snapshots     : N
#              control-plane keys    : K
#              verified              : true     ← required to proceed
#    Exits non-zero (do NOT cut over) if verification fails or the source is empty.
#
# 3. Flip store: etcd on every node and restart. Confirm the boot log:
#      "config plane store selected store=etcd ..."
#      "interop: etcd native control-plane watch enabled ..."   (multi-node)
#
# 4. Confirm the fleet converged on the same version (as in step 5):
#      curl -s :9443/api/config -H "authorization: Bearer $TOKEN" | jq '.version, .applied'
```

Under `store: etcd` **both** planes ride etcd: config doc activations
(`PUT /api/config`, folded toggles) and control-plane convergence
(`set_profile` / `reset_state` / operator access-lists) — with no Redis pub/sub
nudge needed (etcd's native Watch delivers changes directly).

### Rollback to Redis

The cutover copies rather than moves, so Redis still holds the pre-cutover doc.
Config edits made *after* cutover land only in etcd, so re-run the migration in
reverse intent before rolling back if you want them preserved (or simply
re-activate them). To roll back: set `config_plane.store: shared_state` on every
node and restart — the nodes read `config:waf:doc` from Redis again.

> **Operational note.** etcd matters at the scale where config durability is
> worth a second dependency (and for multi-region later). A single-node /
> in-memory deployment gains little — keep `shared_state` there.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Fold returns `400 "publish a baseline via PUT /api/config first"` | Node booted without a file config and no baseline activated. Boot with `--config <file>` or do step 7 once. |
| Boot aborts: `upstream_identity.source: state but no identity is stored` | Store the shared identity (step 10) **before** rolling `source: state`. Fail-closed by design. |
| Pool PUT `400 "… is not an uploaded backend-CA bundle"` | The pool's `upstream_mtls.trust` names a bundle that isn't uploaded. Upload it first, or set `trust` to a CA file path. |
| Upstream handshake failures after enabling mTLS | Check the failure histogram reason: untrusted_backend_cert (trust bundle) / cert_expired (rotate) / san_mismatch / client_identity_error (WAF cert/key). |
| Rotated a cert but nodes still present the old one | Give it one reconcile tick (≈5 s) and check `GET /api/zero-trust/upstream/rotation` `generation` bumped. File-source identities don't hot-rotate — swap the file + reload. A node on `in_memory` can't bootstrap `source: state` (use `redis`). |
| Fold returns `500 "config plane unavailable: no state backend wired"` | No `StateBackend` at all (shouldn't happen on a normal boot). Check `state:` block parsed. |
| `409 {error: "version_conflict", current: X}` | Optimistic-concurrency conflict — another writer activated between this request's read and its CAS. **Folded toggles** (detectors/rules/tiers/upstreams/AI/response-filter) re-read the version server-side, so just **re-issue the same request** (the dashboard auto-retries these). A **full-doc `PUT /api/config`** carries your stale `expected_version` — re-read `GET /api/config`, rebuild on the new version, resend. |
| Edit doesn't reach other nodes | Confirm `state.backend: redis` (not `in_memory`) on **all** nodes + same `state.redis.urls`. Check `GET /api/config` `.applied[]` for a node stuck on an old version → read its logs for `config_reload_failed` (bad blob → node keeps last-good, fail-static). |
| One node shows an old version forever | Its last activation failed validation; it's serving last-good. Activate a valid version; the node converges. |
| `route-activity` / `hits` still look node-local | `state.backend` is `in_memory` (metrics aggregation is redis-only), or no traffic yet (flush cadence ~10 s). |
| Mutation returns `401` / `403` | Re-run `login`; `$CSRF` empty or stale, or the admin session expired. |
| Boot aborts: `config_plane.store = etcd but this binary was built without the etcd_config feature` | Rebuild with `--features "redis etcd_config"` (needs `protoc`), or set `config_plane.store: shared_state`. Fail-closed by design — no silent fallback. |
| Boot aborts: `config_plane.store = etcd requires config_plane.etcd.endpoints` | Add at least one endpoint under `config_plane.etcd.endpoints`. |
| `migrate-config-plane` prints `verified: false` / non-zero exit | Empty source (wrong source store?) or the dest doc didn't read back at the source version. Do **not** flip `store: etcd`; investigate, then re-run (it's idempotent). |
| After `store: etcd`, edits don't survive a Redis restart but config is intact | Expected — the config doc now lives in etcd; Redis only holds the ephemeral hot path. |

---

## Cross-references

- [`../docs/operations/cluster-config-distribution.md`](../docs/operations/cluster-config-distribution.md) — config-plane design + key/endpoint reference.
- [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) — cluster topology + LB recipes.
- [`../docs/security/zero-trust-mtls.md`](../docs/security/zero-trust-mtls.md) — Zero Trust mTLS (both directions), used in step 10.
- [`./GUIDE.md`](./GUIDE.md) — production deployment guide.
- [`../config/README.md`](../config/README.md) — full YAML reference (incl. `rules.inline`, `detectors.per_tier`).
- [`../plans/future/config-etcd-source-of-truth.md`](../plans/future/config-etcd-source-of-truth.md) — the etcd config-plane design (§11 above is the operate guide).
