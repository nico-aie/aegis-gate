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
docker run -d --name aegis-redis -p 6379:6379 redis:7-alpine \
  redis-server --save "" --appendonly no
```

**Verify:**

```sh
docker exec aegis-redis redis-cli PING        # → PONG
```

> Production: enable TLS + AUTH on Redis and point `state.redis.urls` at the
> TLS endpoint. See [`./GUIDE.md`](./GUIDE.md) production checklist.

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

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Fold returns `400 "publish a baseline via PUT /api/config first"` | Node booted without a file config and no baseline activated. Boot with `--config <file>` or do step 7 once. |
| Fold returns `500 "config plane unavailable: no state backend wired"` | No `StateBackend` at all (shouldn't happen on a normal boot). Check `state:` block parsed. |
| `409 {error: "version_conflict", current: X}` | Optimistic-concurrency conflict — another writer activated between this request's read and its CAS. **Folded toggles** (detectors/rules/tiers/upstreams/AI/response-filter) re-read the version server-side, so just **re-issue the same request** (the dashboard auto-retries these). A **full-doc `PUT /api/config`** carries your stale `expected_version` — re-read `GET /api/config`, rebuild on the new version, resend. |
| Edit doesn't reach other nodes | Confirm `state.backend: redis` (not `in_memory`) on **all** nodes + same `state.redis.urls`. Check `GET /api/config` `.applied[]` for a node stuck on an old version → read its logs for `config_reload_failed` (bad blob → node keeps last-good, fail-static). |
| One node shows an old version forever | Its last activation failed validation; it's serving last-good. Activate a valid version; the node converges. |
| `route-activity` / `hits` still look node-local | `state.backend` is `in_memory` (metrics aggregation is redis-only), or no traffic yet (flush cadence ~10 s). |
| Mutation returns `401` / `403` | Re-run `login`; `$CSRF` empty or stale, or the admin session expired. |

---

## Cross-references

- [`../docs/operations/cluster-config-distribution.md`](../docs/operations/cluster-config-distribution.md) — config-plane design + key/endpoint reference.
- [`../docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md) — cluster topology + LB recipes.
- [`./GUIDE.md`](./GUIDE.md) — production deployment guide.
- [`../config/README.md`](../config/README.md) — full YAML reference (incl. `rules.inline`, `detectors.per_tier`).
