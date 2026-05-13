---
id: 2026-05-12-data-plane-https-client-not-rebuilt-on-hot-reload
date: 2026-05-12T13:10Z
severity: HIGH
area: data-plane
component: upstream client / pool registry
status: open
test_mode: full-qc
---

# Flipping `tls: true` via API PUT on a live pool does NOT rebuild the per-pool HTTP client — the data plane keeps using plain HTTP after hot-reload

## Summary

Even after the dashboard saves `tls: true` (via direct API PUT
to `/api/upstreams/pool/<id>`, 200 OK), the data-plane request
still goes plain HTTP to the upstream. The upstream returns 400
"plain HTTP to HTTPS port".

This is a separate bug from HIGH-RU-01 (which is the dashboard
side). HIGH-RU-02 is the data-plane side: the per-pool upstream
HTTP/HTTPS client is built at pool-construction time and
**not rebuilt** when the pool's scheme/tls flags change via
hot-reload. So even if the operator manually corrects the pool
config after the fact, the running data plane keeps using the
client it built at first construction.

This means the only way to recover today is to **restart the
WAF process**. For a production deployment, that's a service
window — for the dashboard's "audit-mutated, hot-swap, no
restart" claim on every Pool modal subtitle, it's a contract
violation.

## Repro

1. Repeat HIGH-RU-01 repro to create the broken pool.
2. Confirm the 400:
   ```js
   const r = await fetch("/news", {headers: {"X-Forwarded-For": "192.0.2.50"}});
   await r.text()
   // → 400, body has "<title>400 Bad Request</title>" + server "TTTT"
   ```
3. Patch the pool to `tls: true` via API PUT:
   ```js
   const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf=')).split('=')[1];
   const cfg = await (await fetch("/api/upstreams/config", {credentials:"include"})).json();
   const pool = cfg.pools["znews-route"];
   pool.connection.tls = true;
   const r = await fetch("/api/upstreams/pool/znews-route", {
     method: "PUT",
     credentials: "include",
     headers: {"content-type": "application/json", "x-csrf-token": csrf},
     body: JSON.stringify(pool),
   });
   await r.text()
   // → {"ok":true, "pool":"znews-route", "request_id":"..."}
   ```
4. Confirm the config has the new flag:
   ```js
   await (await fetch("/api/upstreams/config", {credentials:"include"})).json()
   // pools["znews-route"].connection.tls === true ✓
   ```
5. Wait 5–10 seconds for hot-reload propagation.
6. Re-request `/news`:
   ```js
   const r = await fetch("/news?t=" + Date.now(), {
     headers: {"X-Forwarded-For": "198.51.100.99"}, cache: "no-store"
   });
   await r.text()
   // → still 400 with the same body
   ```

The hot-reload picked up the config (no boot mutations would land
otherwise), the pool registry has the new `tls: true`, but the
in-process HTTPS client for this pool wasn't rebuilt.

## Expected

After a successful PUT that flips `scheme` or `tls`, the data
plane rebuilds the pool's upstream client. New requests use
TLS. The upstream connection succeeds.

`crates/aegis-core/src/config.rs:955` documents `uses_tls(self,
tls_legacy: bool)` as the canonical gate that drives between
`HttpsConnector` and `HttpConnector` in `build_client`. The
expectation is that this function is called on every connection
build — but in practice it's only called once at pool init.

## Actual

Per-pool HTTP client is cached at pool-construction time and
never re-evaluated against the live `cfg.scheme` /
`cfg.tls`. Operators who hot-edit pool TLS settings observe a
silent "the config says X but the data plane still does Y"
divergence.

## Suggested fix

Three possible shapes, ranked by complexity:

### A (cheap, recommended for v1) — rebuild on `apply()`

In `crates/aegis-proxy/src/upstream/registry.rs`, the
`PoolRegistry::apply(pool)` function (the hot-reload entry
point). After persisting the new `PoolConfig` to the
in-memory registry, drop and rebuild the pool's upstream
HTTP client when `cfg.connection.{scheme, tls}` differ from
the previous values.

```rust
pub fn apply(&self, name: &str, new_cfg: PoolConfig) -> Result<()> {
    let cur = self.pools.get(name).cloned();
    self.pools.insert(name.to_string(), new_cfg.clone());

    let scheme_or_tls_changed = cur
        .as_ref()
        .map(|c| {
            c.connection.scheme != new_cfg.connection.scheme
                || c.connection.tls != new_cfg.connection.tls
        })
        .unwrap_or(true);

    if scheme_or_tls_changed {
        self.clients
            .insert(name.to_string(), build_client(&new_cfg.connection)?);
    }
    Ok(())
}
```

Audit the call sites to make sure no thread is holding a stale
`Arc<Client>` after the swap — `arc_swap` or `RwLock<Arc<…>>`
already handles that correctly.

### B (more thorough) — make `build_client` invocations cheap, build per-request

If `build_client` is cheap enough (no per-call DNS / TLS setup —
just constructor configuration), the data plane can call it on
every request. The hyper Client itself does connection pooling
internally; the outer "build" is mostly enum dispatch. Verify
with a microbench before committing.

### C (architecturally clean) — separate "pool config" from "pool runtime"

Move the upstream HTTP client out of the pool registry into a
`ClientCache` keyed by `(scheme, tls, http2, …)`. When a pool's
connection params change, the registry just looks up a different
cached client. Clients themselves are immutable once built; the
cache evicts on idle TTL.

Pick A for v1; B if benchmarks say the constructor is cheap; C
if there's appetite for a small refactor before the next major.

## Severity rationale

HIGH. The dashboard's Routing & Upstreams page subtitle reads
*"audit-mutated, hot-swap (no restart)"* on every Pool modal —
which is true for membership changes but **false** for scheme/
TLS flips. Operators who edit a pool to fix HIGH-RU-01 today
have to restart the WAF to actually get the fix in effect.

In production: any TLS rotation, scheme change (h2c → grpc
upgrade), or operator-fix to a misconfigured pool requires a
service window. For a tool whose competitive pitch includes
"no restart hot-swap", that's a wart.

Not CRITICAL because the workaround (restart) exists and no
security boundary breaks. But the fix is small (option A is
<30 LoC + a regression test) and the operator confidence
improvement is large.

