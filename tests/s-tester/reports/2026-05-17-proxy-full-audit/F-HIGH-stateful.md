---
id: 2026-05-17-high-stateful-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: TLS lifecycle · upstream · service discovery · secrets · state
component: crates/aegis-proxy/src/{acme.rs,ocsp.rs,upstream/forward.rs,upstream/tls.rs,sd/*,secrets/vault.rs,state/in_memory.rs,config_source/reload.rs}
interop_contract: Round 1 stability · README feature claims · §3 timeout action
status: open
test_mode: source-review
---

# F-HIGH-stateful bundle — 7 issues in stateful subsystems

---

## S-01 · Upstream HTTPS client uses webpki roots only — private/internal CAs unsupported despite README claim

**Component:** [upstream/forward.rs:273-285](../../../../crates/aegis-proxy/src/upstream/forward.rs#L273-L285)

The pooled `Client` cache builds rustls `ClientConfig` with
`with_webpki_roots()` only. The dedicated
`upstream/tls.rs::build_upstream_client_config` function knows how
to load operator-supplied `ca_bundle` + mTLS client cert — but it is
NEVER called from the pooled client path. Operators with private-CA
backends (internal services, K8s ingress with self-signed,
service-mesh sidecars) cannot use upstream TLS through the WAF.

This contradicts the README's claim of upstream mTLS support.

**Fix:** thread `UpstreamTlsConfig` into the `PoolKey` cache key
and into `pooled_client` so per-pool TLS settings (CA bundle, mTLS
identity, ALPN, SNI override) actually take effect.

---

## S-02 · Service-discovery watchers (k8s / etcd / consul) exit permanently on 401/403

**Component:** [sd/k8s.rs:169-170](../../../../crates/aegis-proxy/src/sd/k8s.rs#L169-L170) · [sd/etcd.rs:175-176](../../../../crates/aegis-proxy/src/sd/etcd.rs#L175-L176) · [sd/consul.rs:140-143](../../../../crates/aegis-proxy/src/sd/consul.rs#L140-L143) · [config_source/etcd_source.rs:506-508](../../../../crates/aegis-proxy/src/config_source/etcd_source.rs#L506-L508)

On any 401 / 403 response from the discovery backend, the watcher
task returns `Err(...)` and the spawned task exits permanently.
Routine events trigger this:

- k8s SA token rotation (the projected token has a ~hour TTL).
- etcd password rotation.
- Brief ACL hiccup during a leader election.
- Vault token expiry, if the operator wires a Vault-backed
  bootstrap secret for the etcd password.

After exit, the WAF freezes service discovery silently. The upstream
pool stays at whatever member list was current when the watcher
died; new K8s endpoints / new etcd values / new Consul instances are
invisible. Until the WAF is restarted.

**Fix:** on 401/403, log + back-off (exponential, max ~60 s), then
re-authenticate. For k8s specifically, re-read
`/var/run/secrets/kubernetes.io/serviceaccount/token` so the new
projected token is picked up.

---

## S-03 · ACME renewal has no rate-limit backoff — Let's Encrypt 429 → tight retry storm

**Component:** [acme.rs:347-370](../../../../crates/aegis-proxy/src/acme.rs#L347-L370) + [acme_instant.rs](../../../../crates/aegis-proxy/src/acme_instant.rs)

The renewal scheduler calls `manager.issue()` and logs failures with
"will retry next cycle". Cycle minimum is 60 s. Let's Encrypt has
hard rate limits (300 new orders / account / 3 h; 5 duplicate
certificates per 7 days, etc.). When the WAF hits a limit, the ACME
server returns 429 with `urn:ietf:params:acme:error:rateLimited` +
`Retry-After`; the WAF ignores it and retries every 60 s.

This is a self-imposed account ban — Let's Encrypt may revoke ACME
access for repeated abuse.

**Fix:** parse the ACME error type. On `rateLimited`, switch to
exponential backoff starting at `Retry-After` (if present) or
~30 min. Persist the backoff state to disk so a restart doesn't
reset it.

Also: [acme.rs:317-326](../../../../crates/aegis-proxy/src/acme.rs#L317-L326) `needs_renewal` returns `true` on parse
failure (fail-open over-renew). Combined with the rate-limit issue,
a corrupted cert at `cert_dir` triggers continuous re-issuance.

---

## S-04 · OCSP stapling module is a shell — no fetcher, no background task

**Component:** [ocsp.rs](../../../../crates/aegis-proxy/src/ocsp.rs)

The module declares `OcspResponse`, `OcspCache`, `needs_refresh()`
predicate — but ships NO fetcher and NO background task. Nothing
reads the AIA extension from a cert; nothing produces `OcspResponse`;
nothing populates `CertifiedKey::ocsp`.

README claims OCSP stapling. The code does not deliver.

**Fix:** Either implement (extract AIA URL from cert, GET it,
stash response in `CertifiedKey::ocsp`, refresh on cadence) or
delete the module and update README.

---

## S-05 · `forward.rs` body collection has no timeout — slow-drip upstream body hangs forever

**Component:** [upstream/forward.rs:490-516](../../../../crates/aegis-proxy/src/upstream/forward.rs#L490-L516)

`tokio::time::timeout(30s, client.request(fwd_req))` only wraps
the request future, which resolves once response HEADERS are
received. The subsequent `resp.into_body().collect().await` (line
511) has no timeout. A slow-drip upstream that sends headers fast
then dribbles body bytes holds the proxy task forever.

Combined with F-HIGH-003 from the previous audit (no body size
cap), an attacker who controls the upstream can OOM the WAF AND
hang individual requests.

**Fix:** second timeout around the body collect:

```diff
-let body_bytes = resp.into_body().collect().await
+let limit_bytes = cfg.body.max_response_bytes.unwrap_or(64 * 1024 * 1024);
+let limited = http_body_util::Limited::new(resp.into_body(), limit_bytes);
+let body_bytes = tokio::time::timeout(body_timeout, limited.collect()).await??
     .map_err(...)?.to_bytes();
```

Map the timeout to `X-WAF-Action: timeout` per §3.

---

## S-06 · In-memory state has no max-entries cap; risk scores never expire

**Component:** [state/in_memory.rs:26-47, 195-212](../../../../crates/aegis-proxy/src/state/in_memory.rs#L26-L47)

The in-memory backend stores risk scores with `expires_at: None`,
so the reaper at line 44 never evicts them. There's also no
max-entries cap on the underlying `DashMap`. Per-IP + per-device +
per-session keying gives a high-cardinality space; under sustained
high-cardinality traffic (e.g. a botnet rotating User-Agent /
device fingerprints) the map grows without bound.

Round 1's stability criterion bans crash, but a memory leak that
crashes after 6 hours of benchmark traffic ALSO violates the
criterion if the benchmark runs that long.

**Fix:**
1. Set `expires_at: Some(now + risk_ttl)` for every risk-score
   write; respect the configured tier-specific TTL.
2. Add `cfg.state.in_memory.max_entries: usize` (default ~100 000);
   evict LRU on insert when full.
3. Spawn a reaper task that periodically removes expired entries
   independently of access pattern.

---

## S-07 · Vault re-authenticates on every secret resolve — no token renewal loop

**Component:** [secrets/vault.rs:38-41, 128-138](../../../../crates/aegis-proxy/src/secrets/vault.rs#L38-L41)

`resolve_secret_async` does a full Vault login (AppRole / token /
whatever) per call. A hot-reload pass through `expand_secrets_async`
that encounters N `${secret:vault:...}` references opens N Vault
sessions. The token isn't cached across calls; the client isn't
memoized.

Under high mutation cadence (multi-route config reload), this
hammers Vault's auth endpoint. Vault's anti-abuse rate-limiter may
trip and start returning 429 → secrets fail to resolve → WAF boot
or reload fails.

**Fix:**
1. Memoize the Vault client + token across a single
   `expand_secrets_async` pass.
2. Spawn a background renewer that calls `token/renew-self` before
   expiry.
3. Cache resolved secret values for the lesser of the secret's
   lease TTL and a configured `secret_cache_ttl` (e.g. 5 min).

---

## Severity rationale

HIGH. Each is either a "feature claimed but doesn't work" (S-01,
S-04), a "memory leak under sustained traffic" (S-06), or an
"external-system abuse vector" (S-02, S-03, S-07). None alone is
CRITICAL because none triggers immediate crash or contract bypass —
they degrade the WAF's behavior over time or in specific deployments.
