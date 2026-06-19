# Infrastructure & Attack-Surface Source Audit — Run 11 Findings

| Field              | Value                                                                  |
|--------------------|------------------------------------------------------------------------|
| Run ID             | LT-RUN-11                                                              |
| Date               | 2026-06-19                                                            |
| Approach           | Static source audit — infra attack-surface, DoS/crash & state-backend trust |
| Scope              | `crates/aegis-proxy`, `crates/aegis-security`, `crates/aegis-control`, `crates/aegis-core`, `crates/aegis-bin`, `config/` |
| Source files audited | ~50 key files across the request hot path, state/Redis layer, control plane, and shipped configs |
| Total findings     | **16**                                                                |
| Critical           | **5**                                                                 |
| High               | **5**                                                                 |
| Medium             | **2**                                                                 |
| Low                | **4**                                                                 |
| Logic conflicts    | **2 confirmed**                                                       |
| Stubs / unimpl     | **1 confirmed** (deferred/unwired)                                    |
| Partial impl       | **1 confirmed**                                                       |
| Contract violations| **0** (this run is a security/infra pass, not a contract pass)        |
| Test suite         | ⛔ could not run — static security review only; no build/test executed |
| Status             | ⚠ OPEN — awaiting fix planning                                        |

---

## Executive Summary

This run was driven by the operator's lived incident: an attacker who gained control of **Redis flipped it to read-only**, and the WAF mishandled the result. The audit confirms that scenario is not a one-off — it is the single most dangerous structural weakness in the codebase, and it has **two independent exploitation paths plus a deeper root cause**.

The root cause (**STATE-02, High**) is that the state backend connects to Redis over **plaintext `redis://` with no authentication and no TLS enforced anywhere in code or schema**. The `RedisConfig` schema (`config.rs:3269`) has no `password`, `username`, or `tls` field at all; credentials can only be smuggled into the URL string, and **every shipped config** (`dev.yaml`, `prod.yaml`, `cluster-a.yaml`, `cluster-b.yaml`) ships `urls: ["redis://127.0.0.1:6379"]` with no credentials. Nothing warns or refuses to boot when the shared security-state store is unauthenticated. That is exactly how an attacker reaches Redis in the first place.

Once an attacker controls Redis, two things happen. First (**STATE-01, Critical**): the config watcher reads a config document straight from Redis and applies it **fleet-wide with no signature or provenance check** — a Redis attacker can repoint upstreams to a server they own (full traffic interception), disable every detector, or swap the TLS trust bundle, and every node applies it within one poll interval. Second (**STATE-03, Medium**): the *read-only* case specifically is misclassified — `ReconcilingBackend` cannot tell "Redis unreachable" from "Redis read-only," so it silently substitutes a **freshly-empty in-memory fallback** for all writes, resetting cluster-wide rate-limit counters, risk scores, and replay nonces per node. That is the precise behaviour the operator observed.

Independently of Redis, the **request hot path has two trivially-triggerable remote OOM crashes** ("làm chết WAF"). The HTTP/1 path buffers the entire request body into RAM *before* checking the size cap (**PROXY-01, Critical**), and the HTTP/3 path has no body cap at all. The `RiskTracker` and per-IP rate-limiter keep unbounded maps keyed on an attacker-controlled session cookie, holding entries for up to an hour (**PROXY-02, Critical**) — a flood of unique cookies exhausts memory without tripping any detector. Slowloris is open (no header-read timeout, no connection cap — **PROXY-04**).

Finally, the control plane ships a **hardcoded default control secret** (`waf-hackathon-2026-ctrl`) live in `prod-balanced.yaml` (**CTL-01, Critical**), and the PoW/challenge-pass signing key is derived from that same secret (**SEC-01, Critical**) — so with the shipped defaults an attacker can forge admin control-plane calls *and* mint challenge-pass tokens that bypass the entire bot-mitigation ladder. Empty-secret fail-open (**CTL-02**) and a no-op secret scrubber (**CTL-03**) compound the exposure.

Recommended first action: **STATE-02 + CTL-01 + SEC-01 together** — make Redis auth/TLS mandatory and remove the shared default secret. These are the changes that would have prevented the original incident and close the highest-impact bypasses, and they are small, config-and-boot-validation edits.

---

## Finding Index

### State Backend / Redis Trust Boundary (STATE-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| STATE-01 | **Critical** | Contract Violation / Trust boundary | Config doc read from Redis is applied fleet-wide with no signature/provenance check — Redis attacker injects valid-but-malicious config |
| STATE-02 | **High** | Logic Conflict / Hardening gap | State backend connects over plaintext `redis://` with no auth/TLS; schema has no password/tls field; all shipped configs are unauthenticated |
| STATE-03 | **Medium** | Logic Conflict / Fail-open | Read-only Redis misclassified as a partition → silent empty in-memory fallback resets shared rate-limit/risk/nonce state |
| STATE-04 | **Low** | Logic Conflict (doc/code) | `redis.rs` module doc claims the binary always wires `InMemoryBackend`; `state_select.rs` actually wires `RedisBackend` |

### Proxy Data Plane — DoS / Crash (PROXY-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| PROXY-01 | **Critical** | Resource exhaustion / Crash | HTTP/1 request body fully buffered via `collect()` before the size cap is checked → trivial remote OOM |
| PROXY-02 | **Critical** | Resource exhaustion | `RiskTracker` map keyed on attacker-controlled session cookie, entries live 1h, inserted on every request → unbounded growth → OOM |
| PROXY-03 | **High** | Resource exhaustion / Crash | HTTP/3 ingress drains the whole body into `BytesMut` with no size cap at any point |
| PROXY-04 | **High** | DoS (slowloris) | No `header_read_timeout`, no whole-connection timeout, no connection-count cap → connection/worker exhaustion |
| PROXY-05 | **High** | Resource exhaustion | Per-IP limiter map unbounded (same key problem) and `DEFAULT_LIMIT = 1,000,000/60s` so the volumetric backstop never fires |
| PROXY-07 | **Low** | DoS | Inspecting WS bridge loop has no idle/read timeout — a silent client pins a task + sockets indefinitely |

### Control Plane / Secrets (CTL-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| CTL-01 | **Critical** | Hardcoded credential | Default control secret `waf-hackathon-2026-ctrl` shipped live in `prod-balanced.yaml`; gates all `/__waf_control/*` mutations |
| CTL-02 | **High** | Auth fail-open | Empty `csrf_secret` only warns, then signs admin session cookies with the constant key `blake3("")` |
| CTL-03 | **Medium** | Partial Impl | `scrub_secrets` is a no-op clone; `GET /api/config` + YAML backup return inline secrets verbatim |

### Security Crate — Control Bypass (SEC-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| SEC-01 | **Critical** | Predictable key / bypass | PoW + challenge-pass signing key derived from `control_secret`; with the default secret the challenge ladder is fully forgeable |
| SEC-02 | **Low** | Logic Conflict | TOTP code compared with non-constant-time `==` (low exploitability — server-generated, rotates 30s, replay-guarded) |
| SEC-03 | **Low** | Not Implemented | JWT `validate()` never checks the signature; CAPTCHA `verify()` returns `Ok(true)` — both documented, unwired (zero callers) |

---

## Detailed Findings

---

### STATE-01 — Unauthenticated config from Redis applied fleet-wide ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-proxy/src/config_source/redis_source.rs:189–205` (apply on parse)
- `crates/aegis-proxy/src/config_source/config_store.rs:65–83` (`ConfigDoc` — no signature field)
- `crates/aegis-proxy/src/config_source/redis_source.rs:317–407` (`apply_and_swap` rebuilds routes/upstreams/detectors/TLS)
- `crates/aegis-core/src/config.rs:63–73` (`load_config_str` — parse + structural validate only)

**Description:**

The config watcher loads a versioned document from the shared backend and applies it across the whole fleet if it merely parses. There is no provenance/integrity check — `ConfigDoc` carries `version`, `blob`, `actor`, `ts`, `summary` but **no signature or MAC**.

```rust
match aegis_core::load_config_str(&doc.blob) {
    Ok(new_cfg) => {
        apply_and_swap(&new_cfg, &cfg, &bus, &targets, doc.version).await;
        applied_version = doc.version;   // ← trusted purely because it parsed
    }
    // ...
}
```

`apply_and_swap` then rebuilds the live route table, upstream pool registry, detector mask, rule set, and TLS resolver.

**Impact:** This is the operator's Redis-takeover scenario weaponised. Anyone with write access to Redis writes `config:waf:doc` with `version+1` and a syntactically valid YAML blob; within one poll interval every node applies it. The attacker can repoint `upstreams` to a server they control (full traffic interception / credential harvesting / SSRF), disable every detector or force `observe_only`, or swap the Zero-Trust CA bundle. A read-only Redis that was *seeded* with a malicious doc before lockdown is still applied.

**What the code should do:** Authenticate config provenance independently of Redis's own ACLs. Add a detached signature to `ConfigDoc` (Ed25519, or HMAC keyed on a boot-time secret held only in node memory / a secrets manager — never in Redis) and reject any doc whose signature does not verify before calling `apply_and_swap`. Additionally apply a semantic floor on the most dangerous fields applied from a shared source: validate upstream hosts against an allowlist and refuse to *loosen* TLS trust or disable detectors below a configured minimum via the shared path.

---

### STATE-02 — State backend connects over plaintext, unauthenticated Redis ⚠

**Severity:** High (root cause of the original incident)
**Files:**
- `crates/aegis-core/src/config.rs:3269–3277` (`RedisConfig` schema — only `urls`, `cluster`, `pool_size`, `timeout`; **no `password`, `username`, or `tls`**)
- `crates/aegis-proxy/src/state/redis.rs:52–61` (default URL `redis://127.0.0.1:6379`)
- `crates/aegis-proxy/src/state/redis.rs:275–282` (`connect` — `PoolConfig::from_url`, no credential/TLS enforcement)
- `config/dev.yaml:126`, `config/prod.yaml:123`, `config/cluster-a.yaml:89`, `config/cluster-b.yaml:53` (all ship plaintext, credential-less URLs)

**Description:**

The shared security-state store — which holds rate-limit counters, risk scores, replay nonces, auto-blocks, and (per STATE-01) live config — is reached with no transport security and no required authentication. The schema cannot even express a password or TLS setting:

```rust
pub struct RedisConfig {
    pub urls: Vec<String>,
    #[serde(default)] pub cluster: bool,
    #[serde(default = "default_pool_size")] pub pool_size: u32,
    #[serde(default = "default_redis_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}   // ← no password / username / tls field
```

```yaml
# config/prod.yaml:122
redis:
  urls: ["redis://127.0.0.1:6379"]   # REPLACE FOR PRODUCTION  ← plaintext, no creds
```

Credentials can only be embedded inside the URL string (`redis://user:pass@host`, `rediss://…`), and nothing in code warns or refuses to boot when the URL is plaintext and credential-less.

**Impact:** This is *how the attacker reached Redis in the first place*. An exposed, unauthenticated Redis is directly controllable by anyone who can reach the port (a `CONFIG SET`, `FLUSHALL`, or `REPLICAOF` away from full takeover — including flipping it read-only, exactly as happened). Combined with STATE-01 it escalates to full data-plane compromise; combined with CTL-02/SEC-01 (which assume the same secret on every node) it widens further.

**What the code should do:** Add first-class `username`, `password_ref`, and `tls` fields to `RedisConfig`; build the connection with TLS (`rediss://`) and AUTH by default. At boot, **refuse to start (or emit a loud, unmissable warning) when `state.backend = redis` and the resolved connection is both plaintext and unauthenticated**, mirroring how the admin plane treats an empty `csrf_secret` — except this should fail closed. Document that production Redis must require AUTH + TLS and must not be network-reachable from untrusted hosts.

---

### STATE-03 — Read-only Redis silently degrades to an empty in-memory fallback ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-proxy/src/state/reconcile.rs:236–260` (`incr_window`; same pattern for `token_bucket`, `add_risk`, `put_nonce`, `auto_block`, `set`)

**Description:**

This is the operator's exact symptom. When Redis is flipped read-only, every *write* command fails with a READONLY error surfaced as `WafError::State`. `ReconcilingBackend` cannot distinguish "Redis unreachable" from "Redis read-only" and treats both as a partition, falling through to a **freshly-empty** `InMemoryBackend`:

```rust
match self.primary.incr_window(key, window, limit).await {
    Ok(r) => { self.maybe_exit_partition().await; Ok(r) }
    Err(e @ WafError::State(_)) => {
        self.enter_partition("incr_window", &e);          // ← READONLY == "partition"
        self.fallback.incr_window(key, window, limit).await  // ← empty local backend
    }
    Err(other) => Err(other),
}
```

Reads still succeed against Redis, so affected nodes flap: writes go to the empty local fallback, reads partly hit Redis. Cluster-wide rate-limit counters, risk scores, and replay nonces effectively reset to zero per node, and `put_nonce`/`consume_nonce` against an empty fallback opens a replay window. (The hot-path detector gate uses in-memory structures, so this degrades shared controls rather than fully bypassing them — hence Medium.)

**Impact:** Silent loss of shared rate-limiting / risk / replay protection across the fleet during a read-only Redis event, logged only as a generic "partition" so operators don't see the real cause.

**What the code should do:** Classify the Redis error string — treat `READONLY`/`-READONLY` (and `MISCONF`, `NOAUTH`) distinctly from connectivity failures. On a read-only primary, do **not** silently substitute an empty fallback for security-relevant writes; surface a distinct degraded-mode metric/alert and apply the configured per-tier failure mode (fail-closed on critical tiers) rather than fail-open-with-reset.

---

### STATE-04 — Stale module doc contradicts actual backend wiring ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-proxy/src/state/redis.rs:31–36` (doc: "the binary always wires `InMemoryBackend` … nothing instantiates `RedisBackend`")
- `crates/aegis-bin/src/state_select.rs:120,127` (actually wires `RedisBackend` + `ReconcilingBackend`)

**Description:**

The `redis.rs` module header still claims the Redis backend is purely additive and never instantiated at runtime ("until B1-T2 lands"). B1-T2 has clearly landed — `state_select.rs` constructs `RedisBackend::connect(...)` and wraps it in `ReconcilingBackend`. The doc understates the live attack surface and could mislead a reviewer into thinking Redis code is dead.

**Impact:** Documentation drift that hides the fact that STATE-01/02/03 are live in production builds.

**What the code should do:** Update the module doc to reflect that `RedisBackend` is wired via `state_select::select` when `state.backend = redis`, and cross-reference the reconcile fallback semantics.

---

### PROXY-01 — Request body fully buffered before the size cap (remote OOM) ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-proxy/src/data_plane.rs:731–745`

**Description:**

```rust
let (parts, body) = req.into_parts();
let body_bytes = match body.collect().await {   // ← reads the ENTIRE body into RAM
    Ok(c) => c.to_bytes(),
    Err(e) => { /* 400 */ }
};
if body_bytes.len() > max_body_bytes {           // ← cap checked only AFTER buffering
    /* 413 */
}
```

`body.collect().await` buffers the whole client body with no bound; the `max_body_bytes` check happens only after the bytes are resident. hyper's default builder (see PROXY-04) imposes no body limit, so one request with a multi-gigabyte or unbounded-chunked body is buffered in full before the 413 can fire.

**Impact:** Trivially triggerable remote OOM — a handful of concurrent large-body requests kill the worker. This is the "make my WAF die" class.

**What the code should do:** Wrap the body in the limiter the codebase already uses on the response side — `http_body_util::Limited::new(body, max_body_bytes).collect()` — and map the overflow error to 413; additionally short-circuit on a declared `Content-Length` that exceeds the cap before any buffering. The pattern already exists at `upstream/forward.rs:660–678`.

---

### PROXY-02 — RiskTracker grows unbounded for an hour, keyed by attacker session ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-security/src/risk/tracker.rs:55–56,180,255,297`
- `crates/aegis-proxy/src/data_plane.rs:1153` (runs on every allowed request)

**Description:**

```rust
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const IDLE_TTL: Duration = Duration::from_secs(3600);   // slot lives 1 HOUR
// ...
risk.record_clean_with_key(build_risk_key(peer_ip, &parts.headers, tls_fingerprint));
```

The map key is `RiskKey { ip, device_fp, session }`, where `session` comes straight from the request's `session`/`sid`/`jsessionid` cookie. `record_clean_with_key` does `entry(key).or_insert(...)`, so **even ordinary allowed traffic** inserts a fresh slot whenever the cookie value is new. Slots are evicted only after a full hour idle.

**Impact:** An attacker sending `Cookie: session=<random-per-request>` at a few thousand req/s (well under the PROXY-05 default limit) accumulates tens of millions of live entries within an hour → multi-GB heap → OOM. No detector needs to fire.

**What the code should do:** Add a hard cardinality cap on the DashMap (reject new-key inserts or evict LRU once `len()` exceeds e.g. 1–2M) and drop the idle TTL to minutes for zero-score slots (a clean slot carries no security value). Apply the same cap to PROXY-05.

---

### PROXY-03 — HTTP/3 request body has no size cap at all ⚠

**Severity:** High
**Files:**
- `crates/aegis-proxy/src/listener/http3.rs:301–318`
- `crates/aegis-proxy/src/proxy.rs:138` (`max_body_bytes` field exists but is never read in `handle_request`)

**Description:**

```rust
let mut body = bytes::BytesMut::new();
loop {
    match stream.recv_data().await {
        Ok(Some(mut chunk)) => {
            while chunk.has_remaining() {
                body.extend_from_slice(chunk.chunk());   // ← no bound, ever
                chunk.advance(len);
            }
        }
        Ok(None) => break, // ...
    }
}
```

The h3 listener buffers the entire QUIC body into `BytesMut` with no cap, then hands it to `proxy::handle_request`, which — unlike the legacy data-plane path — never consults `max_body_bytes`.

**Impact:** OOM over QUIC whenever `http3` is enabled, with no size limit anywhere on that ingress path.

**What the code should do:** Track `body.len()` in the accumulation loop and abort with 413 once it exceeds `ctx.max_body_bytes`; and/or apply the PROXY-01 `Limited` fix inside `handle_request` so both ingress paths share one enforced cap.

---

### PROXY-04 — No header/connection read timeout; no connection cap (slowloris) ⚠

**Severity:** High
**Files:**
- `crates/aegis-proxy/src/accept.rs:1426,1432,2216–2240` (and the admin mount)

**Description:**

```rust
http1::Builder::new().serve_connection(io, svc).await
// and:
let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
builder.serve_connection_with_upgrades(io, svc).await
```

Connections are accepted and unconditionally `tokio::spawn`ed; `conn_inflight.admit()` is only a drain-tracking counter, not a limiter. The hyper builders use defaults: no `header_read_timeout`, no overall connection timeout. The `LoadShedder` only gates inflight request *processing*, which is reached after the body is read — so a connection stalled in slow-header/slow-body never reaches it.

**Impact:** Classic slowloris — an attacker opening many connections and dribbling bytes exhausts file descriptors and tokio tasks while the WAF waits forever; legitimate traffic is starved.

**What the code should do:** Set `header_read_timeout` (5–10s) on both plain and admin builders and the `auto::Builder` equivalent; wrap each spawned connection in an overall `tokio::time::timeout` for the header/first-body phase; and bound total concurrent connections with a `Semaphore` acquired before `tokio::spawn`.

---

### PROXY-05 — Per-IP rate-limiter map unbounded; default limit effectively disabled ⚠

**Severity:** High
**Files:**
- `crates/aegis-security/src/rate_limit/ip_limiter.rs:44,103,167–235`

**Description:**

```rust
const DEFAULT_LIMIT: u32 = 1_000_000;              // ~16k req/s before it fires
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
// ...
map: DashMap<aegis_core::risk::RiskKey, VecDeque<Instant>>,   // no size cap
```

Same `RiskKey` cardinality problem as PROXY-02: the hot-path volumetric limiter is keyed on IP+device_fp+session, so a unique session cookie per request creates a new `VecDeque`; the idle sweep runs at most once/60s. The `DEFAULT_LIMIT` of 1,000,000/60s (loosened for benchmarking) means the volumetric backstop is wide open by default.

**Impact:** Memory growth under flood, plus a near-useless default volumetric cap that won't stop a real flood.

**What the code should do:** Add a hard `map.len()` ceiling with LRU eviction (shared with PROXY-02), and ship a sane production `DEFAULT_LIMIT` (low thousands/60s) with the benchmark value confined to the benchmark profile.

---

### PROXY-07 — Inspecting WS bridge has no idle timeout ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-proxy/src/proto/ws_inspect.rs:384–449`

**Description:**

```rust
loop {
    tokio::select! {
        read = read_one_frame(&mut client_read, &mut cbuf) => { ... }
        read = upstream_read.read(&mut up_chunk) => { ... }
    }
}
```

The bridge awaits client/upstream reads with no inactivity timeout. A client that completes the WS upgrade then sends nothing pins a tokio task, two split halves, and the upstream socket indefinitely. Frame size is bounded (`MAX_FRAME_PAYLOAD`), so this is connection/task pinning, not memory — hence Low, but it stacks with PROXY-04.

**Impact:** Slow connection-slot/task exhaustion via idle upgraded WebSocket connections.

**What the code should do:** Wrap each read in a `tokio::time::timeout` (configurable WS idle, 60–120s) and tear down the bridge with a close frame on expiry, mirroring the idle timeout already present on the upstream response stream.

---

### CTL-01 — Hardcoded default control secret shipped in prod profile ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-control/src/interop/mod.rs:34` (`DEFAULT_CONTROL_SECRET = "waf-hackathon-2026-ctrl"`)
- `crates/aegis-proxy/src/run.rs:2560–2564` (falls back to the default when unset)
- `config/profiles/prod-balanced.yaml:287` (ships the literal value, not a secret-ref)

**Description:**

```rust
pub const DEFAULT_CONTROL_SECRET: &str = "waf-hackathon-2026-ctrl";
```
```yaml
# config/profiles/prod-balanced.yaml:287
control_secret: "waf-hackathon-2026-ctrl"
```

This secret is the only credential on `/__waf_control/*` (the compare itself, `interop/control.rs:298–308`, is correctly constant-time — the problem is the value). Those endpoints include `set_profile` (flip enforcement to `log_only`) and `reset_state` (wipe rate-limit windows, risk scores, auto-blocks, nonces).

**Impact:** Any deployment using `prod-balanced.yaml` unchanged (or forgetting to set `control_secret`) exposes the control plane under a public, source-committed secret — an attacker can disable enforcement or wipe accumulated state on demand. The `prod-strict` / `prod-high-throughput` profiles correctly use `${secret:...}`; prod-balanced is the outlier.

**What the code should do:** Remove the hardcoded fallback constant; make `control_secret` mandatory when `interop.enabled` (fail boot if unset). Replace the literal in `prod-balanced.yaml` with a `${secret:...}` reference and rotate the value out of git history.

---

### CTL-02 — Empty CSRF/session secret fails open to a constant signing key ⚠

**Severity:** High
**Files:**
- `crates/aegis-proxy/src/accept.rs:411–432` (warns-and-continues on empty secret)
- `crates/aegis-control/src/api/login.rs:347–350` (`derive_session_key` = `blake3(secret)`)

**Description:**

```rust
let secret = auth.csrf_secret_ref.trim();
if secret.is_empty() {
    tracing::warn!("admin auth: csrf_secret is EMPTY — session cookies are signed with a fixed key...");
}
// ...
pub fn derive_session_key(secret: &str) -> [u8; 32] {
    let hash = blake3::hash(secret.as_bytes());  // blake3("") = a fixed, public constant
    *hash.as_bytes()
}
```

With an empty secret the admin session-cookie HMAC key becomes `blake3(b"")`, a constant anyone can compute from this open-source repo.

**Impact:** An attacker who can also place a matching `SessionRecord` in the backend (e.g. the Redis-takeover scenario — write `adminsess:<id>`) can forge a fully valid admin session cookie and obtain `Scopes::FULL`. Even without Redis write access, a constant signing key is a serious integrity weakness, and the boot path fails open rather than refusing to start.

**What the code should do:** Fail boot (hard error) when `csrf_secret_ref` is empty or shorter than ~32 chars and admin auth is reachable; reject the `blake3("")` derived key; require operator-supplied CSPRNG material identical across nodes.

---

### CTL-03 — Config API "scrub_secrets" is a no-op; inline secrets disclosed ℹ️

**Severity:** Medium
**Files:**
- `crates/aegis-control/src/api/config.rs:11–13` (used at `:16–19,37–39`)

**Description:**

```rust
pub fn scrub_secrets(config_json: &Value) -> Value {
    config_json.clone()   // ← returns input unchanged
}
```

The function name promises scrubbing but returns the input verbatim. The security model relies on every secret being a `${secret:...}` reference — which breaks for any inline secret. Since `prod-balanced.yaml` inlines `control_secret` (CTL-01), `GET /api/config` and the YAML backup return the live control secret in plaintext to any authenticated reader (including a read-scoped account).

**Impact:** A read-only dashboard user or read-scoped token can exfiltrate inline secrets (control secret, inlined password hashes / API keys). Combined with CTL-01/SEC-01 this hands over the control plane and challenge bypass to a low-privilege reader.

**What the code should do:** Make `scrub_secrets` actually redact — walk the JSON and replace values at sensitive paths (`interop.control_secret`, `*.password_hash`, `*.token_hash`, `*.csrf_secret`, `*.api_key*`, TLS private keys) with `"***"` unless already a `${secret:...}` reference; restrict config-export endpoints to admin/write scopes.

---

### SEC-01 — PoW challenge key derived from the (default) control secret → challenge bypass ⛔

**Severity:** Critical
**Files:**
- `crates/aegis-proxy/src/run.rs:2292–2295` (`derive_pow_key`)
- `crates/aegis-security/src/challenge/pow.rs:216–242` (`issue_pass` / `pass_valid`)
- `crates/aegis-proxy/src/data_plane.rs:1385–1386` (challenge gate honors a valid pass cookie)

**Description:**

```rust
fn derive_pow_key(control_secret: &str) -> [u8; 32] {
    let h = blake3::hash(format!("aegis-pow-key-v1:{control_secret}").as_bytes());
    *h.as_bytes()
}
```

The same key signs both PoW challenges and the `waf_challenge_pass` token; the data plane skips the challenge gate when a valid pass cookie is present. Because the key is a pure function of `control_secret`, and that defaults to the public `waf-hackathon-2026-ctrl` (CTL-01), an attacker can reconstruct the key locally and mint an unexpired pass token — bypassing the entire JS/PoW/CAPTCHA ladder fleet-wide. The MAC logic itself is sound (constant-time, expiry, single-use nonce); the weakness is the predictable key.

**Impact:** Bot-mitigation / challenge tier is fully defeated whenever the default secret is in use — which is the shipped prod-balanced posture. Converts CTL-01 from a control-plane issue into a data-plane security-control bypass.

**What the code should do:** Derive the PoW/challenge-pass key from an independent high-entropy secret (its own `${secret:...}` ref), not from `control_secret`. If one secret must seed both, require operator-set high-entropy material (reject the default per CTL-01). Rotate the key when the secret rotates.

---

### SEC-02 — TOTP code compared with non-constant-time `==` ℹ️

**Severity:** Low
**Files:**
- `crates/aegis-control/src/admin_auth/totp.rs:91–93`

**Description:**

```rust
if generate(secret, time + offset * step, config) == code {
    return Some(base_counter + offset);
}
```

The candidate is compared with `==`. The compared operand is server-generated, the code rotates every 30s, and `verify_and_consume` provides replay protection — so exploitability is very limited, but it is inconsistent with the constant-time compares used elsewhere (session, CSRF, control secret).

**Impact:** Marginal timing leak on a short-lived 6-digit value; not practically exploitable given rotation + lockout.

**What the code should do:** Use the existing `constant_time_eq` helper over fixed-width byte slices of the formatted code.

---

### SEC-03 — Deferred stubs: JWT signature never verified; CAPTCHA returns Ok(true) ℹ️

**Severity:** Low (latent — documented, unwired)
**Files:**
- `crates/aegis-security/src/auth/jwt.rs:55–110` (`validate()` checks iss/aud/exp but not the signature)
- `crates/aegis-security/src/challenge/captcha.rs:42–86` (each vendor `verify()` returns `Ok(true)`)

**Description:**

`validate()` decodes and checks claims but never verifies the signature (`// In production, use jsonwebtoken crate with JWKS`); CAPTCHA `verify()` unconditionally returns success. Both modules carry headers stating they are deferred with **zero callers** in `aegis-proxy/src` + `aegis-bin/src` (grep-confirmed), and `Implement-Progress.md` lists them as dormant. There is no current attack surface — the risk is purely a future implementer wiring them in without first adding real verification.

**Impact:** None today (unreachable). If wired as-is later, JWT auth would accept forged tokens and CAPTCHA would pass everyone.

**What the code should do:** Before any wiring, implement `jsonwebtoken` + JWKS signature verification and the real CAPTCHA siteverify HTTP calls (or default them to `Ok(false)` / `unimplemented!` so an accidental wire fails closed). Add a CI guard asserting they remain uncalled until then.

---

## Cross-Crate Wiring Analysis

| Feature | Configured In | Implemented In | Wired Into Pipeline | Net Status |
|---------|--------------|----------------|--------------------|-----------| 
| Redis config provenance/signature | config_source ✓ | _none_ ✗ | `redis_source.rs::apply_and_swap` ✓ | **Logic conflict** (applied unsigned) |
| Redis transport auth/TLS | `RedisConfig` schema ✗ (no field) | `state/redis.rs::connect` ✗ | `state_select.rs` ✓ | **Bypass — plaintext default** |
| Read-only Redis handling | reconcile mode ✓ | `reconcile.rs` (partial) ✗ | data plane ✓ | **Silent drop** (empty fallback) |
| Request body size cap (H1) | `max_body_bytes` ✓ | `data_plane.rs` (after buffer) ✗ | data plane ✓ | **Logic conflict** (cap after OOM) |
| Request body size cap (H3) | `max_body_bytes` ✓ | `proxy::handle_request` ✗ | h3 listener ✓ | **Dead — not enforced** |
| RiskTracker cardinality bound | — | `risk/tracker.rs` ✗ (no cap) | data plane ✓ | **Resource exhaustion** |
| Per-IP volumetric limit | config ✓ | `ip_limiter.rs` ✓ | data plane ✓ | **Logic conflict** (default 1M ≈ off) |
| Header/connection read timeout | — | hyper defaults ✗ | `accept.rs` ✓ | **Bypass — slowloris open** |
| Control-plane secret | `prod-balanced.yaml` ✓ (hardcoded) | `interop/control.rs` ✓ | `/__waf_control/*` ✓ | **Bypass — known default** |
| Challenge-pass key independence | derived from control_secret ✗ | `pow.rs` ✓ | challenge gate ✓ | **Bypass — predictable key** |
| Admin session signing key | `csrf_secret` (may be empty) | `login.rs::derive_session_key` ✓ | admin middleware ✓ | **Bypass — constant key on empty** |
| Config API secret redaction | — | `config.rs::scrub_secrets` ✗ (no-op) | `GET /api/config` ✓ | **Silent drop** (secrets leaked) |
| JWT signature verify | config (dormant) | `auth/jwt.rs` ✗ stub | _no callers_ ✗ | **Stub — unwired** |
| CAPTCHA verify | config (dormant) | `challenge/captcha.rs` ✗ stub | _no callers_ ✗ | **Stub — unwired** |

---

## Priority Fix Order

1. **STATE-02** — Make Redis AUTH + TLS first-class and mandatory; fail boot on plaintext/unauthenticated Redis. This is the root cause of the original incident. _(effort: medium)_
2. **CTL-01 + SEC-01** — Remove the hardcoded default control secret; require an operator-set value and derive the challenge key from an independent secret. Fixes the control-plane takeover and the challenge bypass together. _(effort: low)_
3. **STATE-01** — Sign config docs (Ed25519/HMAC with a non-Redis key) and reject unsigned/invalid docs before apply. Closes the "Redis attacker rewrites the WAF" path. _(effort: medium)_
4. **PROXY-01 + PROXY-03** — Bound the request body before buffering on both H1 and H3 (reuse the existing `Limited` pattern). Closes the trivial remote OOM. _(effort: low)_
5. **PROXY-02 + PROXY-05** — Add a hard cardinality cap + LRU eviction on the RiskTracker / IP-limiter maps; ship a sane default volumetric limit. _(effort: low–medium)_
6. **PROXY-04** — Add header-read and connection timeouts plus a connection-count semaphore (slowloris). _(effort: low)_
7. **CTL-02** — Fail boot on empty/short `csrf_secret` instead of warning. _(effort: low)_
8. **STATE-03** — Distinguish READONLY from connectivity loss; don't fail-open-with-reset on read-only primary. _(effort: medium)_
9. **CTL-03** — Make `scrub_secrets` actually redact; restrict config-export endpoints. _(effort: low)_
10. **PROXY-07, SEC-02, STATE-04, SEC-03** — Idle-timeout the WS bridge; constant-time TOTP compare; fix the stale doc; CI-guard the dormant stubs. _(effort: low)_

---

## Findings Deferred from Previous Run(s)

Runs 8–10 were different scopes (Run 8: v2.6 contract; Run 9: UI dashboard; Run 10: v2.6 contract deep scan). Their findings were **not** re-verified in this run, which is a fresh infrastructure / attack-surface security pass. No prior finding is claimed fixed or open here; a contract-focused re-verification should be tracked separately.

| Prior Run Finding | Status in This Run |
|-------------------|--------------------|
| LT-RUN-10 (4 findings, contract/v2.6) | Not re-verified — out of scope for this security pass |
| LT-RUN-8 / LT-RUN-9 (contract / UI) | Not re-verified — out of scope for this security pass |

---

*Report generated by master-waf-tester skill — Run 11 (2026-06-19).
Next action: engineer fix planning per priority order above. Highest impact: make Redis auth/TLS mandatory (STATE-02), kill the shared default secret (CTL-01/SEC-01), and sign config docs (STATE-01) — these three would have prevented the original Redis-takeover incident.*
