---
id: 2026-05-17-high-domain-types-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: domain types
component: crates/aegis-core/src/{secrets,cache,verbosity,cluster,error,tcp_destination,health}.rs
interop_contract: type discipline · §5.7 cache observability · §5.8 readiness
status: open
test_mode: source-review
---

# F-HIGH-domain-types bundle — 7 issues in domain/runtime types

---

## DT-01 · `secrets.rs::Secret` exposes raw bytes; no constant-time compare API

**Component:** [secrets.rs:11-14](../../../../crates/aegis-core/src/secrets.rs#L11-L14)

`Secret::as_bytes` exposes raw bytes; callers must use raw `==` for
token/HMAC compare → timing-side-channel exploitable for admin
tokens / TOTP / API keys / CSRF tokens. The `subtle` crate isn't
even in Cargo.toml.

`Clone` on `Secret` doubles RAM lifetime; no `ZeroizeOnDrop` derive
on the wrapper (relies on inner `Zeroizing<Vec<u8>>`).

No `Serialize`/`Deserialize` block — nothing prevents a future
serde derive from leaking.

**Fix:**
- Add `subtle = "2"` to workspace deps.
- Add `pub fn ct_eq(&self, other: &Self) -> bool` using
  `subtle::ConstantTimeEq`.
- Forbid `PartialEq` derive (use a marker trait or doc warning).
- Derive `ZeroizeOnDrop` on the wrapper struct itself.
- Add `#[serde(skip)]` markers in any containing struct.

---

## DT-02 · `cache.rs::CacheKey` derives NOTHING

**Component:** [cache.rs:1-12](../../../../crates/aegis-core/src/cache.rs#L1-L12)

`CacheKey` derives no `Hash`, `Eq`, `PartialEq`, `Clone`, `Debug` —
the type **literally cannot be used as a HashMap key**, despite the
name. `CachedResponse` also lacks `Clone`.

No `CacheDecision` enum exists at all. §9 cache observability
(`X-WAF-Cache: HIT|MISS|BYPASS`) requires this enum.

**Fix:**

```rust
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct CacheKey { ... }

#[derive(Clone, Debug)]
pub struct CachedResponse { ... }

pub enum CacheDecision {
    Hit,
    Miss,
    Bypass,
}
```

---

## DT-03 · `cache.rs::CacheKey.vary_headers: Vec<(String, String)>` is case-sensitive

**Component:** [cache.rs:5](../../../../crates/aegis-core/src/cache.rs#L5)

HTTP header names are case-insensitive (RFC 9110 §5.1). A request
with `Accept` vs `accept` hashes to different cache slots →
fragmentation OR **cache-poisoning via case-variant header
smuggling** (origin returns `Vary: Accept`; attacker uses `accept:`
to land on a different slot serving the wrong content type).

**Fix:** normalize to lowercase at construction:

```rust
pub fn new(method: ..., vary_headers: Vec<(String, String)>) -> Self {
    let vary_headers = vary_headers.into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    Self { ..., vary_headers }
}
```

---

## DT-04 · `verbosity.rs::Trace` level has no body-redaction contract

**Component:** [verbosity.rs:31-39](../../../../crates/aegis-core/src/verbosity.rs#L31-L39)

Doc says Trace is "noisiest, short-lived debugging only" but no
type-level guarantee that an emitter at Trace won't include request
bodies, Authorization headers, cookies, or break-glass tokens. The
PII-leak vector.

The hot-path `allows(Trace)` predicate is the only gate — emitter
sites are on their honour.

Compounding: `SharedVerbosity::set` (lines 104-128) has no audit
emission and no permission check. Anyone holding a clone can flip
Trace on a live process.

**Fix:**

1. Add a `SafeForLogging` newtype wrapping any field that survives
   `Trace`, with `Redacted<T>` for the rest.
2. Wrap the verbosity setter:

```rust
pub fn set_with_audit(
    &self,
    level: VerbosityLevel,
    actor: &str,
    bus: &AuditBus,
) {
    self.inner.store(Arc::new(level));
    bus.publish(AuditEvent {
        action: "verbosity_set",
        actor: actor.into(),
        fields: serde_json::json!({ "level": level }),
        ...
    });
}
```

Remove the unaudited `set()` method (or make it pub(crate)).

---

## DT-05 · `cluster.rs::ClusterMembership`, `NodeInfo`, `Lease` are dead code

**Component:** [cluster.rs:25-48](../../../../crates/aegis-core/src/cluster.rs#L25-L48)

Zero `impl` and zero `dyn` consumers in the entire workspace.
`NodeInfo` is only constructed in `cluster.rs`'s own tests. The active
surface is `LeaseStore` below.

Misleading at the type-contract level — readers see two cluster APIs
and can't tell which is canonical.

**Fix:** delete `ClusterMembership`, `NodeInfo`, `Lease`. Update the
re-exports in `lib.rs:25`. `LeaseStore::self_id` + `holder()` cover
the live needs.

Bonus: `NodeId(pub String)` (line 58) has a `pub` inner — anyone can
mutate `node_id.0 = "spoofed".into()`. Make the field private +
force construction through `new()` with validation.

---

## DT-06 · `error.rs::WafError` is too coarse — ~50% of error sites use `Other`/`Config`

**Component:** [error.rs:1-13](../../../../crates/aegis-core/src/error.rs#L1-L13)

110 `WafError::Other` / `WafError::Config` call sites in the
workspace vs ~230 total `.map_err` sites — half the error wrapping
funnels into stringly-typed `Other`. Missing variants: `Parse`,
`Tls`, `Upstream`, `Auth`, `Timeout`, `RateLimited`, `NotFound`.

No `Backtrace` capture, no `source()` chaining beyond the single
`#[from] io::Error`.

Additionally, `WafError::Config("...")` etc. wrap arbitrary `String`
re-emitted via `tracing` / HTTP 502 bodies. With attacker-controlled
inputs like CONNECT authorities + Host headers (e.g.
`tcp_destination::parse_rule` returning
`format!("...entry '{input}'...")`), a malformed input becomes a
log line — **log-injection vector** if logs flow to a JSON parser
without escaping.

**Fix:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum WafError {
    #[error("config error: {0}")]
    Config(String),
    #[error("parse error: {kind} — {detail}")]
    Parse { kind: &'static str, detail: String },
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("timeout after {ms}ms")]
    Timeout { ms: u32 },
    #[error("rate limited")]
    RateLimited,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
}
```

Escape attacker-controlled data in error messages:

```rust
fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_control() { '_' } else { c })
        .collect()
}
```

Apply at every `format!` site that interpolates request-derived data.

---

## DT-07 · `tcp_destination.rs` env-var read on hot path + missing IPv4-mapped IPv6 + CGNAT rejection

**Component:** [tcp_destination.rs:110-116, 199-204](../../../../crates/aegis-core/src/tcp_destination.rs#L110-L116) + [tcp_destination.rs:167-186](../../../../crates/aegis-core/src/tcp_destination.rs#L167-L186)

Two issues:

### Env-var on hot path

`AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1` is checked via `std::env::var`
on every CONNECT call. `std::env::var` is a libc call with a
process-global mutex on glibc → contention under load.

**Fix:** cache the value at startup as an `AtomicBool` like
`break_glass.rs` does (`init_from_env`).

### Missing IPv4-mapped IPv6 + CGNAT rejection

`is_internal_address` does NOT reject:

- IPv4-mapped IPv6 (`::ffff:127.0.0.1`) — `IpAddr::V6(...)::is_loopback()` returns false in stable Rust pre-1.75; classic SSRF bypass
- CGNAT range 100.64.0.0/10 (RFC 6598)
- 198.18.0.0/15 (RFC 2544 benchmarking)
- Other RFC 6890 special-use blocks

**Fix:**

```rust
fn is_internal_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            // Normalize IPv4-mapped before checking.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_v4(v4);
            }
            is_internal_v6(v6)
        }
    }
}

fn is_internal_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
        || ip.is_broadcast() || ip.is_documentation() || ip.is_unspecified()
        // CGNAT
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 0x40)
        // RFC 2544 benchmark
        || (ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19))
}
```

Cross-ref: F-HIGH-MA-02 (control audit) reported `aegis-control::validate_pool` accepts `169.254.169.254`. This aegis-core function DOES reject 169.254/16 — the bug is in the control-side validator
not calling this gate.

---

## Severity rationale

HIGH. DT-01 (constant-time compare absent) is a real timing-channel
risk on admin auth. DT-02 (CacheKey can't be HashMap key) is a
type-level absurdity. DT-04 (Trace no redaction contract) is a PII
vector. Others are robustness / hygiene.
