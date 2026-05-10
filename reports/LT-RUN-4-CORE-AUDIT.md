# aegis-core Source Audit — Run 4 Findings

| Field              | Value                                                   |
|--------------------|---------------------------------------------------------|
| Run ID             | LT-RUN-4                                               |
| Date               | 2026-05-10                                              |
| Approach           | Static source audit — unimplemented / partial / conflicting logic |
| Scope              | `crates/aegis-core/src/` (primary) + cross-crate references     |
| aegis-core files   | 20 source files audited                                 |
| Total findings     | **12 findings**                                         |
| Logic conflicts    | **1 confirmed** (DdosConfig default mismatch)           |
| Stubs / unimpl     | **7 confirmed**                                         |
| Partial impl       | **4 confirmed**                                         |
| Status             | ⚠ OPEN — awaiting fix planning                         |

---

## Executive Summary

A full static audit of `crates/aegis-core/src/` (20 files) plus cross-crate wiring in `aegis-proxy`, `aegis-control`, `aegis-security`, and `aegis-bin` reveals 12 findings. The most critical is a **logic conflict in `DdosConfig`** where the top-level field documentation contradicts the actual `Default` implementation — operators reading the public API doc will believe the DDoS gate defaults to shadow mode, but it actually defaults to enforce mode. Seven features are stub/unimplemented behind explicit error returns or `None` fallbacks; four are partially built with dead fields, missing wiring, or hardcoded placeholder values.

No `todo!()` or `unimplemented!()` macro calls appear anywhere in `aegis-core/src/`. All gaps are expressed through trait defaults that return stubs, config parsing that succeeds but runtime behavior that fails, or documentation that disagrees with code.

---

## Finding Index

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| CORE-01 | **High** | Logic Conflict | `DdosConfig.observe_only` default contradicts field doc in `WafConfig` |
| CORE-02 | **High** | Not Implemented | `UpstreamScheme::Tcp` passes config validation but returns HTTP 502 at runtime |
| CORE-03 | **High** | Not Implemented | `CacheProvider` trait has no in-crate implementation; `flush_cache` always `supported: false` |
| CORE-04 | **Medium** | Not Implemented | AI `extract_confidence()` is a stub that always returns `None`; `confidence_threshold` config has no effect |
| CORE-05 | **Medium** | Not Implemented | `pool_snapshot_provider` hardcodes `healthy = total`; member health is never actually tracked |
| CORE-06 | **Medium** | Not Implemented | `StateBackend::health()` default returns `unknown/disconnected` for any backend that doesn't override it |
| CORE-07 | **Medium** | Not Implemented | `GitOps` / witness / threat-intel tasks are not spawned as background tasks; `// TODO` at boot seam |
| CORE-08 | **Medium** | Partial Impl | `ServiceDiscovery` trait exists in `aegis-core` but no in-process impl and no config field to select a backend |
| CORE-09 | **Medium** | Partial Impl | State reconcile modes `latest` and `fail_safe` are parsed but return `WafError::Config` at boot |
| CORE-10 | **Low** | Partial Impl | `GitPollDriver.config_path` field is `#[allow(dead_code)]` — stored but never read |
| CORE-11 | **Low** | Partial Impl | `io_driver_fd_count` runtime metric is a no-op; gauge stays at 0 on every build |
| CORE-12 | **Low** | Not Implemented | Secret providers `vault`, `aws`, `gcp`, `azure`, `hsm` return `NotImplemented` in sync resolver |

---

## Detailed Findings

### CORE-01 — DdosConfig `observe_only` Default: Logic Conflict ⚠

**Severity:** High  
**Files:**
- `crates/aegis-core/src/config.rs:129–141` (WafConfig field doc)
- `crates/aegis-core/src/config.rs:1748–1786` (DdosConfig struct + Default impl)

**Description:**

The `WafConfig.ddos` field documentation (lines 129–141) says:

```
/// Defaults to `enabled: true, observe_only: true` so the detector
/// runs in shadow mode out of the box: every per-IP-flood
/// burst is counted, every spike is observed, but no
/// request is 503'd until the operator flips
/// `observe_only: false` after baking the metrics.
```

The actual `DdosConfig::default()` implementation (line 1774–1786) has:

```rust
impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: false,   // ← ENFORCE, not shadow mode
            ...
        }
    }
}
```

The `DdosConfig.observe_only` field doc at line 1752 agrees with the impl: `"Default `false` — enforce by default."` The conflict is between the `WafConfig` field doc (promises shadow mode) and the actual `Default` impl (enforces by default).

**Impact:** Any operator who reads the `WafConfig` field documentation and skips setting `ddos.observe_only` explicitly will expect shadow-mode behavior (observe but don't block). Actual behavior: all DDoS bursts trigger 403 responses immediately on first deploy. This is a silent security vs. reliability trade-off that is hidden by a doc mismatch, not a config validation gap.

**What the code should do:** Either (a) change `DdosConfig::default()` to `observe_only: true` to match the WafConfig doc, or (b) fix the WafConfig doc to say "defaults to `observe_only: false`" if enforce-by-default is intentional.

---

### CORE-02 — `UpstreamScheme::Tcp` Passes Validation, Fails at Runtime ⚠

**Severity:** High  
**Files:**
- `crates/aegis-core/src/config.rs:852–857` (`UpstreamScheme::Tcp` doc comment)
- `crates/aegis-core/src/config.rs:373–455` (`WafConfig::validate()`)

**Description:**

`UpstreamScheme::Tcp` is declared with an explicit doc comment saying:

```rust
/// Raw TCP byte forwarding (no HTTP framing). Phase 4 work —
/// when set today the forwarder logs an error and returns
/// 502 Bad Gateway with `x-waf-rule-id: tcp-not-implemented`.
Tcp,
```

`WafConfig::validate()` explicitly validates `scheme: tcp` routes (lines 400–426): it requires a non-empty `tcp_destination_allowlist` and validates each allowlist entry. A config with `scheme: tcp` and a valid allowlist **passes `validate()` without error**.

At runtime the forwarder immediately returns `502 Bad Gateway` with `x-waf-rule-id: tcp-not-implemented`.

**Impact:** The validator gives a false green light. An operator who follows the docs, configures a TCP pool, and restarts the WAF will see no error at startup — but every client CONNECT request will fail with an opaque 502. There is no mechanism to fail-fast at boot.

**Suggested fix:** Add a check in `validate_tls_hardening` or `WafConfig::validate()`:

```rust
for (name, pool) in &self.upstreams {
    if pool.connection.scheme == UpstreamScheme::Tcp {
        return Err(WafError::Config(format!(
            "upstream '{name}': scheme=tcp is not yet implemented (Phase 4)"
        )));
    }
}
```

---

### CORE-03 — `CacheProvider` Trait Has No Implementation; `flush_cache` Always `supported: false` ⚠

**Severity:** High  
**Files:**
- `crates/aegis-core/src/cache.rs` (trait only, no implementation)
- `crates/aegis-control/src/interop/control.rs:219–221` (flush_callback field)

**Description:**

`crates/aegis-core/src/cache.rs` defines `CacheProvider` as a trait with three async methods (`get`, `put`, `invalidate`). There is no concrete implementation anywhere in the codebase — no in-memory cache, no Redis cache, no stub.

In `ControlContext`, the `flush_callback` field is:

```rust
/// `flush_cache` callback. `None` = no cache implemented;
/// the endpoint returns `supported: false`.
pub flush_callback: Option<ResetCallback>,
```

The boot path never wires a concrete `CacheProvider` and never sets `flush_callback`. Every call to `POST /__waf_control/flush_cache` returns:

```json
{"ok": true, "action": "flush_cache", "supported": false, "ts_ms": ...}
```

**Contract impact:** WAF Interop Contract v2.3 §9 (`Cache Control`) defines `flush_cache` as a required endpoint. While the contract does not mandate caching to be implemented, returning `supported: false` signals to the benchmark harness that caching is not operational. Any OC test that checks cache behavior after a `flush_cache` call will find stale responses.

---

### CORE-04 — AI `extract_confidence()` Always Returns `None`; `confidence_threshold` Config Has No Effect

**Severity:** Medium  
**Files:**
- `crates/aegis-security/src/detectors/ai/model.rs:155–165`
- `crates/aegis-core/src/config.rs:248–255` (AiConfig.confidence_threshold)

**Description:**

`AiConfig.confidence_threshold` is documented as:

```rust
/// Softmax-confidence threshold above which a non-Normal
/// class is treated as a verdict. Default `0.85`.
pub confidence_threshold: f32,
```

The actual extraction function in the AI detector:

```rust
fn extract_confidence(_outputs: &SessionOutputs, _class_idx: i64) -> Option<f32> {
    // TODO: support the Sequence<Map<i64, f32>> shape produced
    // by sklearn's ONNX exporter...
    None   // ← always None
}
```

When `extract_confidence` returns `None`, the detector falls back to treating every non-Normal argmax class as a confident hit (the comment says "let the detector treat it as a confident hit").

**Impact:** The `confidence_threshold: 0.85` in `AiConfig` is never consulted. Any ONNX model that outputs the sklearn `Sequence<Map<i64, f32>>` shape (the standard sklearn export) will fire on every misclassification regardless of probability, generating high false-positive rates. The `AiConfig.confidence_threshold` field is a no-op config.

---

### CORE-05 — `pool_snapshot_provider` Hardcodes `healthy = total`

**Severity:** Medium  
**Files:**
- `crates/aegis-control/src/dashboard_services.rs:544–578`

**Description:**

```rust
/// All pools report `healthy = total` (every member assumed up)
/// until the cluster runtime lands real per-member health probes.
pub fn pool_snapshot_provider(cfg: &aegis_core::config::WafConfig) -> PoolSnapshotProvider {
    let pools: Vec<PoolHealthEntry> = cfg
        .upstreams
        .iter()
        .map(|(name, pool)| {
            let total = pool.members.len() as u32;
            PoolHealthEntry {
                name: name.clone(),
                healthy: total,   // ← always = total
                total,
            }
        })
        .collect();
    ...
}
```

Operators who configure `health:` blocks in their upstream pools will see per-member probes run (the probe tasks do flip the member's `healthy` `AtomicBool` in `PoolRegistry`). But the dashboard health page always shows `healthy = total` regardless of actual probe results. A pool with 3/4 members healthy is shown as "4/4" in the UI.

**Why this matters:** The operator's only signal that an upstream member is down is the elevated error rate in access logs. The dashboard "scaling" pill stays green even when multiple members have failed health probes.

---

### CORE-06 — `StateBackend::health()` Default Always Returns `BackendHealth::unknown()`

**Severity:** Medium  
**Files:**
- `crates/aegis-core/src/state.rs:155–161`

**Description:**

The default implementation of `health()` on `StateBackend`:

```rust
async fn health(&self) -> BackendHealth {
    BackendHealth::unknown()  // connected: false, backend: "unknown"
}
```

`BackendHealth::unknown()` returns `connected: false`. Any backend that compiles without overriding this method (which is all backends that haven't explicitly implemented the health surface) will appear as "disconnected" in the dashboard.

The in-memory backend and Redis backend do override this. But the pattern means any **new** `StateBackend` implementor — including test stubs and third-party integrations — will show as permanently disconnected unless they remember to override `health()`. The dashboard "data plane status" pill will show red for any unimplemented backend even when it's serving traffic successfully.

**What would be better:** The default should return `BackendHealth { backend: "unknown", connected: true, ... }` — indicating "status unknown but assumed up" — rather than `connected: false` which actively signals a problem that doesn't exist.

---

### CORE-07 — GitOps / Witness / Threat-Intel Tasks Not Wired; TODO at Boot Seam

**Severity:** Medium  
**Files:**
- `crates/aegis-proxy/src/run.rs:1011–1017`
- `crates/aegis-control/src/gitops/poll_driver.rs:26–32`

**Description:**

In `aegis-proxy/src/run.rs`, the boot path explicitly documents an unwired subsystem:

```rust
// TODO(B1-T4 follow-up): when GitOps poll, witness export,
// and threat-intel fetcher are wired into the boot path,
// gate each on a `"leader:<name>"` lease using the same
// `crate::cluster_lease::spawn_with_lease(...)` pattern.
// None of those subsystems run as background tasks today,
// so there's no live code to gate; documenting the seam here
// so the next dev knows where it goes.
```

The `GitPollDriver` in `aegis-control` is a fully-implemented git client (uses `tokio::process` to shell out to `git`), but it is never spawned. The gitops module doc says "Lease gating... happens at the boot site — a TODO at the boot site documents the seam." The seam is the `run.rs` TODO above.

**Impact:** GitOps config sync, witness export, and threat-intel fetches are completely non-operational regardless of configuration. There are no config schema fields to enable these features (no `gitops:` block in `WafConfig`), so operators cannot configure them even if they wanted to.

---

### CORE-08 — `ServiceDiscovery` Trait in `aegis-core` Has No Default Implementation and No Config Field

**Severity:** Medium  
**Files:**
- `crates/aegis-core/src/sd.rs` (trait only)
- `crates/aegis-core/src/config.rs` (no `service_discovery:` field in `WafConfig`)
- `crates/aegis-proxy/src/sd/mod.rs:3–16` (backends are feature-gated)

**Description:**

`aegis-core/src/sd.rs` defines:

```rust
#[async_trait::async_trait]
pub trait ServiceDiscovery: Send + Sync + 'static {
    async fn subscribe(
        &self,
        pool: &str,
    ) -> Result<tokio::sync::watch::Receiver<Vec<MemberAddr>>>;
}
```

There are three concrete implementations — `consul`, `etcd`, `k8s` — all behind Cargo feature flags in `aegis-proxy/src/sd/`. The `WafConfig` struct has no `service_discovery:` configuration field. There is no way for an operator to select or configure an SD backend through the YAML configuration.

**Impact:** The service discovery trait is unreachable from the operator surface. Even if an operator builds the binary with `--features consul`, there is no config key to point the consul watcher at a service name or cluster address. The Consul-specific config (`AEGIS_CONSUL_ADDR`, `AEGIS_CONSUL_TOKEN`) is environment-only.

This is the gap documented in `Implement-Progress.md` as: "service discovery Consul/etcd/k8s adapters: not implemented despite being mentioned in the module doc."

---

### CORE-09 — State Reconcile Modes `latest` and `fail_safe` Parse Successfully but Fail at Boot

**Severity:** Medium  
**Files:**
- `crates/aegis-proxy/src/state/reconcile.rs:38–42`
- `crates/aegis-bin/src/state_select.rs:86–91`

**Description:**

`state.reconcile.mode` is a config field with three accepted values. Two of them immediately fail:

```rust
// state_select.rs:86–91
"state.reconcile.mode = latest is not implemented; use `max` until a Phase B follow-up lands the latest-wins merge".into()

"state.reconcile.mode = fail_safe is not implemented; use `max` until a Phase B follow-up lands the fail-safe merge".into()
```

Both `latest` and `fail_safe` are parsed by the YAML deserializer without error, then raise `WafError::Config` in the boot path — after the config is loaded and validated. This means:

1. `WafConfig::validate()` does **not** catch these modes — they pass silently.
2. The boot path (`aegis-bin`) catches them and returns an error.
3. There is no `validate()` guard in `aegis-core` itself.

**Impact:** Operators writing configs with `state.reconcile.mode: latest` will see a successful `validate()` but a failed boot. The error is loud (boot stops) but the validation gap means tools that run `load_config_str()` and `validate()` as a lint step will not catch the problem.

---

### CORE-10 — `GitPollDriver.config_path` Is `#[allow(dead_code)]`

**Severity:** Low  
**Files:**
- `crates/aegis-control/src/gitops/poll_driver.rs:59–61`

**Description:**

```rust
/// Path of the file the loader watches inside the repo
/// (e.g. `waf.yaml`). Reserved for the "follow this file's
/// last-modifying commit" enhancement; today the trait
/// passes path explicitly via `read_file(sha, path)`, so
/// this just records the operator's intent for future
/// extensions.
#[allow(dead_code)]
config_path: String,
```

The field is populated in `GitPollDriver::new()` but never read by any method. The `#[allow(dead_code)]` annotation suppresses the compiler warning. The enhancement it targets — following a specific file's commit history — is not scheduled.

**Impact:** Low risk, cosmetic waste. Any refactor that removes the field will break `GitPollDriver::new()` call sites.

---

### CORE-11 — `io_driver_fd_count` Runtime Metric Is a No-Op

**Severity:** Low  
**Files:**
- `crates/aegis-control/src/metrics/runtime.rs:105–110`

**Description:**

```rust
// `io_driver_fd_count` requires tokio's
// `io-driver-metrics` cfg in addition to `tokio_unstable`
// — not yet exposed in stable tokio releases as of writing.
// Gauge stays at zero until tokio promotes the API; the
// operator gets a clear "not yet implemented" reading
// rather than a missing series.
```

The `io_driver_fd_count` Prometheus gauge is registered but always reports 0. Operators using it to monitor open file-descriptor counts will always see a flat zero signal.

The `#[cfg(not(tokio_unstable))]` branch is a no-op stub:

```rust
pub fn sample_now(&self) {
    // No-op. Gauges read 0; that's the documented behaviour.
}
```

---

### CORE-12 — Sync Secret Resolver Returns `NotImplemented` for Network Providers

**Severity:** Low  
**Files:**
- `crates/aegis-proxy/src/secrets/mod.rs:106–116`

**Description:**

`resolve_secret()` (sync path) handles only `env` and `file` providers. For `vault`, `aws`, `gcp`, `azure`, and `hsm`, it returns `SecretError::NotImplemented`:

```rust
pub fn resolve_secret(provider: &str, path: &str, _field: Option<&str>) -> Result<SecretValue, SecretError> {
    match provider {
        "env" => { ... }
        "file" => { ... }
        other => Err(SecretError::NotImplemented(format!(
            "Use resolve_secret_async for '{other}'"
        ))),
    }
}
```

This is **intentional** behavior — sync resolution is only for env/file; async resolution handles network providers. However, any code path that calls `resolve_secret()` (sync) and expects all providers to work will silently fail for network-backed secrets. The error message does guide callers to the async path.

---

## Summary Table

| ID | File | Lines | Category | Severity |
|----|------|-------|----------|----------|
| CORE-01 | `aegis-core/src/config.rs` | 129–141 vs 1774–1786 | Logic Conflict | High |
| CORE-02 | `aegis-core/src/config.rs` | 852–857, 373–455 | Not Implemented | High |
| CORE-03 | `aegis-core/src/cache.rs` + `aegis-control/src/interop/control.rs:219` | — | Not Implemented | High |
| CORE-04 | `aegis-security/src/detectors/ai/model.rs` | 155–165 | Not Implemented | Medium |
| CORE-05 | `aegis-control/src/dashboard_services.rs` | 548–577 | Not Implemented | Medium |
| CORE-06 | `aegis-core/src/state.rs` | 155–161 | Not Implemented | Medium |
| CORE-07 | `aegis-proxy/src/run.rs` | 1011–1017 | Not Implemented | Medium |
| CORE-08 | `aegis-core/src/sd.rs` + `WafConfig` | — | Partial Impl | Medium |
| CORE-09 | `aegis-proxy/src/state/reconcile.rs` + `aegis-bin/src/state_select.rs` | 38–42, 86–91 | Partial Impl | Medium |
| CORE-10 | `aegis-control/src/gitops/poll_driver.rs` | 59–61 | Partial Impl | Low |
| CORE-11 | `aegis-control/src/metrics/runtime.rs` | 105–110 | Partial Impl | Low |
| CORE-12 | `aegis-proxy/src/secrets/mod.rs` | 106–116 | Not Implemented | Low |

---

## What Is Fully Implemented in aegis-core

For completeness — the following `aegis-core` modules are clean with no stubs, unimplemented code, or logic conflicts:

| Module | Status |
|--------|--------|
| `audit.rs` — `AuditEvent`, `AuditBus` | ✅ Complete |
| `break_glass.rs` — MTLS-T9 emergency bypass | ✅ Complete |
| `cluster.rs` — `LeaseStore`, `ClusterMembership` traits + types | ✅ Complete (traits only; impls in aegis-proxy) |
| `context.rs` — `RequestCtx`, `RouteCtx`, `ClientInfo` | ✅ Complete |
| `decision.rs` — `Decision`, `Action`, `ChallengeLevel` | ✅ Complete |
| `error.rs` — `WafError`, `Result` | ✅ Complete |
| `health.rs` — `ReadinessSignal` | ✅ Complete |
| `identity.rs` — `ClientIdentity`, MTLS-T1 types | ✅ Complete |
| `lib.rs` — crate re-exports | ✅ Complete |
| `load_mode.rs` — `LoadMode`, `LoadGauge`, `LoadModeConfig` | ✅ Complete |
| `pipeline.rs` — `SecurityPipeline`, `BodyPeek` | ✅ Complete (trait only; impl in aegis-security) |
| `risk.rs` — `RiskKey` | ✅ Complete |
| `state.rs` — `StateBackend` trait + `BackendHealth` types | ✅ Complete (see CORE-06 for default behavior concern) |
| `tcp_destination.rs` — `parse_rule`, `policy_admits` | ✅ Complete |
| `tier.rs` — `Tier`, `FailureMode` | ✅ Complete |
| `verbosity.rs` — `VerbosityLevel`, `SharedVerbosity` | ✅ Complete |

---

## Key Observations

**Pattern: Traits in `aegis-core`, implementations in `aegis-proxy` / `aegis-security`.**
This is by design — `aegis-core` is a pure contracts/types crate with no I/O dependencies. The pattern is consistent and correct. None of the trait-only files in `aegis-core` are bugs by themselves.

**Pattern: "Phase B" deferred work is clearly labeled and fails loudly.**
`state.reconcile.mode: latest`, `state.backend: raft`, `state.redis.cluster: true` all return explicit `WafError::Config` errors at boot via `aegis-bin/src/state_select.rs`. This is the right approach. The gap is that `WafConfig::validate()` in `aegis-core` does not catch them — they pass the in-crate lint but fail the `aegis-bin` boot path.

**Pattern: Config fields that are documented as operative but are not wired.**
CORE-01 (`observe_only` default), CORE-02 (`scheme: tcp`), CORE-04 (`confidence_threshold`), and CORE-08 (no `service_discovery:` config field) all share the same root cause: the config schema offers a surface that either does nothing or behaves differently from what the documentation says.
