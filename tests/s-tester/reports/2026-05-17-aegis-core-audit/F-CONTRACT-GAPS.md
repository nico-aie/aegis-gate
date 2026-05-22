---
id: 2026-05-17-aegis-core-contract-gaps
date: 2026-05-17T00:00Z
severity: contract-gap (semantic)
area: cross-crate type discipline
component: crates/aegis-core/src/{health,state,tcp_destination,audit}.rs
interop_contract: cross-crate type sourcing
status: open
test_mode: source-review
---

# F-CONTRACT-GAPS · 4 cross-crate type-layering gaps

These are not bugs at the local type level — each type does what its
author intended in isolation. They are CROSS-CRATE gaps where the
TYPES needed to model a contract requirement live in the wrong place
or are split awkwardly.

---

## C-01 · `health.rs::ReadinessSignal` doesn't expose uptime / mode / active_rule_count

**Component:** [health.rs:1-37](../../../../crates/aegis-core/src/health.rs#L1-L37)

Round-1 mandate (per F-CRITICAL-003 in control audit):

> *Health/Status View: Uptime, Mode, số rule active.*

The Round-1 fields don't fit on `ReadinessSignal` (which models 5
booleans for k8s probes). They need a SIBLING type in aegis-core
that the aegis-control `HealthResponse` can compose.

There's also a fragility: `aegis-control::api::about::boot_ts` and
`cluster::NodeInfo::started_at` (and tracing log timestamps) are
**three independent time sources for "when did this process start"**.

**Fix:** add to aegis-core:

```rust
// aegis-core/src/health.rs
pub struct ProcessInfo {
    started_at: std::time::Instant,
    boot_unix_seconds: u64,
}

impl ProcessInfo {
    pub fn new() -> Self { ... }
    pub fn uptime(&self) -> std::time::Duration { self.started_at.elapsed() }
    pub fn boot_unix_seconds(&self) -> u64 { self.boot_unix_seconds }
}

pub struct StatusSurface {
    pub process: Arc<ProcessInfo>,
    pub mode: Arc<ArcSwap<LoadMode>>,
    pub active_rule_count: Arc<AtomicUsize>,
}
```

`HealthResponse` in aegis-control then composes these fields without
forking time-source.

---

## C-02 · `state.rs::token_bucket` returns bare `bool` — no `retry_after`

**Component:** [state.rs:147-152](../../../../crates/aegis-core/src/state.rs#L147-L152)

```rust
async fn token_bucket(&self, key: &str, rate_per_s: u32, burst: u32) -> Result<bool>;
```

Return type is `bool` — admit or deny. There's NO `retry_after`
field for the deny case.

§3 `rate_limit` decision wants a `Retry-After` HTTP header — the
trait can't carry that data. Consumer code in
`aegis-security/src/rate_limit/sliding.rs:33` works around it via
`result.retry_after`, but that's a different return shape from a
different method.

**Fix:** return a struct:

```rust
pub struct TokenBucketResult {
    pub admitted: bool,
    pub retry_after_s: u32,    // populated when admitted=false
    pub tokens_remaining: f64,
}

async fn token_bucket(&self, key: &str, rate: u32, burst: u32) -> Result<TokenBucketResult>;
```

---

## C-03 · `tcp_destination::is_internal_address` is correct + reusable, but `aegis-control::validate_pool` doesn't call it

**Component:** [tcp_destination.rs:167-186](../../../../crates/aegis-core/src/tcp_destination.rs#L167-L186) (correct) vs `aegis-control/src/api/upstreams_config.rs:252-280` (broken)

The aegis-core internal-IP check IS correct (rejects RFC1918,
link-local, etc.). The `validate_pool` function in aegis-control
that should consult it for SSRF protection (per F-HIGH-MA-02 in
control audit) doesn't.

Cross-crate hygiene gap: a security primitive in aegis-core is
duplicated badly in aegis-control instead of being delegated.

**Fix:** in `aegis-control/src/api/upstreams_config.rs::validate_pool`:

```rust
use aegis_core::tcp_destination;

fn validate_member(member: &Member) -> Result<()> {
    let addr = parse_addr(&member.addr)?;
    if tcp_destination::is_internal_address(addr.ip()) {
        return Err(ValidationError::ForbiddenInternalAddress);
    }
    Ok(())
}
```

Reuses the aegis-core gate. Single source of truth for
internal-IP semantics.

Compounding: aegis-core's gate itself has IPv4-mapped IPv6 + CGNAT
gaps (F-HIGH-domain-types DT-07). Fix that FIRST, then have
aegis-control delegate.

---

## C-04 · `ChainEntry` (audit-chain wrapper) lives in aegis-control, but `AuditEvent` in aegis-core has no chain context

**Component:** [audit.rs:4-18](../../../../crates/aegis-core/src/audit.rs#L4-L18) (aegis-core) vs `aegis-control/src/audit/chain.rs:31` (aegis-control)

`AuditEvent` (aegis-core) is the canonical event shape. `ChainEntry`
(aegis-control) wraps it with `prev_hash`, `entry_hash` for the
hash-chain integrity story.

But:

- The jsonl sink in aegis-control writes BARE `AuditEvent`s — no
  chain context (cross-ref F-CRITICAL-013 in control audit).
- The verifier in aegis-control reads `ChainEntry` from those files
  — schema mismatch on every line.

The schema layering is fragile because `AuditEvent` lacks any
embedded chain context, and there's no enforcement that "files
written by the sink can be read by the verifier".

**Fix (architectural)**: pick one of two approaches.

**Option A — aegis-core owns the chain shape too:**

Move `ChainEntry` from `aegis-control::audit::chain` into
`aegis-core::audit`:

```rust
// aegis-core/src/audit.rs
pub struct ChainEntry {
    pub event: AuditEvent,
    pub prev_hash: String,
    pub entry_hash: String,
}
```

Both sink and verifier consume `ChainEntry` directly. No cross-crate
schema split.

**Option B — `AuditEvent` carries its own hash slot:**

Add optional chain fields directly on `AuditEvent`:

```rust
pub struct AuditEvent {
    // ... existing fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
}
```

Option A is cleaner; B is backwards-compatible.

---

## Severity rationale

Contract-gap level. Each is a layering anomaly that causes
downstream bugs (or has caused them per prior audits). Each fix is
small to medium and unlocks cleaner cross-crate semantics.
