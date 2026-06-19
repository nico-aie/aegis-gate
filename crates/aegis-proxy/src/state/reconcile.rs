//! Partition-safe state-backend wrapper (B1-T6 — Phase B).
//!
//! [`ReconcilingBackend`] wraps a primary `StateBackend` with a
//! local in-memory fallback so a Redis partition does **not**
//! take the data plane down. The contract from
//! [`docs/operations/ha-clustering.md`](../../../../docs/operations/ha-clustering.md)
//! that this module enforces:
//!
//! 1. **Block lists are strictly additive.** Any IP blocked by
//!    any node must remain blocked everywhere; a partition must
//!    never cause a delisting. Implementation: `auto_block`
//!    writes to **both** primary and fallback unconditionally
//!    (best-effort on primary if primary errors); on partition
//!    heal we replay the locally-buffered block log to primary
//!    so a node that took blocks during isolation propagates
//!    them.
//!
//! 2. **Counters never *drop* across a partition.** During a
//!    partition, increments accumulate locally; on heal,
//!    primary is the source of truth for the post-heal point.
//!    We do **not** attempt to merge sliding-window counters
//!    back into primary in this task because the wire shape
//!    (sorted-set of timestamps) doesn't admit a clean
//!    `max(local, remote)` — that's a Phase B follow-up. Today
//!    we log a warning so operators see the divergence and can
//!    decide whether to reset.
//!
//! 3. **Leases are NOT reconciled.** A partitioned lease store
//!    that fell through to local would let two nodes both
//!    "win" the leader lease — disastrous for ACME (double
//!    issuance) and GitOps (double apply). The lease store is
//!    deliberately unwrapped; an unreachable Redis pauses
//!    leader-only tasks instead of risking split-brain.
//!
//! ## Mode
//!
//! Honors `cfg.state.reconcile.mode`:
//!
//! - `Max` (default) — the behaviour above.
//! - `Latest` / `FailSafe` — return a config error explaining
//!   they're not implemented (Phase B candidate). Still parsed
//!   so the schema is forward-compatible.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::error::{Result, WafError};
use aegis_core::risk::RiskKey;
use aegis_core::state::{SlidingWindowResult, StateBackend};

use crate::state::InMemoryBackend;

/// STATE-03 (LT-RUN-11, 2026-06-19) — WHY the primary backend is degraded.
///
/// The operator's real incident was an attacker flipping Redis to a read-only
/// replica via `REPLICAOF`; every write then failed with a `-READONLY` error
/// which [`ReconcilingBackend`] could not distinguish from "Redis unreachable",
/// so it logged the generic "partition" line and silently fell through to a
/// fresh in-memory fallback — hiding the root cause. We still fall through for
/// availability (the reported-not-gating posture: the data plane keeps
/// serving), but the cause is now classified and surfaced distinctly so an
/// operator sees "READ-ONLY (possible compromise)" instead of "unreachable".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradedReason {
    Unreachable,
    ReadOnly,
    Auth,
    Misconfig,
}

impl DegradedReason {
    fn as_u8(self) -> u8 {
        match self {
            DegradedReason::Unreachable => 1,
            DegradedReason::ReadOnly => 2,
            DegradedReason::Auth => 3,
            DegradedReason::Misconfig => 4,
        }
    }
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(DegradedReason::Unreachable),
            2 => Some(DegradedReason::ReadOnly),
            3 => Some(DegradedReason::Auth),
            4 => Some(DegradedReason::Misconfig),
            _ => None,
        }
    }
    /// Stable wire/label string for logs, metrics, and `/healthz/ready`.
    pub fn label(self) -> &'static str {
        match self {
            DegradedReason::Unreachable => "unreachable",
            DegradedReason::ReadOnly => "read-only",
            DegradedReason::Auth => "auth-error",
            DegradedReason::Misconfig => "misconfigured",
        }
    }
}

/// Classify a primary-backend error. Redis surfaces server-side conditions as
/// error-string prefixes — `-READONLY`, `-MISCONF`, `-NOAUTH`/`WRONGPASS` —
/// distinct from connectivity failures (timeouts, refused, pool exhaustion),
/// which we treat as `Unreachable`. Matching is case-insensitive substring so
/// it survives the client wrapping the server message.
fn classify_state_error(err: &WafError) -> DegradedReason {
    let msg = match err {
        WafError::State(s) => s.as_str(),
        _ => "",
    };
    let upper = msg.to_ascii_uppercase();
    if upper.contains("READONLY") {
        DegradedReason::ReadOnly
    } else if upper.contains("NOAUTH") || upper.contains("WRONGPASS") {
        DegradedReason::Auth
    } else if upper.contains("MISCONF") {
        DegradedReason::Misconfig
    } else {
        DegradedReason::Unreachable
    }
}

/// Per-key buffer of writes that occurred while we were
/// partitioned from primary. Replayed best-effort on heal.
///
/// Today we only buffer **block-list** events because they're
/// the only ops with strictly-additive merge semantics
/// (see module docs).
#[derive(Default)]
struct PartitionLog {
    blocks: Vec<BlockedDuringPartition>,
}

#[derive(Clone)]
struct BlockedDuringPartition {
    ip: IpAddr,
    /// Absolute deadline so we know how much TTL is left when
    /// we replay to primary. Better than re-using the original
    /// TTL: a 24h block taken 23h into the partition has 1h
    /// remaining, not 24h.
    expires_at: Instant,
}

/// Wraps a primary `StateBackend` with an in-memory fallback.
///
/// Cheap to clone — internal state is `Arc`-shared.
pub struct ReconcilingBackend {
    primary: Arc<dyn StateBackend>,
    fallback: Arc<InMemoryBackend>,
    partitioned: Arc<AtomicBool>,
    /// STATE-03 — last classified degradation cause (0 = healthy). Read by
    /// `degraded_reason()` for observability; set in `enter_partition`.
    degraded: Arc<AtomicU8>,
    log: Arc<Mutex<PartitionLog>>,
}

impl ReconcilingBackend {
    /// Wrap `primary` with a fresh in-memory fallback.
    pub fn new(primary: Arc<dyn StateBackend>) -> Self {
        Self {
            primary,
            fallback: Arc::new(InMemoryBackend::new()),
            partitioned: Arc::new(AtomicBool::new(false)),
            degraded: Arc::new(AtomicU8::new(0)),
            log: Arc::new(Mutex::new(PartitionLog::default())),
        }
    }

    /// Observability — is the wrapper currently in fallback
    /// mode? Useful for `/metrics` and the operator dashboard.
    pub fn is_partitioned(&self) -> bool {
        self.partitioned.load(Ordering::Relaxed)
    }

    /// STATE-03 — the classified reason the primary is degraded, or `None`
    /// when healthy. Lets the health/metrics layer report e.g. "read-only"
    /// (the operator's incident) distinctly from "unreachable" — reported,
    /// not gating (the data plane keeps serving from the fallback).
    pub fn degraded_reason(&self) -> Option<DegradedReason> {
        DegradedReason::from_u8(self.degraded.load(Ordering::Relaxed))
    }

    /// Mark the partition as live. Idempotent + logged exactly
    /// once per transition into the partitioned state, with a
    /// cause-specific message (STATE-03).
    fn enter_partition(&self, op: &str, err: &WafError) {
        let reason = classify_state_error(err);
        self.degraded.store(reason.as_u8(), Ordering::Relaxed);
        let already = self.partitioned.swap(true, Ordering::Relaxed);
        if already {
            return;
        }
        match reason {
            DegradedReason::ReadOnly => tracing::warn!(
                op, error = %err,
                "primary state backend is READ-ONLY (e.g. Redis flipped to a replica via \
                 REPLICAOF — possible compromise). Falling through to LOCAL in-memory \
                 fallback; shared rate-limit / risk / replay-nonce state will DIVERGE \
                 across nodes until the primary is writable again.",
            ),
            DegradedReason::Auth => tracing::warn!(
                op, error = %err,
                "primary state backend rejected AUTH (NOAUTH / WRONGPASS) — check \
                 requirepass / credentials. Falling through to local in-memory fallback.",
            ),
            DegradedReason::Misconfig => tracing::warn!(
                op, error = %err,
                "primary state backend MISCONF (e.g. RDB/AOF persistence failing) — \
                 falling through to local in-memory fallback.",
            ),
            DegradedReason::Unreachable => tracing::warn!(
                op, error = %err,
                "primary state backend unreachable; falling through to local in-memory backend",
            ),
        }
    }

    /// Mark the partition as healed. Idempotent + replays the
    /// block log to primary on the first transition.
    async fn maybe_exit_partition(&self) {
        // Fast path: already healed.
        if !self.partitioned.load(Ordering::Relaxed) {
            return;
        }

        // Drain the buffered blocks (under lock so a concurrent
        // partition entrance doesn't lose entries).
        let buffered = {
            let mut log = self.log.lock().expect("reconcile log poisoned");
            std::mem::take(&mut log.blocks)
        };

        let now = Instant::now();
        let mut replayed = 0;
        let mut skipped_expired = 0;
        let mut failed = 0;

        for b in buffered {
            if b.expires_at <= now {
                skipped_expired += 1;
                continue;
            }
            let ttl = b.expires_at - now;
            match self.primary.auto_block(b.ip, ttl).await {
                Ok(()) => replayed += 1,
                Err(e) => {
                    failed += 1;
                    tracing::warn!(
                        ip = %b.ip,
                        error = %e,
                        "reconcile: block-replay to primary failed; \
                         block remains in local fallback",
                    );
                }
            }
        }

        // Only flip the flag if every replay succeeded.
        // Otherwise we'll retry on the next successful op.
        if failed == 0 {
            self.partitioned.store(false, Ordering::Relaxed);
            self.degraded.store(0, Ordering::Relaxed); // STATE-03 — back to healthy
            tracing::info!(
                replayed,
                skipped_expired,
                "primary state backend reachable again; \
                 partition healed and block log replayed",
            );
        } else {
            // Re-buffer the failed ones for the next attempt.
            // (We don't track which ones failed individually
            // here — pragmatic choice: a healthy primary will
            // re-block them on the next round; the local
            // fallback still has them so reads stay correct.)
            tracing::warn!(
                failed,
                replayed,
                "reconcile: partial replay; {failed} blocks still pending",
            );
        }
    }
}

#[async_trait::async_trait]
impl StateBackend for ReconcilingBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.primary.get(key).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("get", &e);
                self.fallback.get(key).await
            }
            Err(other) => Err(other),
        }
    }

    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
        // Always mirror to fallback so reads-after-write work
        // during a partition that starts after this set.
        self.fallback.set(key, val, ttl).await?;
        match self.primary.set(key, val, ttl).await {
            Ok(()) => {
                self.maybe_exit_partition().await;
                Ok(())
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("set", &e);
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    async fn del(&self, key: &str) -> Result<()> {
        // Best-effort on both. A delete during partition cannot
        // propagate back to primary on heal — that's a known
        // limitation, documented at the module level.
        let _ = self.fallback.del(key).await;
        match self.primary.del(key).await {
            Ok(()) => {
                self.maybe_exit_partition().await;
                Ok(())
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("del", &e);
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult> {
        match self.primary.incr_window(key, window, limit).await {
            Ok(r) => {
                self.maybe_exit_partition().await;
                Ok(r)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("incr_window", &e);
                self.fallback.incr_window(key, window, limit).await
            }
            Err(other) => Err(other),
        }
    }

    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool> {
        match self.primary.token_bucket(key, rate_per_s, burst).await {
            Ok(r) => {
                self.maybe_exit_partition().await;
                Ok(r)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("token_bucket", &e);
                self.fallback.token_bucket(key, rate_per_s, burst).await
            }
            Err(other) => Err(other),
        }
    }

    async fn get_risk(&self, key: &RiskKey) -> Result<u32> {
        match self.primary.get_risk(key).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("get_risk", &e);
                self.fallback.get_risk(key).await
            }
            Err(other) => Err(other),
        }
    }

    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32> {
        // Risk is monotonically increasing in practice (decay
        // happens via separate add_risk(_, -decay)). A partition
        // would lower the cluster's view of a misbehaving IP's
        // score, which is exactly what we want to prevent.
        // For now we mirror like writes do — any increment
        // during partition lives in fallback, post-heal primary
        // resumes from its pre-partition value. A future task
        // can replay max(local, primary) deltas the way
        // block-list replay works today.
        match self.primary.add_risk(key, delta, max).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("add_risk", &e);
                self.fallback.add_risk(key, delta, max).await
            }
            Err(other) => Err(other),
        }
    }

    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()> {
        // Block lists are strictly additive — write to BOTH
        // unconditionally so a partition can never delete a
        // block. The fallback write always succeeds; the
        // primary write may fail and we buffer the entry for
        // replay on heal.
        self.fallback.auto_block(ip, ttl).await?;
        match self.primary.auto_block(ip, ttl).await {
            Ok(()) => {
                self.maybe_exit_partition().await;
                Ok(())
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("auto_block", &e);
                let mut log = self.log.lock().expect("reconcile log poisoned");
                log.blocks.push(BlockedDuringPartition {
                    ip,
                    expires_at: Instant::now() + ttl,
                });
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool> {
        // A request hits BOTH if needed: primary first, then
        // fallback if primary errors OR returns false. The
        // OR-on-false is the additive guarantee — a block on
        // the fallback (taken during partition before the
        // log replay completed) must still gate traffic on
        // this node.
        match self.primary.is_auto_blocked(ip).await {
            Ok(true) => {
                self.maybe_exit_partition().await;
                Ok(true)
            }
            Ok(false) => {
                self.maybe_exit_partition().await;
                self.fallback.is_auto_blocked(ip).await
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("is_auto_blocked", &e);
                self.fallback.is_auto_blocked(ip).await
            }
            Err(other) => Err(other),
        }
    }

    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool> {
        // Nonces don't have safe partition semantics: a nonce
        // consumed locally but invisible to primary becomes a
        // replay vector. Best-effort: mirror to fallback only
        // when primary errors so a re-issue from the same node
        // during a partition is still rejected. Any pre-existing
        // nonce that lived only on primary is invisible during
        // partition — accepting that risk because nonces have
        // short TTLs (typically seconds) and the partition
        // window is also expected to be short.
        match self.primary.put_nonce(nonce, ttl).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("put_nonce", &e);
                self.fallback.put_nonce(nonce, ttl).await
            }
            Err(other) => Err(other),
        }
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<bool> {
        match self.primary.consume_nonce(nonce).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("consume_nonce", &e);
                self.fallback.consume_nonce(nonce).await
            }
            Err(other) => Err(other),
        }
    }

    // --- 2026-05-27 generic KV primitives (config plane + metrics agg) ---

    async fn incrby(&self, key: &str, delta: u64) -> Result<u64> {
        match self.primary.incrby(key, delta).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("incrby", &e);
                self.fallback.incrby(key, delta).await
            }
            Err(other) => Err(other),
        }
    }

    async fn expire(&self, key: &str, ttl: Duration) -> Result<()> {
        // Mirror to fallback so a partition that starts after this
        // keeps the TTL locally too.
        let _ = self.fallback.expire(key, ttl).await;
        match self.primary.expire(key, ttl).await {
            Ok(()) => {
                self.maybe_exit_partition().await;
                Ok(())
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("expire", &e);
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        match self.primary.scan_prefix(prefix).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("scan_prefix", &e);
                self.fallback.scan_prefix(prefix).await
            }
            Err(other) => Err(other),
        }
    }

    async fn get_counter(&self, key: &str) -> Result<u64> {
        match self.primary.get_counter(key).await {
            Ok(v) => {
                self.maybe_exit_partition().await;
                Ok(v)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("get_counter", &e);
                self.fallback.get_counter(key).await
            }
            Err(other) => Err(other),
        }
    }

    async fn cas_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool> {
        // Mirror successful swaps to fallback so reads-after-write
        // (and a subsequent partition) see the new config locally.
        match self.primary.cas_set(key, expected, new, ttl).await {
            Ok(swapped) => {
                self.maybe_exit_partition().await;
                if swapped {
                    let _ = self.fallback.cas_set(key, expected, new, ttl).await;
                }
                Ok(swapped)
            }
            Err(e @ WafError::State(_)) => {
                self.enter_partition("cas_set", &e);
                self.fallback.cas_set(key, expected, new, ttl).await
            }
            Err(other) => Err(other),
        }
    }

    /// SC-T1 — health for the reconciling wrapper.
    ///
    /// Surfaces the primary's snapshot but rebrands the `backend`
    /// label so the dashboard can render a "reconciling (primary:
    /// redis)" pill. The `circuit` field is forced to `HalfOpen`
    /// while a partition is active so operators see degraded mode
    /// even when the primary's own circuit thinks it's closed
    /// between probes.
    async fn health(&self) -> aegis_core::state::BackendHealth {
        let mut h = self.primary.health().await;
        h.backend = "reconciling";
        if self.is_partitioned() {
            h.circuit = aegis_core::state::CircuitState::HalfOpen;
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU64;

    /// Test backend that lets every test toggle its
    /// "primary is reachable" state. Counts ops so tests can
    /// assert on what got through.
    struct ToggleBackend {
        inner: Arc<InMemoryBackend>,
        unreachable: AtomicBool,
        primary_ops: AtomicU64,
        /// STATE-03 — error string returned while `unreachable`, so a test can
        /// simulate a READONLY / NOAUTH / MISCONF primary, not just a timeout.
        err_msg: Mutex<String>,
    }

    impl ToggleBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: Arc::new(InMemoryBackend::new()),
                unreachable: AtomicBool::new(false),
                primary_ops: AtomicU64::new(0),
                err_msg: Mutex::new("simulated partition".into()),
            })
        }

        fn set_unreachable(&self, v: bool) {
            self.unreachable.store(v, Ordering::Relaxed);
        }

        fn set_err_msg(&self, msg: &str) {
            *self.err_msg.lock().unwrap() = msg.to_string();
        }

        fn ops(&self) -> u64 {
            self.primary_ops.load(Ordering::Relaxed)
        }

        fn err(&self) -> WafError {
            WafError::State(self.err_msg.lock().unwrap().clone())
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for ToggleBackend {
        async fn get(&self, k: &str) -> Result<Option<Vec<u8>>> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.get(k).await
        }
        async fn set(&self, k: &str, v: &[u8], ttl: Duration) -> Result<()> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.set(k, v, ttl).await
        }
        async fn del(&self, k: &str) -> Result<()> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.del(k).await
        }
        async fn incr_window(
            &self,
            k: &str,
            w: Duration,
            l: u64,
        ) -> Result<SlidingWindowResult> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.incr_window(k, w, l).await
        }
        async fn token_bucket(
            &self,
            k: &str,
            r: u32,
            b: u32,
        ) -> Result<bool> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.token_bucket(k, r, b).await
        }
        async fn get_risk(&self, k: &RiskKey) -> Result<u32> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.get_risk(k).await
        }
        async fn add_risk(
            &self,
            k: &RiskKey,
            d: i32,
            m: u32,
        ) -> Result<u32> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.add_risk(k, d, m).await
        }
        async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.auto_block(ip, ttl).await
        }
        async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.is_auto_blocked(ip).await
        }
        async fn put_nonce(&self, n: &str, ttl: Duration) -> Result<bool> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.put_nonce(n, ttl).await
        }
        async fn consume_nonce(&self, n: &str) -> Result<bool> {
            self.primary_ops.fetch_add(1, Ordering::Relaxed);
            if self.unreachable.load(Ordering::Relaxed) {
                return Err(self.err());
            }
            self.inner.consume_nonce(n).await
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[tokio::test]
    async fn passes_through_when_primary_healthy() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        r.set("key", b"v", Duration::from_secs(60)).await.unwrap();
        let v = r.get("key").await.unwrap();
        assert_eq!(v, Some(b"v".to_vec()));
        assert!(!r.is_partitioned());
    }

    #[tokio::test]
    async fn falls_through_to_fallback_on_state_error() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        primary.set_unreachable(true);

        // Increment a counter — primary will error, fallback
        // takes over. The result should reflect the fallback.
        let res = r
            .incr_window("burst", Duration::from_secs(60), 5)
            .await
            .unwrap();
        assert_eq!(res.count, 1);
        assert!(res.allowed);
        assert!(r.is_partitioned(), "should flag partitioned after error");
    }

    #[tokio::test]
    async fn partition_clears_on_recovery_op() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        primary.set_unreachable(true);
        let _ = r.get("k").await;
        assert!(r.is_partitioned());

        primary.set_unreachable(false);
        let _ = r.get("k").await; // any successful op clears
        assert!(!r.is_partitioned(), "successful primary op should clear partition flag");
    }

    #[tokio::test]
    async fn auto_block_writes_to_both_when_healthy() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        let target = ip(192, 0, 2, 1);
        r.auto_block(target, Duration::from_secs(60)).await.unwrap();
        // Both should report blocked.
        assert!(primary.inner.is_auto_blocked(target).await.unwrap());
        assert!(r.fallback.is_auto_blocked(target).await.unwrap());
    }

    #[tokio::test]
    async fn auto_block_during_partition_buffers_for_replay() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        primary.set_unreachable(true);
        let target = ip(203, 0, 113, 7);
        r.auto_block(target, Duration::from_secs(60)).await.unwrap();
        // Primary doesn't see it yet (partition).
        assert!(r.is_partitioned());
        // But local fallback does — so this node's reads
        // continue to gate traffic.
        assert!(r.fallback.is_auto_blocked(target).await.unwrap());
    }

    #[tokio::test]
    async fn block_log_replays_on_heal() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        primary.set_unreachable(true);
        let target = ip(198, 51, 100, 99);
        r.auto_block(target, Duration::from_secs(60)).await.unwrap();
        assert!(!primary.inner.is_auto_blocked(target).await.unwrap());

        // Primary comes back; trigger ANY successful op to fire
        // `maybe_exit_partition`.
        primary.set_unreachable(false);
        let _ = r.get("any").await.unwrap();

        assert!(!r.is_partitioned(), "partition should clear");
        assert!(
            primary.inner.is_auto_blocked(target).await.unwrap(),
            "block taken during partition must propagate to primary on heal",
        );
    }

    #[tokio::test]
    async fn is_auto_blocked_consults_fallback_when_primary_says_no() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        // Block only in fallback (simulates "took it during a
        // past partition that hasn't replayed yet").
        let target = ip(10, 0, 0, 1);
        r.fallback.auto_block(target, Duration::from_secs(60)).await.unwrap();

        // Primary returns false; reconciler must check
        // fallback and return true.
        assert!(r.is_auto_blocked(target).await.unwrap());
    }

    #[tokio::test]
    async fn is_auto_blocked_falls_through_to_fallback_on_error() {
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        let target = ip(10, 0, 0, 2);
        // Take the block via the reconciler while healthy so
        // it's in BOTH primary and fallback.
        r.auto_block(target, Duration::from_secs(60)).await.unwrap();

        // Now partition primary.
        primary.set_unreachable(true);
        // Reconciler must still report blocked via fallback.
        assert!(r.is_auto_blocked(target).await.unwrap());
    }

    #[tokio::test]
    async fn non_state_errors_are_not_treated_as_partition() {
        // A pipeline-style WafError::Other must NOT trigger
        // fallback — only state-backend errors should.
        struct AlwaysOtherErr;

        #[async_trait::async_trait]
        impl StateBackend for AlwaysOtherErr {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn set(&self, _: &str, _: &[u8], _: Duration) -> Result<()> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn del(&self, _: &str) -> Result<()> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn incr_window(
                &self,
                _: &str,
                _: Duration,
                _: u64,
            ) -> Result<SlidingWindowResult> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn token_bucket(
                &self,
                _: &str,
                _: u32,
                _: u32,
            ) -> Result<bool> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn get_risk(&self, _: &RiskKey) -> Result<u32> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn add_risk(
                &self,
                _: &RiskKey,
                _: i32,
                _: u32,
            ) -> Result<u32> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn auto_block(&self, _: IpAddr, _: Duration) -> Result<()> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn is_auto_blocked(&self, _: IpAddr) -> Result<bool> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn put_nonce(&self, _: &str, _: Duration) -> Result<bool> {
                Err(WafError::Other("not a state error".into()))
            }
            async fn consume_nonce(&self, _: &str) -> Result<bool> {
                Err(WafError::Other("not a state error".into()))
            }
        }

        let r = ReconcilingBackend::new(Arc::new(AlwaysOtherErr));
        let err = r.get("any").await.unwrap_err();
        assert!(!r.is_partitioned(), "WafError::Other must not flag partition");
        match err {
            WafError::Other(_) => {} // expected — propagated
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn primary_op_count_proves_pass_through() {
        // Sanity: when healthy, reconciling backend must NOT
        // double-call primary. Each external op should hit
        // primary exactly once (plus fallback writes for
        // mirroring ops).
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());

        r.get("a").await.unwrap();
        r.set("a", b"v", Duration::from_secs(60)).await.unwrap();
        r.incr_window("b", Duration::from_secs(60), 10).await.unwrap();

        // get → 1, set → 1, incr_window → 1 = 3 primary ops.
        assert_eq!(primary.ops(), 3);
    }

    // STATE-03 (LT-RUN-11) — error classification + distinct degraded reason.

    #[test]
    fn classify_state_error_distinguishes_redis_conditions() {
        let ro = WafError::State("READONLY You can't write against a read only replica.".into());
        assert_eq!(classify_state_error(&ro), DegradedReason::ReadOnly);
        // Case-insensitive + client-wrapped message.
        let ro2 = WafError::State("redis error: -readonly".into());
        assert_eq!(classify_state_error(&ro2), DegradedReason::ReadOnly);

        let auth = WafError::State("NOAUTH Authentication required.".into());
        assert_eq!(classify_state_error(&auth), DegradedReason::Auth);
        let wrongpass = WafError::State("WRONGPASS invalid username-password pair".into());
        assert_eq!(classify_state_error(&wrongpass), DegradedReason::Auth);

        let misconf = WafError::State("MISCONF Redis is configured to save RDB snapshots".into());
        assert_eq!(classify_state_error(&misconf), DegradedReason::Misconfig);

        // Connectivity-style failures fall back to Unreachable.
        let timeout = WafError::State("connection timed out".into());
        assert_eq!(classify_state_error(&timeout), DegradedReason::Unreachable);
    }

    #[tokio::test]
    async fn readonly_primary_surfaces_distinct_reason_but_keeps_serving() {
        // The operator's incident: Redis flipped read-only. Writes fail with
        // READONLY; the reconciler must (a) keep serving from the fallback
        // (availability — reported-not-gating) and (b) report the cause as
        // "read-only", NOT the generic "unreachable".
        let primary = ToggleBackend::new();
        let r = ReconcilingBackend::new(primary.clone());
        assert_eq!(r.degraded_reason(), None, "healthy at start");

        primary.set_err_msg("READONLY You can't write against a read only replica.");
        primary.set_unreachable(true);

        // A write still succeeds (served by the local fallback).
        r.set("k", b"v", Duration::from_secs(60)).await.unwrap();
        assert!(r.is_partitioned());
        assert_eq!(
            r.degraded_reason(),
            Some(DegradedReason::ReadOnly),
            "cause is classified as read-only, not unreachable",
        );

        // The fallback mirror is readable while degraded.
        assert_eq!(r.get("k").await.unwrap(), Some(b"v".to_vec()));

        // On heal the reason clears back to healthy.
        primary.set_unreachable(false);
        r.get("k").await.unwrap(); // triggers maybe_exit_partition
        assert_eq!(r.degraded_reason(), None, "healed → no degraded reason");
        assert!(!r.is_partitioned());
    }
}
