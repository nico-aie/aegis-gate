//! Per-IP risk tracker with lifetime strikes + trust recovery
//! (P6 of the security-toggle plan).
//!
//! # Design
//!
//! The existing [`super::RiskEngine`] operates on a `StateBackend`
//! and is the right surface for distributed deployments where the
//! score must survive a single-node restart. P6's adaptive
//! mitigation needs three more invariants the legacy engine doesn't
//! offer:
//!
//! 1. **Lifetime strikes** — every malicious detection increments
//!    a counter that *never* decays. Once it crosses
//!    `strikes.block_at`, the client is permanently blocked
//!    regardless of how much the float-score has decayed.
//! 2. **Trust recovery** — clean traffic claws back score, but
//!    capped at `trust_recovery.per_hour` to stop a single benign
//!    request from resetting a flagged client.
//! 3. **Adaptive mitigation** — a single `level()` call returns
//!    `Allow` / `Challenge` / `Block` against the configured
//!    `RiskThresholds`, plus a `Block` short-circuit when the
//!    strike counter is exhausted.
//!
//! This module ships an in-process `DashMap`-backed implementation
//! tuned for the hot path. The next iteration replaces the
//! `DashMap` shard with a `StateBackend`-backed shim once cluster
//! membership lands; the public surface stays put.

#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aegis_core::config::{RiskConfig, RiskThresholds, StrikeConfig};
use aegis_core::risk::RiskKey;
use aegis_core::state::{StateBackend, CONTROL_RISK_KEY};
use dashmap::{DashMap, DashSet};

use super::RiskLevel;

const DEFAULT_TRUST_PER_HOUR: u32 = 30;

/// 2026-05-20 (memory-leak audit) — RiskTracker's `map` had no
/// eviction, so under distinct-source-IP attack traffic it grew
/// one `Slot` per unique `RiskKey` forever (freed only by
/// `reset_state`). Mirror `IpRateLimiter`'s self-throttled
/// idle-sweep: at most one sweep per [`IDLE_SWEEP_INTERVAL`],
/// dropping slots untouched for longer than [`IDLE_TTL`].
///
/// The TTL is generous (1 hour ≫ any benchmark window) so the
/// strike-block guarantee holds for ACTIVELY-offending sources —
/// a repeat attacker keeps `last_seen` fresh and is never swept.
/// Only a source that goes fully silent past the TTL is forgotten,
/// which is exactly what trust-recovery already models (its score
/// would have decayed to 0 long before).
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const IDLE_TTL: Duration = Duration::from_secs(3600);

/// PROXY-02 (LT-RUN-11, 2026-06-19) — hard cardinality ceiling. The map is
/// keyed on `RiskKey` (IP + device_fp + **session cookie**), all
/// attacker-controlled, so a flood of unique session cookies inserted one
/// `Slot` per request and (under the 1-hour [`IDLE_TTL`]) grew to tens of
/// millions of live entries → multi-GB heap → OOM, without tripping any
/// detector. Once the map reaches this ceiling we stop tracking BRAND-NEW
/// keys (an untracked key behaves exactly as it did before it was ever seen —
/// `RiskLevel::Allow`); existing keys keep their slots and strike state, so an
/// actively-offending source is never evicted by a cardinality flood.
#[cfg(not(test))]
const MAX_TRACKED_KEYS: usize = 1_000_000;
/// Small in tests so the cap is exercisable without a million inserts (but
/// comfortably above the distinct-key count any other test in this module
/// inserts, so they are unaffected).
#[cfg(test)]
const MAX_TRACKED_KEYS: usize = 64;

// --- 2026-06-24 — durable-flush tuning for the interim Redis durability
// bridge (`redis-interim-durability` P2). Restart-only knobs for now;
// promoted to a `persistence` config block when config H2a lands (§10.3).
//
/// How often the background task flushes the dirty set to Redis. Temporal
/// coalescing: at most one durable write per key per interval, no matter how
/// many strikes it took in between.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
/// Max fields written per flush tick (highest-strike-first; the overflow is
/// re-marked dirty and flushed next tick). Bounds the per-tick Redis work
/// under an IP flood so persistence can never monopolise the shared pool.
#[cfg(not(test))]
const PER_TICK_FIELD_CAP: usize = 4096;
/// Small in tests so the highest-strike-first overflow path is exercisable
/// without thousands of inserts.
#[cfg(test)]
const PER_TICK_FIELD_CAP: usize = 4;
/// Fields per `hset_multi` round-trip — network batching so a 4k-field tick
/// is a handful of pipelined commands, not 4k.
#[cfg(not(test))]
const HSET_CHUNK: usize = 256;
/// One field per chunk in tests so the per-chunk reset-fence abort path is
/// exercisable with a handful of keys.
#[cfg(test)]
const HSET_CHUNK: usize = 1;

/// Zero-value slots (score 0 AND no strikes — e.g. the clean-traffic cookie
/// flood above) carry no security signal, so they are swept on a much shorter
/// idle horizon than scored/striking slots, which keep the generous
/// [`IDLE_TTL`] so the strike-block guarantee holds for real offenders.
const ZERO_VALUE_IDLE_TTL: Duration = Duration::from_secs(120);

/// Snapshot of one client's risk state. Returned from every
/// mutating call so the caller can act on the post-state without
/// a follow-up read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiskState {
    pub score: u32,
    pub strikes: u32,
    pub last_seen: Instant,
}

/// Wire-friendly snapshot for `/api/risk` responses.
///
/// 2026-05-19 — `device_fp` + `session` surfaced so the dashboard's
/// Top Attackers table can distinguish two browsers on the same
/// NAT'd IP. Both fields are `Option<String>` and use
/// `skip_serializing_if = "Option::is_none"` so legacy JSON
/// consumers continue to see the IP-only shape on rows where the
/// composite axes are absent (plain-HTTP traffic, anonymous
/// public endpoints).
#[derive(Clone, Debug, serde::Serialize)]
pub struct RiskSnapshot {
    pub ip: String,
    /// 16-hex-char blake3 prefix of `(JA4 ‖ User-Agent)`. Stable
    /// across requests within a TLS session. Absent on plain HTTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_fp: Option<String>,
    /// Session cookie value (typically a short opaque id). Absent
    /// when no recognised session cookie is sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub score: u32,
    pub strikes: u32,
    /// Seconds since the client's last request — useful for the
    /// dashboard "stale row" indicator. `last_seen` itself isn't
    /// surfaced because `Instant` doesn't serialise; we expose the
    /// elapsed delta instead.
    pub idle_seconds: u64,
    pub level: &'static str,
    pub strike_blocked: bool,
}

/// In-process per-IP risk store. Cheap to clone (Arc-shared).
#[derive(Clone)]
pub struct RiskTracker {
    inner: Arc<TrackerInner>,
}

struct TrackerInner {
    /// 2026-05-18 F-CRITICAL-001 (security audit, Phase E): the
    /// store key is now `RiskKey` (composite of IP + device_fp +
    /// session + tenant) instead of bare `IpAddr`. Storage shape
    /// upgrade only — the IP-only methods (`record_malicious(ip)`,
    /// `level(ip)`, …) keep working by constructing
    /// `RiskKey::from_ip(ip)` internally. The new `*_with_key`
    /// methods take the full composite key. IP-only and composite
    /// callers populate DIFFERENT buckets (different keys), which
    /// is exactly the audit's intent: "don't conflate sessions on
    /// the same NAT'd IP".
    map: DashMap<aegis_core::risk::RiskKey, Slot>,
    /// CI-T12 — thresholds are atomically swappable so
    /// `PUT /api/risk/thresholds` can hot-apply new values
    /// without a restart. Reads through `Arc::clone` (free)
    /// and the inner clone is cheap (3 u32s).
    thresholds: arc_swap::ArcSwap<RiskThresholds>,
    /// Linear decay rate (points/hour). Atomic so `PUT /api/risk/thresholds`
    /// can hot-tune it (and the cluster reload helper can sync it across
    /// nodes) without a restart — see [`RiskTracker::set_trust_per_hour`].
    trust_per_hour: AtomicU32,
    /// 2026-05-10 — wrapped in ArcSwap so `PUT /api/gates/strikes`
    /// can hot-flip `enabled` and tune `block_at` without a
    /// restart. Per-IP strike *state* in `map` is preserved
    /// across edits — operators tightening thresholds don't
    /// reset every accumulating IP.
    strikes: arc_swap::ArcSwap<StrikeConfig>,
    /// Throttle anchor for [`RiskTracker::maybe_sweep`] — last
    /// time the idle-eviction pass ran. Mirrors
    /// `IpRateLimiter::last_sweep`.
    last_sweep: parking_lot::Mutex<Instant>,
    /// 2026-06-24 — durable-store handle for the interim Redis durability
    /// bridge (`redis-interim-durability` P2). `None` until
    /// [`RiskTracker::attach_backend`] is called post-construction in
    /// `run()` — the tracker is built (`run.rs:513`) BEFORE the state
    /// backend exists (`run.rs:874`), so a constructor arg can't reach it;
    /// the seam is a settable cell instead. `OnceLock` gives set-once
    /// semantics with lock-free reads through the shared `Arc<TrackerInner>`
    /// that every clone of the tracker points at.
    backend: std::sync::OnceLock<Arc<dyn StateBackend>>,
    /// 2026-06-24 (P2) — keys mutated since the last durable flush. The hot
    /// path only ever *inserts* a key here (a cheap concurrent-set op, no
    /// I/O); the background flush task drains it. Populated ONLY when a
    /// backend is attached AND the slot carries a strike, so the no-Redis
    /// path stays empty and an IP flood of clean traffic never grows it
    /// (§9 invariant 2).
    dirty: DashSet<RiskKey>,
    /// 2026-06-24 (P2) — monotonic reset fence. Bumped by every state-clearing
    /// op (`reset_all`, `reset_with_key`). An in-flight `flush_once` captures
    /// it at the start and aborts its remaining chunk writes if it changed —
    /// so a flush can't re-write a strike that an operator/bench reset
    /// (`HDEL` / `UNLINK`) removed mid-flush and resurrect it on the next boot.
    reset_gen: std::sync::atomic::AtomicU64,
}

#[derive(Copy, Clone, Debug)]
struct Slot {
    score: u32,
    strikes: u32,
    last_seen: Instant,
}

impl RiskTracker {
    /// Build a tracker from a config snapshot. Fields not present
    /// in `RiskConfig` (e.g. trust recovery off) fall back to
    /// sensible defaults — the legacy engine still runs alongside.
    pub fn new(cfg: &RiskConfig) -> Self {
        Self {
            inner: Arc::new(TrackerInner {
                map: DashMap::new(),
                thresholds: arc_swap::ArcSwap::from_pointee(cfg.thresholds.clone()),
                trust_per_hour: AtomicU32::new(
                    cfg.trust_recovery.clone().unwrap_or_default().per_hour,
                ),
                strikes: arc_swap::ArcSwap::from_pointee(
                    cfg.strikes.clone().unwrap_or_default(),
                ),
                last_sweep: parking_lot::Mutex::new(Instant::now()),
                backend: std::sync::OnceLock::new(),
                dirty: DashSet::new(),
                reset_gen: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// 2026-06-24 — attach the shared state backend post-construction so
    /// the P2 durability flush/hydrate (A2) can persist lifetime strikes
    /// to `control:waf:risk`. Called once from `run()` AFTER the backend
    /// is resolved, under `#[cfg(feature = "redis")]`. Propagates to every
    /// clone of the tracker (they share one `Arc<TrackerInner>`). A0 stores
    /// the handle only — there is no read path yet, so this is inert.
    /// Idempotent: a second call is ignored (the backend is fixed for the
    /// process lifetime once resolved).
    pub fn attach_backend(&self, backend: Arc<dyn StateBackend>) {
        let _ = self.inner.backend.set(backend);
    }

    /// Test/A2 seam: the currently attached backend, if any.
    pub fn backend(&self) -> Option<Arc<dyn StateBackend>> {
        self.inner.backend.get().cloned()
    }

    // --- 2026-06-24 (redis-interim-durability P2) — durable strikes. ---

    /// Hot-path dirty-marker. Cheap: a `OnceLock::get` (effectively free) to
    /// skip entirely on the no-Redis path, then one concurrent-set insert.
    /// Never does I/O.
    #[inline]
    fn mark_dirty(&self, key: &RiskKey) {
        if self.inner.backend.get().is_some() {
            self.inner.dirty.insert(key.clone());
        }
    }

    /// Spawn the background durability tasks: a one-shot boot hydrate (loads
    /// persisted strikes WITHOUT blocking readiness) and the periodic flush
    /// loop. Call once from `run()` after [`attach_backend`]; both tasks
    /// no-op effectively without a backend (empty dirty set / empty hash).
    /// Returns the flush task handle; the caller may drop it to detach
    /// (fire-and-forget, the established pattern) or hold it to join/abort.
    ///
    /// [`attach_backend`]: Self::attach_backend
    pub fn spawn_persistence(&self) -> tokio::task::JoinHandle<()> {
        // Boot hydrate — background so a cold start under attack enforces
        // from a fresh DashMap immediately while history backfills behind it
        // (§9 invariant 4).
        let hydrator = self.clone();
        tokio::spawn(async move {
            hydrator.hydrate().await;
        });
        // Periodic flush.
        let flusher = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLUSH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                flusher.flush_once().await;
            }
        })
    }

    /// Flush the dirty set to `control:waf:risk` (one tick). Drains the dirty
    /// set, keeps only struck slots still present in the map (the write
    /// filter), caps the batch highest-strike-first (overflow re-dirtied),
    /// and writes in pipelined `hset_multi` chunks. On a backend error
    /// (incl. the bounded checkout-timeout under pool contention) it
    /// re-marks the unflushed keys dirty and returns — never blocks the hot
    /// path, never expands its connection budget (§9 invariant 1). No-op
    /// without a backend.
    pub async fn flush_once(&self) {
        let Some(backend) = self.backend() else {
            return;
        };
        // Reset fence — captured before the snapshot. If any reset bumps it
        // during our async writes, we abort + re-dirty the remainder so we
        // never resurrect a reset-removed strike (see `reset_gen`).
        let gen0 = self.inner.reset_gen.load(std::sync::atomic::Ordering::Acquire);
        // Drain the dirty set in one pass (retain-false removes).
        let mut keys: Vec<RiskKey> = Vec::new();
        self.inner.dirty.retain(|k| {
            keys.push(k.clone());
            false
        });
        if keys.is_empty() {
            return;
        }
        let now = Instant::now();
        let now_wall = SystemTime::now();
        // Build (key, strikes, field, json) for keys still present + struck.
        let mut entries: Vec<(RiskKey, u32, String, Vec<u8>)> = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(slot) = self.inner.map.get(&key).map(|e| *e) else {
                continue; // swept or reset since marked — nothing to persist
            };
            if slot.strikes == 0 {
                continue; // write filter
            }
            let (Some(field), Ok(json)) = (
                risk_field(&key),
                serde_json::to_vec(&slot_to_durable(&slot, now, now_wall)),
            ) else {
                continue;
            };
            entries.push((key, slot.strikes, field, json));
        }
        if entries.is_empty() {
            return;
        }
        // Per-tick cap, highest-strike-first; overflow deferred to next tick.
        if entries.len() > PER_TICK_FIELD_CAP {
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            for (key, ..) in entries.drain(PER_TICK_FIELD_CAP..) {
                self.inner.dirty.insert(key);
            }
        }
        // Pipelined chunked writes; abort + re-dirty the remainder on error.
        let mut flushed = 0usize;
        let total = entries.len();
        for chunk in entries.chunks(HSET_CHUNK) {
            // Abort if a reset landed since our snapshot — its HDEL/UNLINK has
            // run (or is about to), so writing now would resurrect cleared
            // strikes. Re-dirty the remainder; the next tick re-reads the map
            // (reset-removed keys are gone → silently dropped).
            if self.inner.reset_gen.load(std::sync::atomic::Ordering::Acquire) != gen0 {
                for (key, ..) in &entries[flushed..] {
                    self.inner.dirty.insert(key.clone());
                }
                tracing::debug!(flushed, "risk flush: aborted by concurrent reset");
                return;
            }
            let fields: Vec<(String, Vec<u8>)> = chunk
                .iter()
                .map(|(_, _, f, j)| (f.clone(), j.clone()))
                .collect();
            if let Err(e) = backend.hset_multi(CONTROL_RISK_KEY, &fields).await {
                // Re-dirty everything not yet written (this chunk onward) and
                // bail — persistence yields, enforcement is untouched.
                for (key, ..) in &entries[flushed..] {
                    self.inner.dirty.insert(key.clone());
                }
                tracing::warn!(
                    error = %e,
                    flushed,
                    deferred = total - flushed,
                    "risk flush: deferred on backend contention",
                );
                return;
            }
            flushed += chunk.len();
        }
        tracing::debug!(flushed, "risk flush: persisted struck slots");
    }

    /// Boot hydration (P2): load persisted struck slots from
    /// `control:waf:risk` into the live `DashMap`, re-anchoring each
    /// `last_seen` onto this process's clock. Respects `MAX_TRACKED_KEYS`
    /// and never clobbers a live entry (`or_insert`), so concurrent traffic
    /// during warm-up wins. A corrupt field is skipped, not fatal. No-op
    /// without a backend.
    pub async fn hydrate(&self) {
        let Some(backend) = self.backend() else {
            return;
        };
        let fields = match backend.hscan(CONTROL_RISK_KEY).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "risk hydrate: hscan failed");
                return;
            }
        };
        let now = Instant::now();
        let now_wall = SystemTime::now();
        let mut loaded = 0usize;
        for (field, bytes) in fields {
            let Some(key) = risk_key_from_field(&field) else {
                continue;
            };
            let Ok(durable) = serde_json::from_slice::<DurableSlot>(&bytes) else {
                continue;
            };
            if durable.strikes == 0 {
                continue; // defensive: only struck slots are durable-relevant
            }
            // A live entry already won (concurrent traffic during warm-up) —
            // skip without consuming a cardinality slot or counting it, so the
            // cap isn't hit prematurely and `loaded` reflects real restores.
            if self.inner.map.contains_key(&key) {
                continue;
            }
            if !self.may_insert_new_key() {
                break; // cardinality cap — stop hydrating new keys
            }
            let slot = slot_from_durable(&durable, now, now_wall);
            // `or_insert` guards the narrow contains_key→insert race: a key
            // that appeared in between is left untouched (live still wins).
            self.inner.map.entry(key).or_insert(slot);
            loaded += 1;
        }
        if loaded > 0 {
            tracing::info!(loaded, "risk strikes hydrated from durable store");
        }
    }

    /// Reset hook (async half) — `UNLINK` the whole durable risk hash. O(1)
    /// wall-time (single hash, not per-key), so `reset_state` stays fast
    /// under bench churn (§9 invariant 3). No-op without a backend.
    pub async fn unlink_durable(&self) {
        let Some(backend) = self.backend() else {
            return;
        };
        if let Err(e) = backend.unlink(CONTROL_RISK_KEY).await {
            tracing::warn!(error = %e, "risk reset: durable unlink failed");
        }
    }

    /// Per-key durable forget — `HDEL` one operator-reset key from the
    /// durable hash so it doesn't resurrect on the next boot (§4). Also
    /// drops any pending dirty mark for it. No-op without a backend.
    pub async fn forget_durable(&self, key: &RiskKey) {
        self.inner.dirty.remove(key);
        let Some(backend) = self.backend() else {
            return;
        };
        let Some(field) = risk_field(key) else {
            return;
        };
        if let Err(e) = backend.hdel(CONTROL_RISK_KEY, &[field]).await {
            tracing::warn!(error = %e, "risk reset: durable hdel failed");
        }
    }

    /// 2026-05-20 — self-throttled idle eviction. Drops `Slot`s
    /// untouched for longer than [`IDLE_TTL`]; runs at most once
    /// per [`IDLE_SWEEP_INTERVAL`]. Called from the record paths so
    /// the map stays bounded under high-cardinality (distinct-IP /
    /// distinct-session) traffic without a dedicated reaper task.
    /// Hot-path cost is one `try_lock` on the common (no-sweep)
    /// path. Identical pattern to `IpRateLimiter::maybe_sweep`.
    fn maybe_sweep(&self, now: Instant) {
        let mut guard = match self.inner.last_sweep.try_lock() {
            Some(g) => g,
            None => return,
        };
        if now.saturating_duration_since(*guard) < IDLE_SWEEP_INTERVAL {
            return;
        }
        *guard = now;
        drop(guard);

        self.inner.map.retain(|_, slot| {
            let ttl = if slot.score == 0 && slot.strikes == 0 {
                ZERO_VALUE_IDLE_TTL
            } else {
                IDLE_TTL
            };
            now.saturating_duration_since(slot.last_seen) < ttl
        });
    }

    /// PROXY-02 — may a brand-new `RiskKey` be inserted? `false` once the map
    /// hits [`MAX_TRACKED_KEYS`], which bounds memory under a unique-key
    /// (session-cookie) flood. Approximate by design: a few concurrent inserts
    /// may race past the ceiling, which is harmless.
    fn may_insert_new_key(&self) -> bool {
        self.inner.map.len() < MAX_TRACKED_KEYS
    }

    /// 2026-05-10 — atomic Strike-Block config swap. The next
    /// `is_strike_blocked()` call sees the new `enabled` /
    /// `block_at`. Per-IP strike counters in `map` survive the
    /// swap: operators flipping the gate on/off or tightening
    /// the threshold mid-incident don't get a free reset.
    pub fn set_strike_config(&self, c: StrikeConfig) {
        self.inner.strikes.store(Arc::new(c));
    }

    /// Snapshot the current Strike-Block config — used by
    /// `/api/gates/strikes` GET, the `before` capture in the
    /// audit-mutated PUT, and tests.
    pub fn strike_config_snapshot(&self) -> StrikeConfig {
        (**self.inner.strikes.load()).clone()
    }

    /// CI-T12 — atomic threshold swap. The next `level()` /
    /// `record_*` call sees the new values; in-flight observations
    /// finish on whichever pointer they captured. `max` is enforced
    /// going forward only (existing scores aren't re-clamped).
    pub fn set_thresholds(&self, t: RiskThresholds) {
        self.inner.thresholds.store(Arc::new(t));
    }

    /// Snapshot the current thresholds — used by `/api/risk/thresholds`
    /// GET and tests.
    pub fn thresholds(&self) -> RiskThresholds {
        (**self.inner.thresholds.load()).clone()
    }

    /// Linear decay rate (points per hour) applied to the cumulative score,
    /// both as trust-recovery on clean traffic and as decay-on-read. Surfaced
    /// to `/api/risk/thresholds` so the dashboard shows the real rate.
    pub fn trust_per_hour(&self) -> u32 {
        self.inner.trust_per_hour.load(Ordering::Relaxed)
    }

    /// Hot-swap the linear decay rate (points/hour). Used by the audit-mutated
    /// `PUT /api/risk/thresholds` and the cluster reload helper so a decay-rate
    /// change applies live and converges across nodes. Per-IP score state is
    /// preserved — only the rate at which it ages changes.
    pub fn set_trust_per_hour(&self, per_hour: u32) {
        self.inner.trust_per_hour.store(per_hour, Ordering::Relaxed);
    }

    /// Register a malicious event. Adds `delta` to the score
    /// (clamped at `max`) and increments the lifetime strike
    /// counter by one. Returns the post-state.
    pub fn record_malicious(&self, ip: IpAddr, delta: u32) -> RiskState {
        self.record_malicious_at(ip, delta, Instant::now())
    }

    /// `record_malicious` with an explicit clock — kept public for
    /// deterministic tests.
    pub fn record_malicious_at(
        &self,
        ip: IpAddr,
        delta: u32,
        now: Instant,
    ) -> RiskState {
        self.record_malicious_at_with_key(
            aegis_core::risk::RiskKey::from_ip(ip),
            delta,
            now,
        )
    }

    /// 2026-05-18 F-CRITICAL-001 (security audit, Phase E):
    /// composite-key variant of [`record_malicious`]. Caller
    /// builds the full `RiskKey` (IP + device_fp + session +
    /// tenant) and gets a bucket scoped to that exact tuple. Two
    /// sessions on the same NAT'd IP accumulate independent risk.
    pub fn record_malicious_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        delta: u32,
    ) -> RiskState {
        self.record_malicious_at_with_key(key, delta, Instant::now())
    }

    /// Composite-key + explicit-clock variant (deterministic tests).
    pub fn record_malicious_at_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        delta: u32,
        now: Instant,
    ) -> RiskState {
        let max = self.inner.thresholds.load().max;
        let per_hour = self.inner.trust_per_hour.load(Ordering::Relaxed);
        let state = if let Some(mut entry) = self.inner.map.get_mut(&key) {
            // Age the stored score for time elapsed since last touch, THEN add
            // the new strike's delta — so the decay-on-read value and the
            // post-malicious value agree (no jump back up to a stale peak).
            let decayed = decayed_slot(*entry, now, per_hour).score;
            entry.score = (decayed + delta).min(max);
            entry.strikes = entry.strikes.saturating_add(1);
            entry.last_seen = now;
            let snapshot = slot_to_state(*entry);
            drop(entry);
            // P2 — a stored strike is durable-relevant; mark dirty (no I/O,
            // backend-gated). The clean path deliberately does NOT mark:
            // strikes never decay, and score decay is recomputed on read from
            // the persisted wall-clock anchor, so persisting on malicious-only
            // keeps the dirty set bounded to struck keys while preserving the
            // "permanent block survives restart" guarantee.
            self.mark_dirty(&key);
            snapshot
        } else if self.may_insert_new_key() {
            let slot = Slot { score: delta.min(max), strikes: 1, last_seen: now };
            self.inner.map.insert(key.clone(), slot);
            self.mark_dirty(&key);
            slot_to_state(slot)
        } else {
            // PROXY-02 — at the cardinality cap: don't persist this new key.
            // Return the would-be state so this single request is still scored,
            // but nothing is stored (no accumulation across a flood).
            slot_to_state(Slot { score: delta.min(max), strikes: 1, last_seen: now })
        };
        self.maybe_sweep(now);
        state
    }

    /// Register a clean request. Applies the trust-recovery cap
    /// based on time since the last touch. Strikes never change
    /// here — only score decays.
    pub fn record_clean(&self, ip: IpAddr) -> RiskState {
        self.record_clean_at(ip, Instant::now())
    }

    pub fn record_clean_at(&self, ip: IpAddr, now: Instant) -> RiskState {
        self.record_clean_at_with_key(
            aegis_core::risk::RiskKey::from_ip(ip),
            now,
        )
    }

    /// Composite-key variant of [`record_clean`]. See
    /// `record_malicious_with_key` for the migration rationale.
    pub fn record_clean_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
    ) -> RiskState {
        self.record_clean_at_with_key(key, Instant::now())
    }

    pub fn record_clean_at_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        now: Instant,
    ) -> RiskState {
        let state = if let Some(mut entry) = self.inner.map.get_mut(&key) {
            let elapsed = now.saturating_duration_since(entry.last_seen);
            let recovery = trust_decay_points(elapsed, self.inner.trust_per_hour.load(Ordering::Relaxed));
            entry.score = entry.score.saturating_sub(recovery);
            entry.last_seen = now;
            slot_to_state(*entry)
        } else if self.may_insert_new_key() {
            let slot = Slot { score: 0, strikes: 0, last_seen: now };
            self.inner.map.insert(key, slot);
            slot_to_state(slot)
        } else {
            // PROXY-02 — at the cardinality cap: a clean, never-seen key has
            // zero security value, so don't persist it. Behaves as Allow.
            slot_to_state(Slot { score: 0, strikes: 0, last_seen: now })
        };
        self.maybe_sweep(now);
        state
    }

    /// Read the current state without mutating. Applies decay-on-read so the
    /// returned score reflects time elapsed since the IP's last request.
    pub fn snapshot(&self, ip: IpAddr) -> Option<RiskState> {
        self.snapshot_with_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// IP-only, explicit-clock read variant (deterministic tests).
    pub fn snapshot_at(&self, ip: IpAddr, now: Instant) -> Option<RiskState> {
        self.snapshot_with_key_at(&aegis_core::risk::RiskKey::from_ip(ip), now)
    }

    /// Composite-key variant of [`snapshot`].
    pub fn snapshot_with_key(
        &self,
        key: &aegis_core::risk::RiskKey,
    ) -> Option<RiskState> {
        self.snapshot_with_key_at(key, Instant::now())
    }

    /// Composite-key + explicit-clock read variant. Applies decay-on-read
    /// (see [`decayed_slot`]) — the score is aged by elapsed time without
    /// mutating the store, so the gate decision and `/api/risk` view age
    /// consistently even for an IP that has gone silent.
    pub fn snapshot_with_key_at(
        &self,
        key: &aegis_core::risk::RiskKey,
        now: Instant,
    ) -> Option<RiskState> {
        let per_hour = self.inner.trust_per_hour.load(Ordering::Relaxed);
        self.inner
            .map
            .get(key)
            .map(|e| slot_to_state(decayed_slot(*e, now, per_hour)))
    }

    /// Adaptive mitigation decision for a given IP. Strike-block
    /// short-circuits to `Block` regardless of score — that's the
    /// "permanent block on repeated offence" guarantee from the
    /// requirements.
    pub fn level(&self, ip: IpAddr) -> RiskLevel {
        self.level_for_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// IP-only, explicit-clock variant of [`level`] (deterministic tests).
    pub fn level_at(&self, ip: IpAddr, now: Instant) -> RiskLevel {
        self.level_for_key_at(&aegis_core::risk::RiskKey::from_ip(ip), now)
    }

    /// Composite-key variant of [`level`].
    pub fn level_for_key(&self, key: &aegis_core::risk::RiskKey) -> RiskLevel {
        self.level_for_key_at(key, Instant::now())
    }

    /// Composite-key + explicit-clock variant. Evaluates against the
    /// decay-on-read score so a quiet IP's gate level relaxes over time,
    /// while strike-block (which never decays) still short-circuits to Block.
    pub fn level_for_key_at(
        &self,
        key: &aegis_core::risk::RiskKey,
        now: Instant,
    ) -> RiskLevel {
        let Some(state) = self.snapshot_with_key_at(key, now) else {
            return RiskLevel::Allow;
        };
        if self.is_strike_blocked_for_key(key) {
            return RiskLevel::Block;
        }
        let t = self.inner.thresholds.load();
        // 2026-05-21 — cumulative-gate master toggle. When off, the
        // accumulated score never gates traffic (it's still recorded
        // for forensics). Strike-block above is a separate gate.
        if !t.enabled {
            return RiskLevel::Allow;
        }
        if state.score >= t.block_at {
            RiskLevel::Block
        } else if state.score >= t.challenge_at {
            RiskLevel::Challenge
        } else {
            RiskLevel::Allow
        }
    }

    /// 2026-05-10 — Option B per-tier evaluation. Same shape as
    /// [`level`] but uses caller-supplied `challenge_at` /
    /// `block_at` thresholds instead of the global config. Used by
    /// the data plane after route resolution to honor per-tier
    /// `cumulative_challenge_at` / `cumulative_block_at` overrides.
    /// Strike-block check is unchanged (it doesn't have a per-tier
    /// concept — it's a gate-level shedder).
    pub fn level_with(&self, ip: IpAddr, challenge_at: u32, block_at: u32) -> RiskLevel {
        self.level_with_for_key(
            &aegis_core::risk::RiskKey::from_ip(ip),
            challenge_at,
            block_at,
        )
    }

    /// Composite-key variant of [`level_with`].
    pub fn level_with_for_key(
        &self,
        key: &aegis_core::risk::RiskKey,
        challenge_at: u32,
        block_at: u32,
    ) -> RiskLevel {
        if self.is_strike_blocked_for_key(key) {
            return RiskLevel::Block;
        }
        // 2026-05-21 — cumulative-gate master toggle (global config),
        // honored even when per-tier cumulative thresholds are passed.
        if !self.inner.thresholds.load().enabled {
            return RiskLevel::Allow;
        }
        let Some(state) = self.snapshot_with_key(key) else {
            return RiskLevel::Allow;
        };
        if state.score >= block_at {
            RiskLevel::Block
        } else if state.score >= challenge_at {
            RiskLevel::Challenge
        } else {
            RiskLevel::Allow
        }
    }

    /// `true` when the IP's lifetime strike counter has crossed
    /// the configured threshold AND the Strike-Block gate is
    /// enabled. With `enabled = false` (the 2026-05-10 default)
    /// this always returns `false` regardless of strike count
    /// — the counter still climbs in `/api/risk` for forensics
    /// but the data plane does not 403.
    pub fn is_strike_blocked(&self, ip: IpAddr) -> bool {
        self.is_strike_blocked_for_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// Composite-key variant of [`is_strike_blocked`].
    pub fn is_strike_blocked_for_key(
        &self,
        key: &aegis_core::risk::RiskKey,
    ) -> bool {
        let cfg = self.inner.strikes.load();
        if !cfg.enabled {
            return false;
        }
        self.snapshot_with_key(key)
            .map(|s| s.strikes >= cfg.block_at)
            .unwrap_or(false)
    }

    /// Operator override: clear an IP's strikes and zero its
    /// score. Returns `true` if a row was removed. Gated by the
    /// `AuditedMutate` pipeline at the API layer.
    pub fn reset(&self, ip: IpAddr) -> bool {
        self.reset_with_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// Composite-key variant of [`reset`].
    pub fn reset_with_key(&self, key: &aegis_core::risk::RiskKey) -> bool {
        // Bump the fence BEFORE the removal so a concurrent flush that already
        // snapshotted this key aborts its remaining writes (P2 §4 — the
        // durable HDEL is issued by `forget_durable` at the handler).
        self.inner
            .reset_gen
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.inner.dirty.remove(key);
        self.inner.map.remove(key).is_some()
    }

    /// Drop every tracked IP — score, strikes, last-seen.
    /// Used by the external control plane's `reset_state` to
    /// wipe runtime state between phases. Also drops the pending
    /// dirty set (nothing left to flush); the durable hash is wiped
    /// separately by [`unlink_durable`] on the async reset half (§4).
    ///
    /// [`unlink_durable`]: Self::unlink_durable
    pub fn reset_all(&self) {
        // Bump the fence FIRST so an in-flight flush aborts before the durable
        // UNLINK (the async reset half) — otherwise a late flush write could
        // re-create the hash after it was wiped (§4).
        self.inner
            .reset_gen
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.inner.map.clear();
        self.inner.dirty.clear();
    }

    /// Top-N riskiest IPs sorted by `(strikes desc, score desc)`.
    /// `level` is recomputed inline so callers can render the
    /// snapshot without a follow-up `level()` call per row.
    pub fn top(&self, n: usize) -> Vec<RiskSnapshot> {
        let now = Instant::now();
        // 2026-05-18 F-CRITICAL-001: iterate composite-key map.
        // The wire-shape snapshot renders only the IP for backward
        // compatibility (the dashboard's Top Attackers list reads
        // `ip` to build deep-links). Composite-key dimensions
        // (device_fp / session / tenant_id) are dropped from the
        // wire shape today; if the dashboard wants per-session
        // resolution later, extend `RiskSnapshot` and the
        // `/api/risk/top` JSON shape additively (Phase E follow-up).
        let mut all: Vec<(aegis_core::risk::RiskKey, Slot)> = self
            .inner
            .map
            .iter()
            .map(|kv| (kv.key().clone(), *kv.value()))
            .collect();
        all.sort_by(|a, b| {
            b.1.strikes
                .cmp(&a.1.strikes)
                .then_with(|| b.1.score.cmp(&a.1.score))
        });
        let t = self.inner.thresholds.load();
        let block_at = t.block_at;
        let challenge_at = t.challenge_at;
        drop(t);
        let strikes_cfg = self.inner.strikes.load();
        let strikes_enabled = strikes_cfg.enabled;
        let strikes_block_at = strikes_cfg.block_at;
        drop(strikes_cfg);
        all.into_iter()
            .take(n)
            .map(|(key, slot)| {
                let strike_blocked =
                    strikes_enabled && slot.strikes >= strikes_block_at;
                let level = if strike_blocked || slot.score >= block_at {
                    "block"
                } else if slot.score >= challenge_at {
                    "challenge"
                } else {
                    "allow"
                };
                RiskSnapshot {
                    ip: key.ip.to_string(),
                    // 2026-05-19 — composite-key axes now surfaced
                    // so the dashboard can render one row per
                    // (ip, device_fp, session) bucket. The plan
                    // is for the SPA to truncate device_fp to the
                    // first 8 hex chars for display; we ship the
                    // full 16-char value here so future tooling
                    // (e.g. the surgical reset endpoint) doesn't
                    // need a round-trip to disambiguate.
                    device_fp: key.device_fp.clone(),
                    session: key.session.clone(),
                    score: slot.score,
                    strikes: slot.strikes,
                    idle_seconds: now
                        .saturating_duration_since(slot.last_seen)
                        .as_secs(),
                    level,
                    strike_blocked,
                }
            })
            .collect()
    }

    /// Number of tracked IPs. Used for the dashboard summary +
    /// metrics export.
    pub fn len(&self) -> usize {
        self.inner.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.map.is_empty()
    }

    /// Render a single IP's snapshot in the wire shape. `None` if
    /// the IP isn't tracked.
    pub fn snapshot_wire(&self, ip: IpAddr) -> Option<RiskSnapshot> {
        let now = Instant::now();
        let state = self.snapshot(ip)?;
        let strike_blocked = self.is_strike_blocked(ip);
        let t = self.inner.thresholds.load();
        let level = if strike_blocked || state.score >= t.block_at {
            "block"
        } else if state.score >= t.challenge_at {
            "challenge"
        } else {
            "allow"
        };
        Some(RiskSnapshot {
            ip: ip.to_string(),
            // IP-only API → composite axes are unknown here.
            device_fp: None,
            session: None,
            score: state.score,
            strikes: state.strikes,
            idle_seconds: now
                .saturating_duration_since(state.last_seen)
                .as_secs(),
            level,
            strike_blocked,
        })
    }
}

fn slot_to_state(slot: Slot) -> RiskState {
    RiskState {
        score: slot.score,
        strikes: slot.strikes,
        last_seen: slot.last_seen,
    }
}

/// 2026-06-24 — durable wire shape for one risk slot, the value half of
/// the `control:waf:risk` HASH (`redis-interim-durability` P2). A0 adds
/// only the (de)serialization seam; the flush/hydrate that calls it lands
/// in A2.
///
/// The live [`Slot::last_seen`] is a process-local [`Instant`], which is
/// NOT serde-able and meaningless across a restart (a fresh process's
/// monotonic clock has a different origin). We persist it as a wall-clock
/// unix-millis timestamp instead, so a slot's *age* — what trust-decay and
/// idle-eviction actually care about — survives the restart, downtime
/// included (the wall clock advances while the process is down, correctly
/// ageing strikes out).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub(crate) struct DurableSlot {
    pub score: u32,
    pub strikes: u32,
    /// Wall-clock last-seen, unix milliseconds.
    pub last_seen_unix_ms: u64,
}

/// Canonical durable-hash field for a risk key: deterministic JSON of the
/// `RiskKey` (struct fields serialize in declaration order). `None` only on
/// the practically-impossible serde failure. The same key always yields the
/// same field, so a flush is an idempotent overwrite.
fn risk_field(key: &RiskKey) -> Option<String> {
    serde_json::to_string(key).ok()
}

/// Inverse of [`risk_field`] — reconstruct the `RiskKey` from a hash field
/// on hydrate. `None` on a corrupt / unparseable field (skipped, not fatal).
fn risk_key_from_field(field: &str) -> Option<RiskKey> {
    serde_json::from_str(field).ok()
}

/// Convert a live slot to its durable shape. `now_instant` / `now_wall`
/// are the *current* monotonic + wall clocks (passed in so the function is
/// pure and unit-testable); the slot's age is measured against the
/// monotonic clock and re-expressed against the wall clock.
fn slot_to_durable(slot: &Slot, now_instant: Instant, now_wall: SystemTime) -> DurableSlot {
    let age = now_instant.saturating_duration_since(slot.last_seen);
    let last_seen_wall = now_wall.checked_sub(age).unwrap_or(UNIX_EPOCH);
    let last_seen_unix_ms = last_seen_wall
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    DurableSlot {
        score: slot.score,
        strikes: slot.strikes,
        last_seen_unix_ms,
    }
}

/// Rehydrate a durable slot back into a live [`Slot`], re-anchoring
/// `last_seen` onto this process's monotonic clock. A slot whose wall-clock
/// timestamp is in the future (clock skew) clamps to "just now".
fn slot_from_durable(d: &DurableSlot, now_instant: Instant, now_wall: SystemTime) -> Slot {
    // `checked_add` (not `+`): a corrupted / adversarial hash field with a
    // huge `last_seen_unix_ms` must not panic `SystemTime` at hydrate time.
    // An unrepresentable timestamp clamps to "now" (age 0) — fail-safe.
    let last_seen_wall = UNIX_EPOCH
        .checked_add(Duration::from_millis(d.last_seen_unix_ms))
        .unwrap_or(now_wall);
    let age = now_wall
        .duration_since(last_seen_wall)
        .unwrap_or(Duration::ZERO);
    let last_seen = now_instant.checked_sub(age).unwrap_or(now_instant);
    Slot {
        score: d.score,
        strikes: d.strikes,
        last_seen,
    }
}

/// 2026-06-21 — time-based decay applied on READ (decay-on-access). Returns a
/// copy of `slot` with its score aged by the elapsed time since `last_seen` at
/// the linear trust-recovery rate (`per_hour`). `last_seen` is preserved so the
/// dashboard's idle indicator stays accurate and repeated reads decay from the
/// same anchor (idempotent). Strikes are NEVER decayed — that is the lifetime
/// repeat-offender guarantee. Used by every read path and as the rebase step on
/// `record_malicious`, so a gate decision, the `/api/risk` view, and the next
/// write all see the same aged score instead of a value frozen at last touch.
fn decayed_slot(slot: Slot, now: Instant, per_hour: u32) -> Slot {
    let elapsed = now.saturating_duration_since(slot.last_seen);
    let recovered = trust_decay_points(elapsed, per_hour);
    Slot {
        score: slot.score.saturating_sub(recovered),
        strikes: slot.strikes,
        last_seen: slot.last_seen,
    }
}

/// Trust-recovery formula. Linear ramp at `per_hour` points per
/// hour of clean traffic. Sub-second elapsed time still
/// contributes (microsecond precision) so a burst of clean
/// requests during a steady stream can pull a flagged client back
/// down — the cap prevents one request from doing it all.
fn trust_decay_points(elapsed: Duration, per_hour: u32) -> u32 {
    if per_hour == 0 {
        return 0;
    }
    let secs = elapsed.as_secs_f64();
    let recovery = secs * (per_hour as f64) / 3600.0;
    recovery.floor().clamp(0.0, u32::MAX as f64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only: the live tracker stores the rate as an atomic, so the
    // struct type is only referenced when building test configs.
    use aegis_core::config::TrustRecoveryConfig;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg() -> RiskConfig {
        let mut c = RiskConfig::default();
        c.trust_recovery = Some(TrustRecoveryConfig { per_hour: 30 });
        // 2026-05-10 — explicitly enable Strike-Block. The
        // production default is `enabled: false` (gate is opt-in),
        // but these tests are about verifying the mechanism, so we
        // turn it on here. See `strike_block_disabled_by_default_*`
        // tests below for the off-by-default behavior.
        c.strikes = Some(StrikeConfig { enabled: true, block_at: 5 });
        c
    }

    #[test]
    fn snapshot_returns_none_for_unknown_ip() {
        let t = RiskTracker::new(&cfg());
        assert!(t.snapshot(ip("1.1.1.1")).is_none());
        assert_eq!(t.level(ip("1.1.1.1")), RiskLevel::Allow);
    }

    // ---- 2026-06-24 durable risk-slot serde (P2 seam, A0) -------------

    #[test]
    fn durable_slot_round_trips_score_strikes_and_age_through_json() {
        // A slot last seen 100s ago, serialized and rehydrated against the
        // SAME clocks, must come back with identical score/strikes and a
        // last_seen that is ~100s before "now" (within a few ms tolerance).
        let now_instant = Instant::now();
        let now_wall = SystemTime::now();
        let slot = Slot {
            score: 73,
            strikes: 4,
            last_seen: now_instant - Duration::from_secs(100),
        };

        let durable = slot_to_durable(&slot, now_instant, now_wall);
        // Survives a real JSON hop (the actual on-wire path in A2).
        let bytes = serde_json::to_vec(&durable).unwrap();
        let decoded: DurableSlot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, durable);

        let rehydrated = slot_from_durable(&decoded, now_instant, now_wall);
        assert_eq!(rehydrated.score, 73);
        assert_eq!(rehydrated.strikes, 4);
        let recovered_age = now_instant.saturating_duration_since(rehydrated.last_seen);
        let drift = recovered_age.as_millis().abs_diff(100_000);
        assert!(drift < 50, "age drift {drift}ms exceeds tolerance");
    }

    // ---- 2026-06-24 P2 risk-strike durability (A2) --------------------

    /// Stateful in-test backend with real hash storage + an optional
    /// failure switch (to exercise the contention/skip path).
    type WriteHook = Arc<std::sync::Mutex<Option<Box<dyn FnMut() + Send>>>>;

    #[derive(Clone, Default)]
    struct MapHashBackend {
        hashes: Arc<std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, Vec<u8>>>>>,
        fail: Arc<std::sync::atomic::AtomicBool>,
        /// Fired at the START of every `hset_multi` — lets a test inject a
        /// concurrent reset between flush snapshot and write (the TOCTOU).
        before_write: WriteHook,
    }
    impl MapHashBackend {
        fn fields(&self, key: &str) -> usize {
            self.hashes.lock().unwrap().get(key).map(|h| h.len()).unwrap_or(0)
        }
        fn set_fail(&self, v: bool) {
            self.fail.store(v, std::sync::atomic::Ordering::Relaxed);
        }
        fn on_before_write(&self, f: impl FnMut() + Send + 'static) {
            *self.before_write.lock().unwrap() = Some(Box::new(f));
        }
        fn err<T>() -> aegis_core::Result<T> {
            Err(aegis_core::WafError::State("induced".into()))
        }
    }
    #[async_trait::async_trait]
    impl StateBackend for MapHashBackend {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
        async fn hset_multi(&self, key: &str, fields: &[(String, Vec<u8>)]) -> aegis_core::Result<()> {
            if let Some(hook) = self.before_write.lock().unwrap().as_mut() {
                hook();
            }
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) { return Self::err(); }
            let mut g = self.hashes.lock().unwrap();
            let h = g.entry(key.to_string()).or_default();
            for (f, v) in fields { h.insert(f.clone(), v.clone()); }
            Ok(())
        }
        async fn hdel(&self, key: &str, fields: &[String]) -> aegis_core::Result<()> {
            if let Some(h) = self.hashes.lock().unwrap().get_mut(key) {
                for f in fields { h.remove(f); }
            }
            Ok(())
        }
        async fn hscan(&self, key: &str) -> aegis_core::Result<Vec<(String, Vec<u8>)>> {
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) { return Self::err(); }
            Ok(self.hashes.lock().unwrap().get(key)
                .map(|h| h.iter().map(|(f, v)| (f.clone(), v.clone())).collect())
                .unwrap_or_default())
        }
        async fn unlink(&self, key: &str) -> aegis_core::Result<()> {
            self.hashes.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn be() -> Arc<MapHashBackend> {
        Arc::new(MapHashBackend::default())
    }

    fn tracker_with(be: &Arc<MapHashBackend>) -> RiskTracker {
        let t = RiskTracker::new(&cfg());
        t.attach_backend(be.clone() as Arc<dyn StateBackend>);
        t
    }

    #[tokio::test]
    async fn malicious_strike_flushes_and_survives_restart() {
        let backend = be();
        let t = tracker_with(&backend);
        // Two strikes on one IP → strikes=2, marked dirty.
        t.record_malicious(ip("9.9.9.9"), 60);
        t.record_malicious(ip("9.9.9.9"), 60);
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 1, "one struck key persisted");

        // Fresh tracker hydrates the strike from the same backend.
        let restarted = tracker_with(&backend);
        assert!(restarted.snapshot(ip("9.9.9.9")).is_none(), "empty before hydrate");
        restarted.hydrate().await;
        let s = restarted.snapshot(ip("9.9.9.9")).expect("strike rehydrated");
        assert_eq!(s.strikes, 2, "lifetime strikes survived restart");
    }

    #[tokio::test]
    async fn clean_only_traffic_is_never_persisted() {
        let backend = be();
        let t = tracker_with(&backend);
        // Clean requests on never-struck keys carry no durable value.
        for i in 0..10 {
            t.record_clean(ip(&format!("10.0.0.{i}")));
        }
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 0, "no clean keys persisted");
    }

    #[tokio::test]
    async fn reset_between_mark_and_flush_drops_the_key() {
        let backend = be();
        let t = tracker_with(&backend);
        t.record_malicious(ip("1.2.3.4"), 60); // dirty + stored
        t.reset(ip("1.2.3.4")); // removed from the map before flush
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 0, "removed key not persisted");
    }

    #[tokio::test]
    async fn forget_durable_hdels_one_key_only() {
        let backend = be();
        let t = tracker_with(&backend);
        t.record_malicious(ip("1.1.1.1"), 60);
        t.record_malicious(ip("2.2.2.2"), 60);
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 2);

        t.forget_durable(&RiskKey::from_ip(ip("1.1.1.1"))).await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 1);
        // The survivor rehydrates; the forgotten one does not.
        let restarted = tracker_with(&backend);
        restarted.hydrate().await;
        assert!(restarted.snapshot(ip("2.2.2.2")).is_some());
        assert!(restarted.snapshot(ip("1.1.1.1")).is_none());
    }

    #[tokio::test]
    async fn unlink_durable_wipes_the_whole_hash() {
        let backend = be();
        let t = tracker_with(&backend);
        t.record_malicious(ip("3.3.3.3"), 60);
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 1);
        t.unlink_durable().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 0);
    }

    #[tokio::test]
    async fn reset_all_clears_map_and_dirty() {
        let backend = be();
        let t = tracker_with(&backend);
        t.record_malicious(ip("4.4.4.4"), 60);
        t.reset_all();
        // Nothing dirty → flush writes nothing; map empty.
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 0);
        assert!(t.snapshot(ip("4.4.4.4")).is_none());
    }

    #[tokio::test]
    async fn flush_caps_per_tick_highest_strike_first_and_defers_rest() {
        // PER_TICK_FIELD_CAP is 4 in tests. Create 6 struck keys with
        // increasing strike counts; the flush keeps the 4 highest, defers 2.
        let backend = be();
        let t = tracker_with(&backend);
        for i in 0..6u32 {
            let addr = ip(&format!("5.5.5.{i}"));
            // i+1 strikes on key i.
            for _ in 0..=i {
                t.record_malicious(addr, 10);
            }
        }
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 4, "capped to PER_TICK_FIELD_CAP");
        // The two lowest-strike keys (1 and 2 strikes) were deferred; a second
        // flush drains them.
        t.flush_once().await;
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 6, "deferred keys flushed next tick");
    }

    #[tokio::test]
    async fn flush_defers_everything_on_backend_error() {
        let backend = be();
        let t = tracker_with(&backend);
        t.record_malicious(ip("6.6.6.6"), 60);
        backend.set_fail(true);
        t.flush_once().await; // backend errors → key stays dirty
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 0, "nothing written on error");
        backend.set_fail(false);
        t.flush_once().await; // retry succeeds
        assert_eq!(backend.fields(CONTROL_RISK_KEY), 1, "deferred key flushed on recovery");
    }

    #[tokio::test]
    async fn flush_aborts_remaining_writes_when_a_reset_lands_mid_flush() {
        // The TOCTOU: a reset bumps the fence AFTER flush_once snapshots but
        // BEFORE it finishes its (multi-chunk, HSET_CHUNK=1 in tests) writes.
        // The first write's hook fires a concurrent reset_all; the fence must
        // then abort the remaining writes so cleared strikes aren't resurrected.
        let backend = be();
        let t = tracker_with(&backend);
        for i in 0..3u32 {
            // Distinct strike counts so all three become separate fields.
            for _ in 0..=i {
                t.record_malicious(ip(&format!("9.0.0.{i}")), 10);
            }
        }
        // On the very first chunk write, simulate an operator/bench reset
        // landing concurrently (bumps the fence + clears state).
        let t_for_hook = t.clone();
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_c = fired.clone();
        backend.on_before_write(move || {
            if !fired_c.swap(true, std::sync::atomic::Ordering::Relaxed) {
                t_for_hook.reset_all();
            }
        });
        t.flush_once().await;
        // Exactly the first key was written before the reset took effect; the
        // fence aborted the remaining two. (Without the fence, all 3 would be
        // written and would resurrect on the next boot despite the reset.)
        assert_eq!(
            backend.fields(CONTROL_RISK_KEY),
            1,
            "fence aborted post-reset writes; only the pre-reset chunk landed"
        );
    }

    #[tokio::test]
    async fn hydrate_does_not_clobber_a_live_entry() {
        let backend = be();
        // Seed durable with strikes=1 for an IP.
        let seeder = tracker_with(&backend);
        seeder.record_malicious(ip("7.7.7.7"), 60);
        seeder.flush_once().await;

        // A fresh tracker accrues a LIVE strike for the same IP, THEN hydrates.
        let t = tracker_with(&backend);
        t.record_malicious(ip("7.7.7.7"), 60);
        t.record_malicious(ip("7.7.7.7"), 60); // live strikes = 2
        t.hydrate().await;
        // Live entry (2) must win over the durable (1) — or_insert skips it.
        assert_eq!(t.snapshot(ip("7.7.7.7")).unwrap().strikes, 2);
    }

    #[tokio::test]
    async fn no_backend_path_marks_nothing_and_hooks_are_inert() {
        // Without a backend: no dirty growth, durable hooks are no-ops.
        let t = RiskTracker::new(&cfg());
        t.record_malicious(ip("8.8.8.8"), 60);
        assert!(t.snapshot(ip("8.8.8.8")).is_some(), "in-memory strike still works");
        // flush/hydrate/unlink/forget all no-op without panicking.
        t.flush_once().await;
        t.hydrate().await;
        t.unlink_durable().await;
        t.forget_durable(&RiskKey::from_ip(ip("8.8.8.8"))).await;
        assert_eq!(t.snapshot(ip("8.8.8.8")).unwrap().strikes, 1);
    }

    #[test]
    fn attach_backend_is_settable_and_idempotent() {
        let t = RiskTracker::new(&cfg());
        assert!(t.backend().is_none(), "no backend before attach");
        t.attach_backend(Arc::new(NoopBackend) as Arc<dyn StateBackend>);
        assert!(t.backend().is_some(), "backend present after attach");
        // Idempotent — a second attach must not panic.
        t.attach_backend(Arc::new(NoopBackend) as Arc<dyn StateBackend>);
        assert!(t.backend().is_some());
    }

    /// Minimal stub: relies on the trait's default impls for everything
    /// except the still-required (non-default) methods.
    struct NoopBackend;
    #[async_trait::async_trait]
    impl StateBackend for NoopBackend {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _key: &aegis_core::risk::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _key: &aegis_core::risk::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
    }

    #[test]
    fn slot_from_durable_clamps_corrupt_timestamp_without_panicking() {
        // A garbage/adversarial last_seen near u64::MAX must NOT panic
        // SystemTime at hydrate — it clamps to "now" (age 0).
        let corrupt = DurableSlot { score: 10, strikes: 1, last_seen_unix_ms: u64::MAX };
        let now_instant = Instant::now();
        let rehydrated = slot_from_durable(&corrupt, now_instant, SystemTime::now());
        assert_eq!(rehydrated.strikes, 1);
        let age = now_instant.saturating_duration_since(rehydrated.last_seen);
        assert!(age < Duration::from_millis(50), "clamped to ~now");
    }

    #[test]
    fn durable_slot_ages_further_across_simulated_downtime() {
        // Persist "now", then rehydrate as if the wall clock advanced 1h
        // (process was down). The rehydrated slot must be ~1h old so trust
        // decay correctly claws the score back after a restart.
        let persist_instant = Instant::now();
        let persist_wall = SystemTime::now();
        let slot = Slot { score: 50, strikes: 2, last_seen: persist_instant };
        let durable = slot_to_durable(&slot, persist_instant, persist_wall);

        let load_instant = Instant::now();
        let load_wall = persist_wall + Duration::from_secs(3600);
        let rehydrated = slot_from_durable(&durable, load_instant, load_wall);
        let age = load_instant.saturating_duration_since(rehydrated.last_seen);
        let drift = age.as_secs().abs_diff(3600);
        assert!(drift <= 1, "expected ~3600s age, got {}s", age.as_secs());
    }

    // 2026-05-20 memory-leak audit — the map must not grow without
    // bound. Idle slots beyond IDLE_TTL get swept on the next
    // record; an actively-touched slot survives.
    #[test]
    fn maybe_sweep_evicts_idle_slots_but_keeps_active() {
        use aegis_core::risk::RiskKey;
        let t = RiskTracker::new(&cfg());
        let t0 = Instant::now();

        // Two distinct keys observed at t0 (simulates a burst of
        // distinct source IPs).
        t.record_malicious_at_with_key(RiskKey::from_ip(ip("10.0.0.1")), 20, t0);
        t.record_malicious_at_with_key(RiskKey::from_ip(ip("10.0.0.2")), 20, t0);
        assert_eq!(t.len(), 2);

        // A third key observed > IDLE_TTL later. This record call
        // triggers maybe_sweep (well past IDLE_SWEEP_INTERVAL), which
        // drops the two now-idle slots and keeps the fresh one.
        let later = t0 + IDLE_TTL + Duration::from_secs(120);
        t.record_malicious_at_with_key(RiskKey::from_ip(ip("10.0.0.3")), 20, later);
        assert_eq!(t.len(), 1, "idle slots should be swept, active one kept");
        assert!(t.snapshot(ip("10.0.0.3")).is_some());
        assert!(t.snapshot(ip("10.0.0.1")).is_none());
    }

    #[test]
    fn maybe_sweep_keeps_recently_active_repeat_offender() {
        use aegis_core::risk::RiskKey;
        let t = RiskTracker::new(&cfg());
        let t0 = Instant::now();
        let key = RiskKey::from_ip(ip("10.0.0.9"));
        // A repeat offender that keeps hitting stays fresh across a
        // span longer than IDLE_TTL, so it's never swept.
        t.record_malicious_at_with_key(key.clone(), 20, t0);
        let mid = t0 + Duration::from_secs(1800); // 30 min — refreshes last_seen
        t.record_malicious_at_with_key(key.clone(), 20, mid);
        let late = t0 + IDLE_TTL + Duration::from_secs(120);
        t.record_malicious_at_with_key(key.clone(), 20, late);
        assert_eq!(t.len(), 1);
        assert!(t.snapshot(ip("10.0.0.9")).is_some(), "active offender survives");
    }

    // PROXY-02 (LT-RUN-11) — a unique-key flood must not grow the map without
    // bound. Once at MAX_TRACKED_KEYS (4 in tests), new keys are not tracked,
    // but existing keys keep accumulating.
    #[test]
    fn cardinality_cap_rejects_new_keys_but_keeps_existing() {
        use aegis_core::risk::RiskKey;
        let t = RiskTracker::new(&cfg());
        let t0 = Instant::now();

        // Fill to the cap with distinct keys (simulates unique session cookies).
        for i in 0..MAX_TRACKED_KEYS {
            let key = RiskKey::from_ip(ip(&format!("10.0.0.{}", i + 1)));
            t.record_malicious_at_with_key(key, 20, t0);
        }
        assert_eq!(t.len(), MAX_TRACKED_KEYS);

        // A brand-new key past the cap is scored for THIS request but not stored.
        let overflow = RiskKey::from_ip(ip("10.0.9.9"));
        let st = t.record_malicious_at_with_key(overflow, 20, t0);
        assert_eq!(st.score, 20, "the request is still scored");
        assert_eq!(t.len(), MAX_TRACKED_KEYS, "but nothing new is persisted");
        assert!(t.snapshot(ip("10.0.9.9")).is_none(), "overflow key is not tracked");

        // An EXISTING key still accumulates after the cap is reached.
        let existing = RiskKey::from_ip(ip("10.0.0.1"));
        let st = t.record_malicious_at_with_key(existing, 20, t0);
        assert_eq!(st.score, 40, "existing offender keeps accumulating");
        assert_eq!(t.len(), MAX_TRACKED_KEYS);
    }

    // PROXY-02 — zero-value (clean, no-strike) slots are swept on the short
    // ZERO_VALUE_IDLE_TTL; scored slots keep the generous IDLE_TTL.
    #[test]
    fn zero_value_slots_swept_faster_than_scored() {
        use aegis_core::risk::RiskKey;
        let t = RiskTracker::new(&cfg());
        let t0 = Instant::now();

        let scored = RiskKey::from_ip(ip("10.1.0.1"));
        let clean = RiskKey::from_ip(ip("10.1.0.2"));
        t.record_malicious_at_with_key(scored, 20, t0); // score 20
        t.record_clean_at_with_key(clean, t0); // score 0, zero-value
        assert_eq!(t.len(), 2);

        // Past ZERO_VALUE_IDLE_TTL but well under IDLE_TTL; also past the sweep
        // throttle. A record on a third key triggers the sweep.
        let later = t0 + ZERO_VALUE_IDLE_TTL + Duration::from_secs(1);
        t.record_malicious_at_with_key(RiskKey::from_ip(ip("10.1.0.3")), 20, later);

        assert!(t.snapshot(ip("10.1.0.2")).is_none(), "zero-value slot swept early");
        assert!(t.snapshot(ip("10.1.0.1")).is_some(), "scored slot survives short TTL");
    }

    /// 2026-05-25 — regression guard for the staging `45.45.237.206`
    /// anomaly. The audit showed 9 under-threshold recon hits (+25 each)
    /// interleaved with clean requests, all from ONE composite key
    /// (IP-only: no session cookie, no TLS device_fp), inside ~760 ms — yet
    /// the reported cumulative bounced 25/50 and the IP NEVER blocked. That
    /// would be a cumulative-evasion bug IF the tracker failed to accumulate
    /// across the clean/malicious interleave.
    ///
    /// This replays that exact interleave on a single shared key with a
    /// deterministic clock (events ms apart → trust decay ≈ 0) and proves the
    /// tracker DOES accumulate monotonically and crosses `block_at` by the
    /// 3rd recon hit (3 × 25 = 75 ≥ 70): clean requests in between do NOT
    /// reset or fragment the score. So the staging non-block is NOT a
    /// tracker-logic bug — it is consistent with the cumulative key being
    /// wiped between request batches (the benchmark harness calling
    /// `POST /__waf_control/reset_state`, which clears cumulative risk keys)
    /// or those requests not actually sharing the key on the wire.
    #[test]
    fn interleaved_clean_does_not_reset_cumulative_for_shared_key() {
        use aegis_core::risk::RiskKey;
        let t = RiskTracker::new(&cfg());
        // IP-only composite key — exactly what plain-HTTP traffic with no
        // session cookie produces (build_risk_key: device_fp None, session None).
        let key = RiskKey::from_ip(ip("45.45.237.206"));
        let t0 = Instant::now();
        let at = |n: u64| t0 + Duration::from_millis(n);

        // (ms_offset, is_recon) — the real ordering/offsets from the staging
        // audit. recon (R) = under-threshold recon detection (request_score 25
        // → max signal 25, recorded to the cumulative key). clean (C) = a
        // benign request that runs the decay path.
        let seq: &[(u64, bool)] = &[
            (0, false), (1, true), (13, true), (231, true), (232, true),
            (249, false), (462, false), (464, false), (486, false), (693, false),
            (696, false), (722, false), (727, false), (733, false), (733, true),
            (735, false), (737, false), (738, false), (739, true), (740, false),
            (744, true), (746, true), (747, false), (756, true), (759, false),
            (760, false),
        ];

        let thr = t.thresholds();
        let mut recon_hits = 0u32;
        let mut first_block_hit: Option<u32> = None;
        for &(off, is_recon) in seq {
            if is_recon {
                recon_hits += 1;
                let st = t.record_malicious_at_with_key(key.clone(), 25, at(off));
                if first_block_hit.is_none() && st.score >= thr.block_at {
                    first_block_hit = Some(recon_hits);
                }
            } else {
                t.record_clean_at_with_key(key.clone(), at(off));
            }
        }

        // 9 recon × 25 = 225, clamped to max=100; the clean interleave decays
        // ~0 over <1 s, so the shared key MUST sit at the cap — NOT bouncing
        // at 25/50 the way the staging audit showed.
        let final_score = t.snapshot_with_key(&key).map(|s| s.score).unwrap_or(0);
        assert_eq!(
            final_score, 100,
            "shared-key cumulative must accumulate across the clean interleave, not reset"
        );
        // The cumulative gate classifies a capped key as Block …
        assert_eq!(
            t.level_with_for_key(&key, thr.challenge_at, thr.block_at),
            RiskLevel::Block,
            "an IP at the score cap must classify as Block"
        );
        // … and it crossed block_at at the 3rd recon hit (75 ≥ 70), long
        // before the 9th. The staging IP allowing all 9 is NOT reproducible
        // against the tracker — confirming the logic accumulates correctly.
        assert_eq!(
            first_block_hit,
            Some(3),
            "block_at (70) must be crossed at the 3rd recon hit"
        );
    }

    #[test]
    fn record_malicious_increments_score_and_strikes() {
        let t = RiskTracker::new(&cfg());
        let s1 = t.record_malicious(ip("10.0.0.1"), 20);
        assert_eq!(s1.score, 20);
        assert_eq!(s1.strikes, 1);
        let s2 = t.record_malicious(ip("10.0.0.1"), 25);
        assert_eq!(s2.score, 45);
        assert_eq!(s2.strikes, 2);
    }

    #[test]
    fn score_clamps_to_thresholds_max() {
        let t = RiskTracker::new(&cfg());
        for _ in 0..50 {
            t.record_malicious(ip("10.0.0.1"), 50);
        }
        let s = t.snapshot(ip("10.0.0.1")).unwrap();
        assert_eq!(s.score, 100); // RiskThresholds default max=100
    }

    #[test]
    fn record_clean_decays_score_within_hourly_cap() {
        // Score=80, per_hour=30. After 30 minutes of clean traffic
        // the cap allows up to 15 points of recovery.
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.1"), 80, now);
        let later = now + Duration::from_secs(1800); // 30 min
        let state = t.record_clean_at(ip("10.0.0.1"), later);
        assert_eq!(state.score, 65); // 80 - 15
    }

    #[test]
    fn record_clean_caps_recovery_at_per_hour() {
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.1"), 80, now);
        // Far more than an hour passes, but we only ever recover
        // 30 points per hour of elapsed time — here, 2h = 60.
        let later = now + Duration::from_secs(2 * 3600);
        let state = t.record_clean_at(ip("10.0.0.1"), later);
        assert_eq!(state.score, 20); // 80 - 60
    }

    #[test]
    fn record_clean_does_not_underflow() {
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.1"), 5, now);
        let later = now + Duration::from_secs(3600);
        let state = t.record_clean_at(ip("10.0.0.1"), later);
        assert_eq!(state.score, 0);
    }

    #[test]
    fn record_clean_does_not_decrement_strikes() {
        let t = RiskTracker::new(&cfg());
        for _ in 0..3 {
            t.record_malicious(ip("10.0.0.1"), 10);
        }
        // Even after enough clean traffic to fully decay the
        // score, strikes stick around — that's the lifetime
        // invariant.
        let now = Instant::now();
        for _ in 0..50 {
            t.record_clean_at(ip("10.0.0.1"), now + Duration::from_secs(7200));
        }
        let s = t.snapshot(ip("10.0.0.1")).unwrap();
        assert_eq!(s.strikes, 3);
    }

    // 2026-06-21 — decay-on-read. The cumulative score must reflect elapsed
    // time when READ, not only when a clean request happens to arrive. Removes
    // the "quiet attacker stuck at peak score" surprise and aligns with how
    // reputation / rate systems age scores on access. Strikes stay permanent.
    #[test]
    fn trust_per_hour_getter_reports_configured_rate() {
        // Surfaced to /api/risk/thresholds so the dashboard can show the
        // real (linear) decay rate instead of a misleading "half-life".
        let t = RiskTracker::new(&cfg()); // cfg() sets per_hour = 30
        assert_eq!(t.trust_per_hour(), 30);
    }

    #[test]
    fn set_trust_per_hour_hot_swaps_decay_rate() {
        // The dashboard PUT edits the decay rate live; it must hot-swap on the
        // tracker AND actually change the decay-on-read maths (no restart).
        let t = RiskTracker::new(&cfg()); // per_hour = 30
        assert_eq!(t.trust_per_hour(), 30);
        t.set_trust_per_hour(60);
        assert_eq!(t.trust_per_hour(), 60);
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.7"), 80, now);
        let later = now + Duration::from_secs(3600); // 1h at the new 60/hr
        let s = t.snapshot_at(ip("10.0.0.7"), later).unwrap();
        assert_eq!(s.score, 20); // 80 − 60
    }

    #[test]
    fn snapshot_decays_score_on_read_without_a_clean_request() {
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.9"), 80, now);
        // One hour later, with NO intervening request, a plain read sees decay.
        let later = now + Duration::from_secs(3600);
        let s = t.snapshot_at(ip("10.0.0.9"), later).unwrap();
        assert_eq!(s.score, 50); // 80 − 30/hr
    }

    #[test]
    fn snapshot_decay_on_read_preserves_strikes() {
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        for _ in 0..4 {
            t.record_malicious_at(ip("10.0.0.9"), 20, now);
        }
        let later = now + Duration::from_secs(10 * 3600); // long enough to zero it
        let s = t.snapshot_at(ip("10.0.0.9"), later).unwrap();
        assert_eq!(s.score, 0);
        assert_eq!(s.strikes, 4); // strikes never decay
    }

    #[test]
    fn level_uses_decayed_score_on_read() {
        // score thresholds: challenge_at=30, block_at=70; strike block at 5.
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.9"), 80, now); // 1 strike, score 80
        assert_eq!(t.level_at(ip("10.0.0.9"), now), RiskLevel::Block);
        // 2h later: 80 − 60 = 20 → below challenge → Allow, on read alone.
        let later = now + Duration::from_secs(2 * 3600);
        assert_eq!(t.level_at(ip("10.0.0.9"), later), RiskLevel::Allow);
    }

    #[test]
    fn record_malicious_rebases_to_decayed_score_before_adding() {
        // Avoids an "un-decay" jump: a returning attacker's score is aged
        // first, THEN the new delta is added — so reads and writes agree.
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.9"), 80, now);
        let later = now + Duration::from_secs(3600); // decay 30 → 50
        let st = t.record_malicious_at(ip("10.0.0.9"), 10, later);
        assert_eq!(st.score, 60); // 50 + 10, not 90
    }

    #[test]
    fn level_classifies_against_thresholds() {
        let t = RiskTracker::new(&cfg());
        // 2026-05-17 F-CRITICAL-007: RiskThresholds defaults are now
        // challenge_at=30, block_at=70 (v2.3 spec). Test updated to
        // match — see crates/aegis-core/src/config.rs.
        let target = ip("10.0.0.1");
        assert_eq!(t.level(target), RiskLevel::Allow);

        t.record_malicious(target, 20);
        assert_eq!(t.level(target), RiskLevel::Allow);

        t.record_malicious(target, 15);
        assert_eq!(t.level(target), RiskLevel::Challenge);

        t.record_malicious(target, 40);
        assert_eq!(t.level(target), RiskLevel::Block);
    }

    #[test]
    fn strike_block_short_circuits_to_block_even_when_score_low() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        // 5 strikes worth `block_at = 5` but tiny score deltas.
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.score, 5); // far below challenge_at=40
        assert!(t.is_strike_blocked(target));
        assert_eq!(t.level(target), RiskLevel::Block);
    }

    #[test]
    fn strike_block_persists_after_score_decay() {
        // Strikes never decay even if score recovers — repeated
        // offenders stay blocked until an operator resets.
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        let now = Instant::now();
        for i in 0..5 {
            t.record_malicious_at(target, 5, now + Duration::from_secs(i));
        }
        for _ in 0..100 {
            t.record_clean_at(target, now + Duration::from_secs(36_000));
        }
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.score, 0); // fully decayed
        assert_eq!(s.strikes, 5);
        assert_eq!(t.level(target), RiskLevel::Block);
    }

    #[test]
    fn reset_clears_strikes_and_score() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        for _ in 0..5 {
            t.record_malicious(target, 10);
        }
        assert!(t.is_strike_blocked(target));
        assert!(t.reset(target));
        assert!(t.snapshot(target).is_none());
        assert_eq!(t.level(target), RiskLevel::Allow);
        assert!(!t.reset(target), "second reset is a no-op");
    }

    #[test]
    fn top_sorts_by_strikes_then_score() {
        let t = RiskTracker::new(&cfg());
        // ip A: 1 strike, score 90 (challenge tier high)
        t.record_malicious(ip("10.0.0.1"), 90);
        // ip B: 4 strikes, score 30 (challenge_at boundary)
        for _ in 0..4 {
            t.record_malicious(ip("10.0.0.2"), 8);
        }
        // ip C: 3 strikes, score 60
        for _ in 0..3 {
            t.record_malicious(ip("10.0.0.3"), 20);
        }
        let top = t.top(10);
        let ips: Vec<&str> = top.iter().map(|s| s.ip.as_str()).collect();
        // Order: B (4 strikes) > C (3 strikes) > A (1 strike).
        assert_eq!(ips, vec!["10.0.0.2", "10.0.0.3", "10.0.0.1"]);
    }

    #[test]
    fn top_respects_limit() {
        let t = RiskTracker::new(&cfg());
        for i in 0..20u8 {
            t.record_malicious(ip(&format!("10.0.0.{i}")), 10);
        }
        assert_eq!(t.top(5).len(), 5);
        assert_eq!(t.top(50).len(), 20);
    }

    #[test]
    fn snapshot_wire_renders_all_fields() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        let snap = t.snapshot_wire(target).unwrap();
        assert_eq!(snap.ip, "10.0.0.1");
        assert_eq!(snap.strikes, 5);
        assert!(snap.strike_blocked);
        assert_eq!(snap.level, "block");
    }

    #[test]
    fn trust_decay_points_caps_at_per_hour() {
        assert_eq!(trust_decay_points(Duration::from_secs(3600), 30), 30);
        assert_eq!(trust_decay_points(Duration::from_secs(7200), 30), 60);
        assert_eq!(trust_decay_points(Duration::from_secs(60), 30), 0);
        // 5 minutes of clean traffic at 30/hr → 2 points.
        assert_eq!(trust_decay_points(Duration::from_secs(300), 30), 2);
    }

    #[test]
    fn trust_decay_zero_per_hour_means_no_recovery() {
        // Operator can disable trust recovery by setting per_hour=0
        // — score then only ever goes up (legacy half-life still
        // applies separately via RiskEngine).
        assert_eq!(trust_decay_points(Duration::from_secs(36_000), 0), 0);
    }

    // ---------- 2026-05-10 — Strike-Block enable/disable wiring ----------

    fn cfg_strikes_disabled() -> RiskConfig {
        let mut c = RiskConfig::default();
        c.trust_recovery = Some(TrustRecoveryConfig { per_hour: 30 });
        c.strikes = Some(StrikeConfig { enabled: false, block_at: 5 });
        c
    }

    #[test]
    fn strike_block_disabled_does_not_fire_even_at_threshold() {
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.42");
        for _ in 0..10 {
            t.record_malicious(target, 1);
        }
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.strikes, 10);
        assert!(
            !t.is_strike_blocked(target),
            "Strike-Block must not fire when enabled=false"
        );
        // level() also gets the score-based path because the gate
        // is off — score is 10 (below challenge_at=40).
        assert_eq!(t.level(target), RiskLevel::Allow);
    }

    #[test]
    fn strike_config_snapshot_reads_live_config() {
        let t = RiskTracker::new(&cfg());
        let snap = t.strike_config_snapshot();
        assert!(snap.enabled);
        assert_eq!(snap.block_at, 5);
    }

    #[test]
    fn set_strike_config_hot_swaps_without_reset() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.99");
        // Accumulate 5 strikes — gate is enabled with block_at=5.
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        assert!(t.is_strike_blocked(target));
        // Hot-flip the gate off; the IP is no longer blocked at
        // the gate even though its lifetime counter is unchanged.
        t.set_strike_config(StrikeConfig { enabled: false, block_at: 5 });
        assert!(!t.is_strike_blocked(target));
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.strikes, 5, "per-IP state preserved across swap");
        // Hot-flip back on — the same accumulated count fires
        // immediately, no reset needed.
        t.set_strike_config(StrikeConfig { enabled: true, block_at: 5 });
        assert!(t.is_strike_blocked(target));
    }

    #[test]
    fn set_strike_config_can_tighten_threshold_mid_incident() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.55");
        // 3 strikes at block_at=5 — not yet blocked.
        for _ in 0..3 {
            t.record_malicious(target, 1);
        }
        assert!(!t.is_strike_blocked(target));
        // Tighten threshold to 3 — the IP is now over the limit
        // without any new attack signals.
        t.set_strike_config(StrikeConfig { enabled: true, block_at: 3 });
        assert!(t.is_strike_blocked(target));
    }

    // ---------- 2026-05-10 — level_with (Option B per-tier) -------------

    #[test]
    fn level_with_uses_caller_supplied_thresholds() {
        // Use the strikes-disabled fixture so the lifetime
        // strike check doesn't short-circuit before we get to
        // the threshold comparison. The point of this test is
        // to verify the per-tier cumulative thresholds, not the
        // strike-block interaction (covered in level_with_strike_block_*).
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.20");
        // Drive the cumulative score to 50 with two hits.
        t.record_malicious(target, 30);
        t.record_malicious(target, 20);
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.score, 50);
        // Strict tier thresholds (challenge=20, block=40) → Block.
        assert_eq!(
            t.level_with(target, 20, 40),
            RiskLevel::Block,
            "score 50 should block when tier block_at=40"
        );
        // Permissive tier thresholds (challenge=80, block=99) → Allow.
        assert_eq!(
            t.level_with(target, 80, 99),
            RiskLevel::Allow,
            "score 50 should pass when tier challenge_at=80"
        );
        // Mid-bucket tier thresholds (challenge=40, block=80) → Challenge.
        assert_eq!(
            t.level_with(target, 40, 80),
            RiskLevel::Challenge,
            "score 50 should challenge between tier challenge_at=40 and block_at=80"
        );
    }

    #[test]
    fn level_with_returns_allow_for_unknown_ip() {
        let t = RiskTracker::new(&cfg());
        assert_eq!(t.level_with(ip("8.8.8.8"), 40, 80), RiskLevel::Allow);
    }

    /// 2026-05-21 — cumulative-gate master toggle. When disabled, an
    /// over-block score never gates (neither `level` nor the per-tier
    /// `level_with`), but the score is still recorded and strike-block
    /// (a separate gate) still fires.
    #[test]
    fn disabled_cumulative_gate_never_blocks_on_score() {
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.77");
        t.record_malicious(target, 90); // well over default block_at=70
        assert_eq!(t.level(target), RiskLevel::Block, "enabled gate blocks at 90");

        let mut th = t.thresholds();
        th.enabled = false;
        t.set_thresholds(th);
        assert_eq!(t.level(target), RiskLevel::Allow, "disabled gate never blocks (level)");
        assert_eq!(
            t.level_with(target, 30, 70),
            RiskLevel::Allow,
            "disabled gate never blocks (per-tier level_with)",
        );
        // Score is still recorded for forensics.
        assert_eq!(t.snapshot(target).unwrap().score, 90);
    }

    #[test]
    fn disabled_cumulative_gate_still_honors_strike_block() {
        let t = RiskTracker::new(&cfg()); // strikes enabled, block_at=5
        let target = ip("10.0.0.78");
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        let mut th = t.thresholds();
        th.enabled = false;
        t.set_thresholds(th);
        // Cumulative gate off, but the strike-block gate is separate.
        assert!(t.is_strike_blocked(target));
        assert_eq!(t.level(target), RiskLevel::Block, "strike-block overrides the disabled cumulative gate");
    }

    #[test]
    fn level_with_strike_block_still_short_circuits() {
        // Strike-block is gate-level — it ignores per-tier
        // thresholds. Even with permissive tier bounds, a
        // strike-blocked IP returns Block.
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.21");
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        assert!(t.is_strike_blocked(target));
        assert_eq!(
            t.level_with(target, 99, 100),
            RiskLevel::Block,
            "strike-block must override permissive tier thresholds"
        );
    }

    #[test]
    fn snapshot_wire_strike_blocked_false_when_gate_disabled() {
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.7");
        for _ in 0..6 {
            t.record_malicious(target, 1);
        }
        let snap = t.snapshot_wire(target).unwrap();
        assert_eq!(snap.strikes, 6);
        assert!(!snap.strike_blocked);
        // score is 6 (well below challenge_at=40), so level=allow.
        assert_eq!(snap.level, "allow");
    }

    // ---- 2026-05-18 F-CRITICAL-001 Phase E composite-key tests ----

    fn key_with(ip_str: &str, device_fp: Option<&str>, session: Option<&str>) -> aegis_core::risk::RiskKey {
        aegis_core::risk::RiskKey {
            ip: ip(ip_str),
            device_fp: device_fp.map(String::from),
            session: session.map(String::from),
        }
    }

    /// Composite-key isolation: two sessions on the same NAT'd IP
    /// accumulate INDEPENDENT risk. Pre-fix both hit the same
    /// IP-only bucket — one user's malicious activity tarred the
    /// whole NAT.
    #[test]
    fn composite_key_isolates_sessions_on_same_ip() {
        let t = RiskTracker::new(&cfg());
        let alice = key_with("10.0.0.1", Some("fp-alice"), Some("sess-alice"));
        let bob = key_with("10.0.0.1", Some("fp-bob"), Some("sess-bob"));

        // Alice goes malicious; Bob does not.
        t.record_malicious_with_key(alice.clone(), 60);
        t.record_malicious_with_key(alice.clone(), 20);
        // Bob is fine.
        let bob_state = t.snapshot_with_key(&bob);
        assert!(bob_state.is_none(), "bob should have no tracked risk");
        assert_eq!(t.level_for_key(&bob), RiskLevel::Allow);

        // Alice is over the block threshold.
        let alice_state = t.snapshot_with_key(&alice).unwrap();
        assert_eq!(alice_state.score, 80);
        // With default thresholds challenge_at=30, block_at=70 →
        // Alice's 80 is Block.
        assert_eq!(t.level_for_key(&alice), RiskLevel::Block);
    }

    /// Different IPs with the SAME session still get independent
    /// buckets — IP rotation by the same attacker doesn't merge,
    /// because the IP axis IS still part of the key. This is the
    /// "Distributed credential stuffing with IP rotation" lifetime-
    /// strikes invariant in §5.5.
    ///
    /// (When operators want the inverse semantic — "same device,
    /// different IPs should accumulate" — they construct a
    /// RiskKey with the IP normalized to a placeholder. That's a
    /// future composite-by-device variant.)
    #[test]
    fn composite_key_with_different_ips_dont_merge() {
        let t = RiskTracker::new(&cfg());
        let same_device = "fp-attacker";
        let ip_a = key_with("203.0.113.1", Some(same_device), None);
        let ip_b = key_with("203.0.113.2", Some(same_device), None);
        t.record_malicious_with_key(ip_a.clone(), 60);
        // ip_b has nothing.
        assert!(t.snapshot_with_key(&ip_b).is_none());
        // ip_a has 60.
        assert_eq!(t.snapshot_with_key(&ip_a).unwrap().score, 60);
    }

    /// IP-only and composite-key calls populate DIFFERENT buckets
    /// even when the IP matches. Auditor's intent: don't conflate.
    #[test]
    fn ip_only_call_and_composite_call_populate_different_buckets() {
        let t = RiskTracker::new(&cfg());
        let p = ip("10.0.0.1");
        let composite = key_with("10.0.0.1", Some("fp-x"), Some("sess-x"));

        // IP-only bucket: 60 → Challenge (60 ≥ challenge_at=30).
        t.record_malicious(p, 60);
        // Composite bucket: 10 → Allow (10 < challenge_at=30).
        t.record_malicious_with_key(composite.clone(), 10);

        assert_eq!(t.snapshot(p).unwrap().score, 60);
        assert_eq!(t.snapshot_with_key(&composite).unwrap().score, 10);
        assert_eq!(t.level(p), RiskLevel::Challenge);
        assert_eq!(t.level_for_key(&composite), RiskLevel::Allow);
    }

    /// Composite-key + threshold-based level gating uses the
    /// composite bucket's score, not the IP-only bucket's.
    #[test]
    fn level_for_key_reads_composite_bucket() {
        let t = RiskTracker::new(&cfg());
        let p = ip("10.0.0.42");
        let k = key_with("10.0.0.42", Some("fp"), None);

        // IP-only bucket: high risk.
        t.record_malicious(p, 80);
        // Composite bucket: clean.
        // level(ip) → Block; level_for_key(composite) → Allow.
        assert_eq!(t.level(p), RiskLevel::Block);
        assert_eq!(t.level_for_key(&k), RiskLevel::Allow);
    }

    /// `reset_with_key` clears one composite bucket without
    /// touching the IP-only bucket or other composites.
    #[test]
    fn reset_with_key_drops_only_target_bucket() {
        let t = RiskTracker::new(&cfg());
        let p = ip("10.0.0.5");
        let k1 = key_with("10.0.0.5", Some("fp1"), None);
        let k2 = key_with("10.0.0.5", Some("fp2"), None);
        t.record_malicious(p, 10);
        t.record_malicious_with_key(k1.clone(), 20);
        t.record_malicious_with_key(k2.clone(), 30);

        assert!(t.reset_with_key(&k1));
        // k1 gone; k2 + ip-only untouched.
        assert!(t.snapshot_with_key(&k1).is_none());
        assert!(t.snapshot_with_key(&k2).is_some());
        assert!(t.snapshot(p).is_some());
    }

    /// 2026-05-19 — `top()` surfaces device_fp + session in the
    /// wire shape so the dashboard can render one row per
    /// composite-key bucket.
    #[test]
    fn top_populates_composite_axes_in_snapshot() {
        let t = RiskTracker::new(&cfg());
        let alice = key_with("10.0.0.10", Some("fp-alice-1234"), Some("sess-alice"));
        let bob = key_with("10.0.0.10", Some("fp-bob-5678"), Some("sess-bob"));
        let anon = key_with("10.0.0.11", None, None);
        t.record_malicious_with_key(alice.clone(), 25);
        t.record_malicious_with_key(bob.clone(), 35);
        t.record_malicious_with_key(anon.clone(), 15);

        let rows = t.top(10);
        // Two NAT'd-IP buckets + one IP-only bucket = 3 rows.
        assert_eq!(rows.len(), 3);
        let alice_row = rows
            .iter()
            .find(|r| r.device_fp.as_deref() == Some("fp-alice-1234"))
            .expect("alice row");
        assert_eq!(alice_row.ip, "10.0.0.10");
        assert_eq!(alice_row.session.as_deref(), Some("sess-alice"));
        let bob_row = rows
            .iter()
            .find(|r| r.device_fp.as_deref() == Some("fp-bob-5678"))
            .expect("bob row");
        assert_eq!(bob_row.ip, "10.0.0.10");
        assert_eq!(bob_row.session.as_deref(), Some("sess-bob"));
        let anon_row = rows
            .iter()
            .find(|r| r.ip == "10.0.0.11")
            .expect("anon row");
        assert!(anon_row.device_fp.is_none(), "no TLS → device_fp is None");
        assert!(anon_row.session.is_none(), "no cookie → session is None");
    }
}
