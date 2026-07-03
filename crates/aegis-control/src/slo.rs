// SLO / SLI engine + multi-window multi-burn-rate alerting.
//
// SLIs tracked:
//   - Data-plane availability (1 - error_rate); SLO-P1: errors =
//     gateway failures (timeout/circuit_breaker) + forwarded
//     origin 5xx — security enforcement is EXCLUDED and tracked
//     on the separate enforcement counter (see `classify`)
//   - WAF overhead p50/p95/p99 latency (declared, no producer yet)
//   - Upstream availability per pool (declared, no producer yet)
//   - Audit delivery rate (declared; objective dropped in SLO-P1 —
//     the old producer was a hardcoded-1.0 tautology)
//   - Cert freshness (days to expiry; declared, no producer yet)
//
// Multi-burn: fast (1h/2%) → page; slow (6h/5%, 3d/10%) → ticket.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub mod classify;
pub mod dispatch;
pub mod producers;

// ---------------------------------------------------------------------------
// SLI definitions
// ---------------------------------------------------------------------------

/// SLI kind — each tracked indicator.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliKind {
    DataPlaneAvailability,
    WafOverheadP50,
    WafOverheadP95,
    WafOverheadP99,
    /// Per-pool upstream availability. No producer yet (SLO-P5
    /// candidate); when one lands, `pool` MUST come from the
    /// fixed configured pool list — each distinct kind lazily
    /// allocates a ~1.6MB bucket store, so unbounded/user-derived
    /// names would grow the SLI map without limit.
    UpstreamAvailability {
        pool: String,
    },
    AuditDeliveryRate,
    CertFreshnessDays,
}

/// A single SLI observation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SliSample {
    pub kind: SliKind,
    pub value: f64,
    pub ts: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// SLO configuration
// ---------------------------------------------------------------------------

/// SLO objective: target value and error budget.
///
/// `deny_unknown_fields` (P3 review MEDIUM-6): when SLO-P4 wires
/// config-driven objectives, a stale key (e.g. the removed
/// `budget_pct`) must fail validation loudly, not deserialize to
/// silently-defaulted thresholds.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SloObjective {
    pub sli: SliKind,
    pub target: f64,
    pub window_days: u32,
    pub burn_rates: Vec<BurnRateWindow>,
    /// SLO-P3 — minimum observations in a burn window before it
    /// may fire. 1 bad request out of 3 at 04:00 is 33% "error
    /// rate" but not an incident.
    #[serde(default = "default_min_events")]
    pub min_events: u64,
}

/// Default [`SloObjective::min_events`].
pub fn default_min_events() -> u64 {
    60
}

/// SLO-P4 — default seconds of post-traffic silence before the
/// telemetry-absent watchdog fires. Overridable via the `slo:`
/// config section (`telemetry_absent_after_secs`; 0 disables).
pub const DEFAULT_TELEMETRY_ABSENT_AFTER_SECS: u64 = 600;

/// A burn-rate alerting window (SLO-P3: a multi-window pair per
/// Google SRE Workbook ch.5 — fire only when BOTH the long and
/// the short window burn above `burn_threshold`; the short
/// window makes alerts stop firing quickly after recovery and
/// prevents stale re-fires).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurnRateWindow {
    pub window_hours: u64,
    /// Short confirmation window of the pair.
    #[serde(default = "default_short_window_minutes")]
    pub short_window_minutes: u64,
    /// Burn-rate threshold: multiples of the break-even budget
    /// burn pace (1.0 = spending exactly the whole budget over
    /// the SLO window). 14.4 over 1h ⇔ 2% of a 30d budget/hour.
    #[serde(default = "default_burn_threshold")]
    pub burn_threshold: f64,
    pub severity: AlertSeverity,
}

/// Default [`BurnRateWindow::short_window_minutes`].
pub fn default_short_window_minutes() -> u64 {
    5
}

/// Default [`BurnRateWindow::burn_threshold`] — the standard
/// fast-burn page threshold.
pub fn default_burn_threshold() -> f64 {
    14.4
}

/// Alert severity.
///
/// `Info` was added 2026-05-20 alongside the alerts refactor so
/// resolved / informational events (e.g. `DdosModeCleared`,
/// `UpstreamPoolRecovered`) can be routed away from the on-call
/// pager room. Existing JSON payloads serialise unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Page,
    Ticket,
    Info,
}

/// Default SLO set for a WAF.
pub fn default_objectives() -> Vec<SloObjective> {
    vec![
        SloObjective {
            sli: SliKind::DataPlaneAvailability,
            target: 0.999,
            window_days: 30,
            // SLO-P3 — standard multi-window multi-burn pairs:
            // 14.4× over 1h (2% of the 30d budget) pages, 6× over
            // 6h (5%) pages, 1× over 3d (10% and on pace to spend
            // it all) tickets. Each long window is gated by its
            // short confirmation window.
            burn_rates: vec![
                BurnRateWindow {
                    window_hours: 1,
                    short_window_minutes: 5,
                    burn_threshold: 14.4,
                    severity: AlertSeverity::Page,
                },
                BurnRateWindow {
                    window_hours: 6,
                    short_window_minutes: 30,
                    burn_threshold: 6.0,
                    severity: AlertSeverity::Page,
                },
                BurnRateWindow {
                    window_hours: 72,
                    short_window_minutes: 360,
                    burn_threshold: 1.0,
                    severity: AlertSeverity::Ticket,
                },
            ],
            min_events: default_min_events(),
        },
        // SLO-P1 (2026-07-03): the AuditDeliveryRate objective was
        // dropped — its producer hardcoded `1.0` per observed
        // event, so the 99.99% target was a tautology that could
        // never breach. Real delivery measurement (events in vs
        // sink-acked) is future work; the SliKind stays for wire
        // compat.
    ]
}

// ---------------------------------------------------------------------------
// Alert
// ---------------------------------------------------------------------------

/// A fired SLO alert.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SloAlert {
    pub sli: SliKind,
    pub severity: AlertSeverity,
    pub fired_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub burn_rate: f64,
    /// % of the SLO budget one `window_hours` window spends at
    /// the measured burn (SLO-P3). NOTE: a short-horizon
    /// *projection* — `BudgetStatus::budget_remaining_pct` is the
    /// measured 30d figure; the two legitimately differ.
    pub budget_consumed_pct: f64,
    pub window_hours: u64,
    pub runbook_url: String,
    /// Measured SLI value over the window (a ratio in `[0, 1]`,
    /// e.g. `0.123` = 12.3% availability). Carried so the alert
    /// message can show measured-vs-target instead of only the
    /// derived burn rate. 2026-06-02 — observability alert P1.
    #[serde(default)]
    pub measured: f64,
    /// The objective's target value (ratio in `[0, 1]`, e.g.
    /// `0.999`). 2026-06-02 — observability alert P1.
    #[serde(default)]
    pub target: f64,
}

/// Multi-source operator alert (2026-05-20 alerts refactor).
///
/// Subsumes [`SloAlert`] plus the operationally-important non-
/// SLO event classes. The dispatcher routes by
/// [`Self::severity`]; per-variant chat formatting lives in
/// [`crate::slo::dispatch::format_event_text`].
///
/// SLO-P5 (2026-07-03): the "wired" flags below were re-verified
/// against actual producers — several pre-P5 comments claimed
/// wiring that never existed. `StrikeBlockSurge` and
/// `AuditChainBreak` remain the only placeholders (producers need
/// new detection logic — see `plans/future/`); the removed
/// `GitOpsDrift` variant went with its deleted module.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertEvent {
    /// SLO burn-rate breach (wired: the evaluation loop).
    Slo(SloAlert),
    /// DDoS spike gate engaged (wired SLO-P5: polled per
    /// evaluation tick from `DdosRuntime::is_spike_active`).
    DdosModeEntered {
        fired_at: DateTime<Utc>,
        trigger: String,
        observed_rps: u32,
    },
    /// DDoS spike gate released (wired SLO-P5).
    DdosModeCleared {
        fired_at: DateTime<Utc>,
        duration_seconds: u64,
    },
    /// A TLS cert crossed an expiry band — <30d Ticket, <7d Page
    /// (wired SLO-P5: hourly sweep of the cert inventory;
    /// `producers::CertAlertState` fires once per band).
    CertExpiringSoon {
        fired_at: DateTime<Utc>,
        host: String,
        days_remaining: u32,
        not_after: DateTime<Utc>,
    },
    /// Risk tracker observed N unique source IPs hitting
    /// strike-block in a short window (placeholder — producer
    /// needs new detection logic).
    StrikeBlockSurge {
        fired_at: DateTime<Utc>,
        unique_ips: u32,
        window_seconds: u32,
        top_rule_ids: Vec<String>,
    },
    /// Upstream pool dropped below full healthy membership
    /// (wired SLO-P5: both health monitors via
    /// `producers::PoolAlertState`; healthy=0 pages, partial
    /// tickets).
    UpstreamPoolDegraded {
        fired_at: DateTime<Utc>,
        pool: String,
        healthy: u32,
        total: u32,
        first_down: String,
    },
    /// Upstream pool returned to fully healthy (wired SLO-P5).
    UpstreamPoolRecovered {
        fired_at: DateTime<Utc>,
        pool: String,
    },
    // Phase 1 (leaderless): the `LeaderLost` alert variant was
    // removed with the global leader concept — it never had a
    // producer (was "not yet wired").
    /// Hot-reload of config failed; last-known-good is still
    /// live (wired SLO-P5: file-watcher validation/publish
    /// failures + shared-config NACK).
    HotReloadFailed {
        fired_at: DateTime<Utc>,
        reason: String,
        last_known_good_version: u64,
    },
    // SLO-P5: `GitOpsDrift` deleted — the gitops module was
    // removed 2026-05-17 (F-CRITICAL-005) and the variant never
    // had a producer.
    /// Audit-chain verify detected a hash mismatch (placeholder —
    /// producer needs new detection logic).
    AuditChainBreak {
        fired_at: DateTime<Utc>,
        last_good_seq: u64,
        observed_seq: u64,
    },
    /// A scheduled AI-copilot situational briefing pushed into the
    /// alerts pipeline (Copilot P4). Informational; `body` is the
    /// copilot's brief text. Produced by the briefing scheduler when
    /// the copilot is enabled and a briefing interval is configured.
    OperatorBriefing {
        fired_at: DateTime<Utc>,
        body: String,
    },
    /// SLO-P3 — an SLI that had been producing samples went
    /// silent for `silent_seconds`: a wedged data plane, not an
    /// idle one. Closes the blackout hole where zero traffic
    /// meant zero samples meant no alert (wired by the SLO
    /// evaluation loop via
    /// [`crate::slo::SloEngine::telemetry_absent`]).
    TelemetryAbsent {
        fired_at: DateTime<Utc>,
        sli: String,
        silent_seconds: u64,
    },
}

impl AlertEvent {
    /// Routing severity. Operators wire one receiver per
    /// severity class (Page → on-call, Ticket → ITSM, Info →
    /// audit feed) via [`AlertReceiver::severities`].
    pub fn severity(&self) -> AlertSeverity {
        match self {
            AlertEvent::Slo(a) => a.severity,
            AlertEvent::DdosModeEntered { .. } => AlertSeverity::Page,
            AlertEvent::DdosModeCleared { .. } => AlertSeverity::Info,
            AlertEvent::CertExpiringSoon { days_remaining, .. } => {
                // < 7 days is page-worthy; 7–30 is a ticket.
                if *days_remaining < 7 {
                    AlertSeverity::Page
                } else {
                    AlertSeverity::Ticket
                }
            }
            AlertEvent::StrikeBlockSurge { .. } => AlertSeverity::Page,
            // SLO-P5 — zero healthy members means the pool is DOWN
            // (page-worthy); losing some members while others still
            // serve is a Ticket (`pick()` fails closed, traffic
            // still flows).
            AlertEvent::UpstreamPoolDegraded { healthy, .. } => {
                if *healthy == 0 {
                    AlertSeverity::Page
                } else {
                    AlertSeverity::Ticket
                }
            }
            AlertEvent::UpstreamPoolRecovered { .. } => AlertSeverity::Info,
            AlertEvent::HotReloadFailed { .. } => AlertSeverity::Ticket,
            AlertEvent::AuditChainBreak { .. } => AlertSeverity::Page,
            AlertEvent::OperatorBriefing { .. } => AlertSeverity::Info,
            AlertEvent::TelemetryAbsent { .. } => AlertSeverity::Ticket,
        }
    }

    /// Time the event fired. Used for dedup-window math.
    pub fn fired_at(&self) -> DateTime<Utc> {
        match self {
            AlertEvent::Slo(a) => a.fired_at,
            AlertEvent::DdosModeEntered { fired_at, .. } => *fired_at,
            AlertEvent::DdosModeCleared { fired_at, .. } => *fired_at,
            AlertEvent::CertExpiringSoon { fired_at, .. } => *fired_at,
            AlertEvent::StrikeBlockSurge { fired_at, .. } => *fired_at,
            AlertEvent::UpstreamPoolDegraded { fired_at, .. } => *fired_at,
            AlertEvent::UpstreamPoolRecovered { fired_at, .. } => *fired_at,
            AlertEvent::HotReloadFailed { fired_at, .. } => *fired_at,
            AlertEvent::AuditChainBreak { fired_at, .. } => *fired_at,
            AlertEvent::OperatorBriefing { fired_at, .. } => *fired_at,
            AlertEvent::TelemetryAbsent { fired_at, .. } => *fired_at,
        }
    }

    /// Dedup fingerprint — a hash of the variant tag plus its
    /// load-bearing fields. Two events with the same fingerprint
    /// inside the dedup window get suppressed (with a
    /// `(+N suppressed)` note on the next emission).
    ///
    /// `SloAlert` keys on `(sli, severity, window_hours)` so a
    /// repeated burn-rate breach in the same window dedups.
    /// `CertExpiringSoon` keys on `(host, not_after_day)` so a
    /// re-fire on the same calendar day suppresses.
    pub fn fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        match self {
            AlertEvent::Slo(a) => {
                "slo".hash(&mut h);
                format!("{:?}", a.sli).hash(&mut h);
                a.severity.hash(&mut h);
                a.window_hours.hash(&mut h);
                // P3 review MEDIUM-4 — fire and resolve are
                // distinct notifications; without this a resolve
                // landing within the dedup window of its fire was
                // silently swallowed (P3's short-window recovery
                // makes minute-scale cycles legitimate).
                a.resolved_at.is_some().hash(&mut h);
            }
            AlertEvent::DdosModeEntered { trigger, .. } => {
                "ddos_entered".hash(&mut h);
                trigger.hash(&mut h);
            }
            AlertEvent::DdosModeCleared { .. } => {
                "ddos_cleared".hash(&mut h);
            }
            AlertEvent::CertExpiringSoon {
                host, not_after, ..
            } => {
                "cert_expiring".hash(&mut h);
                host.hash(&mut h);
                not_after.date_naive().to_string().hash(&mut h);
            }
            AlertEvent::StrikeBlockSurge { window_seconds, .. } => {
                "strike_surge".hash(&mut h);
                window_seconds.hash(&mut h);
            }
            AlertEvent::UpstreamPoolDegraded { pool, .. } => {
                "pool_degraded".hash(&mut h);
                pool.hash(&mut h);
            }
            AlertEvent::UpstreamPoolRecovered { pool, .. } => {
                "pool_recovered".hash(&mut h);
                pool.hash(&mut h);
            }
            AlertEvent::HotReloadFailed {
                last_known_good_version,
                ..
            } => {
                "hot_reload_failed".hash(&mut h);
                last_known_good_version.hash(&mut h);
            }
            AlertEvent::AuditChainBreak { observed_seq, .. } => {
                "audit_chain_break".hash(&mut h);
                observed_seq.hash(&mut h);
            }
            // Each scheduled briefing is distinct content — key on the
            // fire time so two briefings never dedup against each other.
            AlertEvent::OperatorBriefing { fired_at, .. } => {
                "operator_briefing".hash(&mut h);
                fired_at.timestamp().hash(&mut h);
            }
            // Keyed on the SLI so a continuing blackout dedups
            // (the loop also fires only on the transition).
            AlertEvent::TelemetryAbsent { sli, .. } => {
                "telemetry_absent".hash(&mut h);
                sli.hash(&mut h);
            }
        }
        h.finish()
    }
}

// ---------------------------------------------------------------------------
// Dedup cache
// ---------------------------------------------------------------------------

/// Size above which [`AlertDedupCache::check`] runs a stale-entry
/// prune. Generous — the event-class fingerprint space is small;
/// crossing this means a high-cardinality variant (e.g.
/// `CertExpiringSoon` keyed on host × date) is accreting.
const DEDUP_PRUNE_THRESHOLD: usize = 256;

/// In-memory dedup cache used by
/// [`dispatch::dispatch_event`] to suppress refires of the same
/// fingerprint inside a sliding window.
///
/// Operator default is 5 minutes; configure via
/// `cfg.slo.dedup_seconds` (0 disables — preserves the pre-
/// 2026-05-20 behaviour where every tick fires).
#[derive(Debug)]
pub struct AlertDedupCache {
    window: Duration,
    /// fingerprint → (last_emit_ts, suppressed_since_last_emit)
    entries: Mutex<HashMap<u64, (DateTime<Utc>, u32)>>,
}

impl AlertDedupCache {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 5-minute default — the operator-recommended value.
    pub fn default_window() -> Self {
        Self::new(300)
    }

    /// Returns `(should_emit, suppressed_count)`. When
    /// `should_emit` is true, the suppressed count is the
    /// number of fires we silently dropped since the last
    /// successful emission for this fingerprint (zero on the
    /// first emit).
    pub fn check(&self, fingerprint: u64, now: DateTime<Utc>) -> DedupDecision {
        let mut entries = self.entries.lock().expect("dedup cache poisoned");

        // 2026-05-20 memory-leak audit — the cache was insert-only,
        // so distinct fingerprints (e.g. CertExpiringSoon keyed on
        // host × date) accreted over long uptime. Prune entries
        // stale beyond 2× the window when the map grows past a soft
        // threshold. Pruning an entry loses nothing: if its
        // fingerprint fires again it Emits fresh; a stale entry
        // would have Emitted (not Suppressed) on the next check
        // anyway. Throttled by size so the common path stays O(1).
        if entries.len() > DEDUP_PRUNE_THRESHOLD {
            let stale_after = self.window * 2;
            entries.retain(|_, (last_emit, _)| now - *last_emit < stale_after);
        }

        match entries.get_mut(&fingerprint) {
            Some((last_emit, suppressed)) => {
                if now - *last_emit < self.window {
                    *suppressed = suppressed.saturating_add(1);
                    DedupDecision::Suppress
                } else {
                    let drained = *suppressed;
                    *last_emit = now;
                    *suppressed = 0;
                    DedupDecision::Emit {
                        suppressed: drained,
                    }
                }
            }
            None => {
                entries.insert(fingerprint, (now, 0));
                DedupDecision::Emit { suppressed: 0 }
            }
        }
    }

    /// Test helper — reset the cache.
    #[cfg(test)]
    pub fn clear(&self) {
        self.entries.lock().expect("dedup cache poisoned").clear();
    }

    /// Test helper — number of tracked fingerprints. Used to
    /// assert the stale-entry prune keeps the map bounded.
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().expect("dedup cache poisoned").len()
    }
}

impl Default for AlertDedupCache {
    fn default() -> Self {
        Self::default_window()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupDecision {
    Emit { suppressed: u32 },
    Suppress,
}

/// Alert receiver configuration.
///
/// `severities` (2026-05-20) is an optional filter — when set,
/// the dispatcher only routes events whose severity is in the
/// list. An empty / missing list means "all severities", which
/// preserves the pre-refactor behaviour. Typical use: one
/// receiver pointed at the on-call room with `severities:
/// [Page]`, a separate receiver pointed at the audit/ops room
/// with `severities: [Ticket, Info]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertReceiver {
    pub name: String,
    pub kind: ReceiverKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severities: Vec<AlertSeverity>,
}

impl AlertReceiver {
    /// True if this receiver should accept an event of the
    /// given severity. Empty filter = accept everything.
    pub fn accepts(&self, severity: AlertSeverity) -> bool {
        self.severities.is_empty() || self.severities.contains(&severity)
    }
}

/// Alert receiver kind.
///
/// Most variants describe routing destinations; with the
/// `aegis-control/alerts` feature on, [`dispatch::send_alert`]
/// performs real HTTP delivery for [`ReceiverKind::VipTalk`].
/// The rest are descriptive metadata read by an operator-side
/// dispatcher (Alertmanager / a sidecar / a CronJob).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceiverKind {
    AlertmanagerWebhook {
        url: String,
    },
    Slack {
        webhook_url: String,
    },
    PagerDuty {
        routing_key: String,
    },
    ServiceNow {
        instance: String,
        table: String,
    },
    Jira {
        base_url: String,
        project: String,
    },
    /// VipTalk Bot routing — the project's default chat
    /// receiver. Token is the bot identity slug from
    /// `https://api.viptalk.org/v1/bot/<token>/sendMessage`;
    /// `room_ids` are Matrix-style room identifiers like
    /// `!QNxJHzVzJBrLWIOLPo:matrix-uat.viptalk.org`. Override
    /// either via env vars `AEGIS_VIPTALK_BOT_TOKEN` /
    /// `AEGIS_VIPTALK_ROOM_IDS` (comma-separated) at boot.
    VipTalk {
        bot_token: String,
        room_ids: Vec<String>,
    },
}

/// Build the VipTalk default receiver list ONLY when both
/// `AEGIS_VIPTALK_BOT_TOKEN` and `AEGIS_VIPTALK_ROOM_IDS` are set
/// in the environment.
///
/// 2026-05-17 F-CRITICAL-017 (control audit): pre-fix this function
/// returned a hard-coded `bot_token = "xxx-dev-uat-bot-token-xxx"`
/// + `room_ids = ["!Qn...:matrix-uat.viptalk.org"]` when the env
/// vars were missing. Production deployments that forgot to set
/// the env var silently POSTed every SLO alert (with SLI + severity
/// payload) to the project's dev/UAT Matrix room — a third-party
/// disclosure surface for any operator that took the framework's
/// defaults at face value.
///
/// Now: if either env var is unset or empty, return `vec![]` and
/// emit a one-time `tracing::warn!` so the operator notices.
/// Operators who want VipTalk routing set BOTH env vars; operators
/// who want a different sink build their own
/// `Vec<AlertReceiver>` directly.
pub fn default_receivers() -> Vec<AlertReceiver> {
    let bot_token = std::env::var("AEGIS_VIPTALK_BOT_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let room_ids_raw = std::env::var("AEGIS_VIPTALK_ROOM_IDS")
        .ok()
        .filter(|s| !s.is_empty());

    match (bot_token, room_ids_raw) {
        (Some(bot_token), Some(rooms)) => {
            let room_ids: Vec<String> = rooms.split(',').map(|r| r.trim().to_string()).collect();
            vec![AlertReceiver {
                name: "default-viptalk".to_string(),
                kind: ReceiverKind::VipTalk {
                    bot_token,
                    room_ids,
                },
                severities: Vec::new(),
            }]
        }
        _ => {
            tracing::warn!(
                "alert receivers: AEGIS_VIPTALK_BOT_TOKEN + AEGIS_VIPTALK_ROOM_IDS \
                 not both set — SLO alerts will not route to VipTalk. Set both env \
                 vars OR populate `cfg.slo.receivers` explicitly to suppress this warning.",
            );
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// SLI bucket store (in-memory time series) — SLO-P2
// ---------------------------------------------------------------------------

// SLO-P2 (2026-07-03): replaced the 10 000-sample ring buffer.
// The ring capped HISTORY BY SAMPLE COUNT, so at production rates
// the 6h/72h burn windows and the 30d budget silently evaluated
// over the last few minutes of traffic — slow burns were
// undetectable and error bursts "resolved" as soon as enough
// healthy volume evicted them. Fixed-width time buckets keep the
// windows exact at O(1) record cost and bounded memory, and make
// "no data" distinguishable from "healthy".
//
// (History: the ring itself replaced a `Vec::remove(0)` buffer —
// F-CRITICAL-016, 2026-05-17. The hot-path O(1) record property
// is preserved here: one add per tier under the same mutex.)

/// Fine tier: 10s buckets retained 72h — serves every burn
/// window up to the longest (3d) alerting window.
const FINE_BUCKET_SECS: i64 = 10;
const FINE_RETENTION_SECS: i64 = 72 * 3_600;
/// Coarse tier: 1m buckets retained 30d — serves the SLO budget
/// window.
const COARSE_BUCKET_SECS: i64 = 60;
const COARSE_RETENTION_SECS: i64 = 30 * 86_400;

/// One time bucket: sum of sample values (`good`) over `count`
/// observations for bucket index `epoch` (= unix_secs / width).
#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    epoch: i64,
    good: f64,
    count: u64,
}

/// Fixed-size circular bucket array for one tier. Slot index is
/// `epoch % len`; a slot is live for a queried epoch only when
/// its stored `epoch` matches, so recycled slots never leak into
/// window sums.
struct TierRing {
    width_secs: i64,
    slots: Vec<Bucket>,
}

impl TierRing {
    fn new(width_secs: i64, retention_secs: i64) -> Self {
        Self {
            width_secs,
            slots: vec![Bucket::default(); (retention_secs / width_secs) as usize],
        }
    }

    fn record(&mut self, ts_secs: i64, value: f64) {
        let epoch = ts_secs.div_euclid(self.width_secs);
        let len = self.slots.len() as i64;
        let slot = &mut self.slots[epoch.rem_euclid(len) as usize];
        if slot.count > 0 && slot.epoch > epoch {
            // Sample older than retention — its slot has been
            // recycled by a newer epoch. Drop it.
            return;
        }
        if slot.count == 0 || slot.epoch < epoch {
            *slot = Bucket {
                epoch,
                good: 0.0,
                count: 0,
            };
        }
        slot.good += value;
        slot.count += 1;
    }

    /// Sum `(good, count)` over buckets covering
    /// `[from_secs, to_secs]`, clamped to retention.
    ///
    /// The bucket containing `from_secs` is included WHOLE, so a
    /// window can over-include up to one bucket width of history
    /// (10s fine / 60s coarse) — negligible vs. the ≥1h windows
    /// served, and the price of fixed-width buckets.
    fn totals(&self, from_secs: i64, to_secs: i64) -> (f64, u64) {
        let len = self.slots.len() as i64;
        let to_epoch = to_secs.div_euclid(self.width_secs);
        let first = from_secs
            .div_euclid(self.width_secs)
            .max(to_epoch - len + 1);
        let (mut good, mut count) = (0.0_f64, 0_u64);
        for epoch in first..=to_epoch {
            let slot = &self.slots[epoch.rem_euclid(len) as usize];
            if slot.epoch == epoch && slot.count > 0 {
                good += slot.good;
                count += slot.count;
            }
        }
        (good, count)
    }
}

/// Per-SLI two-tier bucket store.
struct BucketStore {
    fine: TierRing,
    coarse: TierRing,
}

impl BucketStore {
    fn new() -> Self {
        Self {
            fine: TierRing::new(FINE_BUCKET_SECS, FINE_RETENTION_SECS),
            coarse: TierRing::new(COARSE_BUCKET_SECS, COARSE_RETENTION_SECS),
        }
    }

    fn record(&mut self, ts: DateTime<Utc>, value: f64) {
        let secs = ts.timestamp();
        self.fine.record(secs, value);
        self.coarse.record(secs, value);
    }

    /// `(good_sum, observation_count)` in the trailing `window`
    /// as of `now`. Windows within fine retention read the fine
    /// tier; longer windows (the 30d budget) read the coarse tier.
    fn window_totals(&self, now: DateTime<Utc>, window: Duration) -> (f64, u64) {
        let ring = if window.num_seconds() <= FINE_RETENTION_SECS {
            &self.fine
        } else {
            &self.coarse
        };
        ring.totals((now - window).timestamp(), now.timestamp())
    }

    /// Mean sample value in the window; `None` when there are no
    /// observations (no data ≠ healthy).
    fn average_in_window(&self, now: DateTime<Utc>, window: Duration) -> Option<f64> {
        let (good, count) = self.window_totals(now, window);
        (count > 0).then(|| good / count as f64)
    }
}

// ---------------------------------------------------------------------------
// SLO engine
// ---------------------------------------------------------------------------

/// Cap on `SloEngine::fired_history`. Mirrors the audit ring's
/// 200-entry bound — enough for the dashboard's history view
/// without growing unbounded over a long-running process.
const MAX_FIRED_HISTORY: usize = 200;

/// Cap on retained enforcement timestamps — same bound as the
/// SLI ring. `EnforcementStats::last_hour` is therefore a floor
/// under extreme block volume (>10k enforcements/hour); `total`
/// is exact.
const MAX_ENFORCEMENT_EVENTS: usize = 10_000;

/// Node-local enforcement counter (SLO-P1). Blocks / challenges /
/// rate-limits are the WAF *working* — excluded from the
/// availability SLI and surfaced as this info series instead
/// (`/api/slo`), never as an objective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementStats {
    /// Enforcement events since boot.
    pub total: u64,
    /// Enforcement events in the trailing hour (capped by the
    /// retention ring — see [`MAX_ENFORCEMENT_EVENTS`]).
    pub last_hour: u64,
}

/// Retention ring behind [`SloEngine::record_enforcement`].
#[derive(Debug)]
struct EnforcementRing {
    recent: std::collections::VecDeque<DateTime<Utc>>,
    total: u64,
}

impl Default for EnforcementRing {
    fn default() -> Self {
        Self {
            // Pre-allocate to the cap for the same reason as
            // `SliRingBuffer::new` above (F-CRITICAL-016): this is
            // fed from the audit-bus hot path, and growth
            // reallocations under the mutex are avoidable stalls.
            recent: std::collections::VecDeque::with_capacity(MAX_ENFORCEMENT_EVENTS),
            total: 0,
        }
    }
}

/// The SLO engine: tracks SLIs and fires alerts.
pub struct SloEngine {
    /// Behind a mutex since SLO-P4 (config-driven hot swap via
    /// [`Self::set_objectives`]). Read once per evaluation /
    /// status call — 30s / 10s cadence, contention-free.
    objectives: Mutex<Vec<SloObjective>>,
    buffers: Mutex<HashMap<SliKind, BucketStore>>,
    active_alerts: Mutex<Vec<SloAlert>>,
    fired_history: Mutex<Vec<SloAlert>>,
    enforcement: Mutex<EnforcementRing>,
}

impl SloEngine {
    pub fn new(objectives: Vec<SloObjective>) -> Self {
        // SLO-P2/P4 — a window wider than the bucket-store
        // retention would silently evaluate over truncated
        // history, which is exactly the dishonesty P2 removes.
        // Boot construction refuses loudly in dev; the config
        // path ([`Self::set_objectives`]) returns the error.
        debug_assert!(
            Self::validate_objectives(&objectives).is_ok(),
            "invalid boot objectives: {:?}",
            Self::validate_objectives(&objectives),
        );
        Self {
            objectives: Mutex::new(objectives),
            buffers: Mutex::new(HashMap::new()),
            active_alerts: Mutex::new(Vec::new()),
            fired_history: Mutex::new(Vec::new()),
            enforcement: Mutex::new(EnforcementRing::default()),
        }
    }

    /// Record one security-enforcement event (block / challenge /
    /// rate_limit) — SLO-P1. Kept OFF the availability SLI.
    pub fn record_enforcement(&self, ts: DateTime<Utc>) {
        let mut ring = self.enforcement.lock().unwrap();
        ring.total = ring.total.saturating_add(1);
        if ring.recent.len() >= MAX_ENFORCEMENT_EVENTS {
            ring.recent.pop_front();
        }
        ring.recent.push_back(ts);
    }

    /// SLO-P4 — validate an objective set against the engine's
    /// invariants (bucket-store retention, meaningful budget).
    /// Shared by [`Self::set_objectives`] and the config API so a
    /// bad `slo:` section fails loudly at the boundary.
    pub fn validate_objectives(objectives: &[SloObjective]) -> Result<(), String> {
        for obj in objectives {
            if !(obj.target > 0.0 && obj.target < 1.0) {
                return Err(format!(
                    "objective {:?}: target {} must be within (0, 1) — a target \
                     of 1.0 leaves no error budget to alert on",
                    obj.sli, obj.target,
                ));
            }
            if obj.window_days as i64 * 86_400 > COARSE_RETENTION_SECS {
                return Err(format!(
                    "objective {:?}: window_days {} exceeds the 30d bucket \
                     retention — the budget would be computed over truncated \
                     history",
                    obj.sli, obj.window_days,
                ));
            }
            for burn in &obj.burn_rates {
                if burn.window_hours as i64 * 3_600 > FINE_RETENTION_SECS {
                    return Err(format!(
                        "objective {:?}: burn window {}h exceeds the 72h \
                         bucket retention",
                        obj.sli, burn.window_hours,
                    ));
                }
                if burn.short_window_minutes >= burn.window_hours * 60 {
                    return Err(format!(
                        "objective {:?}: short window {}m must be shorter \
                         than its long window {}h",
                        obj.sli, burn.short_window_minutes, burn.window_hours,
                    ));
                }
            }
        }
        Ok(())
    }

    /// SLO-P4 — hot-swap the objective set (config apply path).
    /// Thresholds change; the SLI **buffers are untouched**, so a
    /// threshold edit does not discard observed history. Active
    /// alerts for removed/changed windows resolve or refire on
    /// the next evaluation naturally.
    pub fn set_objectives(&self, objectives: Vec<SloObjective>) -> Result<(), String> {
        Self::validate_objectives(&objectives)?;
        *self.objectives.lock().unwrap() = objectives;
        Ok(())
    }

    /// SLO-P3 telemetry-absent watchdog seam: `true` when `kind`
    /// has produced at least one sample since boot but none in
    /// the trailing `absent_after` window — a wedged data plane,
    /// not an idle one (a never-served kind returns `false`).
    pub fn telemetry_absent(
        &self,
        kind: &SliKind,
        absent_after: Duration,
        now: DateTime<Utc>,
    ) -> bool {
        let buffers = self.buffers.lock().unwrap();
        match buffers.get(kind) {
            // Never served since boot — an idle node, not a
            // blackout.
            None => false,
            Some(buf) => buf.window_totals(now, absent_after).1 == 0,
        }
    }

    /// Objective-driven variant of [`Self::telemetry_absent`]
    /// (P3 review MEDIUM-5): every SLI with a configured
    /// objective that has gone silent after serving. The
    /// watchdog loop iterates this instead of hardcoding one
    /// kind, so a future second objective inherits blackout
    /// coverage automatically.
    pub fn telemetry_absent_slis(
        &self,
        absent_after: Duration,
        now: DateTime<Utc>,
    ) -> Vec<SliKind> {
        // Collect kinds first so the objectives lock is released
        // before telemetry_absent takes the buffers lock.
        let kinds: Vec<SliKind> = self
            .objectives
            .lock()
            .unwrap()
            .iter()
            .map(|o| o.sli.clone())
            .collect();
        kinds
            .into_iter()
            .filter(|kind| self.telemetry_absent(kind, absent_after, now))
            .collect()
    }

    /// Current enforcement counter snapshot for `/api/slo`.
    pub fn enforcement_stats(&self) -> EnforcementStats {
        let ring = self.enforcement.lock().unwrap();
        let cutoff = Utc::now() - Duration::hours(1);
        let last_hour = ring.recent.iter().filter(|ts| **ts >= cutoff).count() as u64;
        EnforcementStats {
            total: ring.total,
            last_hour,
        }
    }

    /// Record an SLI observation.
    pub fn record(&self, sample: SliSample) {
        self.record_at(sample, Utc::now());
    }

    /// Clock-injectable variant of [`Self::record`] (SLO-P2) —
    /// pairs with [`Self::evaluate_at`] for deterministic tests /
    /// simulation. Also the clock-skew guard: a sample stamped
    /// far in the future would park a huge epoch in its slot and
    /// silently drop every legitimate sample hashing there for
    /// the rest of the process's life (one slot per ~72h/30d
    /// cycle), so future-skewed timestamps are clamped to `now`.
    pub fn record_at(&self, sample: SliSample, now: DateTime<Utc>) {
        let ts = if sample.ts > now + Duration::minutes(1) {
            now
        } else {
            sample.ts
        };
        let mut buffers = self.buffers.lock().unwrap();
        let buf = buffers
            .entry(sample.kind.clone())
            .or_insert_with(BucketStore::new);
        buf.record(ts, sample.value);
    }

    /// Evaluate all objectives and return newly fired/resolved alerts.
    pub fn evaluate(&self) -> Vec<SloAlert> {
        self.evaluate_at(Utc::now())
    }

    /// Number of SLI observations recorded for `kind` inside the
    /// trailing `window` as of `now`. Distinguishes "no data"
    /// (0) from "healthy" — the seam the (P3) telemetry-absent
    /// watchdog reads.
    pub fn sample_count_in_window(
        &self,
        kind: &SliKind,
        window: Duration,
        now: DateTime<Utc>,
    ) -> u64 {
        let buffers = self.buffers.lock().unwrap();
        buffers
            .get(kind)
            .map(|b| b.window_totals(now, window).1)
            .unwrap_or(0)
    }

    /// Evaluate all objectives as of `now` and return newly
    /// fired/resolved alerts. SLO-P2 — the injectable clock is
    /// the deterministic seam for tests and the (P6) alert
    /// simulator; production callers use [`Self::evaluate`].
    pub fn evaluate_at(&self, now: DateTime<Utc>) -> Vec<SloAlert> {
        // Snapshot the objective set up front (SLO-P4 hot swap) —
        // small clone, and keeps this lock out of the ordering
        // with the three locks below.
        let objectives = self.objectives.lock().unwrap().clone();
        let buffers = self.buffers.lock().unwrap();
        let mut active = self.active_alerts.lock().unwrap();
        let mut history = self.fired_history.lock().unwrap();
        let mut new_alerts = Vec::new();

        for obj in &objectives {
            let buf = match buffers.get(&obj.sli) {
                Some(b) => b,
                None => continue,
            };
            let budget = 1.0 - obj.target;

            for burn in &obj.burn_rates {
                // SLO-P3 — multi-window pair: fire only when BOTH
                // the long window and its short confirmation
                // window burn above the threshold, and the long
                // window has enough traffic to mean anything.
                // burn rate = error_rate / budget: multiples of
                // the break-even pace that spends exactly the
                // whole budget over the SLO window.
                let long = Duration::hours(burn.window_hours as i64);
                let short = Duration::minutes(burn.short_window_minutes as i64);
                let (long_good, long_count) = buf.window_totals(now, long);
                let long_avg = if long_count > 0 {
                    long_good / long_count as f64
                } else {
                    1.0
                };
                let long_burn = if budget > 0.0 {
                    (1.0 - long_avg) / budget
                } else {
                    0.0
                };
                // Short-window state (P3 review HIGH-1/MEDIUM-3).
                // FIRE needs the short window burning with
                // proportional volume (min_events scaled to the
                // window ratio) — a stale burst or one stray bad
                // sample must not (re-)fire off the long window
                // alone. RESOLVE needs the short window healthy
                // WITH data — an empty short window is silence,
                // not recovery, and must keep a fired alert
                // active (the blackout watchdog rides alongside).
                let (short_good, short_count) = buf.window_totals(now, short);
                let short_min = (obj.min_events * burn.short_window_minutes)
                    .checked_div(burn.window_hours * 60)
                    .unwrap_or(0)
                    .max(1);
                let short_burn = if short_count > 0 && budget > 0.0 {
                    (1.0 - short_good / short_count as f64) / budget
                } else {
                    0.0
                };
                let short_confirms = short_count >= short_min && short_burn >= burn.burn_threshold;
                let short_recovered = short_count > 0 && short_burn < burn.burn_threshold;
                let is_burning = long_count >= obj.min_events
                    && long_burn >= burn.burn_threshold
                    && short_confirms;

                // Check if already active for this SLI + window.
                let already_active = active.iter().any(|a| {
                    a.sli == obj.sli
                        && a.window_hours == burn.window_hours
                        && a.resolved_at.is_none()
                });

                if is_burning && !already_active {
                    // Fraction of the SLO budget actually spent
                    // by one long window at this pace — the
                    // pre-P3 code reported burn×100 here, with
                    // no time factor.
                    let window_fraction =
                        burn.window_hours as f64 / (obj.window_days.max(1) as f64 * 24.0);
                    let alert = SloAlert {
                        sli: obj.sli.clone(),
                        severity: burn.severity,
                        fired_at: now,
                        resolved_at: None,
                        burn_rate: long_burn,
                        budget_consumed_pct: long_burn * window_fraction * 100.0,
                        window_hours: burn.window_hours,
                        runbook_url: format!(
                            "https://runbooks.aegis.local/slo/{:?}/{}h",
                            obj.sli, burn.window_hours
                        ),
                        // `long_avg` is the measured SLI value over
                        // the window; `obj.target` is the objective.
                        // Both carried so the message renders
                        // measured-vs-target (alert P1).
                        measured: long_avg,
                        target: obj.target,
                    };
                    active.push(alert.clone());
                    history.push(alert.clone());
                    // 2026-05-20 memory-leak audit — fired_history was
                    // push-only and grew unbounded over uptime. Cap to
                    // a ring of the most-recent MAX_FIRED_HISTORY.
                    if history.len() > MAX_FIRED_HISTORY {
                        let excess = history.len() - MAX_FIRED_HISTORY;
                        history.drain(0..excess);
                    }
                    new_alerts.push(alert);
                } else if !is_burning && already_active && short_recovered {
                    // Resolve — only on CONFIRMED recovery
                    // (healthy short window with data), never on
                    // silence (P3 review HIGH-1).
                    for a in active.iter_mut() {
                        if a.sli == obj.sli
                            && a.window_hours == burn.window_hours
                            && a.resolved_at.is_none()
                        {
                            a.resolved_at = Some(now);
                            let mut resolved = a.clone();
                            resolved.resolved_at = Some(now);
                            new_alerts.push(resolved);
                        }
                    }
                }
            }
        }

        // 2026-05-20 memory-leak audit — `active_alerts` previously
        // marked entries resolved but never removed them, so the Vec
        // grew unbounded. The resolution has now been emitted into
        // `new_alerts`; drop the resolved rows so `active` only ever
        // holds genuinely-active alerts (the getter already filters
        // these out, but the storage was still accreting them).
        active.retain(|a| a.resolved_at.is_none());

        new_alerts
    }

    /// Get currently active (unresolved) alerts.
    pub fn active_alerts(&self) -> Vec<SloAlert> {
        self.active_alerts
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.resolved_at.is_none())
            .cloned()
            .collect()
    }

    /// Get full alert history.
    pub fn alert_history(&self) -> Vec<SloAlert> {
        self.fired_history.lock().unwrap().clone()
    }

    /// Test-only — raw length of the `active_alerts` storage Vec
    /// (NOT filtered by `resolved_at`). Used to assert the
    /// memory-leak fix: resolved entries are dropped rather than
    /// accreted.
    #[cfg(test)]
    fn active_storage_len(&self) -> usize {
        self.active_alerts.lock().unwrap().len()
    }

    /// Get current budget status for all objectives. Includes a
    /// per-burn-window burn rate so the dashboard can render real
    /// 1h/6h/3d numbers instead of the placeholder zeros that
    /// shipped with CI-T4.
    pub fn budget_status(&self) -> Vec<BudgetStatus> {
        self.budget_status_at(Utc::now())
    }

    /// Clock-injectable variant of [`Self::budget_status`]
    /// (SLO-P2) — same seam rationale as [`Self::evaluate_at`].
    pub fn budget_status_at(&self, now: DateTime<Utc>) -> Vec<BudgetStatus> {
        let objectives = self.objectives.lock().unwrap().clone();
        let buffers = self.buffers.lock().unwrap();
        objectives
            .iter()
            .map(|obj| {
                let window = Duration::days(obj.window_days as i64);
                let buf = buffers.get(&obj.sli);
                let avg = buf.and_then(|b| b.average_in_window(now, window));
                let budget = 1.0 - obj.target;
                let consumed = match avg {
                    Some(v) => {
                        let error_rate = 1.0 - v;
                        if budget > 0.0 {
                            (error_rate / budget) * 100.0
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };
                // Per-window burn rate = (error_rate in window) /
                // (error budget). Same arithmetic the engine's
                // `evaluate()` uses for the alert decision; surface
                // it here so /api/slo can show it without firing
                // an alert.
                let burn_rates = obj
                    .burn_rates
                    .iter()
                    .map(|burn| {
                        let win_dur = Duration::hours(burn.window_hours as i64);
                        let win_avg = buf.and_then(|b| b.average_in_window(now, win_dur));
                        let rate = match win_avg {
                            Some(v) if budget > 0.0 => (1.0 - v) / budget,
                            _ => 0.0,
                        };
                        BurnRate {
                            window_hours: burn.window_hours,
                            rate,
                        }
                    })
                    .collect();
                BudgetStatus {
                    sli: obj.sli.clone(),
                    target: obj.target,
                    current: avg.unwrap_or(1.0),
                    budget_remaining_pct: (100.0 - consumed).max(0.0),
                    burn_rates,
                }
            })
            .collect()
    }
}

/// One row of [`BudgetStatus::burn_rates`]. `rate` is the ratio
/// `error_rate / error_budget` measured over `window_hours`. A
/// value of `1.0` means the SLO is being burned at exactly the
/// long-run break-even pace; values above the burn-window's
/// configured `burn_threshold` (with short-window confirmation —
/// SLO-P3) trip the alert.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BurnRate {
    pub window_hours: u64,
    pub rate: f64,
}

/// Budget consumption status for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub sli: SliKind,
    pub target: f64,
    pub current: f64,
    pub budget_remaining_pct: f64,
    /// Per-burn-window burn rate. One entry per window declared
    /// on the [`SloObjective`]. Empty when the objective has no
    /// burn-rate windows configured.
    #[serde(default)]
    pub burn_rates: Vec<BurnRate>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn availability_sample(value: f64) -> SliSample {
        SliSample {
            kind: SliKind::DataPlaneAvailability,
            value,
            ts: Utc::now(),
        }
    }

    fn audit_sample(value: f64) -> SliSample {
        SliSample {
            kind: SliKind::AuditDeliveryRate,
            value,
            ts: Utc::now(),
        }
    }

    fn fast_burn_objective() -> Vec<SloObjective> {
        vec![SloObjective {
            sli: SliKind::DataPlaneAvailability,
            target: 0.999,
            window_days: 30,
            burn_rates: vec![BurnRateWindow {
                window_hours: 1,
                short_window_minutes: 5,
                burn_threshold: 14.4,
                severity: AlertSeverity::Page,
            }],
            min_events: 60,
        }]
    }

    // -- SLI recording tests -----------------------------------------------

    #[test]
    fn record_and_retrieve_budget() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..10 {
            engine.record(availability_sample(1.0));
        }
        let status = engine.budget_status();
        assert_eq!(status.len(), 1);
        assert!(status[0].budget_remaining_pct > 99.0);
    }

    #[test]
    fn budget_consumed_when_errors() {
        let engine = SloEngine::new(fast_burn_objective());
        // Push samples with 50% error rate → way over budget.
        for _ in 0..100 {
            engine.record(availability_sample(0.5));
        }
        let status = engine.budget_status();
        // 50% error rate / 0.1% budget = 500x → 50000% consumed → 0% remaining.
        assert!(status[0].budget_remaining_pct < 1.0);
    }

    // -- Alert firing tests ------------------------------------------------

    #[test]
    fn no_alert_when_healthy() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..100 {
            engine.record(availability_sample(1.0));
        }
        let alerts = engine.evaluate();
        assert!(alerts.is_empty());
        assert!(engine.active_alerts().is_empty());
    }

    #[test]
    fn alert_fires_on_high_error_rate() {
        let engine = SloEngine::new(fast_burn_objective());
        // Push bad samples.
        for _ in 0..100 {
            engine.record(availability_sample(0.9));
        }
        let alerts = engine.evaluate();
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, AlertSeverity::Page);
        assert_eq!(alerts[0].sli, SliKind::DataPlaneAvailability);
        assert!(alerts[0].budget_consumed_pct > 2.0);
    }

    #[test]
    fn alert_does_not_double_fire() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..100 {
            engine.record(availability_sample(0.9));
        }
        engine.evaluate();
        let alerts2 = engine.evaluate();
        // No new alerts on second evaluate.
        assert!(alerts2.is_empty());
        // But still active.
        assert_eq!(engine.active_alerts().len(), 1);
    }

    // (SLO-P2: the old `alert_resolves_when_healthy` test relied
    // on 10k healthy samples EVICTING the bad ones from the ring —
    // the exact bug the bucket store fixes. Deterministic
    // fire→resolve coverage now lives in
    // `alert_fires_then_resolves_when_burst_ages_out`.)

    #[test]
    fn alert_history_persists() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..100 {
            engine.record(availability_sample(0.9));
        }
        engine.evaluate();
        let history = engine.alert_history();
        assert_eq!(history.len(), 1);
    }

    // 2026-05-20 memory-leak audit — across repeated fire→resolve
    // cycles, the active_alerts storage must NOT accrete resolved
    // entries (it previously marked-but-never-removed them).
    // SLO-P2: cycles driven by the clock seam (bursts age out of
    // the window) instead of ring eviction.
    #[test]
    fn resolved_alerts_are_dropped_from_active_storage() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for cycle in 0..3 {
            let fire_at = t0 + Duration::hours(3 * cycle);
            // Fire.
            for _ in 0..100 {
                engine.record_at(availability_sample_at(0.9, fire_at), fire_at);
            }
            engine.evaluate_at(fire_at + Duration::minutes(1));
            assert_eq!(engine.active_alerts().len(), 1);
            // Resolve: 2h later the burst is outside the 1h
            // window; fresh healthy traffic is all it sees.
            let recover_at = fire_at + Duration::hours(2);
            for _ in 0..100 {
                engine.record_at(availability_sample_at(1.0, recover_at), recover_at);
            }
            engine.evaluate_at(recover_at);
            assert!(engine.active_alerts().is_empty());
            // Raw storage never carries resolved rows forward.
            assert_eq!(
                engine.active_storage_len(),
                0,
                "resolved entries must be dropped, not accreted",
            );
        }
        // History recorded each of the 3 fires (capped, well under).
        assert_eq!(engine.alert_history().len(), 3);
    }

    #[test]
    fn alert_has_runbook_url() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..100 {
            engine.record(availability_sample(0.9));
        }
        let alerts = engine.evaluate();
        assert!(alerts[0].runbook_url.contains("runbooks.aegis.local"));
    }

    // -- SLO-P4: hot-swappable, validated objectives --------------------------

    #[test]
    fn set_objectives_swaps_thresholds_but_keeps_data() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.98, t0), t0);
        }
        // 2% error rate vs 0.1% budget → budget exhausted.
        assert_eq!(engine.budget_status()[0].budget_remaining_pct, 0.0);

        // Loosen the objective to 97% — same data, new target.
        let mut looser = fast_burn_objective();
        looser[0].target = 0.97;
        engine.set_objectives(looser).expect("valid objectives");
        let status = engine.budget_status();
        assert!((status[0].target - 0.97).abs() < 1e-9);
        assert!(
            (status[0].current - 0.98).abs() < 1e-6,
            "observed history must survive the swap, got {}",
            status[0].current,
        );
        assert!(
            status[0].budget_remaining_pct > 0.0,
            "2% errors within a 3% budget leaves budget remaining",
        );
    }

    #[test]
    fn validate_objectives_rejects_out_of_range_configs() {
        // Budget window beyond the 30d coarse retention.
        let mut too_wide = fast_burn_objective();
        too_wide[0].window_days = 45;
        assert!(SloEngine::validate_objectives(&too_wide).is_err());

        // Burn window beyond the 72h fine retention.
        let mut too_long = fast_burn_objective();
        too_long[0].burn_rates[0].window_hours = 100;
        assert!(SloEngine::validate_objectives(&too_long).is_err());

        // Target must leave a non-empty budget below 100%.
        for bad_target in [1.0, 1.5, 0.0, -0.1] {
            let mut bad = fast_burn_objective();
            bad[0].target = bad_target;
            assert!(
                SloEngine::validate_objectives(&bad).is_err(),
                "target {bad_target} must be rejected",
            );
        }

        // Short window must be shorter than its long window.
        let mut inverted = fast_burn_objective();
        inverted[0].burn_rates[0].short_window_minutes = 120;
        assert!(SloEngine::validate_objectives(&inverted).is_err());

        // The compiled defaults are, of course, valid.
        assert!(SloEngine::validate_objectives(&default_objectives()).is_ok());
        assert!(SloEngine::validate_objectives(&fast_burn_objective()).is_ok());
    }

    #[test]
    fn set_objectives_rejects_invalid_and_keeps_previous() {
        let engine = SloEngine::new(fast_burn_objective());
        let mut bad = fast_burn_objective();
        bad[0].window_days = 90;
        assert!(engine.set_objectives(bad).is_err());
        // Previous objectives still live.
        let status = engine.budget_status();
        assert_eq!(status.len(), 1);
        assert!((status[0].target - 0.999).abs() < 1e-9);
    }

    // -- SLO-P3: multi-window multi-burn + guards -----------------------------
    //
    // Scenario table from the FEAT plan — these encode when the
    // engine must and must NOT alert under the standard
    // (Google SRE Workbook ch.5) thresholds.

    // A ~1% error rate is burn ≈ 9.9 for a 99.9% target — real
    // budget drain, but BELOW the 14.4 fast-burn page threshold.
    // Pre-P3 this paged at burn 0.02 (720× oversensitive).
    #[test]
    fn moderate_burn_below_standard_threshold_does_not_page() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.0, t0), t0);
        }
        for _ in 0..10_000 {
            engine.record_at(availability_sample_at(1.0, t0), t0);
        }
        let alerts = engine.evaluate_at(t0 + Duration::minutes(1));
        assert!(
            alerts.is_empty(),
            "burn 9.9 must not trip the 14.4 page threshold",
        );
    }

    // A burst 30 minutes ago keeps the 1h long window burning,
    // but the short (5m) window has aged past it — the pair must
    // not fire a stale alert.
    #[test]
    fn stale_burst_needs_short_window_confirmation() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.0, t0), t0);
        }
        // 30 min later: nothing in the 5m short window at all.
        let t1 = t0 + Duration::minutes(30);
        assert!(
            engine.evaluate_at(t1).is_empty(),
            "no short-window data → no confirmation → no fire",
        );
        // Fresh healthy traffic in the short window: still no fire.
        for _ in 0..100 {
            engine.record_at(availability_sample_at(1.0, t1), t1);
        }
        assert!(
            engine.evaluate_at(t1).is_empty(),
            "healthy short window must veto the stale long-window burn",
        );
    }

    // 1 bad request out of 3 at 04:00 is a 333× burn on paper —
    // and not an incident.
    #[test]
    fn sparse_traffic_below_min_events_never_fires() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        engine.record_at(availability_sample_at(0.0, t0), t0);
        engine.record_at(availability_sample_at(1.0, t0), t0);
        engine.record_at(availability_sample_at(1.0, t0), t0);
        assert!(
            engine.evaluate_at(t0 + Duration::minutes(1)).is_empty(),
            "3 events < min_events(60) must not alert",
        );
    }

    // A sustained 0.15% error rate (burn 1.5) must raise exactly
    // one slow-burn Ticket on the 3d window — no Page.
    #[test]
    fn slow_burn_raises_ticket_not_page() {
        let engine = SloEngine::new(default_objectives());
        let t0 = Utc::now();
        // 72h of steady traffic at 99.85% availability.
        for h in 0..72 {
            let ts = t0 - Duration::hours(h);
            for _ in 0..100 {
                engine.record_at(availability_sample_at(0.9985, ts), ts);
            }
        }
        let alerts = engine.evaluate_at(t0);
        assert_eq!(
            alerts.len(),
            1,
            "exactly the 3d slow-burn pair fires, got: {alerts:?}",
        );
        assert_eq!(alerts[0].severity, AlertSeverity::Ticket);
        assert_eq!(alerts[0].window_hours, 72);
    }

    // budget_consumed_pct must be a real % of the 30d budget:
    // burn 100 sustained for the 1h window = 100/720 of the
    // budget ≈ 13.9% — not the pre-P3 "burn × 100" = 10,000%.
    #[test]
    fn budget_consumed_pct_is_time_scaled() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.9, t0), t0);
        }
        let alerts = engine.evaluate_at(t0 + Duration::minutes(1));
        assert_eq!(alerts.len(), 1);
        let consumed = alerts[0].budget_consumed_pct;
        assert!(
            (13.0..15.0).contains(&consumed),
            "1h at burn 100 consumes ~13.9% of a 30d budget, got {consumed}",
        );
        assert!((alerts[0].burn_rate - 100.0).abs() < 1.0);
    }

    // Blackout: traffic was flowing, then nothing — the watchdog
    // must see it (a never-served kind must NOT trip it).
    #[test]
    fn telemetry_absent_watchdog_detects_blackout() {
        let engine = SloEngine::new(fast_burn_objective());
        let now = Utc::now();
        let absent_after = Duration::minutes(10);
        let kind = SliKind::DataPlaneAvailability;
        // Never served: idle dev node, not a blackout.
        assert!(!engine.telemetry_absent(&kind, absent_after, now));
        engine.record_at(availability_sample_at(1.0, now), now);
        // Serving normally.
        assert!(!engine.telemetry_absent(&kind, absent_after, now + Duration::minutes(5)));
        // 15 minutes of silence after having served: blackout.
        assert!(engine.telemetry_absent(&kind, absent_after, now + Duration::minutes(15)));
    }

    // P3 review HIGH-1: a total blackout empties the short window
    // within minutes — that must NOT auto-resolve a fired alert
    // (silence is not recovery; only confirmed healthy traffic is).
    #[test]
    fn blackout_does_not_auto_resolve_fired_alert() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.0, t0), t0);
        }
        assert_eq!(engine.evaluate_at(t0 + Duration::minutes(1)).len(), 1);

        // 30 minutes of complete silence: the 5m short window is
        // empty. The alert must stay active — the outage did not
        // end, the telemetry did.
        let resolved = engine.evaluate_at(t0 + Duration::minutes(30));
        assert!(resolved.is_empty(), "silence must not emit a resolve event",);
        assert_eq!(engine.active_alerts().len(), 1, "alert stays active");

        // Real recovery: healthy traffic returns.
        let t2 = t0 + Duration::hours(2);
        for _ in 0..100 {
            engine.record_at(availability_sample_at(1.0, t2), t2);
        }
        let resolved = engine.evaluate_at(t2);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved_at.is_some());
    }

    // P3 review MEDIUM-3: one stray bad sample in the short window
    // must not "confirm" a long-window burn — the short window
    // needs proportional volume too.
    #[test]
    fn single_sample_cannot_confirm_short_window() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        // A real burst 40 minutes ago keeps the 1h long window
        // burning with plenty of volume...
        let burst = t0 - Duration::minutes(40);
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.0, burst), burst);
        }
        // ...and exactly ONE bad request lands in the 5m short
        // window (min_events 60 scaled to 5m/1h → floor of 5).
        engine.record_at(availability_sample_at(0.0, t0), t0);
        assert!(
            engine.evaluate_at(t0).is_empty(),
            "1 sample in the short window is noise, not confirmation",
        );
    }

    #[test]
    fn telemetry_absent_event_routes_as_ticket_and_dedups_per_sli() {
        let ev = |ts: DateTime<Utc>| AlertEvent::TelemetryAbsent {
            fired_at: ts,
            sli: "DataPlaneAvailability".into(),
            silent_seconds: 600,
        };
        let now = Utc::now();
        assert_eq!(ev(now).severity(), AlertSeverity::Ticket);
        // Same SLI, different fire time → same fingerprint (a
        // continuing blackout dedups instead of re-paging).
        assert_eq!(
            ev(now).fingerprint(),
            ev(now + Duration::minutes(30)).fingerprint(),
        );
    }

    // Pin of the P1 contract at the evaluation layer: a 90%-
    // blocked attack wave is enforcement, not unavailability.
    #[test]
    fn blocked_attack_wave_does_not_alert_availability() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..900 {
            engine.record_enforcement(t0);
        }
        for _ in 0..100 {
            engine.record_at(availability_sample_at(1.0, t0), t0);
        }
        assert!(engine.evaluate_at(t0 + Duration::minutes(1)).is_empty());
        assert_eq!(engine.enforcement_stats().total, 900);
    }

    // -- SLO-P2: bucketed store — honest windows ------------------------------

    fn availability_sample_at(value: f64, ts: DateTime<Utc>) -> SliSample {
        SliSample {
            kind: SliKind::DataPlaneAvailability,
            value,
            ts,
        }
    }

    // The 10k sample ring silently evicted an error burst once
    // enough healthy traffic followed — the burst "self-resolved"
    // by volume, not by time. Bucketed counters must keep it
    // inside the window. (SLO-P3: 300 bad of 10,300 ≈ burn 29 —
    // above the 14.4 page threshold.)
    #[test]
    fn error_burst_is_not_flushed_by_later_volume() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..300 {
            engine.record(availability_sample(0.0));
        }
        for _ in 0..10_000 {
            engine.record(availability_sample(1.0));
        }
        let alerts = engine.evaluate();
        assert!(
            !alerts.is_empty(),
            "an error burst must not be evicted by later healthy volume",
        );
    }

    #[test]
    fn long_window_counts_beyond_10k_samples() {
        let engine = SloEngine::new(fast_burn_objective());
        let now = Utc::now();
        let earlier = now - Duration::hours(5);
        for _ in 0..20_000 {
            engine.record(availability_sample_at(1.0, earlier));
        }
        let count =
            engine.sample_count_in_window(&SliKind::DataPlaneAvailability, Duration::hours(6), now);
        assert_eq!(count, 20_000, "6h window must not truncate at 10k samples");
        // And those samples are OUTSIDE a 1h window.
        let count_1h =
            engine.sample_count_in_window(&SliKind::DataPlaneAvailability, Duration::hours(1), now);
        assert_eq!(count_1h, 0);
    }

    #[test]
    fn no_data_is_distinguishable_from_healthy() {
        let engine = SloEngine::new(fast_burn_objective());
        let now = Utc::now();
        assert_eq!(
            engine
                .sample_count_in_window(&SliKind::DataPlaneAvailability, Duration::hours(1), now,),
            0,
            "empty engine → zero observations, not implicit health",
        );
    }

    // Deterministic fire → resolve via the injectable clock: the
    // alert resolves because the burst LEFT THE WINDOW, not
    // because later volume evicted it from a ring.
    #[test]
    fn alert_fires_then_resolves_when_burst_ages_out() {
        let engine = SloEngine::new(fast_burn_objective());
        let t0 = Utc::now();
        for _ in 0..100 {
            engine.record_at(availability_sample_at(0.0, t0), t0);
        }
        let fired = engine.evaluate_at(t0 + Duration::minutes(1));
        assert_eq!(fired.len(), 1, "burst inside 1h window fires");
        assert!(fired[0].resolved_at.is_none());

        // Two hours later the burst is outside the 1h window;
        // fresh healthy traffic is all the window sees.
        let t2 = t0 + Duration::hours(2);
        for _ in 0..100 {
            engine.record_at(availability_sample_at(1.0, t2), t2);
        }
        let resolved = engine.evaluate_at(t2);
        assert_eq!(resolved.len(), 1, "aged-out burst resolves");
        assert!(resolved[0].resolved_at.is_some());
        assert!(engine.active_alerts().is_empty());
    }

    #[test]
    fn thirty_day_budget_sees_old_errors_beyond_ring_capacity() {
        let engine = SloEngine::new(fast_burn_objective());
        let old = Utc::now() - Duration::days(20);
        for _ in 0..100 {
            engine.record(availability_sample_at(0.0, old));
        }
        // 15k healthy samples afterwards — more than the old
        // 10k ring could hold.
        for _ in 0..15_000 {
            engine.record(availability_sample_at(1.0, old + Duration::minutes(1)));
        }
        let status = engine.budget_status();
        // 100/15100 ≈ 0.66% error rate vs 0.1% budget → exhausted.
        assert_eq!(
            status[0].budget_remaining_pct, 0.0,
            "20-day-old burst must still drain the 30d budget",
        );
    }

    // -- SLO-P1: default objectives + enforcement counter --------------------

    // SLO-P1 — the AuditDeliveryRate objective was a tautology
    // (its producer hardcoded 1.0 per observed event, so it could
    // never breach 99.99%). Defaults now carry availability only.
    #[test]
    fn default_objectives_are_availability_only() {
        let objs = default_objectives();
        assert_eq!(objs.len(), 1, "audit-delivery tautology objective dropped");
        assert_eq!(objs[0].sli, SliKind::DataPlaneAvailability);
    }

    #[test]
    fn enforcement_counter_tracks_total_and_last_hour() {
        let engine = SloEngine::new(fast_burn_objective());
        // Two recent, one stale (2h old — outside the 1h window).
        engine.record_enforcement(Utc::now());
        engine.record_enforcement(Utc::now());
        engine.record_enforcement(Utc::now() - Duration::hours(2));
        let stats = engine.enforcement_stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.last_hour, 2);
    }

    #[test]
    fn enforcement_events_do_not_touch_availability_budget() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..10 {
            engine.record(availability_sample(1.0));
            engine.record_enforcement(Utc::now());
        }
        // Pre-P1 a blocked attack wave drained the availability
        // budget; enforcement must now leave it untouched.
        assert!(engine.evaluate().is_empty());
        let status = engine.budget_status();
        assert_eq!(status[0].budget_remaining_pct, 100.0);
    }

    #[test]
    fn enforcement_ring_is_bounded() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..(MAX_ENFORCEMENT_EVENTS + 500) {
            engine.record_enforcement(Utc::now());
        }
        let stats = engine.enforcement_stats();
        assert_eq!(stats.total, (MAX_ENFORCEMENT_EVENTS + 500) as u64);
        // Windowed count is capped by retention, never above it.
        assert_eq!(stats.last_hour, MAX_ENFORCEMENT_EVENTS as u64);
    }

    // -- Multi-burn tests --------------------------------------------------

    #[test]
    fn multi_burn_rate_config() {
        let objs = default_objectives();
        let avail = &objs[0];
        assert_eq!(avail.burn_rates.len(), 3);
        // SLO-P3 — standard pairs: fast + medium burn page, slow
        // burn tickets. (Pre-P3 the 6h window was a Ticket.)
        assert_eq!(avail.burn_rates[0].severity, AlertSeverity::Page);
        assert!((avail.burn_rates[0].burn_threshold - 14.4).abs() < 1e-9);
        assert_eq!(avail.burn_rates[1].severity, AlertSeverity::Page);
        assert!((avail.burn_rates[1].burn_threshold - 6.0).abs() < 1e-9);
        assert_eq!(avail.burn_rates[2].severity, AlertSeverity::Ticket);
        assert!((avail.burn_rates[2].burn_threshold - 1.0).abs() < 1e-9);
        assert_eq!(avail.min_events, 60);
    }

    // SLO-P1 — samples for an SLI with no configured objective
    // (here AuditDeliveryRate) are stored but never surface in
    // budget_status, and never alert.
    #[test]
    fn unconfigured_sli_samples_do_not_surface() {
        let engine = SloEngine::new(default_objectives());
        engine.record(availability_sample(1.0));
        engine.record(audit_sample(0.0)); // would breach if it had an objective
        let status = engine.budget_status();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].sli, SliKind::DataPlaneAvailability);
        assert!(engine.evaluate().is_empty());
    }

    // -- SLI kind tests ----------------------------------------------------

    #[test]
    fn sli_kind_equality() {
        assert_eq!(
            SliKind::DataPlaneAvailability,
            SliKind::DataPlaneAvailability
        );
        assert_ne!(SliKind::DataPlaneAvailability, SliKind::AuditDeliveryRate);
    }

    #[test]
    fn sli_kind_upstream_pool() {
        let a = SliKind::UpstreamAvailability { pool: "api".into() };
        let b = SliKind::UpstreamAvailability { pool: "web".into() };
        assert_ne!(a, b);
    }

    #[test]
    fn sli_kind_serialization() {
        let kind = SliKind::WafOverheadP99;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: SliKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
    }

    // -- Alert receiver tests ----------------------------------------------

    #[test]
    fn receiver_serialization() {
        let recv = AlertReceiver {
            name: "pager".into(),
            kind: ReceiverKind::PagerDuty {
                routing_key: "key123".into(),
            },
            severities: Vec::new(),
        };
        let json = serde_json::to_string(&recv).unwrap();
        assert!(json.contains("PagerDuty"));
        assert!(json.contains("key123"));
    }

    #[test]
    fn receiver_kinds() {
        let kinds = vec![
            ReceiverKind::AlertmanagerWebhook {
                url: "http://am:9093".into(),
            },
            ReceiverKind::Slack {
                webhook_url: "https://hooks.slack.com/x".into(),
            },
            ReceiverKind::ServiceNow {
                instance: "prod".into(),
                table: "incident".into(),
            },
            ReceiverKind::Jira {
                base_url: "https://jira.example.com".into(),
                project: "SRE".into(),
            },
            ReceiverKind::VipTalk {
                bot_token: "test-token".into(),
                room_ids: vec!["!room:matrix.example.com".into()],
            },
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let _: ReceiverKind = serde_json::from_str(&json).unwrap();
        }
    }

    /// Process-wide mutex serialising tests that mutate
    /// `AEGIS_VIPTALK_*` env vars. Same pattern as the secret
    /// resolvers' tests.
    static VIPTALK_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn with_viptalk_env<R>(pairs: &[(&str, Option<&str>)], f: impl FnOnce() -> R) -> R {
        let _lock = VIPTALK_ENV_LOCK.lock();
        let prior: Vec<(String, Option<String>)> = pairs
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in pairs {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        let result = f();
        for (k, v) in prior {
            match v {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
        result
    }

    // F-CRITICAL-017 (2026-05-17 control audit): pre-fix this
    // module pinned a hardcoded "xxx-dev-uat-bot-token-xxx" default
    // bot token + a dev/UAT Matrix room ID. Tests that asserted
    // those defaults applied when env was missing or empty have
    // been removed — they were the on-disk record of the bug.
    // Replacement tests below pin the new behaviour: when either
    // env var is missing OR empty, `default_receivers()` returns
    // an empty Vec (no third-party disclosure).

    #[test]
    fn default_receivers_empty_when_env_missing() {
        let receivers = with_viptalk_env(
            &[
                ("AEGIS_VIPTALK_BOT_TOKEN", None),
                ("AEGIS_VIPTALK_ROOM_IDS", None),
            ],
            default_receivers,
        );
        assert!(receivers.is_empty(), "no env → no receivers");
    }

    #[test]
    fn default_receivers_empty_when_env_empty_strings() {
        let receivers = with_viptalk_env(
            &[
                ("AEGIS_VIPTALK_BOT_TOKEN", Some("")),
                ("AEGIS_VIPTALK_ROOM_IDS", Some("")),
            ],
            default_receivers,
        );
        assert!(receivers.is_empty(), "empty strings → no receivers");
    }

    #[test]
    fn default_receivers_empty_when_only_token_set() {
        let receivers = with_viptalk_env(
            &[
                ("AEGIS_VIPTALK_BOT_TOKEN", Some("real-token")),
                ("AEGIS_VIPTALK_ROOM_IDS", None),
            ],
            default_receivers,
        );
        assert!(
            receivers.is_empty(),
            "token-only → no receivers (need room IDs too)"
        );
    }

    #[test]
    fn default_receivers_built_when_both_env_set() {
        let receivers = with_viptalk_env(
            &[
                ("AEGIS_VIPTALK_BOT_TOKEN", Some("real-token")),
                (
                    "AEGIS_VIPTALK_ROOM_IDS",
                    Some("!room1:m.example.com,!room2:m.example.com"),
                ),
            ],
            default_receivers,
        );
        assert_eq!(receivers.len(), 1);
        match &receivers[0].kind {
            ReceiverKind::VipTalk {
                bot_token,
                room_ids,
            } => {
                assert_eq!(bot_token, "real-token");
                assert_eq!(
                    room_ids,
                    &[
                        "!room1:m.example.com".to_string(),
                        "!room2:m.example.com".to_string(),
                    ]
                );
            }
            other => panic!("expected VipTalk, got {other:?}"),
        }
    }

    // -- Budget status tests -----------------------------------------------

    #[test]
    fn budget_status_serialization() {
        let bs = BudgetStatus {
            sli: SliKind::CertFreshnessDays,
            target: 0.999,
            current: 0.998,
            budget_remaining_pct: 50.0,
            burn_rates: vec![BurnRate {
                window_hours: 1,
                rate: 0.4,
            }],
        };
        let json = serde_json::to_string(&bs).unwrap();
        assert!(json.contains("CertFreshnessDays"));
        assert!(json.contains("burn_rates"));
        assert!(json.contains("\"window_hours\":1"));
    }

    #[test]
    fn budget_remaining_clamps_to_zero() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..100 {
            engine.record(availability_sample(0.0)); // 100% errors.
        }
        let status = engine.budget_status();
        assert_eq!(status[0].budget_remaining_pct, 0.0);
    }

    // -- Empty engine tests ------------------------------------------------

    #[test]
    fn empty_engine_no_alerts() {
        let engine = SloEngine::new(fast_burn_objective());
        let alerts = engine.evaluate();
        assert!(alerts.is_empty());
    }

    #[test]
    fn empty_engine_budget_defaults() {
        let engine = SloEngine::new(fast_burn_objective());
        let status = engine.budget_status();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].current, 1.0); // Default when no data.
        assert_eq!(status[0].budget_remaining_pct, 100.0);
    }

    // -- Bucket store tests (SLO-P2) -----------------------------------------

    #[test]
    fn tier_ring_buckets_by_time_and_sums() {
        let mut ring = TierRing::new(10, 100); // 10 slots
        ring.record(0, 1.0);
        ring.record(5, 0.0); // same bucket as ts=0
        ring.record(15, 1.0); // next bucket
        let (good, count) = ring.totals(0, 19);
        assert_eq!(count, 3);
        assert!((good - 2.0).abs() < 1e-9);
        // Window covering only the second bucket.
        let (good, count) = ring.totals(10, 19);
        assert_eq!(count, 1);
        assert!((good - 1.0).abs() < 1e-9);
    }

    #[test]
    fn tier_ring_recycles_slots_past_retention() {
        let mut ring = TierRing::new(10, 100); // 10 slots
        ring.record(0, 1.0);
        // 100s later the epoch-0 slot is recycled by epoch 10.
        ring.record(100, 0.0);
        let (good, count) = ring.totals(0, 109);
        assert_eq!(count, 1, "recycled slot must not leak old data");
        assert!((good - 0.0).abs() < 1e-9);
        // A sample older than retention is dropped, not misfiled.
        ring.record(3, 1.0);
        let (_, count) = ring.totals(0, 109);
        assert_eq!(count, 1);
    }

    // Boundary-exact: a sample stamped exactly `now - window`
    // sits in the bucket containing the window start, which is
    // included whole (documented drift of ≤1 bucket width).
    #[test]
    fn tier_ring_window_start_bucket_is_included_whole() {
        let mut ring = TierRing::new(10, 100);
        ring.record(100, 1.0); // exactly at window start
        let (_, count) = ring.totals(100, 150);
        assert_eq!(count, 1);
        // One bucket earlier is outside.
        let mut ring = TierRing::new(10, 100);
        ring.record(99, 1.0);
        let (_, count) = ring.totals(100, 150);
        assert_eq!(count, 0);
    }

    // Boundary-exact: retention edge. With len slots the ring
    // holds exactly `len` distinct epochs ending at `to`.
    #[test]
    fn tier_ring_retention_edge_is_exact() {
        let mut ring = TierRing::new(10, 100); // 10 slots
                                               // Oldest representable epoch for to=999 is epoch 90..=99.
        ring.record(900, 1.0); // epoch 90 — the oldest retained
        let (_, count) = ring.totals(0, 999);
        assert_eq!(count, 1, "oldest retained epoch must be counted");
        ring.record(999, 1.0); // epoch 99 — newest
        let (_, count) = ring.totals(0, 999);
        assert_eq!(count, 2);
    }

    // Clock-skew guard: a far-future stamp must not park a huge
    // epoch in a slot (it would silently drop every legitimate
    // sample hashing there for the process lifetime).
    #[test]
    fn record_clamps_far_future_timestamps() {
        let engine = SloEngine::new(fast_burn_objective());
        let now = Utc::now();
        engine.record_at(availability_sample_at(1.0, now + Duration::days(400)), now);
        // Clamped to `now` → visible in the current 1h window.
        assert_eq!(
            engine
                .sample_count_in_window(&SliKind::DataPlaneAvailability, Duration::hours(1), now,),
            1,
        );
        // And a normal sample right after still lands (no
        // poisoned slot dropping it).
        engine.record_at(availability_sample_at(1.0, now), now);
        assert_eq!(
            engine
                .sample_count_in_window(&SliKind::DataPlaneAvailability, Duration::hours(1), now,),
            2,
        );
    }

    #[test]
    fn bucket_store_empty_average_is_none() {
        let store = BucketStore::new();
        assert!(store
            .average_in_window(Utc::now(), Duration::hours(1))
            .is_none());
    }

    #[test]
    fn bucket_store_routes_budget_window_to_coarse_tier() {
        let mut store = BucketStore::new();
        let now = Utc::now();
        // Older than fine retention (72h), inside coarse (30d).
        store.record(now - Duration::days(10), 1.0);
        let (_, fine_count) = store.window_totals(now, Duration::hours(72));
        assert_eq!(fine_count, 0);
        let (good, count) = store.window_totals(now, Duration::days(30));
        assert_eq!(count, 1);
        assert!((good - 1.0).abs() < 1e-9);
    }

    // -- SloAlert tests ----------------------------------------------------

    #[test]
    fn alert_serialization() {
        let alert = SloAlert {
            sli: SliKind::DataPlaneAvailability,
            severity: AlertSeverity::Page,
            fired_at: Utc::now(),
            resolved_at: None,
            burn_rate: 5.0,
            budget_consumed_pct: 10.0,
            window_hours: 1,
            runbook_url: "https://example.com".into(),
            measured: 0.995,
            target: 0.999,
        };
        let json = serde_json::to_string(&alert).unwrap();
        let parsed: SloAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.severity, AlertSeverity::Page);
    }
}
