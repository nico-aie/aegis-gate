// SLO / SLI engine + multi-window multi-burn-rate alerting.
//
// SLIs tracked:
//   - Data-plane availability (1 - error_rate)
//   - WAF overhead p50/p95/p99 latency
//   - Upstream availability per pool
//   - Audit delivery rate (events in vs acknowledged)
//   - Cert freshness (days to expiry)
//
// Multi-burn: fast (1h/2%) → page; slow (6h/5%, 3d/10%) → ticket.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub mod dispatch;

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
    UpstreamAvailability { pool: String },
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SloObjective {
    pub sli: SliKind,
    pub target: f64,
    pub window_days: u32,
    pub burn_rates: Vec<BurnRateWindow>,
}

/// A burn-rate alerting window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BurnRateWindow {
    pub window_hours: u64,
    pub budget_pct: f64,
    pub severity: AlertSeverity,
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
            burn_rates: vec![
                BurnRateWindow {
                    window_hours: 1,
                    budget_pct: 2.0,
                    severity: AlertSeverity::Page,
                },
                BurnRateWindow {
                    window_hours: 6,
                    budget_pct: 5.0,
                    severity: AlertSeverity::Ticket,
                },
                BurnRateWindow {
                    window_hours: 72,
                    budget_pct: 10.0,
                    severity: AlertSeverity::Ticket,
                },
            ],
        },
        SloObjective {
            sli: SliKind::AuditDeliveryRate,
            target: 0.9999,
            window_days: 30,
            burn_rates: vec![BurnRateWindow {
                window_hours: 1,
                budget_pct: 5.0,
                severity: AlertSeverity::Page,
            }],
        },
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
    pub budget_consumed_pct: f64,
    pub window_hours: u64,
    pub runbook_url: String,
}

/// Multi-source operator alert (2026-05-20 alerts refactor).
///
/// Subsumes [`SloAlert`] plus the operationally-important non-
/// SLO event classes. The dispatcher routes by
/// [`Self::severity`]; per-variant chat formatting lives in
/// [`crate::slo::dispatch::format_event_text`].
///
/// Variants flagged "wired" emit from a production code path
/// today; the rest are surface placeholders so the dispatcher
/// shape is stable while later phases land the producers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertEvent {
    /// SLO burn-rate breach (legacy path; wired).
    Slo(SloAlert),
    /// DDoS gate flipped into enforce mode (wired).
    DdosModeEntered {
        fired_at: DateTime<Utc>,
        trigger: String,
        observed_rps: u32,
    },
    /// DDoS gate exited enforce mode back to normal (wired).
    DdosModeCleared {
        fired_at: DateTime<Utc>,
        duration_seconds: u64,
    },
    /// One or more TLS certs are within the expiry warning
    /// window (wired by the daily cert poll).
    CertExpiringSoon {
        fired_at: DateTime<Utc>,
        host: String,
        days_remaining: u32,
        not_after: DateTime<Utc>,
    },
    /// Risk tracker observed N unique source IPs hitting
    /// strike-block in a short window (not yet wired —
    /// Phase B producer).
    StrikeBlockSurge {
        fired_at: DateTime<Utc>,
        unique_ips: u32,
        window_seconds: u32,
        top_rule_ids: Vec<String>,
    },
    /// Upstream pool dropped below healthy membership (not
    /// yet wired — Phase B producer).
    UpstreamPoolDegraded {
        fired_at: DateTime<Utc>,
        pool: String,
        healthy: u32,
        total: u32,
        first_down: String,
    },
    /// Upstream pool returned to fully healthy (not yet wired).
    UpstreamPoolRecovered {
        fired_at: DateTime<Utc>,
        pool: String,
    },
    /// Cluster leader lease was lost or rotated (not yet wired).
    LeaderLost {
        fired_at: DateTime<Utc>,
        previous_leader: String,
        our_node: String,
    },
    /// Hot-reload of config failed; last-known-good is still
    /// live (not yet wired — Phase B producer).
    HotReloadFailed {
        fired_at: DateTime<Utc>,
        reason: String,
        last_known_good_version: u64,
    },
    /// GitOps poll detected drift between repo and live config
    /// (not yet wired).
    GitOpsDrift {
        fired_at: DateTime<Utc>,
        repo: String,
        expected: String,
        observed: String,
    },
    /// Audit-chain verify detected a hash mismatch (not yet
    /// wired — Phase B producer).
    AuditChainBreak {
        fired_at: DateTime<Utc>,
        last_good_seq: u64,
        observed_seq: u64,
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
            AlertEvent::UpstreamPoolDegraded { .. } => AlertSeverity::Page,
            AlertEvent::UpstreamPoolRecovered { .. } => AlertSeverity::Info,
            AlertEvent::LeaderLost { .. } => AlertSeverity::Page,
            AlertEvent::HotReloadFailed { .. } => AlertSeverity::Ticket,
            AlertEvent::GitOpsDrift { .. } => AlertSeverity::Ticket,
            AlertEvent::AuditChainBreak { .. } => AlertSeverity::Page,
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
            AlertEvent::LeaderLost { fired_at, .. } => *fired_at,
            AlertEvent::HotReloadFailed { fired_at, .. } => *fired_at,
            AlertEvent::GitOpsDrift { fired_at, .. } => *fired_at,
            AlertEvent::AuditChainBreak { fired_at, .. } => *fired_at,
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
            }
            AlertEvent::DdosModeEntered { trigger, .. } => {
                "ddos_entered".hash(&mut h);
                trigger.hash(&mut h);
            }
            AlertEvent::DdosModeCleared { .. } => {
                "ddos_cleared".hash(&mut h);
            }
            AlertEvent::CertExpiringSoon { host, not_after, .. } => {
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
            AlertEvent::LeaderLost { previous_leader, .. } => {
                "leader_lost".hash(&mut h);
                previous_leader.hash(&mut h);
            }
            AlertEvent::HotReloadFailed { last_known_good_version, .. } => {
                "hot_reload_failed".hash(&mut h);
                last_known_good_version.hash(&mut h);
            }
            AlertEvent::GitOpsDrift { repo, .. } => {
                "gitops_drift".hash(&mut h);
                repo.hash(&mut h);
            }
            AlertEvent::AuditChainBreak { observed_seq, .. } => {
                "audit_chain_break".hash(&mut h);
                observed_seq.hash(&mut h);
            }
        }
        h.finish()
    }
}

// ---------------------------------------------------------------------------
// Dedup cache
// ---------------------------------------------------------------------------

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
        match entries.get_mut(&fingerprint) {
            Some((last_emit, suppressed)) => {
                if now - *last_emit < self.window {
                    *suppressed = suppressed.saturating_add(1);
                    DedupDecision::Suppress
                } else {
                    let drained = *suppressed;
                    *last_emit = now;
                    *suppressed = 0;
                    DedupDecision::Emit { suppressed: drained }
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
    AlertmanagerWebhook { url: String },
    Slack { webhook_url: String },
    PagerDuty { routing_key: String },
    ServiceNow { instance: String, table: String },
    Jira { base_url: String, project: String },
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
            let room_ids: Vec<String> =
                rooms.split(',').map(|r| r.trim().to_string()).collect();
            vec![AlertReceiver {
                name: "default-viptalk".to_string(),
                kind: ReceiverKind::VipTalk { bot_token, room_ids },
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
// SLI ring buffer (in-memory time series)
// ---------------------------------------------------------------------------

// 2026-05-17 F-CRITICAL-016 (control audit): pre-fix this buffer
// stored samples in a `Vec` and used `Vec::remove(0)` on overflow —
// O(n) memcpy of up to 10 000 entries per push under a global
// `Mutex<HashMap<SliKind, SliRingBuffer>>`. At 5k req/s on the
// data plane that's a multi-millisecond stall per record call, on
// the hot path that emits SLI observations. The 20/120 Performance
// rubric breaks before any other gate fires.
//
// `VecDeque::pop_front` is O(1). Same cap (10 000), same access
// pattern (push back, iterate forward), but the overflow path now
// costs a pointer swap instead of 10 000 byte copies.
struct SliRingBuffer {
    samples: std::collections::VecDeque<SliSample>,
    max_len: usize,
}

impl SliRingBuffer {
    fn new(max_len: usize) -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(max_len),
            max_len,
        }
    }

    fn push(&mut self, sample: SliSample) {
        if self.samples.len() >= self.max_len {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    fn average_in_window(&self, window: Duration) -> Option<f64> {
        let cutoff = Utc::now() - window;
        let (sum, count) = self
            .samples
            .iter()
            .filter(|s| s.ts >= cutoff)
            .fold((0.0_f64, 0_u64), |(s, n), x| (s + x.value, n + 1));
        if count == 0 {
            return None;
        }
        Some(sum / count as f64)
    }
}

// ---------------------------------------------------------------------------
// SLO engine
// ---------------------------------------------------------------------------

/// The SLO engine: tracks SLIs and fires alerts.
pub struct SloEngine {
    objectives: Vec<SloObjective>,
    buffers: Mutex<HashMap<SliKind, SliRingBuffer>>,
    active_alerts: Mutex<Vec<SloAlert>>,
    fired_history: Mutex<Vec<SloAlert>>,
}

impl SloEngine {
    pub fn new(objectives: Vec<SloObjective>) -> Self {
        Self {
            objectives,
            buffers: Mutex::new(HashMap::new()),
            active_alerts: Mutex::new(Vec::new()),
            fired_history: Mutex::new(Vec::new()),
        }
    }

    /// Record an SLI observation.
    pub fn record(&self, sample: SliSample) {
        let mut buffers = self.buffers.lock().unwrap();
        let buf = buffers
            .entry(sample.kind.clone())
            .or_insert_with(|| SliRingBuffer::new(10_000));
        buf.push(sample);
    }

    /// Evaluate all objectives and return newly fired/resolved alerts.
    pub fn evaluate(&self) -> Vec<SloAlert> {
        let buffers = self.buffers.lock().unwrap();
        let mut active = self.active_alerts.lock().unwrap();
        let mut history = self.fired_history.lock().unwrap();
        let mut new_alerts = Vec::new();

        for obj in &self.objectives {
            let buf = match buffers.get(&obj.sli) {
                Some(b) => b,
                None => continue,
            };

            for burn in &obj.burn_rates {
                let window = Duration::hours(burn.window_hours as i64);
                let avg = match buf.average_in_window(window) {
                    Some(v) => v,
                    None => continue,
                };

                let error_rate = 1.0 - avg;
                let budget = 1.0 - obj.target;
                let budget_consumed = if budget > 0.0 {
                    (error_rate / budget) * 100.0
                } else {
                    0.0
                };

                let is_burning = budget_consumed >= burn.budget_pct;

                // Check if already active for this SLI + window.
                let already_active = active.iter().any(|a| {
                    a.sli == obj.sli
                        && a.window_hours == burn.window_hours
                        && a.resolved_at.is_none()
                });

                if is_burning && !already_active {
                    let alert = SloAlert {
                        sli: obj.sli.clone(),
                        severity: burn.severity,
                        fired_at: Utc::now(),
                        resolved_at: None,
                        burn_rate: error_rate / budget,
                        budget_consumed_pct: budget_consumed,
                        window_hours: burn.window_hours,
                        runbook_url: format!(
                            "https://runbooks.aegis.local/slo/{:?}/{}h",
                            obj.sli, burn.window_hours
                        ),
                    };
                    active.push(alert.clone());
                    history.push(alert.clone());
                    new_alerts.push(alert);
                } else if !is_burning && already_active {
                    // Resolve.
                    for a in active.iter_mut() {
                        if a.sli == obj.sli
                            && a.window_hours == burn.window_hours
                            && a.resolved_at.is_none()
                        {
                            a.resolved_at = Some(Utc::now());
                            let mut resolved = a.clone();
                            resolved.resolved_at = Some(Utc::now());
                            new_alerts.push(resolved);
                        }
                    }
                }
            }
        }

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

    /// Get current budget status for all objectives. Includes a
    /// per-burn-window burn rate so the dashboard can render real
    /// 1h/6h/3d numbers instead of the placeholder zeros that
    /// shipped with CI-T4.
    pub fn budget_status(&self) -> Vec<BudgetStatus> {
        let buffers = self.buffers.lock().unwrap();
        self.objectives
            .iter()
            .map(|obj| {
                let window = Duration::days(obj.window_days as i64);
                let buf = buffers.get(&obj.sli);
                let avg = buf.and_then(|b| b.average_in_window(window));
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
                        let win_avg = buf.and_then(|b| b.average_in_window(win_dur));
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
/// configured `budget_pct` trip the alert.
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
                budget_pct: 2.0,
                severity: AlertSeverity::Page,
            }],
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

    #[test]
    fn alert_resolves_when_healthy() {
        let engine = SloEngine::new(fast_burn_objective());
        // Fire alert.
        for _ in 0..100 {
            engine.record(availability_sample(0.9));
        }
        engine.evaluate();
        assert_eq!(engine.active_alerts().len(), 1);

        // Push healthy samples to replace the bad ones.
        // We need to exceed the buffer so only healthy ones remain.
        for _ in 0..10_000 {
            engine.record(availability_sample(1.0));
        }
        let alerts = engine.evaluate();
        // Should get a resolve event.
        assert!(!alerts.is_empty());
        assert!(alerts[0].resolved_at.is_some());
        // No active alerts.
        assert!(engine.active_alerts().is_empty());
    }

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

    #[test]
    fn alert_has_runbook_url() {
        let engine = SloEngine::new(fast_burn_objective());
        for _ in 0..100 {
            engine.record(availability_sample(0.9));
        }
        let alerts = engine.evaluate();
        assert!(alerts[0].runbook_url.contains("runbooks.aegis.local"));
    }

    // -- Multi-burn tests --------------------------------------------------

    #[test]
    fn multi_burn_rate_config() {
        let objs = default_objectives();
        assert_eq!(objs.len(), 2);
        let avail = &objs[0];
        assert_eq!(avail.burn_rates.len(), 3);
        assert_eq!(avail.burn_rates[0].severity, AlertSeverity::Page);
        assert_eq!(avail.burn_rates[1].severity, AlertSeverity::Ticket);
    }

    #[test]
    fn multi_objective_tracking() {
        let engine = SloEngine::new(default_objectives());
        engine.record(availability_sample(1.0));
        engine.record(audit_sample(1.0));
        let status = engine.budget_status();
        assert_eq!(status.len(), 2);
    }

    // -- SLI kind tests ----------------------------------------------------

    #[test]
    fn sli_kind_equality() {
        assert_eq!(SliKind::DataPlaneAvailability, SliKind::DataPlaneAvailability);
        assert_ne!(SliKind::DataPlaneAvailability, SliKind::AuditDeliveryRate);
    }

    #[test]
    fn sli_kind_upstream_pool() {
        let a = SliKind::UpstreamAvailability {
            pool: "api".into(),
        };
        let b = SliKind::UpstreamAvailability {
            pool: "web".into(),
        };
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
    static VIPTALK_ENV_LOCK: parking_lot::Mutex<()> =
        parking_lot::Mutex::new(());

    fn with_viptalk_env<R>(
        pairs: &[(&str, Option<&str>)],
        f: impl FnOnce() -> R,
    ) -> R {
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
        assert!(receivers.is_empty(), "token-only → no receivers (need room IDs too)");
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
            ReceiverKind::VipTalk { bot_token, room_ids } => {
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
            burn_rates: vec![BurnRate { window_hours: 1, rate: 0.4 }],
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

    // -- Ring buffer tests -------------------------------------------------

    #[test]
    fn ring_buffer_overflow() {
        let mut buf = SliRingBuffer::new(3);
        for i in 0..5 {
            buf.push(SliSample {
                kind: SliKind::DataPlaneAvailability,
                value: i as f64,
                ts: Utc::now(),
            });
        }
        assert_eq!(buf.samples.len(), 3);
        // Oldest samples removed.
        assert_eq!(buf.samples[0].value, 2.0);
    }

    #[test]
    fn ring_buffer_average() {
        let mut buf = SliRingBuffer::new(100);
        for v in [1.0, 2.0, 3.0] {
            buf.push(SliSample {
                kind: SliKind::DataPlaneAvailability,
                value: v,
                ts: Utc::now(),
            });
        }
        let avg = buf.average_in_window(Duration::hours(1)).unwrap();
        assert!((avg - 2.0).abs() < 0.001);
    }

    #[test]
    fn ring_buffer_empty_average() {
        let buf = SliRingBuffer::new(100);
        assert!(buf.average_in_window(Duration::hours(1)).is_none());
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
        };
        let json = serde_json::to_string(&alert).unwrap();
        let parsed: SloAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.severity, AlertSeverity::Page);
    }
}
