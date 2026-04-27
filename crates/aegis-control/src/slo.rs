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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Page,
    Ticket,
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

/// Alert receiver configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertReceiver {
    pub name: String,
    pub kind: ReceiverKind,
}

/// Alert receiver kind.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceiverKind {
    AlertmanagerWebhook { url: String },
    Slack { webhook_url: String },
    PagerDuty { routing_key: String },
    ServiceNow { instance: String, table: String },
    Jira { base_url: String, project: String },
}

// ---------------------------------------------------------------------------
// SLI ring buffer (in-memory time series)
// ---------------------------------------------------------------------------

struct SliRingBuffer {
    samples: Vec<SliSample>,
    max_len: usize,
}

impl SliRingBuffer {
    fn new(max_len: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_len),
            max_len,
        }
    }

    fn push(&mut self, sample: SliSample) {
        if self.samples.len() >= self.max_len {
            self.samples.remove(0);
        }
        self.samples.push(sample);
    }

    fn average_in_window(&self, window: Duration) -> Option<f64> {
        let cutoff = Utc::now() - window;
        let in_window: Vec<f64> = self
            .samples
            .iter()
            .filter(|s| s.ts >= cutoff)
            .map(|s| s.value)
            .collect();
        if in_window.is_empty() {
            return None;
        }
        Some(in_window.iter().sum::<f64>() / in_window.len() as f64)
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
                        severity: burn.severity.clone(),
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

    /// Get current budget status for all objectives.
    pub fn budget_status(&self) -> Vec<BudgetStatus> {
        let buffers = self.buffers.lock().unwrap();
        self.objectives
            .iter()
            .map(|obj| {
                let window = Duration::days(obj.window_days as i64);
                let avg = buffers
                    .get(&obj.sli)
                    .and_then(|buf| buf.average_in_window(window));
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
                BudgetStatus {
                    sli: obj.sli.clone(),
                    target: obj.target,
                    current: avg.unwrap_or(1.0),
                    budget_remaining_pct: (100.0 - consumed).max(0.0),
                }
            })
            .collect()
    }
}

/// Budget consumption status for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub sli: SliKind,
    pub target: f64,
    pub current: f64,
    pub budget_remaining_pct: f64,
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
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let _: ReceiverKind = serde_json::from_str(&json).unwrap();
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
        };
        let json = serde_json::to_string(&bs).unwrap();
        assert!(json.contains("CertFreshnessDays"));
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
