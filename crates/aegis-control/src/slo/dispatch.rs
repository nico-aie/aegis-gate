//! Alert delivery for the SLO engine.
//!
//! Today this module ships a real implementation for **VipTalk**
//! (the project's default chat receiver) and treats every other
//! receiver kind as "delivered externally" — i.e. the operator's
//! Alertmanager / PagerDuty / sidecar dispatcher reads the
//! receiver list from the SLO engine and handles delivery off-
//! box. This split keeps the data-plane / control-plane process
//! free of long-lived connections to PagerDuty et al. while
//! still letting the project's own chat alerts work
//! out-of-the-box.
//!
//! Feature gate: `aegis-control/alerts` pulls in `reqwest` for
//! the VipTalk POST. Without the feature, [`send_alert`] is a
//! no-op that logs the alert at `info` and returns Ok — useful
//! for development builds.

use crate::slo::{AlertReceiver, ReceiverKind, SloAlert};

/// Outcome of dispatching one alert across one receiver list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchSummary {
    /// Receivers we actually delivered to in-process (today:
    /// VipTalk when the binary is built with `--features alerts`).
    pub delivered: Vec<String>,
    /// Receivers skipped because they're operator-side (today:
    /// every receiver kind except VipTalk).
    pub external: Vec<String>,
    /// Receivers that errored — contains the error message.
    pub failed: Vec<(String, String)>,
    /// Receivers we COULD have delivered to but the binary
    /// wasn't built with the required Cargo feature (today:
    /// VipTalk when `--features alerts` is missing).
    /// Distinct from `failed` because nothing was attempted —
    /// the dispatch path no-op'd at compile-time.
    /// Distinct from `delivered` so the dashboard doesn't
    /// claim a delivery that never happened.
    pub skipped_feature_off: Vec<String>,
}

impl DispatchSummary {
    pub fn empty() -> Self {
        Self {
            delivered: Vec::new(),
            external: Vec::new(),
            failed: Vec::new(),
            skipped_feature_off: Vec::new(),
        }
    }

    pub fn is_clean(&self) -> bool {
        self.failed.is_empty() && self.skipped_feature_off.is_empty()
    }
}

/// VipTalk bot API endpoint used by [`send_alert`]. Override via
/// `AEGIS_VIPTALK_API_BASE` at runtime if your deployment uses a
/// non-default region.
pub const DEFAULT_VIPTALK_API_BASE: &str = "https://api.viptalk.org";

/// Dispatch one alert across a receiver list.
///
/// Returns a [`DispatchSummary`] showing which receivers were
/// delivered in-process, which are operator-side, and which
/// errored. Never panics — every failure is captured in the
/// `failed` vec.
pub async fn send_alert(
    alert: &SloAlert,
    receivers: &[AlertReceiver],
) -> DispatchSummary {
    let mut summary = DispatchSummary::empty();

    for r in receivers {
        match &r.kind {
            ReceiverKind::VipTalk { bot_token, room_ids } => {
                #[cfg(feature = "alerts")]
                {
                    match send_viptalk(bot_token, room_ids, alert).await {
                        Ok(()) => summary.delivered.push(r.name.clone()),
                        Err(e) => {
                            tracing::warn!(
                                receiver = %r.name,
                                error = %e,
                                "viptalk delivery failed",
                            );
                            summary.failed.push((r.name.clone(), e));
                        }
                    }
                }
                #[cfg(not(feature = "alerts"))]
                {
                    let _ = (bot_token, room_ids);
                    // BUG-FIX 2026-05-03: previous behaviour
                    // pushed to `delivered` here even though
                    // the dispatch was a no-op — dashboard +
                    // /api/alert-receivers/{name}/test reported
                    // success when nothing left the WAF.
                    // Surface the skip as its own bucket so
                    // operators see an honest "build doesn't
                    // include alerts; deploy with FEATURES=alerts"
                    // message instead of a phantom green check.
                    tracing::warn!(
                        receiver = %r.name,
                        sli = ?alert.sli,
                        severity = ?alert.severity,
                        "viptalk delivery NOT sent — binary missing `alerts` feature; \
                         rebuild with FEATURES=\"redis geoip alerts\" to enable",
                    );
                    summary.skipped_feature_off.push(r.name.clone());
                }
            }
            // Every other kind is descriptive-only today —
            // operator-side dispatcher (Alertmanager, sidecar,
            // …) reads the receiver and delivers off-box.
            _ => {
                tracing::debug!(
                    receiver = %r.name,
                    "external receiver — delivery handled off-box",
                );
                summary.external.push(r.name.clone());
            }
        }
    }

    summary
}

#[cfg(feature = "alerts")]
async fn send_viptalk(
    bot_token: &str,
    room_ids: &[String],
    alert: &SloAlert,
) -> Result<(), String> {
    use std::time::Duration;

    let api_base = std::env::var("AEGIS_VIPTALK_API_BASE")
        .unwrap_or_else(|_| DEFAULT_VIPTALK_API_BASE.to_string());
    let url = format!(
        "{}/v1/bot/{}/sendMessage",
        api_base.trim_end_matches('/'),
        bot_token
    );

    let text = format_alert_text(alert);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    // VipTalk's API takes a single `roomIds` field. The example
    // curl shows one room; multiple rooms can be sent by
    // repeating the field. The `reqwest::form` helper sends
    // duplicate keys when we pass an array of (key, value)
    // tuples, which matches what the upstream expects.
    let mut form: Vec<(&str, &str)> = vec![("text", text.as_str())];
    for room in room_ids {
        form.push(("roomIds", room.as_str()));
    }

    let resp = http
        .post(&url)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("transport: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("viptalk returned {status}: {body}"));
    }
    Ok(())
}

/// Format an [`SloAlert`] as a single chat message. Kept in a
/// pure function so tests assert on the exact wire format.
pub fn format_alert_text(alert: &SloAlert) -> String {
    let resolved = alert
        .resolved_at
        .map(|t| format!("\nResolved at: {}", t.to_rfc3339()))
        .unwrap_or_default();
    format!(
        "[{severity:?}] SLO breach: {sli:?}\n\
         Burn rate: {burn:.2}× over {window}h window\n\
         Budget consumed: {budget:.1}%\n\
         Fired at: {fired}{resolved}\n\
         Runbook: {runbook}",
        severity = alert.severity,
        sli = alert.sli,
        burn = alert.burn_rate,
        window = alert.window_hours,
        budget = alert.budget_consumed_pct,
        fired = alert.fired_at.to_rfc3339(),
        resolved = resolved,
        runbook = alert.runbook_url,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slo::{AlertSeverity, SliKind, SloAlert};

    fn fake_alert() -> SloAlert {
        SloAlert {
            sli: SliKind::DataPlaneAvailability,
            severity: AlertSeverity::Page,
            fired_at: chrono::Utc::now(),
            resolved_at: None,
            burn_rate: 14.0,
            budget_consumed_pct: 2.0,
            window_hours: 1,
            runbook_url: "https://runbooks.example.com/slo/data-plane".into(),
        }
    }

    #[test]
    fn format_alert_text_includes_severity_sli_burn_rate_and_runbook() {
        let alert = fake_alert();
        let text = format_alert_text(&alert);
        assert!(text.contains("Page"), "got: {text}");
        assert!(text.contains("DataPlaneAvailability"), "got: {text}");
        assert!(text.contains("14.00×"), "got: {text}");
        assert!(text.contains("1h window"), "got: {text}");
        assert!(text.contains("Budget consumed: 2.0%"), "got: {text}");
        assert!(text.contains("https://runbooks.example.com/slo/data-plane"), "got: {text}");
        // Resolved alerts append the resolution timestamp.
        let mut resolved = alert.clone();
        resolved.resolved_at = Some(chrono::Utc::now());
        let resolved_text = format_alert_text(&resolved);
        assert!(resolved_text.contains("Resolved at:"), "got: {resolved_text}");
    }

    #[tokio::test]
    async fn dispatch_classifies_receivers() {
        let receivers = vec![
            AlertReceiver {
                name: "vt".into(),
                kind: ReceiverKind::VipTalk {
                    bot_token: "test-token".into(),
                    room_ids: vec!["!room:example.com".into()],
                },
            },
            AlertReceiver {
                name: "pd".into(),
                kind: ReceiverKind::PagerDuty {
                    routing_key: "test-key".into(),
                },
            },
            AlertReceiver {
                name: "alertmanager".into(),
                kind: ReceiverKind::AlertmanagerWebhook {
                    url: "https://am.example.com/api/v2/alerts".into(),
                },
            },
        ];

        let summary = send_alert(&fake_alert(), &receivers).await;

        // VipTalk is in-process; the other two are external.
        // Without `alerts` feature the VipTalk dispatch logs +
        // counts as delivered; with the feature it actually
        // hits the network — we don't assert on which path
        // fired here because that's environment-dependent.
        // The classification (vt → delivered, pd/am → external)
        // is what matters for the dispatch summary contract.
        assert!(
            summary.delivered.contains(&"vt".to_string())
                || summary.failed.iter().any(|(n, _)| n == "vt")
                || summary.skipped_feature_off.contains(&"vt".to_string()),
            "vt should land in delivered, failed, or skipped_feature_off: {summary:?}"
        );
        assert!(summary.external.contains(&"pd".to_string()));
        assert!(summary.external.contains(&"alertmanager".to_string()));
    }

    #[tokio::test]
    async fn dispatch_to_empty_receivers_is_clean_and_empty() {
        let summary = send_alert(&fake_alert(), &[]).await;
        assert!(summary.delivered.is_empty());
        assert!(summary.external.is_empty());
        assert!(summary.failed.is_empty());
        assert!(summary.skipped_feature_off.is_empty());
        assert!(summary.is_clean());
    }

    #[cfg(not(feature = "alerts"))]
    #[tokio::test]
    async fn vt_without_alerts_feature_lands_in_skipped_not_delivered() {
        // Pin the bug-fix: when the binary is built WITHOUT
        // `--features alerts`, the dispatch must NOT claim
        // a delivery — that was the production lie.
        let receivers = vec![AlertReceiver {
            name: "vt-no-feat".into(),
            kind: ReceiverKind::VipTalk {
                bot_token: "tok".into(),
                room_ids: vec!["!room:matrix".into()],
            },
        }];
        let summary = send_alert(&fake_alert(), &receivers).await;
        assert!(
            summary.skipped_feature_off.contains(&"vt-no-feat".to_string()),
            "expected receiver in skipped_feature_off, got: {summary:?}",
        );
        assert!(
            !summary.delivered.contains(&"vt-no-feat".to_string()),
            "feature-off path must not push to delivered (the production lie)",
        );
        assert!(!summary.is_clean(), "skipped_feature_off counts as not-clean");
    }

    #[cfg(feature = "alerts")]
    #[tokio::test]
    async fn viptalk_to_unreachable_endpoint_lands_in_failed() {
        // Point at a port nothing listens on — the dispatch
        // should record a failure rather than panic.
        std::env::set_var("AEGIS_VIPTALK_API_BASE", "http://127.0.0.1:1");
        let receivers = vec![AlertReceiver {
            name: "vt".into(),
            kind: ReceiverKind::VipTalk {
                bot_token: "tok".into(),
                room_ids: vec!["!room:example.com".into()],
            },
        }];
        let summary = send_alert(&fake_alert(), &receivers).await;
        std::env::remove_var("AEGIS_VIPTALK_API_BASE");

        assert!(
            summary.failed.iter().any(|(n, _)| n == "vt"),
            "expected vt in failed: {summary:?}"
        );
        assert!(!summary.is_clean());
    }
}
