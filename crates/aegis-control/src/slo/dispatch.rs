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

use crate::slo::{
    AlertDedupCache, AlertEvent, AlertReceiver, DedupDecision, ReceiverKind, SloAlert,
};

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

/// Dispatch one SLO alert across a receiver list.
///
/// Back-compat wrapper around [`dispatch_event`] — preserved so
/// existing call sites that hold a `&SloAlert` keep working. New
/// code should build an [`AlertEvent`] and call `dispatch_event`
/// (which adds dedup + severity routing).
pub async fn send_alert(
    alert: &SloAlert,
    receivers: &[AlertReceiver],
) -> DispatchSummary {
    dispatch_event(&AlertEvent::Slo(alert.clone()), receivers, None).await
}

/// Dispatch one [`AlertEvent`] across a receiver list (2026-05-20
/// alerts refactor).
///
/// - **Severity routing**: a receiver only sees the event when
///   [`AlertReceiver::accepts`] returns true for the event's
///   severity. An empty filter accepts everything.
/// - **Dedup**: when `dedup` is `Some`, an event whose
///   fingerprint fired inside the cache window is suppressed;
///   the next emission after the window carries a
///   `(+N suppressed)` note.
/// - **Delivery**: VipTalk is delivered in-process (behind the
///   `alerts` feature). Every other [`ReceiverKind`] is
///   classified `external` for an operator-side dispatcher.
///
/// Never panics — every failure is captured in the `failed` vec.
pub async fn dispatch_event(
    event: &AlertEvent,
    receivers: &[AlertReceiver],
    dedup: Option<&AlertDedupCache>,
) -> DispatchSummary {
    let mut summary = DispatchSummary::empty();
    let severity = event.severity();

    // Dedup gate — short-circuit the whole dispatch when this
    // fingerprint fired recently.
    let suppressed = match dedup {
        Some(cache) => match cache.check(event.fingerprint(), event.fired_at()) {
            DedupDecision::Suppress => {
                tracing::debug!(
                    severity = ?severity,
                    "alert suppressed by dedup window",
                );
                return summary;
            }
            DedupDecision::Emit { suppressed } => suppressed,
        },
        None => 0,
    };

    // `text` is consumed only in the `alerts`-feature VipTalk
    // branch; without the feature the dispatch no-ops.
    #[cfg_attr(not(feature = "alerts"), allow(unused_variables))]
    let text = format_event_text(event, suppressed);

    for r in receivers {
        if !r.accepts(severity) {
            tracing::debug!(
                receiver = %r.name,
                severity = ?severity,
                "receiver severity filter excludes this event",
            );
            continue;
        }
        match &r.kind {
            ReceiverKind::VipTalk { bot_token, room_ids } => {
                #[cfg(feature = "alerts")]
                {
                    match send_viptalk(bot_token, room_ids, &text).await {
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
                        severity = ?severity,
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
    text: &str,
) -> Result<(), String> {
    use std::time::Duration;

    // F-CRITICAL-015 (2026-05-17 control audit): pre-fix
    // `bot_token` was interpolated directly into the URL path with
    // NO validation. Combined with the (now-removed) hardcoded
    // dev/UAT default token and the (separately-fixed) admin
    // no-auth gate, an attacker who set the operator-controlled
    // `bot_token` to a path-traversal or scheme-override payload
    // could pivot the WAF's outbound HTTP client to arbitrary
    // hosts (AWS metadata `169.254.169.254`, internal services,
    // etc.) by abusing the URL composition.
    //
    // Now: reject any bot_token containing characters that have
    // structural meaning in a URL (`:`, `/`, `\`, `@`, `?`, `#`,
    // control chars, or whitespace). Legitimate VipTalk tokens
    // are bot ID strings — alphanumerics + dashes + dots. The
    // structural-character ban also prevents header smuggling
    // through the path component.
    if bot_token.is_empty()
        || bot_token.bytes().any(|b| {
            // Structural URL chars + percent (catches
            // percent-encoded path-traversal like `..%2F`) +
            // anything outside printable ASCII.
            matches!(b, b':' | b'/' | b'\\' | b'@' | b'?' | b'#' | b' ' | b'%')
                || b < 0x21
                || b > 0x7e
        })
        || bot_token.contains("..")
    {
        return Err(
            "viptalk bot_token contains unsafe characters; reject to prevent SSRF"
                .to_string(),
        );
    }

    let api_base = std::env::var("AEGIS_VIPTALK_API_BASE")
        .unwrap_or_else(|_| DEFAULT_VIPTALK_API_BASE.to_string());
    let url = format!(
        "{}/v1/bot/{}/sendMessage",
        api_base.trim_end_matches('/'),
        bot_token
    );

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    // VipTalk's API takes a single `roomIds` field. The example
    // curl shows one room; multiple rooms can be sent by
    // repeating the field. The `reqwest::form` helper sends
    // duplicate keys when we pass an array of (key, value)
    // tuples, which matches what the upstream expects.
    let mut form: Vec<(&str, &str)> = vec![("text", text)];
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

/// Format any [`AlertEvent`] as a single VipTalk chat message
/// (2026-05-20 alerts refactor). Pure function so tests assert
/// the exact wire format. `suppressed` is the dedup-window count
/// of fires we dropped since the last emission — appended as a
/// `(+N suppressed since last alert)` note when non-zero.
pub fn format_event_text(event: &AlertEvent, suppressed: u32) -> String {
    let sev = event.severity();
    let body = match event {
        AlertEvent::Slo(a) => return append_suppressed(format_alert_text(a), suppressed),
        AlertEvent::DdosModeEntered { trigger, observed_rps, .. } => format!(
            "[{sev:?}] DDoS gate entered ENFORCE\n\
             Trigger: {trigger}\n\
             Observed: {observed_rps} rps"
        ),
        AlertEvent::DdosModeCleared { duration_seconds, .. } => format!(
            "[{sev:?}] DDoS gate cleared — back to NORMAL\n\
             Enforce duration: {duration_seconds}s"
        ),
        AlertEvent::CertExpiringSoon { host, days_remaining, not_after, .. } => format!(
            "[{sev:?}] TLS cert expiring soon\n\
             Host: {host}\n\
             Expires: {not_after} ({days_remaining} days)",
            not_after = not_after.to_rfc3339(),
        ),
        AlertEvent::StrikeBlockSurge { unique_ips, window_seconds, top_rule_ids, .. } => format!(
            "[{sev:?}] Strike-block surge\n\
             {unique_ips} unique IPs blocked in {window_seconds}s\n\
             Top rules: {rules}",
            rules = if top_rule_ids.is_empty() {
                "—".to_string()
            } else {
                top_rule_ids.join(", ")
            },
        ),
        AlertEvent::UpstreamPoolDegraded { pool, healthy, total, first_down, .. } => format!(
            "[{sev:?}] Upstream pool degraded\n\
             Pool: {pool} ({healthy}/{total} healthy)\n\
             First down: {first_down}"
        ),
        AlertEvent::UpstreamPoolRecovered { pool, .. } => {
            format!("[{sev:?}] Upstream pool recovered — {pool} fully healthy")
        }
        AlertEvent::LeaderLost { previous_leader, our_node, .. } => format!(
            "[{sev:?}] Cluster leader lost\n\
             Previous: {previous_leader}\n\
             This node: {our_node}"
        ),
        AlertEvent::HotReloadFailed { reason, last_known_good_version, .. } => format!(
            "[{sev:?}] Hot-reload FAILED — last-known-good still live\n\
             Reason: {reason}\n\
             LKG config version: {last_known_good_version}"
        ),
        AlertEvent::GitOpsDrift { repo, expected, observed, .. } => format!(
            "[{sev:?}] GitOps drift detected\n\
             Repo: {repo}\n\
             Expected: {expected}\n\
             Observed: {observed}"
        ),
        AlertEvent::AuditChainBreak { last_good_seq, observed_seq, .. } => format!(
            "[{sev:?}] AUDIT CHAIN BREAK\n\
             Last good seq: {last_good_seq}\n\
             Observed seq: {observed_seq}"
        ),
    };
    append_suppressed(body, suppressed)
}

fn append_suppressed(body: String, suppressed: u32) -> String {
    if suppressed == 0 {
        body
    } else {
        format!("{body}\n(+{suppressed} suppressed since last alert)")
    }
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
                severities: Vec::new(),
            },
            AlertReceiver {
                name: "pd".into(),
                kind: ReceiverKind::PagerDuty {
                    routing_key: "test-key".into(),
                },
                severities: Vec::new(),
            },
            AlertReceiver {
                name: "alertmanager".into(),
                kind: ReceiverKind::AlertmanagerWebhook {
                    url: "https://am.example.com/api/v2/alerts".into(),
                },
                severities: Vec::new(),
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

    #[cfg(feature = "alerts")]
    #[tokio::test]
    async fn send_viptalk_rejects_path_traversal_bot_token() {
        // F-CRITICAL-015 regression. Token containing `/` or `:`
        // or `?` would let an attacker compose a different
        // upstream URL via path-traversal. Reject pre-dispatch
        // so the reqwest client never sees the dirty value.
        let text = format_alert_text(&fake_alert());
        for bad in [
            "..%2F169.254.169.254%2F",
            "evil@attacker.com",
            "real/../169.254.169.254",
            "real:9999/admin",
            "real?query=1",
            "with space",
            "",
        ] {
            let err = send_viptalk(bad, &["!room:example.com".into()], &text)
                .await
                .unwrap_err();
            assert!(
                err.contains("unsafe characters") || err.contains("SSRF"),
                "expected SSRF-reject error for token `{bad}`, got: {err}",
            );
        }
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
            severities: Vec::new(),
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
            severities: Vec::new(),
        }];
        let summary = send_alert(&fake_alert(), &receivers).await;
        std::env::remove_var("AEGIS_VIPTALK_API_BASE");

        assert!(
            summary.failed.iter().any(|(n, _)| n == "vt"),
            "expected vt in failed: {summary:?}"
        );
        assert!(!summary.is_clean());
    }

    // -- 2026-05-20 alerts refactor ----------------------------------------

    use crate::slo::{AlertDedupCache, AlertEvent, DedupDecision};

    fn vt(name: &str, severities: Vec<AlertSeverity>) -> AlertReceiver {
        AlertReceiver {
            name: name.into(),
            kind: ReceiverKind::VipTalk {
                bot_token: "tok".into(),
                room_ids: vec!["!room:example.com".into()],
            },
            severities,
        }
    }

    fn ddos_event() -> AlertEvent {
        AlertEvent::DdosModeEntered {
            fired_at: chrono::Utc::now(),
            trigger: "cumulative-risk".into(),
            observed_rps: 1840,
        }
    }

    #[test]
    fn event_severity_routing_matrix() {
        assert_eq!(ddos_event().severity(), AlertSeverity::Page);
        assert_eq!(
            AlertEvent::DdosModeCleared { fired_at: chrono::Utc::now(), duration_seconds: 12 }
                .severity(),
            AlertSeverity::Info,
        );
        // Cert < 7 days → Page; ≥ 7 days → Ticket.
        let soon = AlertEvent::CertExpiringSoon {
            fired_at: chrono::Utc::now(),
            host: "api.example.com".into(),
            days_remaining: 3,
            not_after: chrono::Utc::now(),
        };
        assert_eq!(soon.severity(), AlertSeverity::Page);
        let later = AlertEvent::CertExpiringSoon {
            fired_at: chrono::Utc::now(),
            host: "api.example.com".into(),
            days_remaining: 21,
            not_after: chrono::Utc::now(),
        };
        assert_eq!(later.severity(), AlertSeverity::Ticket);
    }

    #[test]
    fn receiver_severity_filter() {
        let page_only = vt("oncall", vec![AlertSeverity::Page]);
        let ticket_info = vt("audit", vec![AlertSeverity::Ticket, AlertSeverity::Info]);
        let all = vt("everything", vec![]);
        assert!(page_only.accepts(AlertSeverity::Page));
        assert!(!page_only.accepts(AlertSeverity::Ticket));
        assert!(ticket_info.accepts(AlertSeverity::Info));
        assert!(!ticket_info.accepts(AlertSeverity::Page));
        assert!(all.accepts(AlertSeverity::Page));
        assert!(all.accepts(AlertSeverity::Info));
    }

    #[tokio::test]
    async fn dispatch_event_respects_severity_filter() {
        // DDoS-entered is Page severity; a Ticket-only receiver
        // must be skipped (not delivered, not external).
        let receivers = vec![vt("ticket-only", vec![AlertSeverity::Ticket])];
        let summary = dispatch_event(&ddos_event(), &receivers, None).await;
        assert!(summary.delivered.is_empty());
        assert!(summary.external.is_empty());
        assert!(summary.skipped_feature_off.is_empty());
    }

    #[test]
    fn dedup_suppresses_inside_window_and_counts() {
        let cache = AlertDedupCache::new(300);
        let fp = ddos_event().fingerprint();
        let t0 = chrono::Utc::now();
        // First fire emits with zero suppressed.
        assert_eq!(cache.check(fp, t0), DedupDecision::Emit { suppressed: 0 });
        // Two more inside the window → suppressed.
        assert_eq!(cache.check(fp, t0 + chrono::Duration::seconds(10)), DedupDecision::Suppress);
        assert_eq!(cache.check(fp, t0 + chrono::Duration::seconds(20)), DedupDecision::Suppress);
        // Past the window → emit, carrying the suppressed count.
        assert_eq!(
            cache.check(fp, t0 + chrono::Duration::seconds(400)),
            DedupDecision::Emit { suppressed: 2 },
        );
    }

    #[test]
    fn dedup_distinguishes_fingerprints() {
        let cache = AlertDedupCache::new(300);
        let now = chrono::Utc::now();
        let ddos = ddos_event().fingerprint();
        let cert = AlertEvent::CertExpiringSoon {
            fired_at: now,
            host: "api.example.com".into(),
            days_remaining: 3,
            not_after: now,
        }
        .fingerprint();
        assert_ne!(ddos, cert);
        // Each fingerprint emits independently on first sight.
        assert_eq!(cache.check(ddos, now), DedupDecision::Emit { suppressed: 0 });
        assert_eq!(cache.check(cert, now), DedupDecision::Emit { suppressed: 0 });
    }

    #[test]
    fn format_event_text_covers_variants_and_suppressed_suffix() {
        let text = format_event_text(&ddos_event(), 0);
        assert!(text.contains("[Page]"), "got: {text}");
        assert!(text.contains("DDoS gate entered ENFORCE"), "got: {text}");
        assert!(text.contains("1840 rps"), "got: {text}");
        assert!(!text.contains("suppressed"), "no suffix at 0: {text}");

        let with_suffix = format_event_text(&ddos_event(), 9);
        assert!(
            with_suffix.contains("(+9 suppressed since last alert)"),
            "got: {with_suffix}",
        );

        let surge = AlertEvent::StrikeBlockSurge {
            fired_at: chrono::Utc::now(),
            unique_ips: 27,
            window_seconds: 60,
            top_rule_ids: vec!["sqli".into(), "ai".into()],
        };
        let stext = format_event_text(&surge, 0);
        assert!(stext.contains("27 unique IPs"), "got: {stext}");
        assert!(stext.contains("sqli, ai"), "got: {stext}");
    }
}
