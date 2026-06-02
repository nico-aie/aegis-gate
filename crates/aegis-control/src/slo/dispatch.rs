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
pub async fn send_alert(alert: &SloAlert, receivers: &[AlertReceiver]) -> DispatchSummary {
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
    let text = format_event_text(event, suppressed, current_identity());

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
            ReceiverKind::VipTalk {
                bot_token,
                room_ids,
            } => {
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
async fn send_viptalk(bot_token: &str, room_ids: &[String], text: &str) -> Result<(), String> {
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
            "viptalk bot_token contains unsafe characters; reject to prevent SSRF".to_string(),
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

/// Process-wide alert identity (service / node / environment), set
/// once at boot via [`set_alert_identity`] and rendered as the
/// second line of every SLO alert so an operator reading a chat
/// message knows WHICH deployment fired it. 2026-06-02 alert P1.
#[derive(Clone, Debug, Default)]
pub struct AlertIdentity {
    /// Service name, e.g. `aegis-gate`.
    pub service: String,
    /// Stable node id (`cfg.node.id`).
    pub node: Option<String>,
    /// Deployment environment label (`cfg.admin.environment`).
    pub environment: Option<String>,
}

static ALERT_IDENTITY: std::sync::OnceLock<AlertIdentity> = std::sync::OnceLock::new();

/// Install the process alert identity. First call wins (OnceLock);
/// later calls are ignored. Call once at boot from config so every
/// alert message names the deployment it came from.
pub fn set_alert_identity(id: AlertIdentity) {
    let _ = ALERT_IDENTITY.set(id);
}

/// The installed identity, if any. `dispatch_event` reads this and
/// threads it into the formatters so the pure formatters stay
/// unit-testable (they take the identity as an explicit argument).
pub(crate) fn current_identity() -> Option<&'static AlertIdentity> {
    ALERT_IDENTITY.get()
}

fn severity_glyph(sev: crate::slo::AlertSeverity) -> &'static str {
    use crate::slo::AlertSeverity::*;
    match sev {
        Page => "🔴",
        Ticket => "🟠",
        Info => "🔵",
    }
}

/// Render the identity as `service · node X · env Y`, omitting any
/// piece that's unset. Returns `None` when nothing is known so the
/// caller drops the line entirely.
fn identity_line(identity: Option<&AlertIdentity>) -> Option<String> {
    let id = identity?;
    let mut parts = Vec::new();
    if !id.service.is_empty() {
        parts.push(id.service.clone());
    }
    if let Some(n) = id.node.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("node {n}"));
    }
    if let Some(e) = id.environment.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("env {e}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" · "))
    }
}

/// Humanize "time since `t`" as a coarse relative string. Coarse on
/// purpose — operators want "6 minutes ago", not "6m 12s".
fn humanize_ago(t: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (chrono::Utc::now() - t).num_seconds();
    if secs < 0 {
        return "just now".to_string();
    }
    let plural = |n: i64| if n == 1 { "" } else { "s" };
    match secs {
        s if s < 60 => "just now".to_string(),
        s if s < 3600 => {
            let m = s / 60;
            format!("{m} minute{} ago", plural(m))
        }
        s if s < 86_400 => {
            let h = s / 3600;
            format!("{h} hour{} ago", plural(h))
        }
        s => {
            let d = s / 86_400;
            format!("{d} day{} ago", plural(d))
        }
    }
}

/// Format an [`SloAlert`] as a single chat message. Pure function
/// (identity passed in) so tests assert the exact wire format.
///
/// 2026-06-02 alert P1 — replaces the terse one-number-per-line
/// format. Adds a severity glyph + deployment identity, a plain-
/// language impact line, measured-vs-target, a **clamped** error
/// budget (the old format printed nonsense like `97727%`), and
/// human-readable local timestamps with a relative "(N ago)".
///
/// The runbook line was dropped 2026-06-02 — the engine's runbook
/// URL was a hardcoded `runbooks.aegis.local` placeholder that
/// resolves nowhere; a real configurable link can return in P2.
pub fn format_alert_text(alert: &SloAlert, identity: Option<&AlertIdentity>) -> String {
    let glyph = severity_glyph(alert.severity);
    let sev = format!("{:?}", alert.severity).to_uppercase();
    let sli = format!("{:?}", alert.sli);
    // Clamp the consumed budget to [0, 100] — over a finite window it
    // can't meaningfully exceed 100%, and the raw "how fast" lives in
    // the burn rate. This kills the `Budget consumed: 97727.3%` wart.
    let budget = alert.budget_consumed_pct.clamp(0.0, 100.0);
    let burn = if alert.burn_rate >= 10.0 {
        format!("{:.0}×", alert.burn_rate)
    } else {
        format!("{:.1}×", alert.burn_rate)
    };
    let measured_pct = alert.measured * 100.0;
    let target_pct = alert.target * 100.0;
    let window = alert.window_hours;
    let started = alert
        .fired_at
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S %z");

    let mut s = String::new();
    s.push_str(&format!("{glyph} {sev} · SLO breach — {sli}\n"));
    if let Some(line) = identity_line(identity) {
        s.push_str(&line);
        s.push('\n');
    }
    s.push('\n');
    s.push_str(&format!(
        "{sli} is below target — the {window}h error budget is {budget:.0}% consumed \
         (burning ~{burn} faster than sustainable).\n\n"
    ));
    s.push_str(&format!(
        "  Measured       {measured_pct:.1}%   (target {target_pct:.2}%)\n"
    ));
    s.push_str(&format!("  Burn rate      {burn}   over {window}h\n"));
    s.push_str(&format!(
        "  Error budget   {budget:.0}% consumed   ({window}h window)\n\n"
    ));
    s.push_str(&format!(
        "Started  {started}  ({})",
        humanize_ago(alert.fired_at)
    ));
    if let Some(r) = alert.resolved_at {
        let r_local = r
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %z");
        s.push_str(&format!("\nResolved {r_local}  ({})", humanize_ago(r)));
    }
    s
}

/// Format any [`AlertEvent`] as a single VipTalk chat message
/// (2026-05-20 alerts refactor). Pure function so tests assert
/// the exact wire format. `suppressed` is the dedup-window count
/// of fires we dropped since the last emission — appended as a
/// `(+N suppressed since last alert)` note when non-zero.
pub fn format_event_text(
    event: &AlertEvent,
    suppressed: u32,
    identity: Option<&AlertIdentity>,
) -> String {
    let sev = event.severity();
    let glyph = severity_glyph(sev);
    let sev_label = format!("{sev:?}").to_uppercase();

    // 2026-06-02 alert P2 — every variant now shares the SLO message's
    // shape: `glyph SEV · <title>`, the deployment identity line, the
    // detail body, then an `At <local time> (<N ago>)` footer. Each arm
    // yields just `(title, body)`; the SLO arm delegates to the richer
    // `format_alert_text` (it has measured-vs-target + its own footer).
    let (title, body): (&str, String) = match event {
        AlertEvent::Slo(a) => return append_suppressed(format_alert_text(a, identity), suppressed),
        AlertEvent::DdosModeEntered {
            trigger,
            observed_rps,
            ..
        } => (
            "DDoS gate entered ENFORCE",
            format!("Trigger: {trigger}\nObserved: {observed_rps} rps"),
        ),
        AlertEvent::DdosModeCleared {
            duration_seconds, ..
        } => (
            "DDoS gate cleared — back to NORMAL",
            format!("Enforce duration: {duration_seconds}s"),
        ),
        AlertEvent::CertExpiringSoon {
            host,
            days_remaining,
            not_after,
            ..
        } => (
            "TLS cert expiring soon",
            format!(
                "Host: {host}\nExpires: {} ({days_remaining} days)",
                not_after
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S %z"),
            ),
        ),
        AlertEvent::StrikeBlockSurge {
            unique_ips,
            window_seconds,
            top_rule_ids,
            ..
        } => (
            "Strike-block surge",
            format!(
                "{unique_ips} unique IPs blocked in {window_seconds}s\nTop rules: {rules}",
                rules = if top_rule_ids.is_empty() {
                    "—".to_string()
                } else {
                    top_rule_ids.join(", ")
                },
            ),
        ),
        AlertEvent::UpstreamPoolDegraded {
            pool,
            healthy,
            total,
            first_down,
            ..
        } => (
            "Upstream pool degraded",
            format!("Pool: {pool} ({healthy}/{total} healthy)\nFirst down: {first_down}"),
        ),
        AlertEvent::UpstreamPoolRecovered { pool, .. } => {
            ("Upstream pool recovered", format!("{pool} fully healthy"))
        }
        AlertEvent::LeaderLost {
            previous_leader,
            our_node,
            ..
        } => (
            "Cluster leader lost",
            format!("Previous: {previous_leader}\nThis node: {our_node}"),
        ),
        AlertEvent::HotReloadFailed {
            reason,
            last_known_good_version,
            ..
        } => (
            "Hot-reload FAILED — last-known-good still live",
            format!("Reason: {reason}\nLKG config version: {last_known_good_version}"),
        ),
        AlertEvent::GitOpsDrift {
            repo,
            expected,
            observed,
            ..
        } => (
            "GitOps drift detected",
            format!("Repo: {repo}\nExpected: {expected}\nObserved: {observed}"),
        ),
        AlertEvent::AuditChainBreak {
            last_good_seq,
            observed_seq,
            ..
        } => (
            "AUDIT CHAIN BREAK",
            format!("Last good seq: {last_good_seq}\nObserved seq: {observed_seq}"),
        ),
    };

    let mut s = format!("{glyph} {sev_label} · {title}\n");
    if let Some(line) = identity_line(identity) {
        s.push_str(&line);
        s.push('\n');
    }
    s.push('\n');
    s.push_str(&body);
    let fired = event.fired_at();
    s.push_str(&format!(
        "\n\nAt  {}  ({})",
        fired
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %z"),
        humanize_ago(fired),
    ));
    append_suppressed(s, suppressed)
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
            measured: 0.998,
            target: 0.999,
        }
    }

    #[test]
    fn format_alert_text_includes_severity_sli_burn_rate_and_target() {
        let alert = fake_alert();
        let text = format_alert_text(&alert, None);
        // Title: glyph + uppercase severity + SLI.
        assert!(
            text.contains("🔴 PAGE · SLO breach — DataPlaneAvailability"),
            "got: {text}"
        );
        assert!(
            text.contains("14×"),
            "burn rate ≥10 rounds to integer: {text}"
        );
        assert!(text.contains("over 1h"), "got: {text}");
        // measured-vs-target line.
        assert!(text.contains("Measured       99.8%"), "got: {text}");
        assert!(text.contains("(target 99.90%)"), "got: {text}");
        // Runbook line was dropped (placeholder URL); must not appear.
        assert!(
            !text.contains("Runbook"),
            "runbook line should be gone: {text}"
        );
        assert!(
            !text.contains("runbooks."),
            "no placeholder runbook URL: {text}"
        );
        // Relative "started" line.
        assert!(text.contains("Started"), "got: {text}");
        // Resolved alerts append a resolution line.
        let mut resolved = alert.clone();
        resolved.resolved_at = Some(chrono::Utc::now());
        let resolved_text = format_alert_text(&resolved, None);
        assert!(resolved_text.contains("Resolved"), "got: {resolved_text}");
    }

    #[test]
    fn format_alert_text_clamps_absurd_budget_to_100() {
        // The production wart: budget_consumed_pct of 97727.3% must
        // render as a sane "100% consumed", never the raw number.
        let mut alert = fake_alert();
        alert.burn_rate = 977.27;
        alert.budget_consumed_pct = 97727.3;
        alert.measured = 0.123;
        let text = format_alert_text(&alert, None);
        assert!(!text.contains("97727"), "raw absurd budget leaked: {text}");
        assert!(text.contains("100% consumed"), "got: {text}");
        assert!(
            text.contains("977×"),
            "burn rate carries the real magnitude: {text}"
        );
        assert!(text.contains("Measured       12.3%"), "got: {text}");
    }

    #[test]
    fn format_alert_text_renders_identity_when_set_and_omits_when_not() {
        let alert = fake_alert();
        // No identity → no identity line, straight from title to blank.
        let plain = format_alert_text(&alert, None);
        assert!(!plain.contains("node "), "got: {plain}");
        assert!(!plain.contains("env "), "got: {plain}");

        let id = AlertIdentity {
            service: "aegis-gate".into(),
            node: Some("aegis-prod-2".into()),
            environment: Some("production".into()),
        };
        let with_id = format_alert_text(&alert, Some(&id));
        assert!(
            with_id.contains("aegis-gate · node aegis-prod-2 · env production"),
            "identity line missing: {with_id}",
        );

        // Partial identity (service only) renders just the service.
        let svc_only = AlertIdentity {
            service: "aegis-gate".into(),
            ..Default::default()
        };
        let t = format_alert_text(&alert, Some(&svc_only));
        assert!(t.contains("\naegis-gate\n"), "got: {t}");
        assert!(!t.contains("node "), "got: {t}");
    }

    #[test]
    fn humanize_ago_buckets() {
        let now = chrono::Utc::now();
        assert_eq!(humanize_ago(now), "just now");
        assert_eq!(
            humanize_ago(now - chrono::Duration::minutes(6)),
            "6 minutes ago"
        );
        assert_eq!(
            humanize_ago(now - chrono::Duration::minutes(1)),
            "1 minute ago"
        );
        assert_eq!(
            humanize_ago(now - chrono::Duration::hours(3)),
            "3 hours ago"
        );
        assert_eq!(humanize_ago(now - chrono::Duration::days(2)), "2 days ago");
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
        let text = format_alert_text(&fake_alert(), None);
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
            summary
                .skipped_feature_off
                .contains(&"vt-no-feat".to_string()),
            "expected receiver in skipped_feature_off, got: {summary:?}",
        );
        assert!(
            !summary.delivered.contains(&"vt-no-feat".to_string()),
            "feature-off path must not push to delivered (the production lie)",
        );
        assert!(
            !summary.is_clean(),
            "skipped_feature_off counts as not-clean"
        );
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
            AlertEvent::DdosModeCleared {
                fired_at: chrono::Utc::now(),
                duration_seconds: 12
            }
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
        assert_eq!(
            cache.check(fp, t0 + chrono::Duration::seconds(10)),
            DedupDecision::Suppress
        );
        assert_eq!(
            cache.check(fp, t0 + chrono::Duration::seconds(20)),
            DedupDecision::Suppress
        );
        // Past the window → emit, carrying the suppressed count.
        assert_eq!(
            cache.check(fp, t0 + chrono::Duration::seconds(400)),
            DedupDecision::Emit { suppressed: 2 },
        );
    }

    #[test]
    fn dedup_prunes_stale_entries_beyond_threshold() {
        // 2026-05-20 memory-leak audit — distinct fingerprints must
        // not accrete forever. Past the prune threshold, entries
        // stale beyond 2× the window are dropped.
        let cache = AlertDedupCache::new(60); // 60s window → 120s stale cutoff
        let t0 = chrono::Utc::now();
        // Insert > threshold distinct stale fingerprints at t0.
        for fp in 0..300u64 {
            assert_eq!(cache.check(fp, t0), DedupDecision::Emit { suppressed: 0 });
        }
        // A fresh check 10 minutes later (well past 2× window) triggers
        // the prune; all 300 stale entries are dropped and only the
        // freshly-checked fingerprint remains.
        let later = t0 + chrono::Duration::seconds(600);
        let _ = cache.check(99_999, later);
        assert!(
            cache.entry_count() <= 1,
            "stale entries should be pruned, got {}",
            cache.entry_count(),
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
        assert_eq!(
            cache.check(ddos, now),
            DedupDecision::Emit { suppressed: 0 }
        );
        assert_eq!(
            cache.check(cert, now),
            DedupDecision::Emit { suppressed: 0 }
        );
    }

    #[test]
    fn format_event_text_covers_variants_and_suppressed_suffix() {
        let text = format_event_text(&ddos_event(), 0, None);
        // P2 header: glyph + uppercase severity + title (was `[Page]`).
        assert!(
            text.contains("🔴 PAGE · DDoS gate entered ENFORCE"),
            "got: {text}"
        );
        assert!(text.contains("1840 rps"), "got: {text}");
        // P2 footer: every variant gets an "At <time> (<ago>)" line.
        assert!(text.contains("\nAt  "), "missing timestamp footer: {text}");
        assert!(text.contains("just now"), "got: {text}");
        assert!(!text.contains("suppressed"), "no suffix at 0: {text}");

        let with_suffix = format_event_text(&ddos_event(), 9, None);
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
        let stext = format_event_text(&surge, 0, None);
        assert!(
            stext.contains("🔴 PAGE · Strike-block surge"),
            "got: {stext}"
        );
        assert!(stext.contains("27 unique IPs"), "got: {stext}");
        assert!(stext.contains("sqli, ai"), "got: {stext}");
    }

    #[test]
    fn format_event_text_renders_identity_for_non_slo_variants() {
        let id = AlertIdentity {
            service: "aegis-gate".into(),
            node: Some("aegis-prod-2".into()),
            environment: Some("production".into()),
        };
        let text = format_event_text(&ddos_event(), 0, Some(&id));
        assert!(
            text.contains("aegis-gate · node aegis-prod-2 · env production"),
            "identity line missing on non-SLO variant: {text}",
        );
        // No identity → no identity line.
        let plain = format_event_text(&ddos_event(), 0, None);
        assert!(!plain.contains("node "), "got: {plain}");
    }
}
