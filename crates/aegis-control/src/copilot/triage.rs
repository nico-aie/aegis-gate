//! Smart-catch triage (Copilot P3).
//!
//! Asks the LLM to cluster the telemetry snapshot into attack
//! "campaigns" and propose ONE candidate WAF rule per cluster. Output
//! is **advisory** — suggestions are surfaced in a review queue; the
//! operator previews (`/api/rules/simulate`) and promotes manually.
//! Nothing here writes rules or blocks traffic.
//!
//! v1 reasons over the aggregate [`TelemetrySnapshot`] (top attackers /
//! detectors / SLO). Per-event clustering over the audit ring is a
//! follow-up.

use super::summary::{complete_guarded, TelemetrySnapshot};
use super::{CostGuard, LlmError, LlmProvider, LlmRequest};

/// One advisory campaign + rule suggestion.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Suggestion {
    /// Stable-within-response id (`s0`, `s1`, …).
    pub id: String,
    /// Short campaign/cluster name.
    pub cluster: String,
    /// Plain-language explanation citing the snapshot numbers.
    pub explanation: String,
    /// A candidate rule the operator can review + promote. Free text /
    /// rule-DSL — NEVER auto-applied.
    pub suggested_rule: String,
    /// `low` | `medium` | `high` (as returned by the model).
    pub confidence: String,
}

/// Result of a triage run.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TriageResult {
    pub suggestions: Vec<Suggestion>,
    /// The raw model text, present only when it couldn't be parsed into
    /// structured suggestions — so the operator still sees the reasoning
    /// instead of an empty queue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparsed: Option<String>,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub snapshot: TelemetrySnapshot,
}

const TRIAGE_SYSTEM: &str = "You are a security-operations copilot for a \
Web Application Firewall. From the JSON telemetry snapshot, identify up to \
5 distinct attack campaigns or notable clusters. For each, propose ONE \
candidate WAF rule an operator could review and promote. Use ONLY data \
present in the snapshot — never invent IPs, counts, or events. Respond \
with ONLY a JSON array (no prose, no markdown fences) where each element \
is exactly: {\"cluster\": \"<short name>\", \"explanation\": \"<1-2 \
sentences citing the numbers>\", \"suggested_rule\": \"<a concrete rule, \
e.g. 'block IP 203.0.113.10' or 'rate-limit /login to 10/min'>\", \
\"confidence\": \"low|medium|high\"}. If nothing is notable, return [].";

const MAX_OUTPUT_TOKENS: u32 = 768;

/// Build the (un-redacted) triage prompt from a snapshot. Pure.
pub fn render_triage_prompt(snap: &TelemetrySnapshot) -> LlmRequest {
    let json = serde_json::to_string_pretty(snap).unwrap_or_else(|_| "{}".to_string());
    LlmRequest {
        system: Some(TRIAGE_SYSTEM.to_string()),
        prompt: format!(
            "Telemetry snapshot (last {} minutes):\n{json}",
            snap.window_minutes
        ),
        max_tokens: MAX_OUTPUT_TOKENS,
    }
}

#[derive(serde::Deserialize)]
struct RawSuggestion {
    #[serde(default)]
    cluster: String,
    #[serde(default)]
    explanation: String,
    #[serde(default)]
    suggested_rule: String,
    #[serde(default)]
    confidence: String,
}

/// Lenient extraction of the JSON array from the model's text — tolerates
/// prose/markdown around it by slicing from the first `[` to the last `]`.
fn parse_suggestions(text: &str) -> Option<Vec<RawSuggestion>> {
    let start = text.find('[')?;
    let end = text.rfind(']')?;
    if end < start {
        return None;
    }
    serde_json::from_str(&text[start..=end]).ok()
}

/// Run triage: render → redact → budget → provider → parse suggestions.
/// Same egress/budget guarantees as the other copilot calls (it routes
/// through [`complete_guarded`]).
pub async fn triage(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    snapshot: TelemetrySnapshot,
) -> Result<TriageResult, LlmError> {
    let resp = complete_guarded(provider, guard, render_triage_prompt(&snapshot)).await?;
    let (suggestions, unparsed) = match parse_suggestions(&resp.text) {
        Some(raws) => (
            raws.into_iter()
                .enumerate()
                .map(|(i, r)| Suggestion {
                    id: format!("s{i}"),
                    cluster: r.cluster,
                    explanation: r.explanation,
                    suggested_rule: r.suggested_rule,
                    confidence: r.confidence,
                })
                .collect(),
            None,
        ),
        // Couldn't parse structured output — keep the raw reasoning so
        // the operator isn't left with an empty queue.
        None => (Vec::new(), Some(resp.text.clone())),
    };
    Ok(TriageResult {
        suggestions,
        unparsed,
        model: provider.id().to_string(),
        input_tokens: resp.input_tokens,
        output_tokens: resp.output_tokens,
        snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copilot::summary::{AttackerRow, TelemetrySnapshot};
    use crate::copilot::MockProvider;
    use std::sync::Mutex;
    use std::time::Duration;

    fn guard() -> CostGuard {
        CostGuard::new(1_000_000, 1000, Duration::from_secs(3600))
    }

    fn snap() -> TelemetrySnapshot {
        TelemetrySnapshot {
            window_minutes: 60,
            total_requests: None,
            blocked: 6,
            top_attackers: vec![AttackerRow {
                ip: "203.0.113.10".into(),
                score: 100,
                level: "block".into(),
            }],
            top_detectors: vec![("sqli".into(), 6)],
            active_slo_alerts: vec![],
        }
    }

    #[tokio::test]
    async fn triage_parses_structured_suggestions() {
        let canned = r#"[{"cluster":"SQLi probing","explanation":"6 SQLi blocks from 203.0.113.10.","suggested_rule":"block IP 203.0.113.10","confidence":"high"}]"#;
        let p = MockProvider { canned: canned.into(), last_prompt: Mutex::new(None) };
        let res = triage(&p, &guard(), snap()).await.unwrap();
        assert_eq!(res.suggestions.len(), 1);
        assert_eq!(res.suggestions[0].id, "s0");
        assert_eq!(res.suggestions[0].cluster, "SQLi probing");
        assert_eq!(res.suggestions[0].confidence, "high");
        assert!(res.unparsed.is_none());
    }

    #[tokio::test]
    async fn triage_tolerates_prose_and_markdown_fences() {
        let canned = "Here are the campaigns:\n```json\n[{\"cluster\":\"c\",\"explanation\":\"e\",\"suggested_rule\":\"r\",\"confidence\":\"low\"}]\n```\nHope that helps!";
        let p = MockProvider { canned: canned.into(), last_prompt: Mutex::new(None) };
        let res = triage(&p, &guard(), snap()).await.unwrap();
        assert_eq!(res.suggestions.len(), 1);
        assert_eq!(res.suggestions[0].cluster, "c");
    }

    #[tokio::test]
    async fn triage_keeps_raw_text_when_unparseable() {
        let p = MockProvider {
            canned: "I could not produce JSON, sorry.".into(),
            last_prompt: Mutex::new(None),
        };
        let res = triage(&p, &guard(), snap()).await.unwrap();
        assert!(res.suggestions.is_empty());
        assert_eq!(res.unparsed.as_deref(), Some("I could not produce JSON, sorry."));
    }

    #[tokio::test]
    async fn triage_redacts_snapshot_before_egress() {
        let p = MockProvider { canned: "[]".into(), last_prompt: Mutex::new(None) };
        let mut s = snap();
        s.active_slo_alerts.push("abuse from carol@example.com".into());
        let _ = triage(&p, &guard(), s).await.unwrap();
        let seen = p.last_prompt.lock().unwrap().clone().unwrap();
        assert!(!seen.contains("carol@example.com"), "PII not redacted: {seen}");
    }
}
