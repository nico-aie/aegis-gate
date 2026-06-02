//! Situational-summary orchestration (Copilot P1, layer 1).
//!
//! Turns a pre-aggregated [`TelemetrySnapshot`] into an advisory
//! [`Brief`] via: render prompt → **redact** (mandatory egress gate) →
//! cost-admit → provider → record actual usage. Pure orchestration over
//! [`LlmProvider`] so it's unit-testable with the mock provider; the
//! snapshot *adapter* (reading `RiskTracker`/`SloEngine`) and the
//! `GET /api/copilot/summary` endpoint are the P1 integration layers.

use super::{redact_for_egress, CostGuard, LlmError, LlmProvider, LlmRequest, LlmResponse};

/// One attacker row in the snapshot (from `RiskTracker::top`).
#[derive(Clone, Debug, serde::Serialize)]
pub struct AttackerRow {
    pub ip: String,
    pub score: u32,
    pub level: String,
}

/// Point-in-time, pre-aggregated view of WAF telemetry the copilot
/// summarizes. Plain data on purpose: it keeps [`summarize`] pure +
/// testable and decouples it from the live trackers (the adapter that
/// fills this from `RiskTracker`/`SloEngine`/counters is layer 2).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TelemetrySnapshot {
    pub window_minutes: u32,
    /// Total requests in the window. `None` when no windowed request
    /// counter is available — omitted from the prompt so the model
    /// doesn't misread a placeholder `0` as a total outage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_requests: Option<u64>,
    pub blocked: u64,
    pub top_attackers: Vec<AttackerRow>,
    /// detector class → hit count, highest first.
    pub top_detectors: Vec<(String, u64)>,
    /// e.g. "DataPlaneAvailability (Page, 977x over 1h)".
    pub active_slo_alerts: Vec<String>,
}

/// The advisory brief returned to the operator. Carries the prose AND
/// the snapshot it was derived from, so the UI shows the numbers beside
/// the LLM's words (operators verify, don't trust blind).
#[derive(Clone, Debug, serde::Serialize)]
pub struct Brief {
    pub text: String,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub snapshot: TelemetrySnapshot,
}

const SYSTEM: &str = "You are a security-operations copilot for a Web \
Application Firewall. Given a JSON snapshot of the last N minutes of the \
WAF's own telemetry, write a short situational brief for an on-call \
operator: one headline line, then 2-5 bullet findings that cite the \
numbers from the snapshot, then one suggested next action. Only use data \
present in the snapshot — never invent IPs, counts, or events. Be concise \
and plain-language.";

/// Default output-token ceiling for a summary (also feeds the budget
/// estimate). Briefs are short by design.
const MAX_OUTPUT_TOKENS: u32 = 512;

/// Build the (un-redacted) prompt from a snapshot. Pure.
pub fn render_prompt(snap: &TelemetrySnapshot) -> LlmRequest {
    let json = serde_json::to_string_pretty(snap).unwrap_or_else(|_| "{}".to_string());
    LlmRequest {
        system: Some(SYSTEM.to_string()),
        prompt: format!(
            "Telemetry snapshot (last {} minutes):\n{json}",
            snap.window_minutes
        ),
        max_tokens: MAX_OUTPUT_TOKENS,
    }
}

/// Rough pre-call token estimate (~4 chars/token) for the cost guard,
/// plus the output ceiling. Deliberately conservative so the budget
/// reserves enough before the real usage comes back.
fn estimate_tokens(req: &LlmRequest) -> u64 {
    let chars = req.system.as_deref().map(str::len).unwrap_or(0) + req.prompt.len();
    (chars / 4) as u64 + req.max_tokens as u64
}

const ASK_SYSTEM: &str = "You are a security-operations copilot for a Web \
Application Firewall. Answer the operator's question using ONLY the JSON \
telemetry snapshot provided. Cite the numbers from the snapshot. If the \
snapshot doesn't contain enough to answer, say so plainly rather than \
guessing. Be concise.";

/// Build the (un-redacted) prompt for a free-form operator question over
/// the snapshot. Pure.
pub fn render_ask_prompt(snap: &TelemetrySnapshot, question: &str) -> LlmRequest {
    let json = serde_json::to_string_pretty(snap).unwrap_or_else(|_| "{}".to_string());
    LlmRequest {
        system: Some(ASK_SYSTEM.to_string()),
        prompt: format!(
            "Operator question: {question}\n\nTelemetry snapshot (last {} minutes):\n{json}",
            snap.window_minutes
        ),
        max_tokens: MAX_OUTPUT_TOKENS,
    }
}

/// Shared pipeline: **redact_for_egress** → `CostGuard::try_admit` →
/// `provider.complete` → `CostGuard::record_usage` → `Brief`. Both
/// [`summarize`] and [`ask`] go through here, so the egress gate +
/// budget can never be bypassed.
/// Lowest-level guarded call: **redact** → `try_admit` → `complete` →
/// `record_usage`. Returns the raw [`LlmResponse`] so callers can wrap
/// it (a `Brief`) or parse it (triage suggestions). Shared so the egress
/// gate + budget can never be bypassed. `pub(crate)` for the triage
/// module.
pub(crate) async fn complete_guarded(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    mut req: LlmRequest,
) -> Result<LlmResponse, LlmError> {
    // MANDATORY egress gate — scrub before anything leaves the process.
    req.prompt = redact_for_egress(&req.prompt);
    let estimate = estimate_tokens(&req);
    guard.try_admit(estimate)?;
    let resp = provider.complete(req).await?;
    let actual = (resp.input_tokens + resp.output_tokens) as u64;
    guard.record_usage(estimate, actual);
    Ok(resp)
}

async fn run(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    req: LlmRequest,
    snapshot: TelemetrySnapshot,
) -> Result<Brief, LlmError> {
    let resp = complete_guarded(provider, guard, req).await?;
    Ok(Brief {
        text: resp.text,
        model: provider.id().to_string(),
        input_tokens: resp.input_tokens,
        output_tokens: resp.output_tokens,
        snapshot,
    })
}

/// Produce an advisory situational brief from a snapshot.
///
/// Errors (`Disabled`, `BudgetExceeded`, `RateLimited`, `Provider`)
/// surface to the caller; nothing is acted on automatically.
pub async fn summarize(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    snapshot: TelemetrySnapshot,
) -> Result<Brief, LlmError> {
    run(provider, guard, render_prompt(&snapshot), snapshot).await
}

/// Answer a free-form operator question grounded in the snapshot. Same
/// redaction + budget guarantees as [`summarize`] (the question is
/// operator input, so it's redacted too before egress).
pub async fn ask(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    snapshot: TelemetrySnapshot,
    question: &str,
) -> Result<Brief, LlmError> {
    run(provider, guard, render_ask_prompt(&snapshot, question), snapshot).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copilot::MockProvider;
    use std::sync::Mutex;
    use std::time::Duration;

    fn snap() -> TelemetrySnapshot {
        TelemetrySnapshot {
            window_minutes: 15,
            total_requests: Some(9600),
            blocked: 412,
            top_attackers: vec![AttackerRow {
                ip: "203.0.113.10".into(),
                score: 100,
                level: "blocked".into(),
            }],
            top_detectors: vec![("sqli".into(), 300), ("xss".into(), 90)],
            active_slo_alerts: vec!["DataPlaneAvailability (Page, 977x over 1h)".into()],
        }
    }

    fn guard() -> CostGuard {
        CostGuard::new(1_000_000, 1000, Duration::from_secs(3600))
    }

    #[test]
    fn render_prompt_embeds_window_and_snapshot() {
        let req = render_prompt(&snap());
        assert!(req.system.is_some());
        assert!(req.prompt.contains("last 15 minutes"), "got: {}", req.prompt);
        assert!(req.prompt.contains("203.0.113.10"), "snapshot not in prompt");
        assert!(req.prompt.contains("sqli"), "detectors not in prompt");
        assert_eq!(req.max_tokens, MAX_OUTPUT_TOKENS);
    }

    #[tokio::test]
    async fn summarize_returns_brief_and_records_usage() {
        let p = MockProvider {
            canned: "Elevated SQLi probing; 412 blocks. Watch 203.0.113.10.".into(),
            last_prompt: Mutex::new(None),
        };
        let g = guard();
        let brief = summarize(&p, &g, snap()).await.unwrap();
        assert!(brief.text.contains("SQLi"));
        assert_eq!(brief.model, "mock");
        assert_eq!(brief.input_tokens + brief.output_tokens, 30); // mock: 10+20
        assert_eq!(g.tokens_used(), 30, "guard trued up to actual usage");
        // snapshot echoed for operator verification.
        assert_eq!(brief.snapshot.blocked, 412);
    }

    #[tokio::test]
    async fn summarize_applies_redaction_gate_before_provider() {
        let p = MockProvider {
            canned: "ok".into(),
            last_prompt: Mutex::new(None),
        };
        let mut s = snap();
        // PII sneaking in via a free-text SLO label must be scrubbed.
        s.active_slo_alerts
            .push("login abuse from alice@example.com".into());
        let _ = summarize(&p, &guard(), s).await.unwrap();
        let seen = p.last_prompt.lock().unwrap().clone().unwrap();
        assert!(
            !seen.contains("alice@example.com"),
            "provider saw un-redacted PII: {seen}"
        );
    }

    #[tokio::test]
    async fn ask_includes_question_and_redacts_it() {
        let p = MockProvider {
            canned: "Yes — 412 blocks.".into(),
            last_prompt: Mutex::new(None),
        };
        // Operator question carries PII that must be scrubbed before egress.
        let brief = ask(&p, &guard(), snap(), "is bob@evil.com attacking?")
            .await
            .unwrap();
        assert_eq!(brief.text, "Yes — 412 blocks.");
        let seen = p.last_prompt.lock().unwrap().clone().unwrap();
        assert!(seen.contains("Operator question:"), "question not in prompt: {seen}");
        assert!(!seen.contains("bob@evil.com"), "question PII not redacted: {seen}");
    }

    #[tokio::test]
    async fn summarize_respects_cost_budget() {
        let p = MockProvider {
            canned: "ok".into(),
            last_prompt: Mutex::new(None),
        };
        // Budget far below the prompt estimate → rejected before the call.
        let tiny = CostGuard::new(1, 1000, Duration::from_secs(3600));
        let err = summarize(&p, &tiny, snap()).await.unwrap_err();
        assert!(matches!(err, LlmError::BudgetExceeded { .. }), "got: {err:?}");
        assert!(
            p.last_prompt.lock().unwrap().is_none(),
            "provider must not be called when over budget"
        );
    }
}
