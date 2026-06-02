//! AI Operator Copilot — Phase 0 foundation.
//!
//! A generative-LLM layer that reads the WAF's own telemetry and turns
//! it into plain-language situational summaries + smart-catch triage
//! (plan: `plans/future/ai-operator-copilot.md`). **Advisory only** —
//! nothing here blocks traffic or mutates config; it produces text an
//! operator reads.
//!
//! This module is the **provider-agnostic core**:
//! - [`LlmProvider`] — the trait every backend implements.
//! - [`CostGuard`] — per-window token + request budget (a WAF must not
//!   let an LLM bill run away or hammer an external API).
//! - [`redact_for_egress`] — the **mandatory egress gate**: every byte
//!   that leaves for an LLM passes through `dlp::redact` first, because
//!   WAF telemetry carries URIs / headers / payloads (PII, secrets).
//!
//! The concrete Anthropic adapter lives in [`anthropic`] behind the
//! `llm` Cargo feature (it pulls `reqwest`). Tests use [`MockProvider`].

#[cfg(feature = "llm")]
pub mod anthropic;
#[cfg(feature = "llm")]
pub mod openai;
pub mod service;
pub mod summary;
pub mod triage;

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A request to an LLM provider. `prompt` (and `system`) MUST already
/// have been through [`redact_for_egress`] by the caller — providers
/// don't redact, they send.
#[derive(Clone, Debug)]
pub struct LlmRequest {
    pub system: Option<String>,
    pub prompt: String,
    /// Hard cap on output tokens (also feeds the [`CostGuard`] estimate).
    pub max_tokens: u32,
}

/// A provider's completion plus token accounting for the [`CostGuard`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmResponse {
    pub text: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Why a copilot call didn't produce a completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LlmError {
    /// Feature/endpoint not configured — the copilot is off.
    Disabled,
    /// The per-window token budget would be exceeded.
    BudgetExceeded { used: u64, limit: u64 },
    /// The per-window request rate would be exceeded.
    RateLimited { limit: u32 },
    /// The provider/transport failed (network, auth, 5xx, parse).
    Provider(String),
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Disabled => write!(f, "copilot is disabled (no provider configured)"),
            LlmError::BudgetExceeded { used, limit } => {
                write!(f, "LLM token budget exceeded: {used}/{limit} this window")
            }
            LlmError::RateLimited { limit } => {
                write!(f, "LLM request rate limit reached ({limit}/window)")
            }
            LlmError::Provider(m) => write!(f, "LLM provider error: {m}"),
        }
    }
}

impl std::error::Error for LlmError {}

/// A pluggable LLM backend. Implementors send a (pre-redacted) prompt
/// and return a completion. Advisory only — callers never act on the
/// output without an operator in the loop.
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, LlmError>;
    /// Short identifier for logs/audit (e.g. `anthropic:claude-...`).
    fn id(&self) -> &str;
}

/// **Mandatory egress gate.** Scrub PII / secrets out of any text
/// before it leaves the process for an external LLM. Reuses the WAF's
/// own `dlp::redact` (cards, SSN, IBAN, emails, AWS/GitHub/Stripe/Slack
/// tokens). Callers build prompts from telemetry, then pass the whole
/// thing through here — providers receive only redacted text.
pub fn redact_for_egress(text: &str) -> String {
    aegis_security::dlp::redact(text)
}

/// Per-window token + request budget for LLM calls. A WAF emitting a
/// lot of telemetry must not turn into a runaway external-API bill or
/// hammer the provider, so every call is admitted through here first.
///
/// `try_admit` reserves against an *estimate* (input estimate +
/// `max_tokens`); `record_usage` trues up with the actual count once
/// the provider responds.
pub struct CostGuard {
    inner: Mutex<GuardState>,
    max_tokens_per_window: u64,
    max_requests_per_window: u32,
    window: Duration,
}

struct GuardState {
    window_start: Instant,
    tokens_used: u64,
    requests: u32,
}

impl CostGuard {
    pub fn new(max_tokens_per_window: u64, max_requests_per_window: u32, window: Duration) -> Self {
        Self {
            inner: Mutex::new(GuardState {
                window_start: Instant::now(),
                tokens_used: 0,
                requests: 0,
            }),
            max_tokens_per_window,
            max_requests_per_window,
            window,
        }
    }

    /// Admit a call estimated to cost `estimated_tokens`. Rolls the
    /// window when it has elapsed. Returns the budget/rate error
    /// without reserving when the call wouldn't fit.
    pub fn try_admit(&self, estimated_tokens: u64) -> Result<(), LlmError> {
        let mut s = self.inner.lock().unwrap();
        if s.window_start.elapsed() >= self.window {
            s.window_start = Instant::now();
            s.tokens_used = 0;
            s.requests = 0;
        }
        if s.requests + 1 > self.max_requests_per_window {
            return Err(LlmError::RateLimited {
                limit: self.max_requests_per_window,
            });
        }
        if s.tokens_used + estimated_tokens > self.max_tokens_per_window {
            return Err(LlmError::BudgetExceeded {
                used: s.tokens_used,
                limit: self.max_tokens_per_window,
            });
        }
        s.requests += 1;
        s.tokens_used += estimated_tokens;
        Ok(())
    }

    /// True up the window's token tally with the provider's reported
    /// usage (replaces the estimate added at admit time for this call).
    pub fn record_usage(&self, estimated_tokens: u64, actual_tokens: u64) {
        let mut s = self.inner.lock().unwrap();
        // Remove the estimate, add the actual — saturating so a wild
        // estimate can't underflow the tally.
        s.tokens_used = s.tokens_used.saturating_sub(estimated_tokens) + actual_tokens;
    }

    pub fn tokens_used(&self) -> u64 {
        self.inner.lock().unwrap().tokens_used
    }
}

#[cfg(test)]
pub(crate) struct MockProvider {
    pub canned: String,
    /// Records the last prompt the provider was asked to send — tests
    /// assert the egress gate redacted it BEFORE it reached here.
    pub last_prompt: Mutex<Option<String>>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl LlmProvider for MockProvider {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, LlmError> {
        *self.last_prompt.lock().unwrap() = Some(req.prompt.clone());
        Ok(LlmResponse {
            text: self.canned.clone(),
            input_tokens: 10,
            output_tokens: 20,
        })
    }
    fn id(&self) -> &str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_gate_scrubs_pii_before_egress() {
        let raw = "user alice@example.com hit /pay with card 4111111111111111";
        let safe = redact_for_egress(raw);
        assert!(!safe.contains("alice@example.com"), "email leaked: {safe}");
        assert!(!safe.contains("4111111111111111"), "PAN leaked: {safe}");
    }

    #[test]
    fn cost_guard_blocks_over_token_budget() {
        let g = CostGuard::new(100, 100, Duration::from_secs(3600));
        assert!(g.try_admit(60).is_ok());
        // 60 + 60 > 100 → budget exceeded, not reserved.
        assert!(matches!(g.try_admit(60), Err(LlmError::BudgetExceeded { .. })));
        assert_eq!(g.tokens_used(), 60, "rejected call must not reserve");
        // A smaller call still fits.
        assert!(g.try_admit(30).is_ok());
        assert_eq!(g.tokens_used(), 90);
    }

    #[test]
    fn cost_guard_blocks_over_request_rate() {
        let g = CostGuard::new(1_000_000, 2, Duration::from_secs(3600));
        assert!(g.try_admit(1).is_ok());
        assert!(g.try_admit(1).is_ok());
        assert!(matches!(g.try_admit(1), Err(LlmError::RateLimited { limit: 2 })));
    }

    #[test]
    fn cost_guard_record_usage_trues_up_estimate() {
        let g = CostGuard::new(1000, 100, Duration::from_secs(3600));
        g.try_admit(200).unwrap(); // reserved estimate
        g.record_usage(200, 50); // actual was much less
        assert_eq!(g.tokens_used(), 50);
    }

    #[tokio::test]
    async fn mock_provider_receives_already_redacted_prompt() {
        let p = MockProvider {
            canned: "all quiet".into(),
            last_prompt: Mutex::new(None),
        };
        // Caller redacts BEFORE handing to the provider.
        let prompt = redact_for_egress("spike from bob@evil.com on /login");
        let resp = p
            .complete(LlmRequest {
                system: None,
                prompt: prompt.clone(),
                max_tokens: 256,
            })
            .await
            .unwrap();
        assert_eq!(resp.text, "all quiet");
        let seen = p.last_prompt.lock().unwrap().clone().unwrap();
        assert!(!seen.contains("bob@evil.com"), "provider saw un-redacted PII: {seen}");
    }
}
