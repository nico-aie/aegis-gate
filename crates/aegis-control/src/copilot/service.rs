//! Process-wide copilot service (Copilot P1).
//!
//! Holds the configured [`LlmProvider`] (built from env once at first
//! use) + the [`CostGuard`], and exposes [`CopilotService::summary`].
//! A `OnceLock` global ([`global`]) lets the sync/async admin handlers
//! reach it without threading a new field through `DashboardServices`
//! and every test fixture — same pattern as the OTel provider /
//! alert-identity globals.

use std::sync::OnceLock;
use std::time::Duration;

use super::summary::{self, summarize, Brief, TelemetrySnapshot};
use super::{CostGuard, LlmError, LlmProvider};

/// Default per-window budget. Conservative so an idle copilot can't
/// surprise an operator with an LLM bill; tune later via config.
const MAX_TOKENS_PER_WINDOW: u64 = 200_000;
const MAX_REQUESTS_PER_WINDOW: u32 = 60;
const WINDOW: Duration = Duration::from_secs(3600);

pub struct CopilotService {
    provider: Option<Box<dyn LlmProvider>>,
    guard: CostGuard,
}

impl CopilotService {
    /// Build from environment. The provider is constructed from `LLM_*`
    /// (OpenAI-compatible, preferred) or `ANTHROPIC_API_KEY`; `None`
    /// when neither is configured or the `llm` feature is off, in which
    /// case the copilot is simply disabled.
    pub fn from_env() -> Self {
        Self {
            provider: build_provider_from_env(),
            guard: CostGuard::new(MAX_TOKENS_PER_WINDOW, MAX_REQUESTS_PER_WINDOW, WINDOW),
        }
    }

    pub fn enabled(&self) -> bool {
        self.provider.is_some()
    }

    /// Produce an advisory brief from a snapshot. `Err(Disabled)` when
    /// no provider is configured.
    pub async fn summary(&self, snapshot: TelemetrySnapshot) -> Result<Brief, LlmError> {
        match self.provider.as_deref() {
            Some(p) => summarize(p, &self.guard, snapshot).await,
            None => Err(LlmError::Disabled),
        }
    }

    /// Answer a free-form operator question grounded in the snapshot.
    /// `Err(Disabled)` when no provider is configured.
    pub async fn ask(
        &self,
        snapshot: TelemetrySnapshot,
        question: &str,
    ) -> Result<Brief, LlmError> {
        match self.provider.as_deref() {
            Some(p) => summary::ask(p, &self.guard, snapshot, question).await,
            None => Err(LlmError::Disabled),
        }
    }

    /// Smart-catch triage: cluster the snapshot into campaigns + rule
    /// suggestions (advisory). `Err(Disabled)` when no provider.
    pub async fn triage(
        &self,
        snapshot: TelemetrySnapshot,
    ) -> Result<super::triage::TriageResult, LlmError> {
        match self.provider.as_deref() {
            Some(p) => super::triage::triage(p, &self.guard, snapshot).await,
            None => Err(LlmError::Disabled),
        }
    }
}

#[cfg(feature = "llm")]
fn build_provider_from_env() -> Option<Box<dyn LlmProvider>> {
    // Prefer the OpenAI-compatible endpoint (LLM_* env); fall back to
    // Anthropic (ANTHROPIC_API_KEY). Each returns Disabled when unset.
    if let Ok(p) = super::openai::OpenAiProvider::from_env() {
        return Some(Box::new(p));
    }
    if let Ok(p) = super::anthropic::AnthropicProvider::from_env(super::anthropic::DEFAULT_MODEL) {
        return Some(Box::new(p));
    }
    None
}

#[cfg(not(feature = "llm"))]
fn build_provider_from_env() -> Option<Box<dyn LlmProvider>> {
    None
}

static COPILOT: OnceLock<CopilotService> = OnceLock::new();

/// The process copilot service, built from env on first use.
pub fn global() -> &'static CopilotService {
    COPILOT.get_or_init(CopilotService::from_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_service_returns_disabled() {
        // No provider wired (don't touch env / no llm feature).
        let svc = CopilotService {
            provider: None,
            guard: CostGuard::new(1000, 10, WINDOW),
        };
        assert!(!svc.enabled());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let err = rt.block_on(svc.summary(TelemetrySnapshot::default())).unwrap_err();
        assert_eq!(err, LlmError::Disabled);
    }
}
