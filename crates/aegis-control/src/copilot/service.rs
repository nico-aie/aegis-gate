//! Process-wide copilot service (Copilot P1).
//!
//! Holds the configured [`LlmProvider`] + the [`CostGuard`], and exposes
//! [`CopilotService::summary`]. The live service sits behind an
//! [`ArcSwap`] global ([`global`]) so the config plane can hot-swap it
//! ([`set_global`]) when `observability.copilot` changes — same
//! live-swap pattern as the route table / detector mask. It is built
//! from [`aegis_core::config::CopilotConfig`] at boot
//! ([`CopilotService::from_config`], key resolved by the caller via the
//! secrets resolver); [`CopilotService::from_env`] remains as a
//! back-compat fallback for pure `LLM_*` env deployments.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwap;

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

    /// Build from `observability.copilot` config. The API key is **not**
    /// read here — the caller resolves the `api_key_ref` secret (env /
    /// file / vault / cloud) and passes it in, keeping the secrets
    /// resolver (aegis-proxy) out of this crate. Returns a disabled
    /// service when `cfg.enabled` is false, the key/model/base_url are
    /// missing, or the `llm` feature is off.
    pub fn from_config(cfg: &aegis_core::config::CopilotConfig, api_key: Option<String>) -> Self {
        Self {
            provider: build_provider_from_config(cfg, api_key),
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

/// Build a provider from `observability.copilot`. The key is already
/// resolved by the caller (secrets resolver). Disabled when the master
/// switch is off, the key/model (and base_url for OpenAI) are missing,
/// or the client fails to build.
#[cfg(feature = "llm")]
fn build_provider_from_config(
    cfg: &aegis_core::config::CopilotConfig,
    api_key: Option<String>,
) -> Option<Box<dyn LlmProvider>> {
    use aegis_core::config::CopilotProvider;

    if !cfg.enabled {
        return None;
    }
    let api_key = api_key.filter(|k| !k.trim().is_empty())?;
    let model = cfg.model.clone().filter(|m| !m.trim().is_empty())?;

    match cfg.provider {
        CopilotProvider::OpenAiCompatible => {
            let base_url = cfg.base_url.clone().filter(|b| !b.trim().is_empty())?;
            let timeout = Duration::from_millis(cfg.timeout_ms);
            super::openai::OpenAiProvider::new(&base_url, api_key, model, timeout)
                .ok()
                .map(|p| Box::new(p) as Box<dyn LlmProvider>)
        }
        CopilotProvider::Anthropic => super::anthropic::AnthropicProvider::new(api_key, model)
            .ok()
            .map(|p| Box::new(p) as Box<dyn LlmProvider>),
    }
}

#[cfg(not(feature = "llm"))]
fn build_provider_from_config(
    _cfg: &aegis_core::config::CopilotConfig,
    _api_key: Option<String>,
) -> Option<Box<dyn LlmProvider>> {
    None
}

static COPILOT: OnceLock<ArcSwap<CopilotService>> = OnceLock::new();

/// The `ArcSwap` cell, lazily initialised from env so pure-`LLM_*`
/// deployments (and tests) keep working before boot wiring runs.
fn cell() -> &'static ArcSwap<CopilotService> {
    COPILOT.get_or_init(|| ArcSwap::from_pointee(CopilotService::from_env()))
}

/// The live process copilot service. Returns a cheap `Arc` clone (safe
/// to hold across `.await`, unlike a borrow into the swap cell).
pub fn global() -> Arc<CopilotService> {
    cell().load_full()
}

/// Replace the live copilot service. Called once at boot with the
/// config-built service, and again on every config-plane apply that
/// touches `observability.copilot`.
pub fn set_global(svc: CopilotService) {
    cell().store(Arc::new(svc));
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

    #[test]
    fn from_config_disabled_when_master_switch_off() {
        let mut cfg = aegis_core::config::CopilotConfig::default();
        cfg.enabled = false; // explicit
        cfg.base_url = Some("https://host/v1".into());
        cfg.model = Some("m".into());
        let svc = CopilotService::from_config(&cfg, Some("sk-key".into()));
        assert!(!svc.enabled());
    }

    #[test]
    fn from_config_disabled_when_key_missing() {
        let cfg = aegis_core::config::CopilotConfig {
            enabled: true,
            base_url: Some("https://host/v1".into()),
            model: Some("m".into()),
            ..Default::default()
        };
        // No resolved key (api_key_ref unresolved / unset) → disabled.
        assert!(!CopilotService::from_config(&cfg, None).enabled());
        assert!(!CopilotService::from_config(&cfg, Some("   ".into())).enabled());
    }

    #[cfg(feature = "llm")]
    #[test]
    fn from_config_enabled_with_full_openai_block() {
        let cfg = aegis_core::config::CopilotConfig {
            enabled: true,
            provider: aegis_core::config::CopilotProvider::OpenAiCompatible,
            base_url: Some("https://host/v1".into()),
            model: Some("Qwen3.6-35B-A3B".into()),
            timeout_ms: 4000,
            ..Default::default()
        };
        let svc = CopilotService::from_config(&cfg, Some("sk-resolved".into()));
        assert!(svc.enabled());
    }

    #[cfg(feature = "llm")]
    #[test]
    fn from_config_openai_needs_base_url() {
        let cfg = aegis_core::config::CopilotConfig {
            enabled: true,
            model: Some("m".into()),
            base_url: None, // missing → disabled even with a key
            ..Default::default()
        };
        assert!(!CopilotService::from_config(&cfg, Some("sk".into())).enabled());
    }

    #[test]
    fn set_global_swaps_the_live_service() {
        // Swap in a disabled service, observe it through global().
        set_global(CopilotService {
            provider: None,
            guard: CostGuard::new(1, 1, WINDOW),
        });
        assert!(!global().enabled());
    }
}
