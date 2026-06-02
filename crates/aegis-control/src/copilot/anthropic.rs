//! Anthropic Claude adapter for the operator copilot (Phase 0).
//!
//! Implements [`LlmProvider`](super::LlmProvider) against the Claude
//! **Messages API** (`POST /v1/messages`). Gated by the `llm` Cargo
//! feature (pulls `reqwest`). The API key comes from the operator's
//! secret resolver / env — never hard-coded.
//!
//! Scope: a single non-streaming completion. Streaming, prompt caching,
//! and tool use are later phases. Callers MUST pre-redact the prompt via
//! [`super::redact_for_egress`] — this adapter sends what it's given.

use std::time::Duration;

use super::{LlmError, LlmProvider, LlmRequest, LlmResponse};

/// Default model — Haiku is the cost/latency sweet spot for the
/// frequent, bounded summary calls the copilot makes. Override per
/// deploy if a deeper model is wanted for triage.
pub const DEFAULT_MODEL: &str = "claude-haiku-4-5-20251001";

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    api_key: String,
    model: String,
    id: String,
    http: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        let model = model.into();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| LlmError::Provider(format!("building HTTP client: {e}")))?;
        Ok(Self {
            api_key: api_key.into(),
            id: format!("anthropic:{model}"),
            model,
            http,
        })
    }

    /// Build from the `ANTHROPIC_API_KEY` env var (operators wire this
    /// from their secret manager). Returns [`LlmError::Disabled`] when
    /// unset so the copilot degrades to off rather than erroring.
    pub fn from_env(model: impl Into<String>) -> Result<Self, LlmError> {
        let key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| LlmError::Disabled)?;
        if key.trim().is_empty() {
            return Err(LlmError::Disabled);
        }
        Self::new(key, model)
    }
}

#[derive(serde::Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
    messages: Vec<Message<'a>>,
}

#[derive(serde::Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(serde::Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    usage: Usage,
}

#[derive(serde::Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
}

#[derive(serde::Deserialize, Default)]
struct Usage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, LlmError> {
        let body = MessagesRequest {
            model: &self.model,
            max_tokens: req.max_tokens,
            system: req.system.as_deref(),
            messages: vec![Message {
                role: "user",
                content: &req.prompt,
            }],
        };

        let resp = self
            .http
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Provider(format!("transport: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            // Don't echo the whole body (may be large); cap it.
            let detail: String = detail.chars().take(300).collect();
            return Err(LlmError::Provider(format!("HTTP {status}: {detail}")));
        }

        let parsed: MessagesResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::Provider(format!("decoding response: {e}")))?;

        let text = parsed
            .content
            .into_iter()
            .filter(|b| b.kind == "text")
            .map(|b| b.text)
            .collect::<Vec<_>>()
            .join("");

        Ok(LlmResponse {
            text,
            input_tokens: parsed.usage.input_tokens,
            output_tokens: parsed.usage.output_tokens,
        })
    }

    fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_is_disabled_without_key() {
        // Ensure the var is unset for this assertion.
        std::env::remove_var("ANTHROPIC_API_KEY");
        assert!(matches!(
            AnthropicProvider::from_env(DEFAULT_MODEL),
            Err(LlmError::Disabled)
        ));
    }

    #[test]
    fn new_sets_provider_id_from_model() {
        let p = AnthropicProvider::new("sk-test", "claude-x").unwrap();
        assert_eq!(p.id(), "anthropic:claude-x");
    }
}
