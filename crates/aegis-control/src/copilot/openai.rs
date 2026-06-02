//! OpenAI-compatible LLM adapter (Copilot Phase 0, default provider).
//!
//! Targets any OpenAI-compatible `/v1/chat/completions` endpoint — vLLM,
//! Ollama, LiteLLM, OpenAI itself, etc. Gated by the `llm` Cargo feature
//! (pulls `reqwest`). Config comes from `LLM_*` environment variables
//! (operators wire these from their secret manager); the key is never
//! hard-coded or persisted.
//!
//! ```text
//! LLM_ENABLED=true
//! LLM_BASE_URL=https://host/v1          # /chat/completions is appended
//! LLM_API_KEY=sk-...                    # Authorization: Bearer
//! LLM_MODEL=Qwen3.6-35B-A3B
//! LLM_TIMEOUT_MS=4000
//! ```
//!
//! Callers MUST pre-redact via [`super::redact_for_egress`] — this
//! adapter sends what it's given.

use std::time::Duration;

use super::{LlmError, LlmProvider, LlmRequest, LlmResponse};

const DEFAULT_TIMEOUT_MS: u64 = 4_000;

pub struct OpenAiProvider {
    url: String,
    api_key: String,
    model: String,
    id: String,
    http: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(
        base_url: &str,
        api_key: impl Into<String>,
        model: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, LlmError> {
        let model = model.into();
        // `base_url` is the `/v1` root; the chat endpoint hangs off it.
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| LlmError::Provider(format!("building HTTP client: {e}")))?;
        Ok(Self {
            url,
            api_key: api_key.into(),
            id: format!("openai:{model}"),
            model,
            http,
        })
    }

    /// Build from the `LLM_*` environment variables. Returns
    /// [`LlmError::Disabled`] when `LLM_ENABLED` isn't `true` or the
    /// base URL / key / model are missing — so the copilot degrades to
    /// off rather than erroring at boot.
    pub fn from_env() -> Result<Self, LlmError> {
        let enabled = std::env::var("LLM_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        if !enabled {
            return Err(LlmError::Disabled);
        }
        let base_url = non_empty_env("LLM_BASE_URL").ok_or(LlmError::Disabled)?;
        let api_key = non_empty_env("LLM_API_KEY").ok_or(LlmError::Disabled)?;
        let model = non_empty_env("LLM_MODEL").ok_or(LlmError::Disabled)?;
        let timeout = Duration::from_millis(
            std::env::var("LLM_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(DEFAULT_TIMEOUT_MS),
        );
        Self::new(&base_url, api_key, model, timeout)
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

#[derive(serde::Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<ChatMessage<'a>>,
}

#[derive(serde::Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(serde::Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Usage,
}

#[derive(serde::Deserialize)]
struct Choice {
    #[serde(default)]
    message: ChoiceMessage,
}

#[derive(serde::Deserialize, Default)]
struct ChoiceMessage {
    #[serde(default)]
    content: String,
}

#[derive(serde::Deserialize, Default)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

#[async_trait::async_trait]
impl LlmProvider for OpenAiProvider {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, LlmError> {
        let mut messages = Vec::with_capacity(2);
        if let Some(sys) = req.system.as_deref() {
            messages.push(ChatMessage {
                role: "system",
                content: sys,
            });
        }
        messages.push(ChatMessage {
            role: "user",
            content: &req.prompt,
        });

        let body = ChatRequest {
            model: &self.model,
            max_tokens: req.max_tokens,
            messages,
        };

        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Provider(format!("transport: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let detail: String = resp.text().await.unwrap_or_default().chars().take(300).collect();
            return Err(LlmError::Provider(format!("HTTP {status}: {detail}")));
        }

        let parsed: ChatResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::Provider(format!("decoding response: {e}")))?;

        let text = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default();

        Ok(LlmResponse {
            text,
            input_tokens: parsed.usage.prompt_tokens,
            output_tokens: parsed.usage.completion_tokens,
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
    fn from_env_disabled_when_flag_off() {
        std::env::remove_var("LLM_ENABLED");
        assert!(matches!(OpenAiProvider::from_env(), Err(LlmError::Disabled)));
    }

    #[test]
    fn new_builds_chat_url_and_id() {
        let p = OpenAiProvider::new(
            "https://host/v1/",
            "sk-x",
            "Qwen3.6-35B-A3B",
            Duration::from_millis(4000),
        )
        .unwrap();
        assert_eq!(p.url, "https://host/v1/chat/completions");
        assert_eq!(p.id(), "openai:Qwen3.6-35B-A3B");
    }
}
