//! `pp-upstream` — provider abstraction and the capability-aware failover
//! router over OpenRouter's free models (`ARCHITECTURE.md` §12).
//!
//! `RouterConfig`/`candidates` are pure and unit-testable. `OpenRouterProvider`
//! performs the real async HTTP with failover across the configured models.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use serde_json::Value;

/// One configured upstream model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelEntry {
    /// OpenRouter model id, e.g. `nvidia/nemotron-3-ultra-550b-a55b:free`.
    pub id: String,
    /// Preference rank — **lower is tried first** (1 = primary).
    pub priority: u8,
    /// Whether this model reliably supports tool/function calling.
    pub tools: bool,
    /// Context window in tokens.
    pub context: u32,
}

/// Ordered model preferences for the failover router.
#[derive(Clone, Debug, Default)]
pub struct RouterConfig {
    pub models: Vec<ModelEntry>,
}

impl RouterConfig {
    /// Candidates for a request: filtered by capability (tool-calling requests
    /// only route to `tools == true` models), then ordered by preference.
    pub fn candidates(&self, needs_tools: bool) -> Vec<&ModelEntry> {
        let mut c: Vec<&ModelEntry> = self
            .models
            .iter()
            .filter(|m| !needs_tools || m.tools)
            .collect();
        c.sort_by_key(|m| m.priority);
        c
    }
}

/// Errors from talking to an upstream provider.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("no candidate models for this request")]
    NoCandidates,
    #[error("all upstream models failed (last status: {0:?})")]
    AllFailed(Option<u16>),
    #[error("upstream returned status {0}: {1}")]
    Upstream(u16, String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("could not decode upstream response: {0}")]
    Decode(String),
}

/// An upstream LLM provider. Receives an already-sanitized request body.
#[async_trait]
pub trait Provider: Send + Sync {
    /// `needs_tools` lets the router restrict candidates to tool-capable models.
    async fn chat(&self, body: &Value, needs_tools: bool) -> Result<Value, ProviderError>;
}

/// Talks to OpenRouter's OpenAI-compatible endpoint, with capability-aware
/// failover across the configured free models (retries the next model on
/// 429 / 5xx / transport errors; returns 4xx bodies straight through).
pub struct OpenRouterProvider {
    http: reqwest::Client,
    api_key: String,
    config: RouterConfig,
    endpoint: String,
}

impl OpenRouterProvider {
    pub fn new(api_key: String, config: RouterConfig) -> Self {
        // A per-request timeout is essential: without it a hung/slow free
        // model would stall the whole request instead of failing over.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            api_key,
            config,
            endpoint: "https://openrouter.ai/api/v1/chat/completions".to_string(),
        }
    }
}

#[async_trait]
impl Provider for OpenRouterProvider {
    async fn chat(&self, body: &Value, needs_tools: bool) -> Result<Value, ProviderError> {
        let candidates = self.config.candidates(needs_tools);
        if candidates.is_empty() {
            return Err(ProviderError::NoCandidates);
        }

        let mut last: Option<ProviderError> = None;
        for model in candidates {
            // Route to this candidate by overriding the (advisory) model field.
            let mut payload = body.clone();
            if let Value::Object(map) = &mut payload {
                map.insert("model".into(), Value::String(model.id.clone()));
            }

            let sent = self
                .http
                .post(&self.endpoint)
                .bearer_auth(&self.api_key)
                .json(&payload)
                .send()
                .await;

            match sent {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp
                            .json::<Value>()
                            .await
                            .map_err(|e| ProviderError::Decode(e.to_string()));
                    }
                    let code = status.as_u16();
                    if code == 429 || status.is_server_error() {
                        last = Some(ProviderError::AllFailed(Some(code))); // retryable
                        continue;
                    }
                    // Non-retryable client error — surface it directly.
                    let detail = resp.text().await.unwrap_or_default();
                    return Err(ProviderError::Upstream(code, detail));
                }
                Err(e) => {
                    last = Some(ProviderError::Transport(e.to_string()));
                    continue;
                }
            }
        }
        Err(last.unwrap_or(ProviderError::AllFailed(None)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, priority: u8, tools: bool) -> ModelEntry {
        ModelEntry {
            id: id.into(),
            priority,
            tools,
            context: 0,
        }
    }

    #[test]
    fn tool_requests_skip_non_tool_models() {
        let cfg = RouterConfig {
            models: vec![m("a", 2, false), m("b", 1, true), m("c", 3, true)],
        };
        let ids: Vec<_> = cfg.candidates(true).iter().map(|m| m.id.clone()).collect();
        assert_eq!(ids, vec!["b", "c"]); // "a" filtered out, rest ordered by priority
    }

    #[test]
    fn non_tool_requests_keep_all_ordered() {
        let cfg = RouterConfig {
            models: vec![m("a", 2, false), m("b", 1, true)],
        };
        let ids: Vec<_> = cfg.candidates(false).iter().map(|m| m.id.clone()).collect();
        assert_eq!(ids, vec!["b", "a"]);
    }
}
