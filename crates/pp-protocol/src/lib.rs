//! `pp-protocol` — OpenAI-compatible wire types.
//!
//! Only the fields the gateway reasons about are typed; everything else
//! (`temperature`, `tools`, `max_tokens`, `tool_calls`, …) is preserved
//! verbatim via `extra`, so the gateway stays a transparent proxy and is
//! forward-compatible with fields it doesn't model. The normalisation target
//! is OpenAI Chat Completions (`ARCHITECTURE.md` §6, §19).
//!
//! Limitation: `content` is modelled as an optional string. Array/multimodal
//! content isn't anonymised yet and is a documented follow-up.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Wire dialects the gateway can speak to clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// The default normalisation target; OpenRouter is compatible with it.
    OpenAiChatCompletions,
}

/// A chat-completions request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// All other request fields (tools, temperature, …), preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ChatRequest {
    /// Whether this request carries tool/function definitions — used to gate
    /// failover to tool-capable models.
    pub fn has_tools(&self) -> bool {
        self.extra.contains_key("tools")
    }
}

/// One chat message. `content` is the text surface the gateway anonymises;
/// `tool_calls` / `name` / `tool_call_id` and the rest pass through via `extra`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
