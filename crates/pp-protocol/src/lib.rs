//! `pp-protocol` — OpenAI-compatible wire types.
//!
//! Only the fields the gateway reasons about are typed; everything else
//! (`temperature`, `tools`, `max_tokens`, `tool_calls`, …) is preserved
//! verbatim via `extra`, so the gateway stays a transparent proxy and is
//! forward-compatible with fields it doesn't model. The normalisation target
//! is OpenAI Chat Completions (`ARCHITECTURE.md` §6, §19).
//!
//! `content` is a string *or* an array of typed parts (OpenAI multimodal). Text
//! parts are anonymised like plain message text; non-text parts (e.g. images)
//! pass through verbatim and remain subject to the egress guard.
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
    /// Requested model. Optional: the gateway routes across its own free-model
    /// preference list and overrides this field, so a client may omit it.
    #[serde(default)]
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
    pub content: Option<Content>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Message content: a plain string, or an array of typed parts (OpenAI
/// multimodal). `#[serde(untagged)]` keeps each variant's original JSON shape
/// on the wire, so the gateway stays a transparent proxy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Content {
    /// The common case: a single text string.
    Text(String),
    /// Multimodal parts, e.g. `[{"type":"text","text":"…"}, {"type":"image_url",…}]`.
    /// Preserved verbatim except for the `text` field of each text part.
    Parts(Vec<Value>),
}

impl Content {
    /// The concatenated human-readable text — the surface fed to recall and the
    /// detection ensemble. For `Parts`, joins the `text` field of each text part.
    pub fn text(&self) -> String {
        match self {
            Content::Text(s) => s.clone(),
            Content::Parts(parts) => {
                let mut out = String::new();
                for part in parts {
                    if let Some(t) = part.get("text").and_then(Value::as_str) {
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        out.push_str(t);
                    }
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn string_content_round_trips() {
        let m: Message =
            serde_json::from_value(json!({"role":"user","content":"hi Falcon"})).unwrap();
        assert_eq!(
            m.content.as_ref().map(Content::text).as_deref(),
            Some("hi Falcon")
        );
        // Serialises back to a bare string (untagged), not an object.
        assert_eq!(
            serde_json::to_value(&m).unwrap()["content"],
            json!("hi Falcon")
        );
    }

    #[test]
    fn array_content_is_accepted_not_rejected() {
        // The bug this guards against: array content must deserialize, not 422.
        let m: Message = serde_json::from_value(json!({
            "role": "user",
            "content": [
                {"type": "text", "text": "describe Falcon"},
                {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
            ]
        }))
        .expect("array content must deserialize");
        assert_eq!(m.content.unwrap().text(), "describe Falcon");
    }

    #[test]
    fn null_content_is_none() {
        let m: Message =
            serde_json::from_value(json!({"role":"assistant","content":null})).unwrap();
        assert!(m.content.is_none());
        // And missing content is also None.
        let m2: Message = serde_json::from_value(json!({"role":"assistant"})).unwrap();
        assert!(m2.content.is_none());
    }

    #[test]
    fn model_is_optional() {
        // The gateway routes across its own model list and overrides `model`, so
        // a client omitting it must deserialize (not 422), defaulting to empty.
        let r: ChatRequest =
            serde_json::from_value(json!({"messages":[{"role":"user","content":"hi"}]})).unwrap();
        assert_eq!(r.model, "");
        assert_eq!(r.messages.len(), 1);
    }
}
