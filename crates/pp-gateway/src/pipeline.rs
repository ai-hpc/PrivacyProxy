//! Request/response transforms for the gateway.
//!
//! Outbound: anonymise message content, assistant tool-call arguments, and the
//! free-text `description` fields of the tools schema (`ARCHITECTURE.md` §4/§7).
//! Inbound: rehydrate buffered responses (blanket walk) and streaming deltas
//! (content + tool-call arguments, split-safe via [`StreamRehydrator`]).

use std::collections::HashMap;

use pp_anonymize::{anonymize, rehydrate, StreamRehydrator};
use pp_core::{Redaction, Vault};
use pp_detect::Ensemble;
use pp_protocol::ChatRequest;
use serde_json::{json, Value};

/// Anonymise `*value` in place, appending any redactions to `audit`.
fn anon_into(
    value: &mut String,
    ensemble: &Ensemble,
    vault: &dyn Vault,
    audit: &mut Vec<Redaction>,
) {
    let result = anonymize(value.as_str(), ensemble, vault);
    *value = result.text;
    audit.extend(result.audit);
}

/// Recursively anonymise the value of any `description` key (free text in tool
/// schemas) at any nesting depth, leaving structural fields — function and
/// parameter *names*, enum values, types — untouched.
fn anonymize_descriptions(
    value: &mut Value,
    ensemble: &Ensemble,
    vault: &dyn Vault,
    audit: &mut Vec<Redaction>,
) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(desc)) = map.get_mut("description") {
                anon_into(desc, ensemble, vault, audit);
            }
            for (_, v) in map.iter_mut() {
                anonymize_descriptions(v, ensemble, vault, audit);
            }
        }
        Value::Array(items) => {
            for item in items {
                anonymize_descriptions(item, ensemble, vault, audit);
            }
        }
        _ => {}
    }
}

/// Anonymise the outbound request in place: message content, assistant
/// tool-call arguments, and tool-schema descriptions. One vault for the whole
/// request keeps placeholders consistent. Returns the audit trail (metadata
/// only — never plaintext).
///
/// Structural tool fields (function/parameter *names*, enum values) are left
/// untouched: they can't carry the `⟦…⟧` sentinel (function-name charset), and
/// the egress guard fail-closes if any of them happen to contain detectable
/// PII — so such requests are blocked, never leaked.
pub fn anonymize_request(
    req: &mut ChatRequest,
    ensemble: &Ensemble,
    vault: &dyn Vault,
) -> Vec<Redaction> {
    let mut audit = Vec::new();

    for msg in &mut req.messages {
        if let Some(content) = msg.content.as_mut() {
            anon_into(content, ensemble, vault, &mut audit);
        }
        // Assistant tool-call arguments carry real values from prior turns.
        if let Some(tool_calls) = msg
            .extra
            .get_mut("tool_calls")
            .and_then(Value::as_array_mut)
        {
            for tc in tool_calls {
                if let Some(Value::String(args)) =
                    tc.get_mut("function").and_then(|f| f.get_mut("arguments"))
                {
                    anon_into(args, ensemble, vault, &mut audit);
                }
            }
        }
    }

    if let Some(tools) = req.extra.get_mut("tools") {
        anonymize_descriptions(tools, ensemble, vault, &mut audit);
    }

    audit
}

/// Rehydrate every string in a buffered (non-streaming) response value tree.
/// Placeholders only occur where the gateway put them, so a blanket walk is
/// safe and also covers tool-call argument strings and function names.
pub fn rehydrate_response(value: &mut Value, vault: &dyn Vault) {
    match value {
        Value::String(s) => {
            if s.contains('⟦') {
                *s = rehydrate(s, vault);
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| rehydrate_response(item, vault)),
        Value::Object(map) => map
            .iter_mut()
            .for_each(|(_, v)| rehydrate_response(v, vault)),
        _ => {}
    }
}

/// Per-stream rehydration state: one [`StreamRehydrator`] per content stream
/// (keyed by choice index) and one per tool-call argument stream (keyed by
/// choice + tool-call index), since each is an independent fragment sequence.
#[derive(Default)]
pub struct StreamState {
    content: HashMap<u64, StreamRehydrator>,
    tool_args: HashMap<(u64, u64), StreamRehydrator>,
}

impl StreamState {
    /// Flush every rehydrator at end of stream, returning synthetic delta
    /// chunks for any withheld tails (usually none).
    pub fn flush(&mut self, vault: &dyn Vault) -> Vec<Value> {
        let mut chunks = Vec::new();
        for (ci, r) in self.content.iter_mut() {
            let tail = r.flush(vault);
            if !tail.is_empty() {
                chunks.push(json!({"choices":[{"index": *ci, "delta":{"content": tail}}]}));
            }
        }
        for ((ci, ti), r) in self.tool_args.iter_mut() {
            let tail = r.flush(vault);
            if !tail.is_empty() {
                chunks.push(json!({"choices":[{"index": *ci, "delta":{"tool_calls":[
                    {"index": *ti, "function":{"arguments": tail}}
                ]}}]}));
            }
        }
        chunks
    }
}

/// Rehydrate one streaming SSE chunk in place: `choices[].delta.content` and
/// `choices[].delta.tool_calls[].function.arguments`, reassembling any
/// placeholder split across chunks via the per-stream [`StreamState`].
pub fn rehydrate_deltas(chunk: &mut Value, state: &mut StreamState, vault: &dyn Vault) {
    let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };
    for choice in choices {
        let ci = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
        let Some(delta) = choice.get_mut("delta") else {
            continue;
        };

        if let Some(Value::String(content)) = delta.get_mut("content") {
            *content = state
                .content
                .entry(ci)
                .or_default()
                .push(content.as_str(), vault);
        }

        if let Some(tool_calls) = delta.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for tc in tool_calls {
                let ti = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
                if let Some(Value::String(args)) =
                    tc.get_mut("function").and_then(|f| f.get_mut("arguments"))
                {
                    let r = state.tool_args.entry((ci, ti)).or_default();
                    *args = r.push(args.as_str(), vault);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::{EntityKind, Vault};
    use pp_detect::GazetteerRecognizer;
    use pp_store::MemVault;

    fn floor() -> Ensemble {
        Ensemble::new(vec![Box::new(GazetteerRecognizer::new(vec![(
            "Falcon".into(),
            EntityKind::Custom("project".into()),
        )]))])
    }

    #[test]
    fn round_trip_through_a_simulated_upstream() {
        let vault = MemVault::new();
        let mut req: ChatRequest = serde_json::from_value(json!({
            "model": "x",
            "messages": [{ "role": "user", "content": "Hello Falcon" }]
        }))
        .expect("valid request");
        anonymize_request(&mut req, &floor(), &vault);
        assert_eq!(
            req.messages[0].content.as_deref(),
            Some("Hello ⟦PROJECT_1⟧")
        );

        let mut resp = json!({
            "choices": [{ "message": { "role": "assistant", "content": "Hi ⟦PROJECT_1⟧!" } }]
        });
        rehydrate_response(&mut resp, &vault);
        assert_eq!(
            resp["choices"][0]["message"]["content"],
            json!("Hi Falcon!")
        );
    }

    #[test]
    fn anonymizes_tool_args_and_descriptions_but_not_names() {
        let vault = MemVault::new();
        let mut req: ChatRequest = serde_json::from_value(json!({
            "model": "x",
            "messages": [{
                "role": "assistant", "content": null,
                "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": { "name": "read_file", "arguments": "{\"path\":\"Falcon.md\"}" }
                }]
            }],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file for project Falcon",
                    "parameters": { "type": "object", "properties": {
                        "path": { "type": "string", "description": "path under Falcon" }
                    }}
                }
            }]
        }))
        .expect("valid request");

        anonymize_request(&mut req, &floor(), &vault);
        let body = serde_json::to_value(&req).expect("serialise").to_string();

        assert!(!body.contains("Falcon"), "Falcon leaked: {body}");
        assert!(body.contains("⟦PROJECT_1⟧"), "no placeholder: {body}");
        assert!(
            body.contains("read_file"),
            "function name should be untouched"
        );
    }

    #[test]
    fn streaming_rehydrates_content_across_chunks() {
        let vault = MemVault::new();
        vault.intern("Falcon", &EntityKind::Custom("project".into())); // ⟦PROJECT_1⟧
        let mut state = StreamState::default();

        let mut c1 = json!({"choices":[{"index":0,"delta":{"content":"Hi ⟦PROJ"}}]});
        rehydrate_deltas(&mut c1, &mut state, &vault);
        assert_eq!(c1["choices"][0]["delta"]["content"], json!("Hi "));

        let mut c2 = json!({"choices":[{"index":0,"delta":{"content":"ECT_1⟧!"}}]});
        rehydrate_deltas(&mut c2, &mut state, &vault);
        assert_eq!(c2["choices"][0]["delta"]["content"], json!("Falcon!"));
    }

    #[test]
    fn streaming_rehydrates_tool_call_arguments_across_chunks() {
        let vault = MemVault::new();
        vault.intern("Falcon", &EntityKind::Custom("project".into())); // ⟦PROJECT_1⟧
        let mut state = StreamState::default();

        let mut c1 = json!({"choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"{\"path\":\"⟦PROJ"}}
        ]}}]});
        rehydrate_deltas(&mut c1, &mut state, &vault);
        assert_eq!(
            c1["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            json!("{\"path\":\"")
        );

        let mut c2 = json!({"choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"ECT_1⟧.md\"}"}}
        ]}}]});
        rehydrate_deltas(&mut c2, &mut state, &vault);
        assert_eq!(
            c2["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            json!("Falcon.md\"}")
        );
    }
}
