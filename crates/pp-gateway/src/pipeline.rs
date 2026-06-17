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
use pp_protocol::{ChatRequest, Content};
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
/// untouched: they can't carry the `__…__` sentinel (function-name charset), and
/// the egress guard fail-closes if any of them happen to contain detectable
/// PII — so such requests are blocked, never leaked.
pub fn anonymize_request(
    req: &mut ChatRequest,
    ensemble: &Ensemble,
    vault: &dyn Vault,
) -> Vec<Redaction> {
    let mut audit = Vec::new();

    for msg in &mut req.messages {
        match msg.content.as_mut() {
            Some(Content::Text(s)) => anon_into(s, ensemble, vault, &mut audit),
            // Multimodal: anonymise the text of each text part; other parts
            // (e.g. image_url) pass through and stay subject to the egress guard.
            Some(Content::Parts(parts)) => {
                for part in parts.iter_mut() {
                    if let Some(Value::String(t)) = part.get_mut("text") {
                        anon_into(t, ensemble, vault, &mut audit);
                    }
                }
            }
            None => {}
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
            if s.contains("__") {
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

/// Recover a tool call the model emitted as **text** in a non-OpenAI format and
/// re-emit it in the canonical `tool_calls` schema, so the agent's tool loop
/// doesn't break on a free model that ignores the function-calling contract.
/// Recognises Mistral `[TOOL_CALLS]name{args}`, Qwen `<tool_call>…</tool_call>`
/// XML, and fenced/bare JSON `{"name":…,"arguments":…}`.
///
/// No-op when the message already has `tool_calls` or no call is recoverable.
/// Buffered-path only (a call split across SSE frames can't be reassembled
/// mid-stream); the gateway gates this on `needs_tools` to avoid mistaking a
/// legitimate JSON answer for a tool call.
pub fn rescue_response(value: &mut Value) {
    let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };
    for (i, choice) in choices.iter_mut().enumerate() {
        // Read-only inspection first, so the later mutable borrows don't overlap.
        let recovered = {
            let Some(msg) = choice.get("message") else {
                continue;
            };
            let has_calls = msg
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty());
            if has_calls {
                continue;
            }
            let Some(content) = msg.get("content").and_then(Value::as_str) else {
                continue;
            };
            parse_tool_call(content)
        };
        let Some((name, args)) = recovered else {
            continue;
        };
        if let Some(msg) = choice.get_mut("message").and_then(Value::as_object_mut) {
            msg.insert(
                "tool_calls".into(),
                json!([{
                    "id": format!("call_rescue_{i}"),
                    "type": "function",
                    "function": { "name": name, "arguments": args },
                }]),
            );
            msg.insert("content".into(), Value::Null);
        }
        if let Some(obj) = choice.as_object_mut() {
            obj.insert("finish_reason".into(), json!("tool_calls"));
        }
    }
}

/// Try each known wrong-format tool-call encoding; return `(name, args)` where
/// `args` is a JSON-encoded string (the canonical `function.arguments` shape).
fn parse_tool_call(content: &str) -> Option<(String, String)> {
    parse_mistral(content)
        .or_else(|| parse_qwen(content))
        .or_else(|| parse_json_call(content))
}

/// Mistral: `[TOOL_CALLS]name{json}` or `[TOOL_CALLS][{"name":…,"arguments":…}]`.
fn parse_mistral(content: &str) -> Option<(String, String)> {
    let rest = content.split("[TOOL_CALLS]").nth(1)?.trim_start();
    if rest.starts_with('[') || rest.starts_with('{') {
        return parse_json_call(rest);
    }
    let brace = rest.find('{')?;
    let name = rest[..brace].trim().trim_matches('"').to_string();
    if name.is_empty() {
        return None;
    }
    let obj = first_json(&rest[brace..])?;
    let args: Value = serde_json::from_str(obj).ok()?;
    Some((name, args.to_string()))
}

/// Qwen: `<tool_call>{"name":…,"arguments":…}</tool_call>`.
fn parse_qwen(content: &str) -> Option<(String, String)> {
    let start = content.find("<tool_call>")? + "<tool_call>".len();
    let after = &content[start..];
    let end = after.find("</tool_call>").unwrap_or(after.len());
    parse_json_call(after[..end].trim())
}

/// Fenced or bare JSON: the first balanced `{...}`/`[...]` carrying a `name`
/// plus `arguments`/`parameters` (object or already-stringified).
fn parse_json_call(s: &str) -> Option<(String, String)> {
    let v: Value = serde_json::from_str(first_json(s)?).ok()?;
    let call = if let Some(arr) = v.as_array() {
        arr.first()?.clone()
    } else {
        v
    };
    let name = call
        .get("name")
        .or_else(|| call.get("function").and_then(|f| f.get("name")))
        .and_then(Value::as_str)?
        .to_string();
    let args_val = call
        .get("arguments")
        .or_else(|| call.get("parameters"))
        .or_else(|| call.get("function").and_then(|f| f.get("arguments")))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let args = match args_val {
        Value::String(s) => s,      // already a JSON-encoded string
        other => other.to_string(), // serialise object/array to a string
    };
    Some((name, args))
}

/// The first balanced `{...}` or `[...]` substring, respecting string literals.
fn first_json(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    let start = b.iter().position(|&c| c == b'{' || c == b'[')?;
    let (open, close) = if b[start] == b'{' {
        (b'{', b'}')
    } else {
        (b'[', b']')
    };
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for (i, &c) in b.iter().enumerate().skip(start) {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(&s[start..=i]);
            }
        }
    }
    None
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
            req.messages[0]
                .content
                .as_ref()
                .map(Content::text)
                .as_deref(),
            Some("Hello __PROJECT_1__")
        );

        let mut resp = json!({
            "choices": [{ "message": { "role": "assistant", "content": "Hi __PROJECT_1__!" } }]
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
        assert!(body.contains("__PROJECT_1__"), "no placeholder: {body}");
        assert!(
            body.contains("read_file"),
            "function name should be untouched"
        );
    }

    #[test]
    fn anonymizes_multimodal_text_parts_only() {
        let vault = MemVault::new();
        let mut req: ChatRequest = serde_json::from_value(json!({
            "model": "x",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "look at Falcon"},
                    {"type": "image_url", "image_url": {"url": "https://host/Falcon.png"}}
                ]
            }]
        }))
        .expect("array content must deserialize, not 422");

        anonymize_request(&mut req, &floor(), &vault);
        let body = serde_json::to_value(&req).expect("serialise").to_string();

        // The text part is anonymised …
        assert!(
            body.contains("__PROJECT_1__"),
            "text part not masked: {body}"
        );
        assert!(!body.contains("look at Falcon"), "text leaked: {body}");
        // … the structural image_url part is preserved verbatim.
        assert!(
            body.contains("https://host/Falcon.png"),
            "image part should pass through: {body}"
        );
    }

    fn rescued(content: &str) -> Value {
        let mut v = json!({"choices":[{"message":{"role":"assistant","content": content}}]});
        rescue_response(&mut v);
        v
    }

    #[test]
    fn rescue_mistral_name_brace_args() {
        let v = rescued("[TOOL_CALLS]get_weather{\"city\": \"Paris\"}");
        let f = &v["choices"][0]["message"]["tool_calls"][0]["function"];
        assert_eq!(f["name"], json!("get_weather"));
        let args: Value = serde_json::from_str(f["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["city"], json!("Paris"));
        assert_eq!(v["choices"][0]["finish_reason"], json!("tool_calls"));
        assert!(v["choices"][0]["message"]["content"].is_null());
    }

    #[test]
    fn rescue_qwen_xml() {
        let v = rescued(
            "<tool_call>{\"name\": \"search\", \"arguments\": {\"q\": \"rust\"}}</tool_call>",
        );
        let f = &v["choices"][0]["message"]["tool_calls"][0]["function"];
        assert_eq!(f["name"], json!("search"));
        let args: Value = serde_json::from_str(f["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["q"], json!("rust"));
    }

    #[test]
    fn rescue_fenced_json() {
        let v = rescued(
            "Sure!\n```json\n{\"name\": \"read_file\", \"arguments\": {\"path\": \"a.md\"}}\n```",
        );
        assert_eq!(
            v["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            json!("read_file")
        );
    }

    #[test]
    fn rescue_is_noop_without_a_call_or_when_already_present() {
        // Plain prose → untouched.
        let v = rescued("The weather is sunny today.");
        assert!(v["choices"][0]["message"]["tool_calls"].is_null());
        assert_eq!(
            v["choices"][0]["message"]["content"],
            json!("The weather is sunny today.")
        );

        // Already-canonical tool_calls → untouched.
        let mut v2 = json!({"choices":[{"message":{"role":"assistant","content":null,
            "tool_calls":[{"id":"c1","type":"function","function":{"name":"x","arguments":"{}"}}]}}]});
        rescue_response(&mut v2);
        assert_eq!(
            v2["choices"][0]["message"]["tool_calls"][0]["id"],
            json!("c1")
        );
    }

    #[test]
    fn rescue_then_rehydrate_restores_args() {
        // A rescued Mistral call whose argument is a placeholder must rehydrate.
        let vault = MemVault::new();
        vault.intern("Falcon", &EntityKind::Custom("project".into())); // __PROJECT_1__
        let mut v = json!({"choices":[{"message":{"role":"assistant",
            "content":"[TOOL_CALLS]open{\"project\": \"__PROJECT_1__\"}"}}]});
        rescue_response(&mut v);
        rehydrate_response(&mut v, &vault);
        let args = v["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(args.contains("Falcon"), "args not rehydrated: {args}");
    }

    #[test]
    fn streaming_rehydrates_content_across_chunks() {
        let vault = MemVault::new();
        vault.intern("Falcon", &EntityKind::Custom("project".into())); // __PROJECT_1__
        let mut state = StreamState::default();

        let mut c1 = json!({"choices":[{"index":0,"delta":{"content":"Hi __PROJ"}}]});
        rehydrate_deltas(&mut c1, &mut state, &vault);
        assert_eq!(c1["choices"][0]["delta"]["content"], json!("Hi "));

        let mut c2 = json!({"choices":[{"index":0,"delta":{"content":"ECT_1__!"}}]});
        rehydrate_deltas(&mut c2, &mut state, &vault);
        assert_eq!(c2["choices"][0]["delta"]["content"], json!("Falcon!"));
    }

    #[test]
    fn streaming_rehydrates_tool_call_arguments_across_chunks() {
        let vault = MemVault::new();
        vault.intern("Falcon", &EntityKind::Custom("project".into())); // __PROJECT_1__
        let mut state = StreamState::default();

        let mut c1 = json!({"choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"{\"path\":\"__PROJ"}}
        ]}}]});
        rehydrate_deltas(&mut c1, &mut state, &vault);
        assert_eq!(
            c1["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            json!("{\"path\":\"")
        );

        let mut c2 = json!({"choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"ECT_1__.md\"}"}}
        ]}}]});
        rehydrate_deltas(&mut c2, &mut state, &vault);
        assert_eq!(
            c2["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            json!("Falcon.md\"}")
        );
    }
}
