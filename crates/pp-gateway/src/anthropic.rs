//! Anthropic Messages API ↔ OpenAI chat-completions conversion.
//!
//! Lets Anthropic-native clients (e.g. Claude Code) use the gateway unchanged:
//! the inbound `POST /v1/messages` body is converted to an OpenAI [`ChatRequest`]
//! so the existing privacy pipeline applies verbatim, and the OpenAI response is
//! converted back to an Anthropic Messages response. Buffered only — Anthropic
//! SSE translation is a follow-up.

use pp_protocol::ChatRequest;
use serde_json::{json, Value};

/// Convert an Anthropic Messages request body into an OpenAI [`ChatRequest`].
///
/// `system` becomes a leading system message; assistant `tool_use` blocks become
/// `tool_calls`; user `tool_result` blocks become `role:"tool"` messages (emitted
/// before any user text so OpenAI's ordering holds); `tools[].input_schema`
/// becomes `function.parameters`.
pub fn to_chat_request(body: &Value) -> Result<ChatRequest, String> {
    let mut messages: Vec<Value> = Vec::new();

    if let Some(sys) = body.get("system") {
        let text = anthropic_text(sys);
        if !text.is_empty() {
            messages.push(json!({ "role": "system", "content": text }));
        }
    }

    let in_msgs = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("missing or invalid 'messages'")?;
    for m in in_msgs {
        let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
        let content = m.get("content");
        if role == "assistant" {
            let (text, tool_calls) = split_assistant(content);
            let mut msg = json!({ "role": "assistant" });
            msg["content"] = if text.is_empty() {
                Value::Null
            } else {
                json!(text)
            };
            if !tool_calls.is_empty() {
                msg["tool_calls"] = json!(tool_calls);
            }
            messages.push(msg);
        } else {
            let (text, tool_results) = split_user(content);
            if tool_results.is_empty() {
                messages.push(json!({ "role": "user", "content": text }));
            } else {
                // Tool results must follow the prior assistant turn before any
                // new user text in the OpenAI ordering.
                messages.extend(tool_results);
                if !text.is_empty() {
                    messages.push(json!({ "role": "user", "content": text }));
                }
            }
        }
    }

    let mut req = json!({
        "model": body.get("model").and_then(Value::as_str).unwrap_or(""),
        "messages": messages,
    });

    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.get("name").cloned().unwrap_or(Value::Null),
                        "description": t.get("description").cloned().unwrap_or(Value::Null),
                        "parameters": t.get("input_schema").cloned()
                            .unwrap_or_else(|| json!({ "type": "object" })),
                    }
                })
            })
            .collect();
        req["tools"] = json!(converted);
    }

    // Pass through common sampling params.
    for key in ["max_tokens", "temperature", "top_p"] {
        if let Some(v) = body.get(key) {
            req[key] = v.clone();
        }
    }
    if let Some(stop) = body.get("stop_sequences") {
        req["stop"] = stop.clone();
    }

    serde_json::from_value(req).map_err(|e| e.to_string())
}

/// Convert an OpenAI chat-completions response into an Anthropic Messages
/// response (text + `tool_use` content blocks, mapped `stop_reason`, usage).
pub fn from_chat_response(resp: &Value) -> Value {
    let choice = &resp["choices"][0];
    let msg = &choice["message"];

    let mut blocks: Vec<Value> = Vec::new();
    if let Some(text) = msg.get("content").and_then(Value::as_str) {
        if !text.is_empty() {
            blocks.push(json!({ "type": "text", "text": text }));
        }
    }
    if let Some(calls) = msg.get("tool_calls").and_then(Value::as_array) {
        for tc in calls {
            let f = &tc["function"];
            let input: Value = f
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| json!({}));
            blocks.push(json!({
                "type": "tool_use",
                "id": tc.get("id").cloned().unwrap_or_else(|| json!("toolu_0")),
                "name": f.get("name").cloned().unwrap_or(Value::Null),
                "input": input,
            }));
        }
    }

    let stop_reason = match choice.get("finish_reason").and_then(Value::as_str) {
        Some("tool_calls") => "tool_use",
        Some("length") => "max_tokens",
        _ => "end_turn",
    };
    let usage = &resp["usage"];

    json!({
        "id": resp.get("id").cloned().unwrap_or_else(|| json!("msg_proxy")),
        "type": "message",
        "role": "assistant",
        "model": resp.get("model").cloned().unwrap_or(Value::Null),
        "content": blocks,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": usage.get("prompt_tokens").cloned().unwrap_or_else(|| json!(0)),
            "output_tokens": usage.get("completion_tokens").cloned().unwrap_or_else(|| json!(0)),
        },
    })
}

// --- block helpers ---------------------------------------------------------

fn push_text(buf: &mut String, block: &Value) {
    if let Some(t) = block.get("text").and_then(Value::as_str) {
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(t);
    }
}

/// Flatten an Anthropic content field (string or block array) to plain text.
fn anthropic_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => {
            let mut out = String::new();
            for b in blocks {
                push_text(&mut out, b);
            }
            out
        }
        _ => String::new(),
    }
}

/// Assistant content → (joined text, OpenAI tool_calls).
fn split_assistant(content: Option<&Value>) -> (String, Vec<Value>) {
    let mut text = String::new();
    let mut calls = Vec::new();
    match content {
        Some(Value::String(s)) => text = s.clone(),
        Some(Value::Array(blocks)) => {
            for b in blocks {
                match b.get("type").and_then(Value::as_str) {
                    Some("text") => push_text(&mut text, b),
                    Some("tool_use") => {
                        let input = b.get("input").cloned().unwrap_or_else(|| json!({}));
                        calls.push(json!({
                            "id": b.get("id").cloned().unwrap_or(Value::Null),
                            "type": "function",
                            "function": {
                                "name": b.get("name").cloned().unwrap_or(Value::Null),
                                "arguments": input.to_string(),
                            }
                        }));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    (text, calls)
}

/// User content → (joined text, OpenAI `role:"tool"` messages from tool_results).
fn split_user(content: Option<&Value>) -> (String, Vec<Value>) {
    let mut text = String::new();
    let mut tools = Vec::new();
    match content {
        Some(Value::String(s)) => text = s.clone(),
        Some(Value::Array(blocks)) => {
            for b in blocks {
                match b.get("type").and_then(Value::as_str) {
                    Some("text") => push_text(&mut text, b),
                    Some("tool_result") => tools.push(json!({
                        "role": "tool",
                        "tool_call_id": b.get("tool_use_id").cloned().unwrap_or(Value::Null),
                        "content": block_content_to_string(b.get("content")),
                    })),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    (text, tools)
}

/// A tool_result's `content` (string or block array) flattened to text.
fn block_content_to_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(arr @ Value::Array(_)) => anthropic_text(arr),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_system_and_string_user() {
        let req = to_chat_request(&json!({
            "model": "claude-x",
            "system": "be terse",
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 100
        }))
        .unwrap();
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(
            v["messages"][0],
            json!({"role":"system","content":"be terse"})
        );
        assert_eq!(v["messages"][1], json!({"role":"user","content":"hi"}));
        assert_eq!(v["max_tokens"], json!(100));
    }

    #[test]
    fn request_tool_use_and_tool_result_roundtrip_shapes() {
        let req = to_chat_request(&json!({
            "model": "claude-x",
            "messages": [
                { "role": "assistant", "content": [
                    { "type": "text", "text": "checking" },
                    { "type": "tool_use", "id": "tu_1", "name": "get_weather", "input": { "city": "Paris" } }
                ]},
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "tu_1", "content": "72F" },
                    { "type": "text", "text": "thanks" }
                ]}
            ],
            "tools": [{ "name": "get_weather", "description": "look up weather",
                        "input_schema": { "type": "object", "properties": {} } }]
        }))
        .unwrap();
        let v = serde_json::to_value(&req).unwrap();

        let asst = &v["messages"][0];
        assert_eq!(asst["role"], json!("assistant"));
        assert_eq!(
            asst["tool_calls"][0]["function"]["name"],
            json!("get_weather")
        );
        let args: Value = serde_json::from_str(
            asst["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(args["city"], json!("Paris"));

        // tool_result becomes a tool message, emitted before the user text.
        assert_eq!(v["messages"][1]["role"], json!("tool"));
        assert_eq!(v["messages"][1]["tool_call_id"], json!("tu_1"));
        assert_eq!(v["messages"][1]["content"], json!("72F"));
        assert_eq!(v["messages"][2], json!({"role":"user","content":"thanks"}));

        // tools: input_schema -> parameters.
        assert_eq!(v["tools"][0]["function"]["name"], json!("get_weather"));
        assert_eq!(
            v["tools"][0]["function"]["parameters"]["type"],
            json!("object")
        );
    }

    #[test]
    fn response_text_maps_to_end_turn() {
        let a = from_chat_response(&json!({
            "model": "m",
            "choices": [{ "message": { "role": "assistant", "content": "hello" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 3, "completion_tokens": 1 }
        }));
        assert_eq!(a["type"], json!("message"));
        assert_eq!(a["content"][0], json!({"type":"text","text":"hello"}));
        assert_eq!(a["stop_reason"], json!("end_turn"));
        assert_eq!(a["usage"], json!({"input_tokens":3,"output_tokens":1}));
    }

    #[test]
    fn response_tool_calls_map_to_tool_use() {
        let a = from_chat_response(&json!({
            "choices": [{
                "message": { "role": "assistant", "content": null, "tool_calls": [
                    { "id": "call_1", "type": "function",
                      "function": { "name": "search", "arguments": "{\"q\":\"rust\"}" } }
                ]},
                "finish_reason": "tool_calls"
            }]
        }));
        assert_eq!(a["stop_reason"], json!("tool_use"));
        let block = &a["content"][0];
        assert_eq!(block["type"], json!("tool_use"));
        assert_eq!(block["name"], json!("search"));
        assert_eq!(block["input"], json!({ "q": "rust" }));
    }
}
