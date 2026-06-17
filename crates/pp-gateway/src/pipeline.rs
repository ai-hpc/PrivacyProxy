//! Request/response transforms for the gateway: anonymise outbound message
//! content, rehydrate inbound responses (batch and streaming).

use pp_anonymize::{anonymize, rehydrate, StreamRehydrator};
use pp_core::{Redaction, Vault};
use pp_detect::Ensemble;
use pp_protocol::ChatRequest;
use serde_json::Value;

/// Anonymise every message's text content in place, using one vault for the
/// whole request so placeholders are consistent across the message array.
/// Returns the audit trail (metadata only — never plaintext).
pub fn anonymize_request(
    req: &mut ChatRequest,
    ensemble: &Ensemble,
    vault: &dyn Vault,
) -> Vec<Redaction> {
    let mut audit = Vec::new();
    for msg in &mut req.messages {
        if let Some(content) = msg.content.as_deref() {
            let result = anonymize(content, ensemble, vault);
            msg.content = Some(result.text);
            audit.extend(result.audit);
        }
    }
    audit
}

/// Rehydrate every string in a buffered (non-streaming) response value tree.
/// Placeholders only occur where the gateway put them, so a blanket walk is
/// safe and also covers tool-call argument strings.
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

/// Rehydrate the `choices[].delta.content` of a single streaming SSE chunk,
/// using a per-choice-index [`StreamRehydrator`] so a placeholder split across
/// chunks is reassembled. `rehydrators` persists for the whole stream; a chunk
/// may emit empty content while the tail of a placeholder is withheld.
pub fn rehydrate_deltas(
    chunk: &mut Value,
    rehydrators: &mut Vec<StreamRehydrator>,
    vault: &dyn Vault,
) {
    let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };
    for choice in choices {
        let idx = choice.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
        while rehydrators.len() <= idx {
            rehydrators.push(StreamRehydrator::new());
        }
        if let Some(Value::String(content)) =
            choice.get_mut("delta").and_then(|d| d.get_mut("content"))
        {
            *content = rehydrators[idx].push(content.as_str(), vault);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::{EntityKind, Vault};
    use pp_detect::GazetteerRecognizer;
    use pp_store::MemVault;
    use serde_json::json;

    fn floor() -> Ensemble {
        Ensemble::new(vec![Box::new(GazetteerRecognizer::new(vec![(
            "Alex".into(),
            EntityKind::Person,
        )]))])
    }

    fn req_with(content: &str) -> ChatRequest {
        serde_json::from_value(json!({
            "model": "x",
            "messages": [{ "role": "user", "content": content }]
        }))
        .expect("valid request")
    }

    #[test]
    fn round_trip_through_a_simulated_upstream() {
        let vault = MemVault::new();
        let mut req = req_with("Hello Alex");
        anonymize_request(&mut req, &floor(), &vault);
        assert_eq!(req.messages[0].content.as_deref(), Some("Hello ⟦PERSON_1⟧"));

        let mut resp = json!({
            "choices": [{ "message": { "role": "assistant", "content": "Hi ⟦PERSON_1⟧!" } }]
        });
        rehydrate_response(&mut resp, &vault);
        assert_eq!(resp["choices"][0]["message"]["content"], json!("Hi Alex!"));
    }

    #[test]
    fn streaming_deltas_rehydrate_across_chunks() {
        let vault = MemVault::new();
        let ph = vault.intern("Alex", &EntityKind::Person);
        assert_eq!(ph.as_str(), "⟦PERSON_1⟧");

        let mut rehydrators = Vec::new();

        let mut chunk1 = json!({"choices":[{"index":0,"delta":{"content":"Hi ⟦PER"}}]});
        rehydrate_deltas(&mut chunk1, &mut rehydrators, &vault);
        assert_eq!(chunk1["choices"][0]["delta"]["content"], json!("Hi "));

        let mut chunk2 = json!({"choices":[{"index":0,"delta":{"content":"SON_1⟧!"}}]});
        rehydrate_deltas(&mut chunk2, &mut rehydrators, &vault);
        assert_eq!(chunk2["choices"][0]["delta"]["content"], json!("Alex!"));
    }
}
