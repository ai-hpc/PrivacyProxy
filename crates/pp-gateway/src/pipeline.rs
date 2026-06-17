//! Request/response transforms for the gateway: anonymise outbound message
//! content, rehydrate inbound response strings.

use pp_anonymize::{anonymize, rehydrate};
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

/// Rehydrate every string in the response value tree. Placeholders only occur
/// where the gateway put them, so a blanket walk is safe and also covers
/// tool-call argument strings.
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

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::EntityKind;
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

        // Outbound: "Alex" never leaves the box.
        let mut req = req_with("Hello Alex");
        anonymize_request(&mut req, &floor(), &vault);
        assert_eq!(req.messages[0].content.as_deref(), Some("Hello ⟦PERSON_1⟧"));

        // Inbound: the model echoes the placeholder; we restore it.
        let mut resp = json!({
            "choices": [{ "message": { "role": "assistant", "content": "Hi ⟦PERSON_1⟧!" } }]
        });
        rehydrate_response(&mut resp, &vault);
        assert_eq!(resp["choices"][0]["message"]["content"], json!("Hi Alex!"));
    }
}
