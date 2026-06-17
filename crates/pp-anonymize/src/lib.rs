//! `pp-anonymize` — the outbound/inbound transforms (`ARCHITECTURE.md` §10).
//!
//! * Outbound: detect → intern → splice placeholders.
//! * Inbound (batch): scan for placeholders → resolve via the vault.
//!
//! The streaming `RehydrateStream` (the carry-buffer state machine that
//! handles placeholders split across SSE chunks) lands once the async
//! upstream is wired.
#![forbid(unsafe_code)]

use pp_core::{Entity, Redaction, Vault};
use pp_detect::Ensemble;

/// Result of anonymising text: the sanitized string plus an audit trail.
#[derive(Clone, Debug)]
pub struct Anonymized {
    pub text: String,
    pub audit: Vec<Redaction>,
}

/// Outbound transform: replace every detected entity with a stable placeholder
/// from the vault, recording an audit entry (never plaintext) for each.
pub fn anonymize(text: &str, ensemble: &Ensemble, vault: &dyn Vault) -> Anonymized {
    let entities = ensemble.detect(text); // non-overlapping, left-to-right
    let mut out = String::with_capacity(text.len());
    let mut audit = Vec::new();
    let mut cursor = 0;
    for e in entities {
        // Defensive: skip anything out of order or out of bounds.
        if e.span.start < cursor || e.span.end > text.len() {
            continue;
        }
        out.push_str(&text[cursor..e.span.start]);
        let ph = vault.intern(&text[e.span.clone()], &e.kind);
        out.push_str(ph.as_str());
        audit.push(Redaction {
            kind: e.kind,
            detector: e.source,
            score: e.score,
        });
        cursor = e.span.end;
    }
    out.push_str(&text[cursor..]);
    Anonymized { text: out, audit }
}

/// Inbound batch transform: restore placeholders the vault still maps.
/// Unresolved tokens (e.g. redact-only secrets) are passed through untouched.
pub fn rehydrate(text: &str, vault: &dyn Vault) -> String {
    const OPEN: char = '⟦';
    const CLOSE: char = '⟧';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find(OPEN) {
        out.push_str(&rest[..open]);
        let after = &rest[open..];
        match after.find(CLOSE) {
            Some(close_rel) => {
                let end = close_rel + CLOSE.len_utf8();
                let ph = &after[..end];
                match vault.resolve(ph) {
                    Some(original) => out.push_str(&original),
                    None => out.push_str(ph),
                }
                rest = &after[end..];
            }
            None => {
                out.push_str(after);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Runtime egress guard (`ARCHITECTURE.md` §14): re-run detection over the
/// already-sanitized payload. Anything still detected is an un-anonymised
/// surface (e.g. a tool description the gateway doesn't rewrite yet) — the
/// caller must **fail closed**.
///
/// Pass a *precise* ensemble (deterministic identifiers, not entropy): the
/// guard runs over serialized JSON, where high-recall detectors would
/// false-positive on benign high-entropy fields like `tool_call_id`s.
pub fn egress_guard(sanitized: &str, guard: &Ensemble) -> Result<(), Vec<Entity>> {
    let leaks = guard.detect(sanitized);
    if leaks.is_empty() {
        Ok(())
    } else {
        Err(leaks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::EntityKind;
    use pp_detect::{EmailRecognizer, EntropyRecognizer, GazetteerRecognizer};
    use pp_store::MemVault;

    fn floor() -> Ensemble {
        Ensemble::new(vec![
            Box::new(GazetteerRecognizer::new(vec![(
                "Falcon".into(),
                EntityKind::Custom("project".into()),
            )])),
            Box::new(EmailRecognizer),
            Box::new(EntropyRecognizer::default()),
        ])
    }

    fn precise_guard() -> Ensemble {
        Ensemble::new(vec![
            Box::new(GazetteerRecognizer::new(vec![(
                "Falcon".into(),
                EntityKind::Custom("project".into()),
            )])),
            Box::new(EmailRecognizer),
        ])
    }

    #[test]
    fn anonymize_then_guard_passes() {
        let vault = MemVault::new();
        let a = anonymize("ping me re Falcon at a@b.com", &floor(), &vault);
        assert!(egress_guard(&a.text, &precise_guard()).is_ok());
    }

    #[test]
    fn guard_fails_on_unredacted_identifier() {
        // PII that slipped into a field the gateway did not anonymise.
        assert!(egress_guard("tool desc: contact a@b.com", &precise_guard()).is_err());
    }
}
