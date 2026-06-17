//! `pp-anonymize` — the outbound/inbound transforms (`ARCHITECTURE.md` §10).
//!
//! * Outbound: detect → intern → splice placeholders ([`anonymize`]).
//! * Inbound, batch: scan for placeholders → resolve via the vault ([`rehydrate`]).
//! * Inbound, streaming: [`StreamRehydrator`] — the carry-buffer state machine
//!   that handles placeholders split across SSE chunk boundaries.
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

/// Streaming rehydrator: feed response text fragments through [`push`]; any
/// trailing partial placeholder (a `⟦…` with no closing `⟧` yet) is withheld
/// in `carry` until a later fragment completes it. This is the carry-buffer
/// state machine from `ARCHITECTURE.md` §10 — without it, a placeholder split
/// across SSE chunks (`⟦PER` | `SON_1⟧`) would be emitted broken.
///
/// Each fragment must be valid UTF-8 (it is — it arrives as a parsed JSON
/// string), so this operates at the `char`/`str` level, not raw bytes.
///
/// [`push`]: StreamRehydrator::push
#[derive(Default)]
pub struct StreamRehydrator {
    carry: String,
}

impl StreamRehydrator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a fragment and return the text now safe to emit (completed
    /// placeholders rehydrated; any trailing partial placeholder withheld).
    pub fn push(&mut self, fragment: &str, vault: &dyn Vault) -> String {
        self.carry.push_str(fragment);
        let mut out = String::new();
        loop {
            let Some(open) = self.carry.find('⟦') else {
                out.push_str(&self.carry);
                self.carry.clear();
                break;
            };
            match self.carry[open..].find('⟧') {
                Some(rel) => {
                    let end = open + rel + '⟧'.len_utf8();
                    let before = self.carry[..open].to_string();
                    let placeholder = self.carry[open..end].to_string();
                    let remainder = self.carry[end..].to_string();
                    out.push_str(&before);
                    match vault.resolve(&placeholder) {
                        Some(original) => out.push_str(&original),
                        None => out.push_str(&placeholder),
                    }
                    self.carry = remainder;
                }
                None => {
                    // Incomplete placeholder: emit the safe prefix, hold the rest.
                    let before = self.carry[..open].to_string();
                    out.push_str(&before);
                    self.carry = self.carry[open..].to_string();
                    break;
                }
            }
        }
        out
    }

    /// End of stream: emit whatever remains (resolving a complete placeholder,
    /// else passing an incomplete one through verbatim).
    pub fn flush(&mut self, vault: &dyn Vault) -> String {
        let out = rehydrate(&self.carry, vault);
        self.carry.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::{EntityKind, Vault};
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

    #[test]
    fn stream_rehydrates_split_placeholder() {
        let vault = MemVault::new();
        let ph = vault.intern("Alex", &EntityKind::Person);
        assert_eq!(ph.as_str(), "⟦PERSON_1⟧");

        let mut r = StreamRehydrator::new();
        let mut out = String::new();
        out.push_str(&r.push("Hi ⟦PER", &vault)); // emits "Hi ", holds "⟦PER"
        out.push_str(&r.push("SON_1⟧!", &vault)); // completes → "Alex!"
        out.push_str(&r.flush(&vault));
        assert_eq!(out, "Hi Alex!");
    }

    #[test]
    fn stream_passes_plain_text_and_holds_partial() {
        let vault = MemVault::new();
        let mut r = StreamRehydrator::new();
        assert_eq!(r.push("hello world", &vault), "hello world");
        // A lone opening sentinel is withheld until completion …
        assert_eq!(r.push("tail ⟦PER", &vault), "tail ");
        // … and flushed verbatim if it never completes.
        assert_eq!(r.flush(&vault), "⟦PER");
    }
}
