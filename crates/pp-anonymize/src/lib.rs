//! `pp-anonymize` — the outbound/inbound transforms (`ARCHITECTURE.md` §10).
//!
//! * Outbound: detect → intern → splice placeholders.
//! * Inbound (batch): scan for placeholders → resolve via the vault.
//!
//! The streaming `RehydrateStream` (the carry-buffer state machine that
//! handles placeholders split across SSE chunks) lands once the async
//! upstream is wired.
#![forbid(unsafe_code)]

use pp_core::{Redaction, Vault};
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
