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
    const D: &str = "__";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let Some(open) = rest.find(D) else { break };
        let content_start = open + D.len();
        let Some(rel) = rest[content_start..].find(D) else {
            break;
        };
        let end = content_start + rel + D.len();
        let token = &rest[open..end];
        out.push_str(&rest[..open]);
        match vault.resolve(token) {
            Some(original) => {
                out.push_str(&original);
                rest = &rest[end..];
            }
            None => {
                // Not a known placeholder: emit the opening "__" and rescan
                // (its trailing "__" may open a real one).
                out.push_str(D);
                rest = &rest[content_start..];
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
/// trailing partial placeholder (a `__…` with no closing `__` yet) is withheld
/// in `carry` until a later fragment completes it. This is the carry-buffer
/// state machine from `ARCHITECTURE.md` §10 — without it, a placeholder split
/// across SSE chunks (`__PER` | `SON_1__`) would be emitted broken.
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
            let Some(open) = self.carry.find("__") else {
                break;
            };
            let content_start = open + 2;
            match self.carry[content_start..].find("__") {
                Some(rel) => {
                    let end = content_start + rel + 2;
                    let token = self.carry[open..end].to_string();
                    out.push_str(&self.carry[..open]);
                    match vault.resolve(&token) {
                        Some(original) => {
                            out.push_str(&original);
                            self.carry.replace_range(..end, "");
                        }
                        None => {
                            // Not ours: emit the opening "__" and rescan after it.
                            out.push_str("__");
                            self.carry.replace_range(..content_start, "");
                        }
                    }
                }
                None => {
                    // Partial placeholder from `open`: emit the prefix, hold the rest.
                    out.push_str(&self.carry[..open]);
                    self.carry.replace_range(..open, "");
                    return out;
                }
            }
        }
        // No "__" remains; hold a lone trailing '_' that could begin "__" next.
        if self.carry.ends_with('_') {
            let keep = self.carry.len() - 1;
            out.push_str(&self.carry[..keep]);
            self.carry.replace_range(..keep, "");
        } else {
            out.push_str(&self.carry);
            self.carry.clear();
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
    use pp_detect::{EmailRecognizer, EntropyRecognizer, GazetteerRecognizer, RegexRecognizer};
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
    fn guard_does_not_false_trip_on_our_own_placeholders() {
        // Anonymise a payload covering every structured-PII kind, then re-run a
        // regex-inclusive guard (as the gateway does). The resulting placeholders
        // must NOT themselves match a PII pattern — otherwise every such request
        // would fail closed.
        let vault = MemVault::new();
        let regex_floor = || {
            Ensemble::new(vec![
                Box::new(EmailRecognizer) as Box<dyn pp_core::Detector>,
                Box::new(RegexRecognizer::defaults()),
            ])
        };
        let text = "ssn 123-45-6789 card 4111 1111 1111 1111 ip 203.0.113.7 \
                    iban GB82WEST12345698765432 ph +1 415-555-0132 mail a@b.com";
        let san = anonymize(text, &regex_floor(), &vault);
        assert!(
            egress_guard(&san.text, &regex_floor()).is_ok(),
            "guard false-tripped on placeholders: {}",
            san.text
        );
    }

    #[test]
    fn stream_rehydrates_split_placeholder() {
        let vault = MemVault::new();
        let ph = vault.intern("Alex", &EntityKind::Person);
        assert_eq!(ph.as_str(), "__PERSON_1__");

        let mut r = StreamRehydrator::new();
        let mut out = String::new();
        out.push_str(&r.push("Hi __PER", &vault)); // emits "Hi ", holds "__PER"
        out.push_str(&r.push("SON_1__!", &vault)); // completes → "Alex!"
        out.push_str(&r.flush(&vault));
        assert_eq!(out, "Hi Alex!");
    }

    #[test]
    fn stream_passes_plain_text_and_holds_partial() {
        let vault = MemVault::new();
        let mut r = StreamRehydrator::new();
        assert_eq!(r.push("hello world", &vault), "hello world");
        // A lone opening sentinel is withheld until completion …
        assert_eq!(r.push("tail __PER", &vault), "tail ");
        // … and flushed verbatim if it never completes.
        assert_eq!(r.flush(&vault), "__PER");
    }

    /// Multi-byte text around a matched ASCII term must not panic the byte-offset
    /// splice, and must round-trip with the surrounding emoji/CJK intact.
    #[test]
    fn anonymize_is_utf8_boundary_safe() {
        let vault = MemVault::new();
        let text = "🚀 launch Falcon 飞船 for a@b.com 🎯";
        let san = anonymize(text, &floor(), &vault);
        assert!(!san.text.contains("Falcon"), "term leaked: {}", san.text);
        assert!(san.text.contains("🚀") && san.text.contains("飞船") && san.text.contains("🎯"));
        assert_eq!(rehydrate(&san.text, &vault), text, "round trip lost data");
    }

    /// Core streaming invariant: for **any** way of cutting a string into
    /// fragments, feeding them through `push`+`flush` must equal the batch
    /// `rehydrate` of the whole. Exercises every byte boundary plus the
    /// degenerate char-by-char stream, over adjacent / unknown / trailing
    /// placeholders — the cases most likely to corrupt a streamed response.
    #[test]
    fn stream_equals_batch_for_every_split() {
        let vault = MemVault::new();
        assert_eq!(
            vault.intern("Alex", &EntityKind::Person).as_str(),
            "__PERSON_1__"
        );
        assert_eq!(
            vault
                .intern("Acme", &EntityKind::Custom("org".into()))
                .as_str(),
            "__ORG_1__"
        );

        // Adjacent placeholders, an unknown one (must pass through), a lone "__",
        // a trailing single "_", and plain text with underscores.
        let cases = [
            "a __PERSON_1____ORG_1__ b __NOPE_1__ c",
            "no placeholders here, just under_scores_",
            "__PERSON_1__",
            "edge __ORG_1__ and dangling __",
            "weird ____ and __PERSON_1__ tail _",
        ];

        for whole in cases {
            let expected = rehydrate(whole, &vault);

            // (1) every two-way split at a char boundary.
            for cut in (0..=whole.len()).filter(|&i| whole.is_char_boundary(i)) {
                let mut r = StreamRehydrator::new();
                let mut got = r.push(&whole[..cut], &vault);
                got.push_str(&r.push(&whole[cut..], &vault));
                got.push_str(&r.flush(&vault));
                assert_eq!(got, expected, "split of {whole:?} at {cut}");
            }

            // (2) the degenerate one-char-at-a-time stream.
            let mut r = StreamRehydrator::new();
            let mut got = String::new();
            for ch in whole.chars() {
                got.push_str(&r.push(ch.encode_utf8(&mut [0u8; 4]), &vault));
            }
            got.push_str(&r.flush(&vault));
            assert_eq!(got, expected, "char-by-char of {whole:?}");
        }
    }
}
