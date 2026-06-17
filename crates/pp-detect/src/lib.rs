//! `pp-detect` — the detection ensemble.
//!
//! A deterministic floor (gazetteer, email, entropy) plus span reconciliation.
//! Statistical / local-LLM detectors plug in later behind the same
//! [`pp_core::Detector`] trait (`ARCHITECTURE.md` §8). These detectors are
//! pure Rust with no external dependencies; `regex`-backed recognisers can
//! replace the hand-rolled ones without changing the trait.
#![forbid(unsafe_code)]

use pp_core::{Detector, DetectorId, Entity, EntityKind, SecretClass};

/// Runs every detector and reconciles overlapping spans into a clean,
/// non-overlapping, left-to-right sequence.
pub struct Ensemble {
    detectors: Vec<Box<dyn Detector>>,
}

impl Ensemble {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    pub fn detect(&self, text: &str) -> Vec<Entity> {
        let mut scored: Vec<(u8, Entity)> = Vec::new();
        for d in &self.detectors {
            let p = d.priority();
            for e in d.detect(text) {
                scored.push((p, e));
            }
        }
        reconcile(scored)
    }
}

/// Resolve overlaps: highest detector priority first claims its span, then
/// longer spans, then higher score. Deterministic detectors thus always beat
/// statistical ones on a conflict. Returns entities sorted left-to-right.
fn reconcile(mut scored: Vec<(u8, Entity)>) -> Vec<Entity> {
    scored.sort_by(|(pa, a), (pb, b)| {
        pb.cmp(pa)
            .then_with(|| (b.span.end - b.span.start).cmp(&(a.span.end - a.span.start)))
            .then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.span.start.cmp(&b.span.start))
    });

    let mut kept: Vec<Entity> = Vec::new();
    for (_, e) in scored {
        let overlaps = kept
            .iter()
            .any(|k| e.span.start < k.span.end && k.span.start < e.span.end);
        if !overlaps {
            kept.push(e);
        }
    }
    kept.sort_by_key(|e| e.span.start);
    kept
}

// ---------------------------------------------------------------------------
// Gazetteer — the PRIMARY detector: exact (ASCII case-insensitive, word-
// bounded) matches of the user's private vocabulary.
// ---------------------------------------------------------------------------

/// Matches user private-vocabulary terms.
pub struct GazetteerRecognizer {
    terms: Vec<(String, EntityKind)>,
}

impl GazetteerRecognizer {
    pub fn new(terms: Vec<(String, EntityKind)>) -> Self {
        Self { terms }
    }
}

impl Detector for GazetteerRecognizer {
    fn id(&self) -> DetectorId {
        DetectorId("gazetteer")
    }
    fn priority(&self) -> u8 {
        3
    }
    fn detect(&self, text: &str) -> Vec<Entity> {
        // ASCII-lowercasing preserves byte length, so offsets map back 1:1.
        let hay = text.to_ascii_lowercase();
        let mut out = Vec::new();
        for (term, kind) in &self.terms {
            if term.is_empty() {
                continue;
            }
            let needle = term.to_ascii_lowercase();
            let mut from = 0;
            while let Some(rel) = hay[from..].find(&needle) {
                let start = from + rel;
                let end = start + needle.len();
                if is_word_bounded(text, start, end) {
                    out.push(Entity {
                        span: start..end,
                        kind: kind.clone(),
                        score: 1.0,
                        source: self.id(),
                    });
                }
                from = end;
            }
        }
        out
    }
}

fn is_word_bounded(text: &str, start: usize, end: usize) -> bool {
    let before_ok = text[..start]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_alphanumeric());
    let after_ok = text[end..]
        .chars()
        .next()
        .is_none_or(|c| !c.is_alphanumeric());
    before_ok && after_ok
}

// ---------------------------------------------------------------------------
// Email — hand-rolled ASCII scanner (no regex dependency).
// ---------------------------------------------------------------------------

/// Detects `local@domain.tld` style addresses.
pub struct EmailRecognizer;

impl Detector for EmailRecognizer {
    fn id(&self) -> DetectorId {
        DetectorId("email")
    }
    fn priority(&self) -> u8 {
        3
    }
    fn detect(&self, text: &str) -> Vec<Entity> {
        let b = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'@' {
                let mut start = i;
                while start > 0 && is_local(b[start - 1]) {
                    start -= 1;
                }
                let mut end = i + 1;
                while end < b.len() && is_domain(b[end]) {
                    end += 1;
                }
                let domain = &b[i + 1..end];
                let valid = start < i
                    && domain.len() >= 3
                    && domain.contains(&b'.')
                    && domain[0] != b'.'
                    && *domain.last().unwrap_or(&b'.') != b'.';
                if valid {
                    out.push(Entity {
                        span: start..end,
                        kind: EntityKind::Email,
                        score: 0.95,
                        source: self.id(),
                    });
                    i = end;
                    continue;
                }
            }
            i += 1;
        }
        out
    }
}

fn is_local(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}
fn is_domain(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')
}

// ---------------------------------------------------------------------------
// Entropy — flags long, high-entropy tokens as generic secrets (unknown keys).
// ---------------------------------------------------------------------------

/// Flags high-entropy tokens (likely API keys / tokens) as secrets.
pub struct EntropyRecognizer {
    pub min_len: usize,
    pub min_entropy: f64,
}

impl Default for EntropyRecognizer {
    fn default() -> Self {
        Self {
            min_len: 20,
            min_entropy: 3.5,
        }
    }
}

impl Detector for EntropyRecognizer {
    fn id(&self) -> DetectorId {
        DetectorId("entropy")
    }
    fn priority(&self) -> u8 {
        1 // statistical — loses to the deterministic floor on conflicts
    }
    fn detect(&self, text: &str) -> Vec<Entity> {
        let b = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if is_token(b[i]) {
                let start = i;
                while i < b.len() && is_token(b[i]) {
                    i += 1;
                }
                let token = &text[start..i];
                if token.len() >= self.min_len && shannon_entropy(token) >= self.min_entropy {
                    out.push(Entity {
                        span: start..i,
                        kind: EntityKind::Secret(SecretClass::Generic),
                        score: 0.6,
                        source: self.id(),
                    });
                }
            } else {
                i += 1;
            }
        }
        out
    }
}

fn is_token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+' | b'/' | b'=')
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for &c in s.as_bytes() {
        counts[c as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_detected() {
        let es = EmailRecognizer.detect("ping a.b@example.com now");
        assert_eq!(es.len(), 1);
        assert_eq!(
            &"ping a.b@example.com now"[es[0].span.clone()],
            "a.b@example.com"
        );
    }

    #[test]
    fn deterministic_beats_entropy_on_overlap() {
        // A high-entropy token that is also a known vocabulary term: the
        // gazetteer (priority 3) must win over entropy (priority 1).
        let ens = Ensemble::new(vec![
            Box::new(GazetteerRecognizer::new(vec![(
                "Xq7Kz9Lp2Wm4Bn6Vc8Rt0Yh".into(),
                EntityKind::Custom("codename".into()),
            )])),
            Box::new(EntropyRecognizer::default()),
        ]);
        let found = ens.detect("the codename Xq7Kz9Lp2Wm4Bn6Vc8Rt0Yh ships");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Custom("codename".into()));
    }
}
