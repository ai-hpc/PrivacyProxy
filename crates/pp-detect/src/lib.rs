//! `pp-detect` — the detection ensemble.
//!
//! A deterministic floor (gazetteer, email, entropy) plus span reconciliation.
//! Statistical / local-LLM detectors plug in later behind the same
//! [`pp_core::Detector`] trait (`ARCHITECTURE.md` §8). These detectors are
//! pure Rust with no external dependencies; `regex`-backed recognisers can
//! replace the hand-rolled ones without changing the trait.
#![forbid(unsafe_code)]

use pp_core::{Detector, DetectorId, Entity, EntityKind, SecretClass};
use regex::Regex;
use serde_json::{json, Value};

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
    priority: u8,
}

impl GazetteerRecognizer {
    /// A deterministic-floor gazetteer (priority 3).
    pub fn new(terms: Vec<(String, EntityKind)>) -> Self {
        Self { terms, priority: 3 }
    }

    /// A gazetteer with an explicit priority — e.g. priority 2 for terms
    /// discovered by the (statistical) local LLM, so they lose to the floor
    /// but still beat entropy on a span conflict.
    pub fn with_priority(terms: Vec<(String, EntityKind)>, priority: u8) -> Self {
        Self { terms, priority }
    }
}

impl Detector for GazetteerRecognizer {
    fn id(&self) -> DetectorId {
        DetectorId("gazetteer")
    }
    fn priority(&self) -> u8 {
        self.priority
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
                // Don't swallow a trailing sentence dot into the domain
                // (e.g. "a@b.com." → the email is "a@b.com").
                while end > i + 1 && b[end - 1] == b'.' {
                    end -= 1;
                }
                let domain = &b[i + 1..end];
                let valid =
                    start < i && domain.len() >= 3 && domain.contains(&b'.') && domain[0] != b'.';
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

// ---------------------------------------------------------------------------
// Regex — structured PII (SSN, phone, ...) via high-precision patterns.
// ---------------------------------------------------------------------------

/// Matches structured PII by regular expression; each pattern maps to a kind.
/// Part of the deterministic floor (priority 3).
pub struct RegexRecognizer {
    patterns: Vec<(Regex, EntityKind)>,
}

impl RegexRecognizer {
    /// Compile `(pattern, kind)` pairs; invalid patterns are skipped.
    pub fn new(patterns: Vec<(&str, EntityKind)>) -> Self {
        let patterns = patterns
            .into_iter()
            .filter_map(|(p, k)| Regex::new(p).ok().map(|re| (re, k)))
            .collect();
        Self { patterns }
    }

    /// Built-in structured-PII patterns: SSN, credit cards, IPv4, IBAN, phone.
    /// Phone is listed last so that on a numeric tie (e.g. a 16-digit string)
    /// the more specific card/IP match wins by insertion order in reconcile.
    pub fn defaults() -> Self {
        Self::new(vec![
            (r"\b\d{3}-\d{2}-\d{4}\b", EntityKind::Ssn),
            (
                r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b",
                EntityKind::CreditCard,
            ),
            (
                r"\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b",
                EntityKind::CreditCard,
            ),
            (
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
                EntityKind::IpAddress,
            ),
            (r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", EntityKind::Iban),
            (r"\+?\d{1,4}(?:[ .\-]\d{3,4}){2,4}", EntityKind::Phone),
        ])
    }
}

impl Detector for RegexRecognizer {
    fn id(&self) -> DetectorId {
        DetectorId("regex")
    }
    fn priority(&self) -> u8 {
        3
    }
    fn detect(&self, text: &str) -> Vec<Entity> {
        let mut out = Vec::new();
        for (re, kind) in &self.patterns {
            for m in re.find_iter(text) {
                out.push(Entity {
                    span: m.start()..m.end(),
                    kind: kind.clone(),
                    score: 0.9,
                    source: self.id(),
                });
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// LocalLlmRecognizer — OPTIONAL semantic detector via a local OpenAI-compatible
// LLM (e.g. llama.cpp serving Falcon-H1-0.5B-Instruct). Best-effort recall
// beyond the deterministic floor; on ANY error it returns nothing, so the
// floor's guarantee is never weakened. It is NOT part of that guarantee.
// ---------------------------------------------------------------------------

const LLM_SYSTEM_PROMPT: &str = "You detect personal or confidential identifiers in the \
user's text: people, organizations, locations, project/product code-names, and similar \
sensitive names. Reply with ONLY a JSON object of the form \
{\"entities\":[{\"text\":\"...\",\"type\":\"person|org|location|project|other\"}]}. \
Copy each text span EXACTLY as written. If there are none, reply {\"entities\":[]}.";

/// Calls a local OpenAI-compatible chat endpoint to extract sensitive spans.
pub struct LocalLlmRecognizer {
    http: reqwest::Client,
    endpoint: String,
    model: String,
}

impl LocalLlmRecognizer {
    /// `base_url` is the server root, e.g. `http://127.0.0.1:8081`.
    pub fn new(base_url: &str, model: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            endpoint: format!("{}/v1/chat/completions", base_url.trim_end_matches('/')),
            model: model.to_string(),
        }
    }

    /// Extract `(snippet, kind)` pairs. Returns empty on any error — the
    /// deterministic floor still protects the request.
    pub async fn scan(&self, text: &str) -> Vec<(String, EntityKind)> {
        if text.trim().is_empty() {
            return Vec::new();
        }
        let body = json!({
            "model": self.model,
            "temperature": 0,
            "messages": [
                { "role": "system", "content": LLM_SYSTEM_PROMPT },
                { "role": "user", "content": text },
            ],
        });
        let Ok(resp) = self.http.post(&self.endpoint).json(&body).send().await else {
            return Vec::new();
        };
        if !resp.status().is_success() {
            return Vec::new();
        }
        let Ok(value) = resp.json::<Value>().await else {
            return Vec::new();
        };
        let content = value["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default();
        parse_entities(content)
    }
}

/// Map the model's free-form type label onto an [`EntityKind`].
fn map_kind(label: &str) -> EntityKind {
    match label.to_ascii_lowercase().as_str() {
        "person" | "name" | "people" => EntityKind::Person,
        "org" | "organization" | "organisation" | "company" => EntityKind::Org,
        "location" | "loc" | "place" | "address" | "gpe" => EntityKind::Location,
        _ => EntityKind::Custom("private".to_string()),
    }
}

/// Parse the model's reply into `(snippet, kind)` pairs. Robust to surrounding
/// prose/markdown and malformed output (returns what it can, else empty).
fn parse_entities(content: &str) -> Vec<(String, EntityKind)> {
    let Some(json_str) = extract_json_object(content) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(json_str) else {
        return Vec::new();
    };
    let Some(items) = value.get("entities").and_then(|e| e.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let text = item
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if text.is_empty() {
            continue;
        }
        let label = item.get("type").and_then(Value::as_str).unwrap_or("");
        out.push((text.to_string(), map_kind(label)));
    }
    out
}

/// Extract the first balanced `{...}` object from arbitrary text (models often
/// wrap JSON in prose or markdown fences). Brace-aware of string literals.
fn extract_json_object(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let bytes = s.as_bytes();
    let (mut depth, mut in_str, mut escaped) = (0i32, false, false);
    for (i, &c) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[start..=i]);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_parse_clean_json() {
        let r = parse_entities(
            r#"{"entities":[{"text":"Alex","type":"person"},{"text":"Acme","type":"org"}]}"#,
        );
        assert_eq!(
            r,
            vec![
                ("Alex".to_string(), EntityKind::Person),
                ("Acme".to_string(), EntityKind::Org),
            ]
        );
    }

    #[test]
    fn llm_parse_json_wrapped_in_prose() {
        let reply = "Sure! Here you go:\n```json\n{\"entities\":[{\"text\":\"Falcon\",\"type\":\"project\"}]}\n```\nLet me know if you need more.";
        assert_eq!(
            parse_entities(reply),
            vec![(
                "Falcon".to_string(),
                EntityKind::Custom("private".to_string())
            )]
        );
    }

    #[test]
    fn llm_parse_garbage_is_empty() {
        assert!(parse_entities("I did not find any sensitive entities.").is_empty());
        assert!(parse_entities("").is_empty());
        assert!(parse_entities("{not valid json").is_empty());
    }

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
    fn email_excludes_trailing_sentence_dot() {
        let s = "mail me at a@b.com.";
        let es = EmailRecognizer.detect(s);
        assert_eq!(es.len(), 1);
        assert_eq!(&s[es[0].span.clone()], "a@b.com");
    }

    #[test]
    fn regex_detects_ssn_and_phone() {
        let r = RegexRecognizer::defaults();
        let s = "SSN 000-12-3456, call +1-555-0198 today";
        let found = r.detect(s);
        assert!(
            found
                .iter()
                .any(|e| e.kind == EntityKind::Ssn && &s[e.span.clone()] == "000-12-3456"),
            "SSN not detected: {found:?}"
        );
        assert!(
            found.iter().any(|e| e.kind == EntityKind::Phone),
            "phone not detected: {found:?}"
        );
    }

    #[test]
    fn regex_detects_card_ip_iban() {
        let r = RegexRecognizer::defaults();
        let cases = [
            (
                "pay 4111 1111 1111 1111 now",
                EntityKind::CreditCard,
                "4111 1111 1111 1111",
            ),
            ("host 192.168.0.1 up", EntityKind::IpAddress, "192.168.0.1"),
            (
                "iban GB82WEST12345698765432 ok",
                EntityKind::Iban,
                "GB82WEST12345698765432",
            ),
        ];
        for (text, kind, expect) in cases {
            let found = r.detect(text);
            assert!(
                found
                    .iter()
                    .any(|e| e.kind == kind && &text[e.span.clone()] == expect),
                "{kind:?} not found in {text:?}: {found:?}"
            );
        }
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
