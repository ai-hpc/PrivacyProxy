//! `pp-core` — pure domain types and transform traits for PrivacyProxy.
//!
//! This crate performs no I/O. Detection backends live in `pp-detect`,
//! storage in `pp-store`, and the transforms in `pp-anonymize`. These types
//! implement the model described in `ARCHITECTURE.md` §7.
#![forbid(unsafe_code)]

use std::ops::Range;

/// A class of sensitive value the gateway can recognise.
///
/// [`EntityKind::Secret`] is the must-never-leak tier and is treated as
/// *redact-only* (irreversible) by the vault; everything else is reversibly
/// interned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EntityKind {
    Person,
    Org,
    Location,
    Email,
    Phone,
    FilePath,
    Secret(SecretClass),
    /// User private-vocabulary tag, e.g. `Custom("project")`.
    Custom(String),
}

/// Sub-classification of a detected secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecretClass {
    ApiKey,
    AwsSecret,
    PrivateKey,
    Jwt,
    Generic,
}

impl EntityKind {
    /// Upper-case tag used in placeholders, e.g. the `PERSON` in `⟦PERSON_1⟧`.
    pub fn tag(&self) -> String {
        match self {
            EntityKind::Person => "PERSON".into(),
            EntityKind::Org => "ORG".into(),
            EntityKind::Location => "LOC".into(),
            EntityKind::Email => "EMAIL".into(),
            EntityKind::Phone => "PHONE".into(),
            EntityKind::FilePath => "PATH".into(),
            EntityKind::Secret(_) => "SECRET".into(),
            EntityKind::Custom(s) => s.to_ascii_uppercase(),
        }
    }

    /// Whether this kind is redact-only (never rehydrated).
    pub fn is_secret(&self) -> bool {
        matches!(self, EntityKind::Secret(_))
    }
}

/// Identifies the detector that produced an [`Entity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DetectorId(pub &'static str);

/// A span of sensitive text found by a detector.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    /// Byte offsets into the source text.
    pub span: Range<usize>,
    pub kind: EntityKind,
    pub score: f32,
    pub source: DetectorId,
}

/// An anonymous token that replaces an original value, e.g. `⟦PERSON_1⟧`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Placeholder(pub String);

impl Placeholder {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One redaction, recorded for the audit trail. Never contains plaintext.
#[derive(Clone, Debug, PartialEq)]
pub struct Redaction {
    pub kind: EntityKind,
    pub detector: DetectorId,
    pub score: f32,
}

/// A source of detected entities. Implementations live in `pp-detect`.
pub trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn detect(&self, text: &str) -> Vec<Entity>;

    /// Conflict precedence — **higher wins** when spans overlap. The
    /// deterministic floor (gazetteer/regex/entropy) outranks statistical
    /// detectors (see `ARCHITECTURE.md` §8).
    fn priority(&self) -> u8 {
        1
    }
}

/// The reversible, session-consistent map between originals and placeholders.
///
/// `intern` MUST be deterministic: the same `(original, kind)` within a
/// session always yields the same placeholder, or the cloud model's reasoning
/// fractures into phantom entities. Implementations live in `pp-store`.
pub trait Vault: Send + Sync {
    fn intern(&self, original: &str, kind: &EntityKind) -> Placeholder;
    fn resolve(&self, placeholder: &str) -> Option<String>;
}
