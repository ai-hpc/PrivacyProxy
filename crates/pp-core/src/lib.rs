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
    /// Upper-case tag used in placeholders, e.g. the `PERSON` in `__PERSON_1__`.
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

/// An anonymous token that replaces an original value, e.g. `__PERSON_1__`.
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

// ---------------------------------------------------------------------------
// Memory (M2) — see `doc/MEMORY.md`.
// ---------------------------------------------------------------------------

/// Whether a stored memory may cross the cloud boundary, and how. This is the
/// privacy-gateway adaptation of genie-claw's `spoken_policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressPolicy {
    /// Never injected into a cloud request; usable only on-device (e.g. to seed
    /// the gazetteer or local tools).
    LocalOnly,
    /// May be injected, but only via the anonymize pipeline — the cloud sees
    /// placeholders. The default.
    Anonymized,
}

impl EgressPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::Anonymized => "anonymized",
        }
    }

    /// Parse from stored/user text; defaults to the safe `Anonymized`.
    pub fn from_storage(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "local_only" | "local-only" | "local" => Self::LocalOnly,
            _ => Self::Anonymized,
        }
    }
}

/// A stored memory: a durable fact/preference/context the gateway can recall.
#[derive(Clone, Debug, PartialEq)]
pub struct Memory {
    pub id: String,
    pub content: String,
    pub kind: String,
    pub egress_policy: EgressPolicy,
    pub created_ms: i64,
}
