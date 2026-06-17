//! The privacy guarantee, as a test (the TDD anchor from `ARCHITECTURE.md`
//! §14): no original PII survives anonymisation, reversible entities
//! round-trip, and secrets are redact-only.

use pp_anonymize::{anonymize, rehydrate};
use pp_core::EntityKind;
use pp_detect::{EmailRecognizer, Ensemble, EntropyRecognizer, GazetteerRecognizer};
use pp_store::MemVault;

// Neutral high-entropy fixture: trips the entropy detector but matches no
// real provider key pattern (avoids spurious secret-scanning alerts).
const SECRET: &str = "Zx91Kp7Qw3Er8Tn2Vb6Yh4Mj0Lc5Df8Gs2Na6Rt";

fn floor() -> Ensemble {
    Ensemble::new(vec![
        Box::new(GazetteerRecognizer::new(vec![
            ("Alex".into(), EntityKind::Person),
            ("Falcon".into(), EntityKind::Custom("project".into())),
            ("Neptune Privacy".into(), EntityKind::Org),
        ])),
        Box::new(EmailRecognizer),
        Box::new(EntropyRecognizer::default()),
    ])
}

fn fixture() -> String {
    format!(
        "Ping Alex at alex@example.com about Project Falcon for Neptune Privacy. Deploy key {SECRET}."
    )
}

#[test]
fn no_pii_escapes() {
    let vault = MemVault::new();
    let san = anonymize(&fixture(), &floor(), &vault);

    for leaked in [
        "Alex",
        "alex@example.com",
        "Falcon",
        "Neptune Privacy",
        SECRET,
    ] {
        assert!(
            !san.text.contains(leaked),
            "leaked {leaked:?} in: {}",
            san.text
        );
    }
    for ph in [
        "⟦PERSON_1⟧",
        "⟦EMAIL_1⟧",
        "⟦PROJECT_1⟧",
        "⟦ORG_1⟧",
        "⟦SECRET_1⟧",
    ] {
        assert!(san.text.contains(ph), "missing {ph} in: {}", san.text);
    }
    assert_eq!(san.audit.len(), 5);
}

#[test]
fn reversible_round_trips_but_secrets_stay_redacted() {
    let vault = MemVault::new();
    let san = anonymize(&fixture(), &floor(), &vault);
    let restored = rehydrate(&san.text, &vault);

    for original in ["Alex", "alex@example.com", "Falcon", "Neptune Privacy"] {
        assert!(restored.contains(original), "did not restore {original}");
    }
    // The secret is redact-only: never restored, original never reappears.
    assert!(
        restored.contains("⟦SECRET_1⟧"),
        "secret should remain redacted"
    );
    assert!(
        !restored.contains(SECRET),
        "secret must never be rehydrated"
    );
}
