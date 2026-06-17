//! `pp-gateway` — the binary (`privacyproxy`).
//!
//! For now a CLI demo of the privacy sandwich: anonymise → (would POST to
//! OpenRouter) → rehydrate. The axum server, the OpenAI-compatible routes, and
//! the failover router land next (`ARCHITECTURE.md` §5, §12).
#![forbid(unsafe_code)]

use pp_anonymize::{anonymize, rehydrate};
use pp_core::EntityKind;
use pp_detect::{EmailRecognizer, Ensemble, EntropyRecognizer, GazetteerRecognizer};
use pp_store::MemVault;

fn main() {
    let ensemble = Ensemble::new(vec![
        Box::new(GazetteerRecognizer::new(vec![
            ("Alex".into(), EntityKind::Person),
            ("Falcon".into(), EntityKind::Custom("project".into())),
            ("Neptune Privacy".into(), EntityKind::Org),
        ])),
        Box::new(EmailRecognizer),
        Box::new(EntropyRecognizer::default()),
    ]);
    let vault = MemVault::new();

    let input = "Draft an email to Alex (alex@example.com) about Project Falcon at \
                 Neptune Privacy. Use key Zx91Kp7Qw3Er8Tn2Vb6Yh4Mj0Lc5Df8Gs2Na6Rt.";

    let san = anonymize(input, &ensemble, &vault);
    let restored = rehydrate(&san.text, &vault);

    println!("── PrivacyProxy sandwich demo ────────────────────────────────");
    println!("IN   (local)      : {input}");
    println!();
    println!("OUT  (to cloud)   : {}", san.text);
    println!();
    println!("BACK (rehydrated) : {restored}");
    println!();
    println!("redactions        : {}", san.audit.len());
    println!("note              : ⟦SECRET_n⟧ is redact-only and never restored.");
}
