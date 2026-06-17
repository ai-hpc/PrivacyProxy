//! `pp-store` — vault storage backends.
//!
//! For now an in-memory deterministic vault. The SQLite-backed, two-layer
//! (persistent + ephemeral) vault from `ARCHITECTURE.md` §9 lands later behind
//! the same [`pp_core::Vault`] trait.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use pp_core::{EntityKind, Placeholder, Vault};

/// In-memory deterministic vault.
///
/// * `intern` is deterministic per `(tag, original)`.
/// * Secrets are **redact-only**: they get a stable `⟦SECRET_n⟧` placeholder
///   but no reverse mapping, so [`Vault::resolve`] never restores them.
#[derive(Default)]
pub struct MemVault {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    forward: HashMap<(String, String), Placeholder>, // (tag, original) -> placeholder
    reverse: HashMap<String, String>,                // placeholder -> original
    counters: HashMap<String, usize>,                // tag -> last index used
}

impl MemVault {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Recover the data rather than propagate a panic if a thread poisoned the lock.
fn guard(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Vault for MemVault {
    fn intern(&self, original: &str, kind: &EntityKind) -> Placeholder {
        let tag = kind.tag();
        let key = (tag.clone(), original.to_string());
        let mut inner = guard(&self.inner);
        if let Some(ph) = inner.forward.get(&key) {
            return ph.clone();
        }
        let n = {
            let c = inner.counters.entry(tag.clone()).or_insert(0);
            *c += 1;
            *c
        };
        let ph = Placeholder(format!("⟦{tag}_{n}⟧"));
        inner.forward.insert(key, ph.clone());
        if !kind.is_secret() {
            inner.reverse.insert(ph.0.clone(), original.to_string());
        }
        ph
    }

    fn resolve(&self, placeholder: &str) -> Option<String> {
        guard(&self.inner).reverse.get(placeholder).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::SecretClass;

    #[test]
    fn deterministic_per_original() {
        let v = MemVault::new();
        let a = v.intern("Falcon", &EntityKind::Custom("project".into()));
        let b = v.intern("Falcon", &EntityKind::Custom("project".into()));
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "⟦PROJECT_1⟧");
    }

    #[test]
    fn secrets_are_redact_only() {
        let v = MemVault::new();
        let ph = v.intern(
            "example-secret-value",
            &EntityKind::Secret(SecretClass::ApiKey),
        );
        assert_eq!(ph.as_str(), "⟦SECRET_1⟧");
        assert_eq!(v.resolve(ph.as_str()), None); // never reversible
    }
}
