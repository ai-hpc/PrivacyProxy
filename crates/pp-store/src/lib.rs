//! `pp-store` — vault storage backends (`ARCHITECTURE.md` §9).
//!
//! * [`MemVault`] — in-memory deterministic vault (ephemeral session layer).
//! * [`SqliteVault`] — durable, SQLite-backed vault (persistent personal layer).
//! * [`LayeredVault`] — composes the two: known vocabulary (`Custom` kinds) is
//!   interned durably with stable tokens across runs; everything else
//!   (emails, secrets, discovered entities) stays in the ephemeral layer.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use pp_core::{EntityKind, Placeholder, Vault};
use rusqlite::{params, Connection};

// ---------------------------------------------------------------------------
// MemVault — in-memory, deterministic, ephemeral.
// ---------------------------------------------------------------------------

/// In-memory deterministic vault.
///
/// * `intern` is deterministic per `(tag, original)`.
/// * Secrets are **redact-only**: they get a stable `__SECRET_n__` placeholder
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
        let ph = Placeholder(format!("__{tag}_{n}__"));
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

// ---------------------------------------------------------------------------
// SqliteVault — durable, persistent across runs.
// ---------------------------------------------------------------------------

/// SQLite-backed deterministic vault. Intended for the **durable personal
/// layer** — reversible entities (your private vocabulary) that should keep a
/// stable placeholder across restarts.
///
/// Not intended for secrets: route those to a redact-only ephemeral vault.
/// Originals are stored as plaintext in the local DB (encryption at rest is a
/// follow-up); the file is local-only and git-ignored.
pub struct SqliteVault {
    conn: Mutex<Connection>,
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mappings (
            tag         TEXT NOT NULL,
            original    TEXT NOT NULL,
            placeholder TEXT NOT NULL,
            PRIMARY KEY (tag, original)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_placeholder ON mappings(placeholder);
        CREATE TABLE IF NOT EXISTS counters (
            tag TEXT PRIMARY KEY,
            n   INTEGER NOT NULL
        );",
    )
}

impl SqliteVault {
    /// Open (creating if absent) a vault at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// An ephemeral in-memory SQLite vault (mainly for tests).
    pub fn in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn try_intern(&self, tag: &str, original: &str) -> rusqlite::Result<Placeholder> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Ok(existing) = conn.query_row(
            "SELECT placeholder FROM mappings WHERE tag = ?1 AND original = ?2",
            params![tag, original],
            |row| row.get::<_, String>(0),
        ) {
            return Ok(Placeholder(existing));
        }
        let n: i64 = conn
            .query_row("SELECT n FROM counters WHERE tag = ?1", params![tag], |r| {
                r.get(0)
            })
            .unwrap_or(0)
            + 1;
        conn.execute(
            "INSERT INTO counters (tag, n) VALUES (?1, ?2)
             ON CONFLICT(tag) DO UPDATE SET n = excluded.n",
            params![tag, n],
        )?;
        let placeholder = format!("__{tag}_{n}__");
        conn.execute(
            "INSERT INTO mappings (tag, original, placeholder) VALUES (?1, ?2, ?3)",
            params![tag, original, placeholder],
        )?;
        Ok(Placeholder(placeholder))
    }
}

impl Vault for SqliteVault {
    fn intern(&self, original: &str, kind: &EntityKind) -> Placeholder {
        let tag = kind.tag();
        self.try_intern(&tag, original).unwrap_or_else(|_| {
            // Degraded mode (DB error): a deterministic, *unpersisted* token.
            // Because it isn't stored, resolve() returns None and the value
            // stays anonymised — fail toward privacy.
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (tag.as_str(), original).hash(&mut h);
            Placeholder(format!("__{tag}_h{:x}__", h.finish()))
        })
    }

    fn resolve(&self, placeholder: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT original FROM mappings WHERE placeholder = ?1",
            params![placeholder],
            |row| row.get::<_, String>(0),
        )
        .ok()
    }
}

// ---------------------------------------------------------------------------
// LayeredVault — durable personal layer + ephemeral session layer.
// ---------------------------------------------------------------------------

/// Two-layer vault. `Custom`-kind entities (the user's configured vocabulary)
/// are interned in the durable `personal` layer for stable cross-run tokens;
/// every other kind goes to the ephemeral `session` layer. `resolve` checks
/// both. The kinds are disjoint by tag, so the two layers never collide.
pub struct LayeredVault {
    personal: Arc<dyn Vault>,
    session: Arc<dyn Vault>,
}

impl LayeredVault {
    pub fn new(personal: Arc<dyn Vault>, session: Arc<dyn Vault>) -> Self {
        Self { personal, session }
    }

    fn is_personal(kind: &EntityKind) -> bool {
        matches!(kind, EntityKind::Custom(_))
    }
}

impl Vault for LayeredVault {
    fn intern(&self, original: &str, kind: &EntityKind) -> Placeholder {
        if Self::is_personal(kind) {
            self.personal.intern(original, kind)
        } else {
            self.session.intern(original, kind)
        }
    }

    fn resolve(&self, placeholder: &str) -> Option<String> {
        self.personal
            .resolve(placeholder)
            .or_else(|| self.session.resolve(placeholder))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::SecretClass;

    #[test]
    fn mem_deterministic_per_original() {
        let v = MemVault::new();
        let a = v.intern("Falcon", &EntityKind::Custom("project".into()));
        let b = v.intern("Falcon", &EntityKind::Custom("project".into()));
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "__PROJECT_1__");
    }

    #[test]
    fn mem_secrets_are_redact_only() {
        let v = MemVault::new();
        let ph = v.intern(
            "example-secret-value",
            &EntityKind::Secret(SecretClass::ApiKey),
        );
        assert_eq!(ph.as_str(), "__SECRET_1__");
        assert_eq!(v.resolve(ph.as_str()), None); // never reversible
    }

    #[test]
    fn sqlite_deterministic_and_counts_per_tag() {
        let v = SqliteVault::in_memory().expect("open in-memory");
        let a = v.intern("Falcon", &EntityKind::Custom("private".into()));
        let b = v.intern("Falcon", &EntityKind::Custom("private".into()));
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "__PRIVATE_1__");
        let c = v.intern("Acme", &EntityKind::Custom("private".into()));
        assert_eq!(c.as_str(), "__PRIVATE_2__");
        assert_eq!(v.resolve("__PRIVATE_2__").as_deref(), Some("Acme"));
    }

    #[test]
    fn sqlite_persists_across_connections() {
        let path = std::env::temp_dir().join("pp_store_persistence_test.db");
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().expect("utf-8 path");
        {
            let v = SqliteVault::open(p).expect("open");
            assert_eq!(
                v.intern("Falcon", &EntityKind::Custom("private".into()))
                    .as_str(),
                "__PRIVATE_1__"
            );
        }
        {
            // Reopening the same file = same vault after a restart.
            let v = SqliteVault::open(p).expect("reopen");
            assert_eq!(
                v.intern("Falcon", &EntityKind::Custom("private".into()))
                    .as_str(),
                "__PRIVATE_1__"
            );
            assert_eq!(v.resolve("__PRIVATE_1__").as_deref(), Some("Falcon"));
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn layered_routes_personal_vs_session_and_resolves_both() {
        let personal: Arc<dyn Vault> = Arc::new(SqliteVault::in_memory().expect("mem"));
        let session: Arc<dyn Vault> = Arc::new(MemVault::new());
        let v = LayeredVault::new(personal.clone(), session);

        // Vocabulary (Custom) → durable personal layer.
        let proj = v.intern("Falcon", &EntityKind::Custom("private".into()));
        assert_eq!(proj.as_str(), "__PRIVATE_1__");
        assert_eq!(personal.resolve("__PRIVATE_1__").as_deref(), Some("Falcon"));

        // Email → ephemeral session layer; the personal layer never sees it.
        let email = v.intern("a@b.com", &EntityKind::Email);
        assert_eq!(email.as_str(), "__EMAIL_1__");
        assert_eq!(personal.resolve("__EMAIL_1__"), None);

        // LayeredVault resolves from whichever layer holds the token.
        assert_eq!(v.resolve("__PRIVATE_1__").as_deref(), Some("Falcon"));
        assert_eq!(v.resolve("__EMAIL_1__").as_deref(), Some("a@b.com"));
    }
}
