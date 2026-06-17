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

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use pp_core::{EgressPolicy, EntityKind, Memory, Placeholder, Vault};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

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

/// SQLite-backed deterministic vault for the **durable personal layer** —
/// reversible entities (your private vocabulary) that keep a stable placeholder
/// across restarts. Not for secrets (route those to a redact-only ephemeral
/// vault).
///
/// With a key (see [`SqliteVault::open_with_key`]) stored originals are
/// encrypted at rest with AES-256-GCM, and the lookup column is a keyed hash so
/// rows still dedupe without revealing plaintext. Without a key, originals are
/// stored in plaintext (the file is local-only and git-ignored).
pub struct SqliteVault {
    conn: Mutex<Connection>,
    cipher: Option<VaultCipher>,
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mappings (
            tag         TEXT NOT NULL,
            lookup      TEXT NOT NULL,
            secret      BLOB NOT NULL,
            placeholder TEXT NOT NULL,
            PRIMARY KEY (tag, lookup)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_placeholder ON mappings(placeholder);
        CREATE TABLE IF NOT EXISTS counters (
            tag TEXT PRIMARY KEY,
            n   INTEGER NOT NULL
        );",
    )
}

impl SqliteVault {
    /// Open (creating if absent) an unencrypted vault at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::open_with_key(path, None)
    }

    /// Open a vault at `path`, encrypting originals at rest when `key` is `Some`.
    pub fn open_with_key(path: &str, key: Option<&str>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            cipher: key.map(VaultCipher::derive),
        })
    }

    /// An ephemeral in-memory vault (mainly for tests).
    pub fn in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            cipher: None,
        })
    }

    /// Dedup key for `(tag, original)`: the plaintext original when unencrypted,
    /// else a keyed hash that never reveals it.
    fn lookup_key(&self, tag: &str, original: &str) -> String {
        match &self.cipher {
            Some(c) => c.lookup(tag, original),
            None => original.to_string(),
        }
    }

    fn seal(&self, original: &str) -> Result<Vec<u8>, ()> {
        match &self.cipher {
            Some(c) => c.seal(original),
            None => Ok(original.as_bytes().to_vec()),
        }
    }

    fn unseal(&self, secret: &[u8]) -> Option<String> {
        match &self.cipher {
            Some(c) => c.open(secret),
            None => String::from_utf8(secret.to_vec()).ok(),
        }
    }

    fn try_intern(&self, tag: &str, original: &str) -> Result<Placeholder, ()> {
        let lookup = self.lookup_key(tag, original);
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Ok(existing) = conn.query_row(
            "SELECT placeholder FROM mappings WHERE tag = ?1 AND lookup = ?2",
            params![tag, lookup],
            |row| row.get::<_, String>(0),
        ) {
            return Ok(Placeholder(existing));
        }
        let secret = self.seal(original)?;
        let n: i64 = conn
            .query_row("SELECT n FROM counters WHERE tag = ?1", params![tag], |r| {
                r.get(0)
            })
            .unwrap_or(0)
            + 1;
        let placeholder = format!("__{tag}_{n}__");
        conn.execute(
            "INSERT INTO counters (tag, n) VALUES (?1, ?2)
             ON CONFLICT(tag) DO UPDATE SET n = excluded.n",
            params![tag, n],
        )
        .map_err(|_| ())?;
        conn.execute(
            "INSERT INTO mappings (tag, lookup, secret, placeholder) VALUES (?1, ?2, ?3, ?4)",
            params![tag, lookup, secret, placeholder],
        )
        .map_err(|_| ())?;
        Ok(Placeholder(placeholder))
    }
}

impl Vault for SqliteVault {
    fn intern(&self, original: &str, kind: &EntityKind) -> Placeholder {
        let tag = kind.tag();
        self.try_intern(&tag, original).unwrap_or_else(|_| {
            // Degraded mode (DB or crypto error): a deterministic, *unpersisted*
            // token. Since it isn't stored, resolve() returns None and the value
            // stays anonymised — fail toward privacy.
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (tag.as_str(), original).hash(&mut h);
            Placeholder(format!("__{tag}_h{:x}__", h.finish()))
        })
    }

    fn resolve(&self, placeholder: &str) -> Option<String> {
        let secret: Vec<u8> = {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            conn.query_row(
                "SELECT secret FROM mappings WHERE placeholder = ?1",
                params![placeholder],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()?
        };
        self.unseal(&secret)
    }
}

/// AES-256-GCM encryption + keyed-hash lookup for at-rest protection.
struct VaultCipher {
    aes: Aes256Gcm,
    mac_key: [u8; 32],
}

impl VaultCipher {
    fn derive(passphrase: &str) -> Self {
        let enc = subkey(b"pp-enc-v1", passphrase);
        Self {
            aes: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&enc)),
            mac_key: subkey(b"pp-mac-v1", passphrase),
        }
    }

    /// Deterministic, non-reversible lookup key (keyed SHA-256, hex).
    fn lookup(&self, tag: &str, original: &str) -> String {
        let digest = Sha256::new()
            .chain_update(self.mac_key)
            .chain_update(tag.as_bytes())
            .chain_update([0x1f])
            .chain_update(original.as_bytes())
            .finalize();
        hex(&digest)
    }

    fn seal(&self, plaintext: &str) -> Result<Vec<u8>, ()> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| ())?;
        let ciphertext = self
            .aes
            .encrypt(GenericArray::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| ())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open(&self, blob: &[u8]) -> Option<String> {
        if blob.len() < 12 {
            return None;
        }
        let (nonce, ciphertext) = blob.split_at(12);
        let plaintext = self
            .aes
            .decrypt(GenericArray::from_slice(nonce), ciphertext)
            .ok()?;
        String::from_utf8(plaintext).ok()
    }
}

/// SHA-256 of `domain || passphrase`, as a 32-byte subkey.
fn subkey(domain: &[u8], passphrase: &str) -> [u8; 32] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(passphrase.as_bytes())
        .finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Lower-case hex encoding.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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

// ---------------------------------------------------------------------------
// MemoryStore (M2) — durable, recallable memories with FTS5 keyword search
// (`doc/MEMORY.md`). Content is stored in plaintext because full-text search
// needs it; the file is local-only and git-ignored. (At-rest encryption of a
// *searchable* store is a separate, harder problem and is deferred.)
// ---------------------------------------------------------------------------

/// SQLite + FTS5 backed store of recallable memories.
pub struct MemoryStore {
    conn: Mutex<Connection>,
}

fn init_memory_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS memories (
            id            TEXT PRIMARY KEY,
            content       TEXT NOT NULL,
            kind          TEXT NOT NULL,
            egress_policy TEXT NOT NULL,
            created_ms    INTEGER NOT NULL
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(id UNINDEXED, content);",
    )
}

impl MemoryStore {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        init_memory_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_memory_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Store a memory, returning it with a generated id (`None` on error).
    pub fn add(
        &self,
        content: &str,
        kind: &str,
        egress_policy: EgressPolicy,
        created_ms: i64,
    ) -> Option<Memory> {
        let mut id_bytes = [0u8; 8];
        getrandom::getrandom(&mut id_bytes).ok()?;
        let id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO memories (id, content, kind, egress_policy, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, content, kind, egress_policy.as_str(), created_ms],
        )
        .ok()?;
        conn.execute(
            "INSERT INTO memories_fts (id, content) VALUES (?1, ?2)",
            params![id, content],
        )
        .ok()?;
        Some(Memory {
            id,
            content: content.to_string(),
            kind: kind.to_string(),
            egress_policy,
            created_ms,
        })
    }

    pub fn delete(&self, id: &str) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let _ = conn.execute("DELETE FROM memories_fts WHERE id = ?1", params![id]);
        conn.execute("DELETE FROM memories WHERE id = ?1", params![id])
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    pub fn list(&self) -> Vec<Memory> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, content, kind, egress_policy, created_ms
             FROM memories ORDER BY created_ms DESC",
        ) else {
            return Vec::new();
        };
        stmt.query_map([], row_to_memory)
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            .unwrap_or_default()
    }

    /// Keyword recall (FTS5 / BM25). Returns all matching memories regardless of
    /// `egress_policy`; the caller decides what may be injected.
    pub fn recall(&self, text: &str, limit: usize) -> Vec<Memory> {
        let query = fts_query(text);
        if query.is_empty() {
            return Vec::new();
        }
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let Ok(mut stmt) = conn.prepare(
            "SELECT m.id, m.content, m.kind, m.egress_policy, m.created_ms
             FROM memories_fts f JOIN memories m ON m.id = f.id
             WHERE memories_fts MATCH ?1 ORDER BY rank LIMIT ?2",
        ) else {
            return Vec::new();
        };
        stmt.query_map(params![query, limit as i64], row_to_memory)
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            .unwrap_or_default()
    }

    /// Contents of all `local_only` memories — used on-device to seed the
    /// gazetteer. Never sent anywhere.
    pub fn local_only_terms(&self) -> Vec<String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let Ok(mut stmt) =
            conn.prepare("SELECT content FROM memories WHERE egress_policy = 'local_only'")
        else {
            return Vec::new();
        };
        stmt.query_map([], |row| row.get::<_, String>(0))
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            .unwrap_or_default()
    }
}

fn row_to_memory(row: &rusqlite::Row) -> rusqlite::Result<Memory> {
    Ok(Memory {
        id: row.get(0)?,
        content: row.get(1)?,
        kind: row.get(2)?,
        egress_policy: EgressPolicy::from_storage(&row.get::<_, String>(3)?),
        created_ms: row.get(4)?,
    })
}

/// Build a safe FTS5 query from arbitrary text: unique alphanumeric tokens
/// (len >= 3), each quoted, OR-joined, capped. Empty if no usable tokens.
fn fts_query(text: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut terms: Vec<String> = Vec::new();
    for word in text.split(|c: char| !c.is_alphanumeric()) {
        if word.len() < 3 {
            continue;
        }
        let lower = word.to_ascii_lowercase();
        if seen.insert(lower.clone()) {
            terms.push(format!("\"{lower}\""));
            if terms.len() >= 32 {
                break;
            }
        }
    }
    terms.join(" OR ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pp_core::SecretClass;

    #[test]
    fn memory_add_recall_list_delete() {
        let m = MemoryStore::in_memory().expect("mem");
        m.add(
            "User prefers dark roast coffee",
            "preference",
            EgressPolicy::Anonymized,
            1,
        )
        .expect("add");
        m.add(
            "Project Falcon is the user's startup",
            "fact",
            EgressPolicy::LocalOnly,
            2,
        )
        .expect("add");

        let hits = m.recall("what coffee do I like", 8);
        assert!(
            hits.iter().any(|x| x.content.contains("dark roast")),
            "expected coffee recall, got {hits:?}"
        );

        assert_eq!(
            m.local_only_terms(),
            vec!["Project Falcon is the user's startup".to_string()]
        );

        assert_eq!(m.list().len(), 2);
        let id = m.list()[0].id.clone();
        assert!(m.delete(&id));
        assert_eq!(m.list().len(), 1);
    }

    #[test]
    fn memory_recall_is_safe_on_punctuation_and_misses() {
        let m = MemoryStore::in_memory().expect("mem");
        m.add(
            "The user's startup is called Falcon",
            "fact",
            EgressPolicy::Anonymized,
            1,
        )
        .expect("add");
        assert!(m
            .recall("tell me about Falcon & its roadmap!?", 8)
            .iter()
            .any(|x| x.content.contains("Falcon")));
        assert!(m.recall("zzz", 8).is_empty()); // no usable tokens / no match
    }

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
    fn sqlite_encrypts_originals_at_rest() {
        let path = std::env::temp_dir().join("pp_store_encryption_test.db");
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().expect("utf-8 path");
        {
            let v = SqliteVault::open_with_key(p, Some("correct horse")).expect("open");
            assert_eq!(
                v.intern("Falcon", &EntityKind::Custom("private".into()))
                    .as_str(),
                "__PRIVATE_1__"
            );
            assert_eq!(v.resolve("__PRIVATE_1__").as_deref(), Some("Falcon"));
        }
        // The plaintext must not appear anywhere in the raw DB file.
        let raw = std::fs::read(&path).expect("read db");
        assert!(
            !raw.windows(6).any(|w| w == b"Falcon"),
            "plaintext leaked to disk"
        );
        {
            // Reopening with the key still resolves and keeps a stable token.
            let v = SqliteVault::open_with_key(p, Some("correct horse")).expect("reopen");
            assert_eq!(v.resolve("__PRIVATE_1__").as_deref(), Some("Falcon"));
            assert_eq!(
                v.intern("Falcon", &EntityKind::Custom("private".into()))
                    .as_str(),
                "__PRIVATE_1__"
            );
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
