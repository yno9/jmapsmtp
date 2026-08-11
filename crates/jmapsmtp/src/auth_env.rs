//! Login, and the two files an account's credentials live in. Port of
//! `go-jmapsmtp/auth_env.go`.
//!
//! Two files sit in every account directory:
//!
//! ```text
//! <acctDir>/auth_token_hash   base64(sha256(scoped token))  — what login checks
//! <acctDir>/envelope.json     cryptenv.Envelope             — the client's key material
//! ```
//!
//! They are separate on purpose. The envelope carries its own token hash, but
//! login does **not** use it: the token is scoped per relay, so one stolen from
//! another relay is useless here, and an account with no envelope at all (a
//! DID-less or third-party account) still has to be able to log in.
//!
//! **An account exists iff `auth_token_hash` exists.** Every existence check in
//! the relay uses that file and never `envelope.json` — SPEC.md §2. An account
//! created by the signature flow has no envelope, and treating the envelope as
//! the marker 404s it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use jmap_types::Id;
use jmapserver::{decode_auth_token, devicekeys, verify_auth_token};
use parking_lot::RwLock;

use crate::config::Config;

/// Accounts created while the relay runs, alongside the ones in the config.
///
/// Keyed by full lowercase address, the same as the Go `handler.dyn`.
#[derive(Default)]
pub struct DynAccounts(RwLock<BTreeSet<String>>);

impl DynAccounts {
    pub fn insert(&self, email: String) {
        self.0.write().insert(email.to_lowercase());
    }

    pub fn contains(&self, email: &str) -> bool {
        self.0.read().contains(&email.to_lowercase())
    }

    pub fn remove(&self, email: &str) -> bool {
        self.0.write().remove(&email.to_lowercase())
    }

    pub fn emails(&self) -> Vec<String> {
        self.0.read().iter().cloned().collect()
    }
}

pub fn account_dir(data_dir: &Path, domain: &str, localpart: &str) -> PathBuf {
    data_dir.join(domain).join(localpart)
}

pub fn envelope_file(data_dir: &Path, domain: &str, localpart: &str) -> PathBuf {
    account_dir(data_dir, domain, localpart).join("envelope.json")
}

pub fn auth_hash_file(data_dir: &Path, domain: &str, localpart: &str) -> PathBuf {
    account_dir(data_dir, domain, localpart).join("auth_token_hash")
}

/// The stored token hash, or empty when the account does not exist.
///
/// Trailing whitespace is trimmed because the file is a single line that
/// hand-editing or shell redirection tends to leave a newline on.
pub fn read_auth_hash(data_dir: &Path, domain: &str, localpart: &str) -> String {
    std::fs::read_to_string(auth_hash_file(data_dir, domain, localpart))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn write_auth_hash(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    hash_b64: &str,
) -> std::io::Result<()> {
    let dir = account_dir(data_dir, domain, localpart);
    std::fs::create_dir_all(&dir)?;
    crate::write_private(&dir.join("auth_token_hash"), hash_b64.as_bytes())
}

/// Whether the account exists, by the definition above.
pub fn account_exists(data_dir: &Path, domain: &str, localpart: &str) -> bool {
    !read_auth_hash(data_dir, domain, localpart).is_empty()
}

/// Read and validate an account's envelope. A malformed one reads as absent.
pub fn read_envelope(data_dir: &Path, domain: &str, localpart: &str) -> Option<cryptenv::Envelope> {
    let bytes = std::fs::read(envelope_file(data_dir, domain, localpart)).ok()?;
    cryptenv::Envelope::from_bytes(&bytes).ok()
}

pub fn write_envelope(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    env: &cryptenv::Envelope,
) -> std::io::Result<()> {
    let dir = account_dir(data_dir, domain, localpart);
    std::fs::create_dir_all(&dir)?;
    let bytes = env
        .to_bytes()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    crate::write_private(&dir.join("envelope.json"), &bytes)
}

/// The credential check installed as the JMAP server's `AuthFn`.
///
/// Two accepted credentials, tried in this order:
///
/// 1. **A session token** from a device login. Checked first because it is the
///    common case and because it is the one that can be revoked.
/// 2. **The static `auth_token_hash`**, the account's long-lived password.
///
/// Note the ordering of the second: the account must be *known* — in the
/// config or the dynamic set — before the hash file is consulted. Without that,
/// any `<anything>@<configured-domain>` that happened to have a directory on
/// disk would authenticate.
pub fn authenticate(
    cfg: &Config,
    dynamic: &DynAccounts,
    data_dir: &Path,
    username: &str,
    password: &str,
) -> Option<Id> {
    let username = username.to_lowercase();
    let (localpart, domain) = username.split_once('@')?;

    // A session token authenticates on its own: issuing one already required
    // a signature from a registered device, and the file it is checked
    // against disappears the moment that device is revoked.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if devicekeys::check_session_token(&account_dir(data_dir, domain, localpart), password, now)
        .is_some()
    {
        return Some(Id::from(username.as_str()));
    }

    let static_ok = cfg
        .domains
        .get(domain)
        .is_some_and(|d| d.accounts.contains_key(localpart));
    if !static_ok && !dynamic.contains(&username) {
        return None;
    }

    let hash = read_auth_hash(data_dir, domain, localpart);
    if hash.is_empty() {
        return None;
    }
    let token = decode_auth_token(password)?;
    if !verify_auth_token(&token, &hash) {
        return None;
    }
    Some(Id::from(username.as_str()))
}

#[cfg(test)]
mod tests;
