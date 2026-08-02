//! Onboarding: `/auth/envelope`, `/auth/signup`, `/relay-info`. Port of the
//! remaining handlers in `go-jmapsmtp/auth_env.go` and `main.go`.
//!
//! # Why `GET /auth/envelope` is public
//!
//! It hands out an account's `envelope.json` to anyone who asks. That is not an
//! oversight: the envelope is a master secret wrapped with a key derived from
//! the user's password by Argon2id (t=3, m=64MiB, p=4) and sealed with AES-GCM.
//! Without the password it is inert, and the client needs it *before* it has a
//! credential — the credential is derived from what the envelope unwraps.
//!
//! What it does leak is **which addresses have an account with an envelope**.
//! That is inherent to the flow rather than incidental, and the Go
//! implementation makes the same trade. Worth knowing rather than discovering.
//!
//! # The setup token is a one-shot credential
//!
//! `POST /auth/signup?token=…` turns a token the operator handed out into an
//! account's first credential. The token is deleted on use and the endpoint
//! refuses an account that already has an envelope, so a leaked token is worth
//! nothing once the account is claimed.

use std::path::Path;

use crate::config::{Config, DynamicDomains};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupError {
    /// `?email=` absent or without an `@`.
    EmailRequired,
    /// `?token=` absent.
    TokenRequired,
    /// No account holds this token.
    InvalidToken,
    /// The account already has an envelope. Rotate through
    /// `PUT /auth/envelope` instead.
    AlreadyInitialized,
    InvalidEnvelope,
    NotFound,
    Unauthorized,
}

impl SetupError {
    pub fn status(&self) -> u16 {
        match self {
            SetupError::EmailRequired | SetupError::TokenRequired | SetupError::InvalidEnvelope => {
                400
            }
            SetupError::Unauthorized | SetupError::InvalidToken => 401,
            SetupError::NotFound => 404,
            SetupError::AlreadyInitialized => 409,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            SetupError::EmailRequired => "email required",
            SetupError::TokenRequired => "token required",
            SetupError::InvalidToken => "invalid or expired token",
            SetupError::AlreadyInitialized => "already initialized",
            SetupError::InvalidEnvelope => "invalid envelope",
            SetupError::NotFound => "not found",
            SetupError::Unauthorized => "unauthorized",
        }
    }
}

/// `GET /auth/envelope?email=<addr>` — the stored envelope bytes.
///
/// Served for **any** account that has one on disk, including dynamically
/// provisioned ones that are not in the static config: they need their envelope
/// for the client's add-account and login flows just as much.
///
/// The domain is checked first, so an unknown domain is a 404 before any file
/// is touched. That is not a privacy measure — the next check leaks the same
/// thing — it just keeps a request for a domain this relay does not serve from
/// reading the disk at all.
pub fn read_envelope_for(
    cfg: &Config,
    dynamic_domains: &DynamicDomains,
    data_dir: &Path,
    email_param: &str,
) -> Result<Vec<u8>, SetupError> {
    let email = email_param.to_lowercase();
    let (localpart, domain) = email.split_once('@').ok_or(SetupError::EmailRequired)?;
    if crate::config::domain_config(cfg, dynamic_domains, domain).is_none() {
        return Err(SetupError::NotFound);
    }
    // The raw bytes, not a re-serialisation: the client compares what it
    // uploaded, and a reformat would change the file it gets back.
    std::fs::read(crate::auth_env::envelope_file(data_dir, domain, localpart))
        .map_err(|_| SetupError::NotFound)
}

/// `PUT /auth/envelope` — a password change.
///
/// The relay never sees the master secret. All it enforces is "you held the old
/// credential", and the client does the rewrapping. The account is taken from
/// the *authenticated* identity, never from the request, so this can only ever
/// replace the caller's own envelope.
pub fn replace_envelope(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    body: &[u8],
) -> Result<(), SetupError> {
    let env = cryptenv::Envelope::from_bytes(body).map_err(|_| SetupError::InvalidEnvelope)?;
    crate::auth_env::write_envelope(data_dir, domain, localpart, &env)
        .map_err(|_| SetupError::NotFound)
}

/// Find the account a setup token was issued for.
///
/// Compared in **constant time**, unlike the Go original's `==`. The token is a
/// one-shot account-creation credential, and a byte-at-a-time comparison across
/// a set of accounts is the shape a timing attack wants. 128 bits of randomness
/// makes it impractical either way; constant time costs nothing and removes the
/// question.
pub fn account_for_token(
    cfg: &Config,
    data_dir: &Path,
    token: &str,
) -> Result<(String, String), SetupError> {
    if token.is_empty() {
        return Err(SetupError::TokenRequired);
    }
    use subtle::ConstantTimeEq as _;
    // Every account is checked even after a match, so the work done does not
    // depend on where in the list the token was found.
    let mut found: Option<(String, String)> = None;
    for (domain, dom_cfg) in &cfg.domains {
        for localpart in dom_cfg.accounts.keys() {
            let Ok(stored) =
                std::fs::read_to_string(crate::startup::token_file(data_dir, domain, localpart))
            else {
                continue;
            };
            let stored = stored.trim();
            if bool::from(stored.as_bytes().ct_eq(token.as_bytes())) && found.is_none() {
                found = Some((domain.clone(), localpart.clone()));
            }
        }
    }
    found.ok_or(SetupError::InvalidToken)
}

/// `POST /auth/signup?token=…` — install the client-built envelope as the
/// account's first credential and burn the token.
///
/// Refuses an account that already has an envelope. That makes the endpoint
/// non-idempotent on purpose: a replayed signup must not be able to install a
/// *different* envelope over a claimed account, which would hand it to whoever
/// replayed it. Rotation goes through `PUT /auth/envelope`, which requires the
/// current credential.
pub fn signup(
    cfg: &Config,
    data_dir: &Path,
    token: &str,
    body: &[u8],
) -> Result<(String, String), SetupError> {
    let (domain, localpart) = account_for_token(cfg, data_dir, token)?;

    if crate::auth_env::read_envelope(data_dir, &domain, &localpart).is_some() {
        return Err(SetupError::AlreadyInitialized);
    }
    let env = cryptenv::Envelope::from_bytes(body).map_err(|_| SetupError::InvalidEnvelope)?;
    crate::auth_env::write_envelope(data_dir, &domain, &localpart, &env)
        .map_err(|_| SetupError::NotFound)?;

    // Burn the token only after the envelope is safely written. The other order
    // leaves an account that can never be claimed if the write fails.
    let _ = std::fs::remove_file(crate::startup::token_file(data_dir, &domain, &localpart));
    Ok((domain, localpart))
}

/// `GET /relay-info` — what a login screen can show before it has any
/// credential.
///
/// Four fields and no more. It is public, so anything added here is added for
/// everyone on the internet.
///
/// - `type` reports what this relay **is** (`mail` for jmapsmtp), so a client
///   can classify any relay it connects to rather than inferring it from a
///   URL match against its own config.
/// - `domain` is the domain a **new account actually lands under**, which is
///   not necessarily this relay's hostname — accounts on one domain are often
///   provisioned by a relay running under another. A client previewing
///   `username@<relay hostname>` before signup was wrong whenever the two
///   differ. Absent when nothing is open to self-service registration.
///
/// Serialised as a **sorted map**, not a struct.
///
/// Go builds a `map[string]string` here, and `encoding/json` sorts map keys. A
/// struct would emit declaration order and differ on the wire — found by
/// running the two servers side by side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayInfo {
    pub label: String,
    pub color: String,
    /// Always `"mail"` for this relay.
    pub kind: &'static str,
    pub domain: Option<String>,
}

impl serde::Serialize for RelayInfo {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = std::collections::BTreeMap::from([
            ("label", self.label.as_str()),
            ("color", self.color.as_str()),
            ("type", self.kind),
        ]);
        if let Some(domain) = &self.domain {
            map.insert("domain", domain);
        }
        serde::Serialize::serialize(&map, s)
    }
}

pub fn relay_info(cfg: &Config) -> RelayInfo {
    RelayInfo {
        label: cfg.relay_label().to_string(),
        color: cfg.relay_color().to_string(),
        kind: "mail",
        domain: cfg.provision_domain().map(str::to_string),
    }
}

#[cfg(test)]
mod tests;
