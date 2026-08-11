//! The DID-rooted contact cache. Port of `go-jmapserver/contacts.go`.
//!
//! One JSContact (RFC 9553) Card per resolved contact, stored per account. This
//! is the server-side half of a write-through cache the client also keeps
//! locally: it exists so a **contact binding survives a device change**, or a
//! browser without the vault, by letting a client pull its own history back
//! from its own relay.
//!
//! # What a Card actually binds
//!
//! The DID is the identity (SPEC.md §10-A), and here it lives in `cryptoKeys` —
//! a DID is a URI by construction, so it fits the native JSContact property
//! with no extension. What the card records is *"this address belonged to this
//! DID when I last checked"*, and that is the binding a device change must not
//! lose: an address can move between identities, so a cached address with no
//! DID beside it is worse than no cache.
//!
//! Only biset-specific bookkeeping uses the vendor-extension form the spec
//! requires (`biset.md:verifiedAt`).
//!
//! ```text
//! GET  /contacts        {"cards":[…]}   restore onto a fresh device
//! PUT  /contacts/<uid>  upsert one Card  write-through on each resolve
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A JSContact EmailAddress. `address` is mandatory; nothing else is populated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAddr {
    pub address: String,
}

/// A JSContact CryptoKey. For this use the URI is always a `did:…` string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoKey {
    pub uri: String,
}

/// A JSContact Link — the contact's current relay/service endpoints, as
/// published in their DID document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub uri: String,
}

/// A JSContact Card, restricted to the properties biset populates.
///
/// Field order matters: Go marshals struct fields in declaration order, and
/// this file is compared byte for byte across implementations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    #[serde(rename = "@type")]
    pub kind: String,
    pub version: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub emails: BTreeMap<String, EmailAddr>,
    #[serde(
        rename = "cryptoKeys",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub crypto_keys: BTreeMap<String, CryptoKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, Link>,
    #[serde(
        rename = "biset.md:verifiedAt",
        default,
        skip_serializing_if = "is_zero_i64"
    )]
    pub verified_at: i64,
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

pub fn contacts_path(account_dir: &Path) -> PathBuf {
    account_dir.join("contacts.json")
}

/// Every Card persisted for this account.
///
/// A file that will not parse reads as empty rather than as an error. The cache
/// is a convenience — losing it costs a re-resolve — and failing the whole
/// restore because one card is malformed would lose the rest too.
pub fn read_contacts(account_dir: &Path) -> Vec<Card> {
    let Ok(bytes) = std::fs::read(contacts_path(account_dir)) else {
        return Vec::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Upsert one Card by `uid`.
///
/// Cards arrive one at a time — the client writes through each freshly resolved
/// contact as it learns it — so this merges into the existing list rather than
/// replacing it. A wholesale replace would make every write a chance to lose
/// every other contact.
///
/// The position of an updated card is preserved, so the list does not reshuffle
/// on each write and the file stays diffable.
pub fn put_contact(account_dir: &Path, card: Card) -> std::io::Result<()> {
    let mut cards = read_contacts(account_dir);
    match cards.iter_mut().find(|c| c.uid == card.uid) {
        Some(existing) => *existing = card,
        None => cards.push(card),
    }
    let bytes = jmap_types::go_json::to_vec(&cards)
        .map_err(|e| std::io::Error::other(format!("encoding contacts: {e}")))?;
    std::fs::write(contacts_path(account_dir), bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactError {
    /// The body is not a Card, or has no `uid`.
    InvalidCard,
    /// The `uid` in the body does not match the one in the path.
    UidMismatch,
    Unauthorized,
    NotFound,
}

impl ContactError {
    pub fn status(&self) -> u16 {
        match self {
            ContactError::InvalidCard | ContactError::UidMismatch => 400,
            ContactError::Unauthorized => 401,
            ContactError::NotFound => 404,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            ContactError::InvalidCard => "invalid card",
            ContactError::UidMismatch => "uid mismatch",
            ContactError::Unauthorized => "unauthorized",
            ContactError::NotFound => "not found",
        }
    }
}

/// Parse and check a `PUT /contacts/<uid>` body.
///
/// The path `uid` and the body's must agree. Trusting either alone would let a
/// client overwrite one contact's card by addressing another's — the path is
/// what a caller reasons about, the body is what gets stored, and a mismatch
/// means one of them is wrong.
pub fn parse_upsert(path_uid: &str, body: &[u8]) -> Result<Card, ContactError> {
    if path_uid.is_empty() {
        return Err(ContactError::NotFound);
    }
    let card: Card = serde_json::from_slice(body).map_err(|_| ContactError::InvalidCard)?;
    if card.uid.is_empty() {
        return Err(ContactError::InvalidCard);
    }
    if card.uid != path_uid {
        return Err(ContactError::UidMismatch);
    }
    Ok(card)
}

#[cfg(test)]
mod tests;
