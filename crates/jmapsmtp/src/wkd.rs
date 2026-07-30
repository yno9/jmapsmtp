//! Web Key Directory and the PGP key endpoints. Port of `go-jmapsmtp/wkd.go`.
//!
//! Four routes with three very different exposures, which is the thing to keep
//! straight:
//!
//! | route | auth | why |
//! |---|---|---|
//! | `/.well-known/openpgpkey/policy` | none | a WKD marker; an empty 200 *is* the answer |
//! | `/.well-known/openpgpkey/hu/<hash>` | none | **a public directory by design** — a stranger must be able to find a key before they can encrypt to you |
//! | `/pgp/pubkey` (PUT) | account | writing your own key |
//! | `/pgp/privkey` (GET/PUT) | account | the client-side-encrypted private key blob |
//! | `/pgp/peerkey` (GET/PUT) | account | Autocrypt keys gathered from mail |
//!
//! `/pgp/privkey` holds a blob the client encrypted before sending, so the
//! relay cannot read it — but it is still the private key, and it leaves only
//! against the account's own credential.

use std::path::{Path, PathBuf};

/// The WKD local part hash: `zbase32(sha1(lowercase(localpart)))`.
///
/// SHA-1 here is not a security choice this port gets to make — it is what the
/// WKD draft specifies and what every WKD client computes, so any other hash
/// makes the directory unreadable. It is used as a lookup key, never as a
/// signature or an integrity check.
///
/// The Go implementation has two copies of z-base-32, one here and one in
/// `diddht.go`. Verified to agree by running both; this port shares the one
/// implementation (SPEC.md §4).
pub fn wkd_hash(localpart: &str) -> String {
    use sha1::Digest as _;
    let digest = sha1::Sha1::digest(localpart.to_lowercase().as_bytes());
    jmapserver::diddht::zbase32_encode(&digest)
}

pub fn pubkey_file(data_dir: &Path, domain: &str, localpart: &str) -> PathBuf {
    crate::auth_env::account_dir(data_dir, domain, localpart).join("pubkey.pgp")
}

/// The client-side-encrypted private key blob.
pub fn privkey_enc_file(data_dir: &Path, domain: &str, localpart: &str) -> PathBuf {
    crate::auth_env::account_dir(data_dir, domain, localpart).join("privkey.enc")
}

/// What a WKD lookup resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WkdLookup {
    /// Serve this account's own key.
    UserKey {
        domain: String,
        localpart: String,
    },
    /// Serve the relay-wide key, if one is loaded.
    GlobalKey,
    NotFound,
}

/// Resolve `/.well-known/openpgpkey/hu/<hash>?l=<localpart>`.
///
/// A per-account key wins over the relay-wide one. The `l=` parameter is
/// **checked against the hash**, not trusted: the hash is what a WKD client
/// computed from the address it has, and honouring a mismatched `l=` would let
/// a caller ask for one person's key under another's hash.
///
/// Note what happens with no `l=` at all: the request falls through to the
/// global key. The hash alone is not reversible, so there is nothing to look up
/// per-account — that is a property of WKD, not a shortcut here.
///
/// # The localpart is folded before the account lookup, unlike in Go
///
/// `wkdHash` lowercases its input, so the hash comparison is case-insensitive.
/// The Go account lookup that follows is not — it indexes `domCfg.Accounts`
/// with the raw parameter. So `?l=Alice` passes the hash check ("this is
/// alice") and then misses the account ("no such localpart"), **falling through
/// to the relay-wide key**.
///
/// Measured on the oracle with a relay key configured that differs from
/// alice's: `?l=alice` served alice's key, `?l=Alice` served the relay's.
///
/// A sender whose address book holds `Alice@a.test` therefore encrypts to a key
/// **the relay holds and alice does not** — silently, while believing the mail
/// is end-to-end encrypted. Folding here is safe: account keys are always
/// lowercase (provisioning folds usernames), so folding can only ever find the
/// one account the hash already identified, never a different user's.
/// SPEC.md §11.15.
pub fn resolve_wkd(
    cfg: &crate::config::Config,
    hash: &str,
    localpart_param: &str,
    has_global_key: bool,
    has_user_key: impl Fn(&str, &str) -> bool,
) -> WkdLookup {
    let localpart = localpart_param.to_lowercase();
    if !localpart.is_empty() && wkd_hash(&localpart) == hash {
        // Sorted, because Go ranges over the domain map here: with the same
        // localpart configured on two domains its answer varies between runs,
        // and which key a stranger gets should not (SPEC.md §11.5).
        for (domain, dom_cfg) in &cfg.domains {
            if dom_cfg.accounts.contains_key(&localpart) && has_user_key(domain, &localpart) {
                return WkdLookup::UserKey {
                    domain: domain.clone(),
                    localpart: localpart.clone(),
                };
            }
        }
    }
    if !has_global_key {
        return WkdLookup::NotFound;
    }
    // An `l=` that does not match the hash is refused rather than ignored.
    // Falling back to the global key here would answer a question the caller
    // did not ask, having just proved it was asking inconsistently.
    if !localpart.is_empty() && wkd_hash(&localpart) != hash {
        return WkdLookup::NotFound;
    }
    WkdLookup::GlobalKey
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The payload is not a parseable OpenPGP public key.
    InvalidKey,
    /// `/pgp/peerkey` with no `addr`.
    AddrRequired,
    NotFound,
    Unauthorized,
}

impl KeyError {
    pub fn status(&self) -> u16 {
        match self {
            KeyError::InvalidKey | KeyError::AddrRequired => 400,
            KeyError::Unauthorized => 401,
            KeyError::NotFound => 404,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            KeyError::InvalidKey => "invalid PGP key",
            KeyError::AddrRequired => "addr required",
            KeyError::NotFound => "not found",
            KeyError::Unauthorized => "unauthorized",
        }
    }
}

/// Store an account's own public key, after checking it parses.
///
/// Validated before writing for the reason `store_peer_key` gives: a file that
/// cannot be read back later is worse than no file, because the account looks
/// like it has a key and everything addressed to it silently goes out in the
/// clear.
///
/// The **armored bytes as uploaded** are stored, not a re-serialisation, so a
/// round trip is byte-identical and the user's own key comes back exactly as
/// they provided it.
pub fn store_pubkey(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    armored: &[u8],
) -> Result<(), KeyError> {
    crate::pgp::parse_public_key(armored).map_err(|_| KeyError::InvalidKey)?;
    let dir = crate::auth_env::account_dir(data_dir, domain, localpart);
    std::fs::create_dir_all(&dir).map_err(|_| KeyError::NotFound)?;
    crate::write_private(&dir.join("pubkey.pgp"), armored).map_err(|_| KeyError::NotFound)
}

/// An account's public key in **binary** OpenPGP form, which is what WKD
/// serves — clients fetching from a directory expect packets, not armor.
pub fn serve_pubkey(data_dir: &Path, domain: &str, localpart: &str) -> Option<Vec<u8>> {
    let armored = std::fs::read(pubkey_file(data_dir, domain, localpart)).ok()?;
    let key = crate::pgp::parse_public_key(&armored).ok()?;
    let binary = crate::pgp::serialize_public_key(&key).ok()?;
    // An empty serialisation is a failure, not an empty key: answering 200 with
    // no bytes tells a client it found a key and then hands it nothing.
    (!binary.is_empty()).then_some(binary)
}

/// The stored private key blob. Opaque — encrypted client-side, so this is
/// bytes in and bytes out.
pub fn read_privkey(data_dir: &Path, domain: &str, localpart: &str) -> Option<Vec<u8>> {
    std::fs::read(privkey_enc_file(data_dir, domain, localpart)).ok()
}

/// Store the private key blob **without inspecting it**.
///
/// Deliberately unvalidated, unlike [`store_pubkey`]: the relay cannot parse
/// what it cannot decrypt, and a validation step here would be a claim to
/// understand the contents that is not true. The format is the client's
/// business.
pub fn store_privkey(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    blob: &[u8],
) -> std::io::Result<()> {
    let dir = crate::auth_env::account_dir(data_dir, domain, localpart);
    std::fs::create_dir_all(&dir)?;
    crate::write_private(&dir.join("privkey.enc"), blob)
}

/// An Autocrypt peer key, looked up by address.
///
/// Peer keys are **per domain**, not per account: they are gathered from
/// incoming mail, and two accounts on one domain writing to the same person
/// should not each have to rediscover their key.
pub fn peer_key_path(data_dir: &Path, domain: &str, addr: &str) -> PathBuf {
    crate::pgp::peer_key_path(data_dir, domain, addr)
}

#[cfg(test)]
mod tests;
