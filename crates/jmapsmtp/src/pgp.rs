//! OpenPGP key handling and inline encryption.
//!
//! Port of the OpenPGP half of `go-jmapsmtp/autocrypt.go` and `wkd.go`.
//!
//! This is **Layer 1** only — encryption at rest, to the recipient's own key,
//! so a message sitting on disk is not readable by whoever holds the disk.
//! Layer 2, the end-to-end encryption between correspondents, happens in the
//! client and never passes through here. Nothing in this module signs: the
//! relay has no key that would mean anything to a reader.
//!
//! Encryption picks a fresh session key every time, so its output cannot be
//! compared byte for byte with the Go implementation's. Cross-decryption is
//! the check instead: what one encrypts, the other opens.

use std::io;
use std::path::Path;

use pgp::composed::{Deserializable, MessageBuilder, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize as _;

#[derive(Debug)]
pub enum PgpError {
    Parse(String),
    Encrypt(String),
    Io(io::Error),
}

impl std::fmt::Display for PgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgpError::Parse(m) => write!(f, "parsing key: {m}"),
            PgpError::Encrypt(m) => write!(f, "encrypting: {m}"),
            PgpError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for PgpError {
    fn from(e: io::Error) -> Self {
        PgpError::Io(e)
    }
}

/// Parse a public key, armoured or binary.
///
/// Both forms occur: an account's own `pubkey.pgp` is armoured, while an
/// Autocrypt peer key is stored as the raw packets the header carried.
pub fn parse_public_key(data: &[u8]) -> Result<SignedPublicKey, PgpError> {
    let looks_armoured = data.starts_with(b"-----BEGIN PGP");
    let parsed = if looks_armoured {
        SignedPublicKey::from_armor_single(io::Cursor::new(data)).map(|(k, _)| k)
    } else {
        SignedPublicKey::from_bytes(io::Cursor::new(data))
    };
    parsed.map_err(|e| PgpError::Parse(e.to_string()))
}

/// Serialise a public key to its binary packets — what an `Autocrypt:`
/// header's `keydata` carries, base64-encoded and unarmoured.
pub fn serialize_public_key(key: &SignedPublicKey) -> Result<Vec<u8>, PgpError> {
    let mut out = Vec::new();
    key.to_writer(&mut out)
        .map_err(|e| PgpError::Parse(e.to_string()))?;
    Ok(out)
}

/// Encrypt to one or more recipients, producing an armoured `PGP MESSAGE`.
///
/// No signing, matching the Go original: this is storage encryption, and the
/// relay's signature would attest to nothing the reader cares about.
///
/// AES-256 under SEIPD v1, the same shape Go's `openpgp.Encrypt` produces for
/// an RSA key. SEIPD v2 would be stronger and is not interoperable with what
/// the existing clients read.
pub fn encrypt_inline(
    plaintext: &[u8],
    recipients: &[SignedPublicKey],
) -> Result<Vec<u8>, PgpError> {
    if recipients.is_empty() {
        return Err(PgpError::Encrypt("no recipients".into()));
    }
    // rpgp is built on rand 0.8, whose RngCore is a different trait from the
    // workspace's rand 0.9. The aliased dependency is the one its bounds
    // accept; mixing them is a compile error, not a silent weakening.
    let mut rng = pgp_rand::rngs::OsRng;

    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    for key in recipients {
        // The encryption subkey when there is one, else the primary — a key
        // whose primary is sign-only cannot receive on it. `encrypt_to_key`
        // takes a sized generic, so the two cases cannot share a variable.
        match encryption_subkey(key) {
            Some(sub) => builder.encrypt_to_key(&mut rng, sub),
            None => builder.encrypt_to_key(&mut rng, key),
        }
        .map_err(|e| PgpError::Encrypt(e.to_string()))?;
    }
    let armored = builder
        .to_armored_string(rng, Default::default())
        .map_err(|e| PgpError::Encrypt(e.to_string()))?;
    Ok(armored.into_bytes())
}

/// The first subkey able to receive, if any.
fn encryption_subkey(key: &SignedPublicKey) -> Option<&pgp::composed::SignedPublicSubKey> {
    use pgp::types::PublicKeyTrait as _;
    key.public_subkeys
        .iter()
        .find(|sub| sub.is_encryption_key())
}

/// Read an account's own public key from `<dir>/pubkey.pgp`.
///
/// `None` for an absent or unparseable key — an account without one simply
/// gets its mail stored in the clear, which is the Go behaviour and the only
/// one that keeps delivery working.
pub fn load_account_key(dir: &Path) -> Option<SignedPublicKey> {
    let data = std::fs::read(dir.join("pubkey.pgp")).ok()?;
    parse_public_key(&data).ok()
}

/// The path an Autocrypt peer key is stored at.
///
/// Per domain rather than per account, and lower-cased: a peer's key is the
/// same key whoever on the domain is talking to them.
pub fn peer_key_path(data_dir: &Path, domain: &str, addr: &str) -> std::path::PathBuf {
    data_dir
        .join(domain)
        .join("peers")
        .join(format!("{}.pgp", addr.to_lowercase()))
}

/// Store a peer's key from an `Autocrypt:` header.
///
/// `keydata` is base64 of the binary packets, possibly folded across lines.
/// It is decoded and **parsed** before anything is written: a header that is
/// not a key must not leave a file that later fails to load.
///
/// Written as the binary packets, not armour — that is the on-disk format.
pub fn store_peer_key(
    data_dir: &Path,
    domain: &str,
    addr: &str,
    keydata: &str,
) -> Result<(), PgpError> {
    use base64::Engine as _;
    let unfolded = crate::autocrypt::unfold_keydata(keydata);
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&unfolded)
        .map_err(|e| PgpError::Parse(format!("base64: {e}")))?;
    parse_public_key(&raw)?;

    let path = peer_key_path(data_dir, domain, addr);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private(&path, &raw)?;
    tracing::info!("[autocrypt] stored key for {addr} in {domain}/peers");
    Ok(())
}

/// Load a stored peer key. `None` when absent or unparseable.
pub fn load_peer_key(data_dir: &Path, domain: &str, addr: &str) -> Option<SignedPublicKey> {
    let data = std::fs::read(peer_key_path(data_dir, domain, addr)).ok()?;
    parse_public_key(&data).ok()
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests;
