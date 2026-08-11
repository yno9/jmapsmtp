//! did:dht and zbase32. Port of `go-jmapserver/diddht.go`.
//!
//! `did:dht` is self-certifying: the identifier **is** a z-base-32 encoding of
//! the identity's raw ed25519 public key, so verifying anything that key
//! signed needs the string and nothing else — no resolution, no anchor, no
//! network. That is what lets a relay with no identity anchor still support
//! per-device credentials for a did:dht identity.
//!
//! `did:webvh` has no such shortcut: its root key lives only in a resolved
//! log, never in the identifier, so it needs the anchor unconditionally.

/// Zooko Wilcox-O'Hearn's human-oriented base32 — did:dht's own encoding,
/// and **not** RFC 4648's.
const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// How far a signature's timestamp may be from now. Matches the anchor's
/// `BIND_WINDOW_SECONDS`.
pub const FRESHNESS_WINDOW: i64 = 300;

pub fn zbase32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut bits, mut value) = (0u32, 0u32);
    for &b in data {
        value = (value << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode exactly `byte_len` bytes, discarding the encoder's trailing padding
/// bits. `None` when the input has a character outside the alphabet, or does
/// not yield exactly that many bytes.
pub fn zbase32_decode(s: &str, byte_len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(byte_len);
    let (mut bits, mut value) = (0u32, 0u32);
    for c in s.bytes() {
        let idx = ALPHABET.iter().position(|&a| a == c)? as u32;
        value = (value << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out.len() < byte_len {
                out.push(((value >> bits) & 0xff) as u8);
            }
        }
    }
    (out.len() == byte_len).then_some(out)
}

/// The ed25519 public key a `did:dht` identifier names.
pub fn did_dht_root_key(did: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let suffix = did.strip_prefix("did:dht:")?;
    if suffix.is_empty() {
        return None;
    }
    let bytes = zbase32_decode(suffix, 32)?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// The statement a device signs to log in. Byte-identical with biset's
/// `sessionLoginStatement`; three implementations have to agree on one string.
pub fn session_login_statement(did: &str, device_pub_key_b64url: &str, ts: i64) -> String {
    format!("session:{did}:{device_pub_key_b64url}:{ts}")
}

/// The statement an identity signs to authorise a device. Byte-identical with
/// biset's `vouchStatement`.
pub fn vouch_statement(did: &str, device_pub_key_b64url: &str, label: &str, ts: i64) -> String {
    format!("devkey:{did}:{device_pub_key_b64url}:{label}:{ts}")
}

/// Verify a device vouch signed by a `did:dht` identity, without an anchor.
///
/// `false` for any other DID method — the caller falls back to the anchor for
/// those.
#[must_use]
pub fn verify_did_dht_vouch_local(
    did: &str,
    device_pub_key_b64url: &str,
    label: &str,
    ts: i64,
    sig_b64: &str,
    now_unix: i64,
) -> bool {
    let Some(key) = did_dht_root_key(did) else {
        return false;
    };
    if !is_fresh(ts, now_unix) {
        return false;
    }
    let statement = vouch_statement(did, device_pub_key_b64url, label, ts);
    verify_signature(&key, statement.as_bytes(), sig_b64)
}

/// Whether a timestamp is inside the freshness window, in either direction —
/// a signer's clock can be ahead as easily as behind.
pub fn is_fresh(ts: i64, now_unix: i64) -> bool {
    let drift = now_unix - ts;
    drift.abs() <= FRESHNESS_WINDOW
}

/// Check an ed25519 signature carried as **standard** base64, not URL-safe.
#[must_use]
pub fn verify_signature(key: &ed25519_dalek::VerifyingKey, msg: &[u8], sig_b64: &str) -> bool {
    use base64::Engine as _;
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(sig_b64) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
        return false;
    };
    key.verify_strict(msg, &sig).is_ok()
}

/// Decode a device's public key: base64url, raw first then padded, matching
/// the Go original's order.
pub fn decode_device_key(b64url: &str) -> Option<ed25519_dalek::VerifyingKey> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    let bytes = URL_SAFE_NO_PAD
        .decode(b64url)
        .or_else(|_| URL_SAFE.decode(b64url))
        .ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

#[cfg(test)]
mod tests;
