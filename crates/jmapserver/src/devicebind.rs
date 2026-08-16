//! The signed statements a device binding is made of, and the checks on them.
//!
//! Named after biset's `src/did/devicebind.ts`, which is where the strings come
//! from. Three implementations — biset, this relay, the anchor — have to agree
//! on two of them byte for byte:
//!
//! ```text
//! DID root key
//!   └─ vouch:   devkey:<did>:<devicePubKey>:<label>:<ts>              signed by the root key
//!        └─ device key            <acct>/devices/<pubkey>.json
//!             └─ session: session:<did>:<devicePubKey>:<relayHost>:<ts>  signed by the device
//! ```
//!
//! The session statement grew a `relayHost` segment (2026-08-16) it had been
//! missing relative to `vouch:` above — without it, a device signature
//! captured by one relay verified just as well replayed against a DIFFERENT
//! relay this device is also registered with, inside the freshness window.
//! Still not a server-issued nonce: each relay reports the host IT observed
//! (same shape `bind:`'s check uses), which stops a cross-relay replay but not
//! a same-relay one inside the same window — a real gap, not assumed closed.
//!
//! None of this is specific to a DID method. It lived in a module called
//! `diddht` until did:dht was removed, and that misfiling is why the removal
//! first looked as though it would take device binding with it: a statement
//! format was filed under one of the methods that happens to use it.
//!
//! What *was* method-specific went with did:dht — a `did:dht` identifier is a
//! z-base-32 encoding of the identity's raw ed25519 key, so a vouch could be
//! verified from the string alone, with no anchor and no network. `did:webvh`
//! has no such shortcut: its root key lives only in a resolved log, never in
//! the identifier, so every binding now needs the anchor.

/// How far a signature's timestamp may be from now. Matches the anchor's
/// `BIND_WINDOW_SECONDS`.
pub const FRESHNESS_WINDOW: i64 = 300;

/// The statement a device signs to log in. Byte-identical with biset's
/// `sessionLoginStatement`; three implementations have to agree on one string.
pub fn session_login_statement(
    did: &str,
    device_pub_key_b64url: &str,
    relay_host: &str,
    ts: i64,
) -> String {
    format!("session:{did}:{device_pub_key_b64url}:{relay_host}:{ts}")
}

/// The statement an identity signs to authorise a device. Byte-identical with
/// biset's `vouchStatement`.
pub fn vouch_statement(did: &str, device_pub_key_b64url: &str, label: &str, ts: i64) -> String {
    format!("devkey:{did}:{device_pub_key_b64url}:{label}:{ts}")
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
