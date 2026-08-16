//! The statements, the freshness window, and the signature checks.
//!
//! Moved here from `diddht/tests.rs`: none of this was ever about a DID
//! method. What went with did:dht was the local-verification path, which is
//! the one thing that genuinely depended on the identifier being the key.

use super::*;
use pretty_assertions::assert_eq;

const WEBVH: &str = "did:webvh:QmSCIDPlaceholder1111111111111111111111111111:biset.md:dids:alice";

fn identity() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
}

/// The DID is opaque to the relay. A webvh DID has an optional port and
/// arbitrary path segments, so anything that splits on `:` and reinterprets
/// gets it wrong — and the signed statements embed the DID verbatim, colons
/// and all.
#[test]
fn the_signed_statement_embeds_a_webvh_did_verbatim() {
    assert_eq!(
        vouch_statement(WEBVH, "KEY", "Laptop", 1),
        format!("devkey:{WEBVH}:KEY:Laptop:1"),
        "no normalisation, no re-encoding — biset signs this exact string"
    );
    assert_eq!(
        session_login_statement(WEBVH, "KEY", "mail.biset.md", 1),
        format!("session:{WEBVH}:KEY:mail.biset.md:1")
    );
}

// ── statements ────────────────────────────────────────────────────────────

/// Three implementations — this one, biset's client and the anchor — have to
/// agree on these strings byte for byte.
#[test]
fn the_signed_statements_have_their_exact_shape() {
    assert_eq!(
        session_login_statement("did:dht:abc", "KEY", "mail.example.com", 1700000000),
        "session:did:dht:abc:KEY:mail.example.com:1700000000"
    );
    assert_eq!(
        vouch_statement("did:dht:abc", "KEY", "MacBook", 1700000000),
        "devkey:did:dht:abc:KEY:MacBook:1700000000"
    );
    // An empty label still produces the separator, not a collapsed string.
    assert_eq!(vouch_statement("d", "K", "", 1), "devkey:d:K::1");
}

// ── freshness ─────────────────────────────────────────────────────────────

/// The window is symmetric: a signer's clock can be ahead as easily as behind.
#[test]
fn the_freshness_window_is_symmetric() {
    let now = 1_700_000_000;
    assert!(is_fresh(now, now));
    assert!(is_fresh(now - FRESHNESS_WINDOW, now));
    assert!(is_fresh(now + FRESHNESS_WINDOW, now));
    assert!(!is_fresh(now - FRESHNESS_WINDOW - 1, now));
    assert!(!is_fresh(now + FRESHNESS_WINDOW + 1, now));
}

#[test]
fn the_window_is_the_anchors_five_minutes() {
    assert_eq!(FRESHNESS_WINDOW, 300);
}

// ── signatures ────────────────────────────────────────────────────────────

/// Signatures ride as **standard** base64, not URL-safe.
#[test]
fn a_url_safe_signature_is_rejected() {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let key = identity();
    // A message whose signature contains a character the two alphabets differ
    // on, so the encoding actually matters.
    let msg = b"the message";
    let sig = key.sign(msg);
    let standard = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    assert!(verify_signature(&key.verifying_key(), msg, &standard));

    let url_safe = base64::engine::general_purpose::URL_SAFE.encode(sig.to_bytes());
    if url_safe != standard {
        assert!(
            !verify_signature(&key.verifying_key(), msg, &url_safe),
            "URL-safe base64 must not be accepted where standard is specified"
        );
    }
}

#[test]
fn a_malformed_signature_is_rejected_not_a_panic() {
    let key = identity().verifying_key();
    for sig in ["", "not base64!!", "AAAA", "QUJD"] {
        assert!(!verify_signature(&key, b"msg", sig), "{sig}");
    }
}

/// Device keys arrive base64url, raw or padded.
#[test]
fn device_keys_decode_in_either_url_safe_form() {
    use base64::Engine as _;
    let key = identity().verifying_key();
    for encoded in [
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes()),
        base64::engine::general_purpose::URL_SAFE.encode(key.to_bytes()),
    ] {
        assert_eq!(
            decode_device_key(&encoded).unwrap().to_bytes(),
            key.to_bytes(),
            "{encoded}"
        );
    }
    assert!(decode_device_key("too short").is_none());
}
