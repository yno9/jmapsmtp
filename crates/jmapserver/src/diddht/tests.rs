//! zbase32 and the signed statements.
//!
//! The statements are checked against the Go implementation in
//! `tests/devicekeys_interop.rs`; these pin the encoding and the parsing.

use super::*;
use pretty_assertions::assert_eq;

/// The value the Go implementation produces, confirmed by running it.
#[test]
fn zbase32_matches_the_go_implementation() {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(b"alice");
    assert_eq!(zbase32_encode(&digest), "kei1q4tipxxu1yj79k9kfukdhfy631xe");
}

#[test]
fn zbase32_round_trips() {
    for len in [0usize, 1, 5, 20, 32, 33] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let encoded = zbase32_encode(&data);
        assert_eq!(
            zbase32_decode(&encoded, len).as_deref(),
            Some(data.as_slice()),
            "length {len}"
        );
    }
}

/// The alphabet is Zooko's, not RFC 4648's — decoding must reject a character
/// from the wrong one rather than quietly mapping it.
#[test]
fn a_character_outside_the_alphabet_is_rejected() {
    // 'l', 'v' and '2' are absent from zbase32.
    assert_eq!(zbase32_decode("lvvv", 2), None);
    assert_eq!(zbase32_decode("22222", 3), None);
    assert_eq!(zbase32_decode("ABC", 1), None, "and it is case-sensitive");
}

/// Asking for **more** bytes than the input holds fails; asking for fewer
/// silently truncates. That asymmetry is the Go original's — its loop stops
/// filling once `byteLen` bytes are in hand and then only checks that it got
/// that many — and it does not matter for did:dht, where the length is always
/// 32. Pinned so the contract is stated rather than assumed.
#[test]
fn a_short_request_truncates_and_a_long_one_fails() {
    let encoded = zbase32_encode(&[1, 2, 3]);
    assert_eq!(
        zbase32_decode(&encoded, 3).as_deref(),
        Some(&[1u8, 2, 3][..])
    );
    assert_eq!(zbase32_decode(&encoded, 32), None, "not enough input");
    assert_eq!(
        zbase32_decode(&encoded, 1).as_deref(),
        Some(&[1u8][..]),
        "extra input is ignored once the request is satisfied"
    );
}

// ── did:dht ───────────────────────────────────────────────────────────────

fn identity() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
}

#[test]
fn a_did_dht_identifier_yields_its_own_key() {
    let key = identity().verifying_key();
    let did = format!("did:dht:{}", zbase32_encode(&key.to_bytes()));
    assert_eq!(did_dht_root_key(&did).unwrap().to_bytes(), key.to_bytes());
}

#[test]
fn anything_that_is_not_a_did_dht_yields_nothing() {
    for did in [
        "",
        "did:dht:",
        "did:webvh:example.com",
        "did:dht:not-valid-zbase32-l",
        // Right alphabet, wrong length.
        "did:dht:ybnd",
    ] {
        assert!(did_dht_root_key(did).is_none(), "{did}");
    }
}

// ── statements ────────────────────────────────────────────────────────────

/// Three implementations — this one, biset's client and the anchor — have to
/// agree on these strings byte for byte.
#[test]
fn the_signed_statements_have_their_exact_shape() {
    assert_eq!(
        session_login_statement("did:dht:abc", "KEY", 1700000000),
        "session:did:dht:abc:KEY:1700000000"
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
