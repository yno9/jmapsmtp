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

// ── did:webvh must never resolve locally ──────────────────────────────────

/// biset's canonical shape, from `buildBisetWebvhDid`: the username lives in
/// the path so every account on a relay shares one domain.
const WEBVH: &str = "did:webvh:QmSCIDPlaceholder1111111111111111111111111111:biset.md:dids:alice";

/// The reason `did:webvh` has no local shortcut, stated as a test.
///
/// A did:dht identifier **is** its root public key, z-base-32 encoded. A
/// did:webvh SCID looks like it plays the same role — it is called
/// self-certifying, and it is: `base58btc(multihash(JCS(genesis log entry),
/// sha256))` (biset `src/did/webvh/scid.ts`). But it certifies the **DID
/// document log**, not a signing key. The current key is only in the resolved
/// log, so there is nothing here to verify a signature against, and the anchor
/// is the only path.
///
/// Treating the first segment as a key would let anyone forge a device vouch
/// for any webvh identity by choosing their own.
#[test]
fn a_did_webvh_never_yields_a_local_root_key() {
    assert!(did_dht_root_key(WEBVH).is_none());
    assert!(
        did_dht_root_key(&WEBVH.replace("did:webvh:", "did:dht:")).is_none(),
        "not even with the method swapped: an SCID is 46 base58 chars and \
         cannot decode to a 32-byte key"
    );
}

/// The adversarial version, which the length coincidence above does *not*
/// cover: a webvh-shaped DID whose first segment is a genuine z-base-32
/// encoding of an attacker's key, with a correctly signed vouch to match.
///
/// The method prefix is what refuses it. That is the barrier being tested —
/// the SCID's 46-character length happening not to decode to 32 bytes is a
/// coincidence, not a defence, and must not be the thing standing between an
/// attacker and someone else's inbox.
#[test]
fn a_webvh_did_carrying_a_real_key_in_its_scid_slot_is_still_refused() {
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let fake_scid = zbase32_encode(&attacker.verifying_key().to_bytes());
    let did = format!("did:webvh:{fake_scid}:biset.md:dids:alice");
    let ts = 1_700_000_000;

    // A signature that would verify, if anything looked at it.
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let sig = base64::engine::general_purpose::STANDARD.encode(
        attacker
            .sign(vouch_statement(&did, "DEVICE", "Laptop", ts).as_bytes())
            .to_bytes(),
    );

    assert!(
        !verify_did_dht_vouch_local(&did, "DEVICE", "Laptop", ts, &sig, ts),
        "a did:webvh vouch must reach the anchor or fail — never verify here"
    );

    // The same key and signature under did:dht *do* verify, which is what
    // makes the refusal above about the method and nothing else.
    let honest = format!("did:dht:{fake_scid}");
    let sig = base64::engine::general_purpose::STANDARD.encode(
        attacker
            .sign(vouch_statement(&honest, "DEVICE", "Laptop", ts).as_bytes())
            .to_bytes(),
    );
    assert!(verify_did_dht_vouch_local(
        &honest, "DEVICE", "Laptop", ts, &sig, ts
    ));
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
        session_login_statement(WEBVH, "KEY", 1),
        format!("session:{WEBVH}:KEY:1")
    );
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
