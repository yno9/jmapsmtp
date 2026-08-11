//! The encoding, pinned against the Go implementation.
//!
//! These moved here from `diddht/tests.rs` when did:dht was removed. They are
//! not about DIDs: WKD hashes a localpart with this alphabet, and that is the
//! caller that survives.

use super::*;
use pretty_assertions::assert_eq;

/// The value the Go implementation produces, confirmed by running it.
///
/// It is also the WKD hash of `alice`, which is what makes this the one
/// assertion that matters most: a stranger's client computes the same string
/// from the address and asks for it by name.
#[test]
fn it_matches_the_go_implementation() {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(b"alice");
    assert_eq!(encode(&digest), "kei1q4tipxxu1yj79k9kfukdhfy631xe");
}

#[test]
fn it_round_trips() {
    for len in [0usize, 1, 5, 20, 32, 33] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let encoded = encode(&data);
        assert_eq!(
            decode(&encoded, len).as_deref(),
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
    assert_eq!(decode("lvvv", 2), None);
    assert_eq!(decode("22222", 3), None);
    assert_eq!(decode("ABC", 1), None, "and it is case-sensitive");
}

/// Asking for **more** bytes than the input holds fails; asking for fewer
/// silently truncates. That asymmetry is the Go original's — its loop stops
/// filling once `byteLen` bytes are in hand and then only checks that it got
/// that many. Pinned so the contract is stated rather than assumed.
#[test]
fn a_short_request_truncates_and_a_long_one_fails() {
    let encoded = encode(&[1, 2, 3]);
    assert_eq!(decode(&encoded, 3).as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(decode(&encoded, 32), None, "not enough input");
    assert_eq!(
        decode(&encoded, 1).as_deref(),
        Some(&[1u8][..]),
        "extra input is ignored once the request is satisfied"
    );
}
