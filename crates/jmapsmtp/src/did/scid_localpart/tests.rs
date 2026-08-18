//! The SCID<->localpart round trip, and what it rejects.

use super::*;
use pretty_assertions::assert_eq;

/// A real SCID from this design's own discussion (biset.md, 2026-08-18) —
/// confirmed 34 bytes (`12 20` = the SHA-256 multihash prefix, then the
/// digest) by decoding it directly, the same shape every did:webvh SCID has.
const EXAMPLE_SCID: &str = "QmWpmYGewT1KjvvugqN7SDpTQzLEP2Z9CcDSXXdHtsD5t8";

#[test]
fn it_round_trips_a_real_scid() {
    let localpart = to_localpart(EXAMPLE_SCID).expect("a real SCID decodes");
    assert_eq!(from_localpart(&localpart).as_deref(), Some(EXAMPLE_SCID));
}

/// The whole point: two SCIDs differing only in case must project to two
/// DIFFERENT localparts, not the same one — this is exactly the collision
/// `.to_lowercase()` alone would have created. Constructed rather than using
/// [`EXAMPLE_SCID`]: flipping an arbitrary character's case does not always
/// yield another 34-byte-decodable string (base58 has no fixed-width
/// alignment), so this builds a synthetic SCID and picks a position
/// confirmed — by direct decode, not assumption — to still decode to 34
/// bytes after the flip, so the assertion below is never vacuously skipped.
#[test]
fn case_differing_scids_project_to_different_localparts() {
    let data: Vec<u8> = (0..34u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
    let scid = base58::encode(&data);

    let mut chars: Vec<char> = scid.chars().collect();
    let flip_at = chars
        .iter()
        .position(|c| c.is_ascii_alphabetic())
        .expect("a 34-byte encoding has at least one letter");
    chars[flip_at] = if chars[flip_at].is_ascii_uppercase() {
        chars[flip_at].to_ascii_lowercase()
    } else {
        chars[flip_at].to_ascii_uppercase()
    };
    let flipped: String = chars.into_iter().collect();
    assert_ne!(scid, flipped);

    let localpart = to_localpart(&scid).expect("the constructed SCID decodes");
    let flipped_localpart = to_localpart(&flipped).expect("flipping one letter's case still decodes to 34 bytes");
    assert_ne!(localpart, flipped_localpart, "case-flipped SCID must not project to the same localpart");
}

/// The projection is itself lowercase-only — that is the entire property
/// being bought here: it must survive this relay's pervasive
/// `.to_lowercase()` folding unchanged.
#[test]
fn the_localpart_is_already_lowercase() {
    let localpart = to_localpart(EXAMPLE_SCID).unwrap();
    assert_eq!(localpart, localpart.to_lowercase());
}

#[test]
fn wrong_length_is_rejected() {
    assert_eq!(to_localpart("not-a-real-scid"), None);
    assert_eq!(to_localpart(""), None);
}

#[test]
fn a_foreign_localpart_is_rejected() {
    assert_eq!(from_localpart("not-a-zbase32-localpart-at-all"), None);
    assert_eq!(from_localpart(""), None);
}
