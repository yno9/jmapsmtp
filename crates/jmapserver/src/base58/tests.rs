//! The codec, pinned against known-good vectors and round-tripped against
//! itself.

use super::*;
use pretty_assertions::assert_eq;

/// Standard base58check test vectors (Bitcoin's own, widely reused —
/// `bs58`'s test suite carries the same three). Confirms this hand-rolled
/// codec agrees with every other implementation, not just itself.
#[test]
fn it_matches_known_vectors() {
    assert_eq!(encode(b""), "");
    assert_eq!(encode(b"\0"), "1");
    assert_eq!(encode(b"\0\0\0"), "111");
    assert_eq!(encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
    assert_eq!(
        encode(b"The quick brown fox jumps over the lazy dog."),
        "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
    );
    assert_eq!(decode("2NEpo7TZRRrLZSi2U").as_deref(), Some(&b"Hello World!"[..]));
}

#[test]
fn it_round_trips() {
    for len in [0usize, 1, 2, 5, 20, 34, 40] {
        let data: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
        assert_eq!(decode(&encode(&data)).as_deref(), Some(data.as_slice()), "length {len}");
    }
}

/// Leading zero bytes are the one thing an ordinary base conversion loses —
/// `0x00` carries no weight in a positional number, so a naive decode would
/// drop it. base58's own convention (a leading `1` per leading zero byte) is
/// what makes the round trip exact instead of merely numerically equivalent.
#[test]
fn leading_zero_bytes_round_trip_exactly() {
    let data = [0u8, 0, 0, 1, 2, 3];
    let encoded = encode(&data);
    assert!(encoded.starts_with("111"), "{encoded}");
    assert_eq!(decode(&encoded).as_deref(), Some(&data[..]));
}

/// A 0x30/O/I/l typo must not silently decode to something else — those four
/// characters are exactly what base58 excludes to avoid visual ambiguity in
/// the first place.
#[test]
fn a_character_outside_the_alphabet_is_rejected() {
    assert_eq!(decode("0"), None);
    assert_eq!(decode("O"), None);
    assert_eq!(decode("I"), None);
    assert_eq!(decode("l"), None);
    assert_ne!(
        decode("2NEpo7TZRRrLZSi2u"),
        decode("2NEpo7TZRRrLZSi2U"),
        "case-sensitive: 'u' and 'U' are different, both valid, alphabet symbols"
    );
}
