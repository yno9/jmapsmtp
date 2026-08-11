//! Unit tests for the parts the interop corpus does not isolate.
//!
//! The corpus in `tests/autocrypt_interop.rs` is the real check — it compares
//! against the Go functions byte for byte.

use super::*;
use pretty_assertions::assert_eq;

#[test]
fn keydata_folded_across_lines_is_put_back_together() {
    assert_eq!(unfold_keydata("mDME\r\n ZAAA\tBBB CCC"), "mDMEZAAABBBCCC");
    assert_eq!(unfold_keydata("unfolded"), "unfolded");
    assert_eq!(unfold_keydata(""), "");
}

#[test]
fn a_new_header_lands_last_in_the_block() {
    let out = inject_chat_version(b"From: a@x\r\nSubject: s\r\n\r\nbody");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "From: a@x\r\nSubject: s\r\nChat-Version: 1.0\r\n\r\nbody"
    );
}

#[test]
fn an_autocrypt_header_carries_the_address_and_key() {
    let out = inject_autocrypt(b"From: a@x\r\n\r\nbody", "a@x", "KEYDATA");
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("Autocrypt: addr=a@x; prefer-encrypt=mutual; keydata=KEYDATA\r\n"));
    assert!(out.ends_with("\r\n\r\nbody"));
}

/// Injection and parsing are each other's inverse for the fields that matter.
#[test]
fn an_injected_header_parses_back() {
    let out = inject_autocrypt(b"From: a@x\r\n\r\nbody", "alice@example.com", "mDMEZAAA");
    let out = String::from_utf8(out).unwrap();
    let value = out
        .lines()
        .find_map(|l| l.strip_prefix("Autocrypt: "))
        .expect("the header must be there");
    let (addr, key) = parse_autocrypt_header(value);
    assert_eq!(addr, "alice@example.com");
    assert_eq!(key, "mDMEZAAA");
}

/// Nothing here may destroy a message it cannot process.
#[test]
fn a_message_with_no_separator_is_returned_unchanged() {
    let raw = b"From: a@x\r\nSubject: s\r\n";
    assert_eq!(inject_chat_version(raw), raw.to_vec());
    assert_eq!(inject_autocrypt(raw, "a@x", "K"), raw.to_vec());
    assert!(pgp_mime_wrap_inline(raw).is_none());
}

#[test]
fn the_wrapper_drops_content_headers_and_keeps_the_rest() {
    let raw = b"From: a@x\r\n\
                Content-Type: text/plain\r\n\
                Content-Transfer-Encoding: 8bit\r\n\
                X-Keep: yes\r\n\
                \r\n\
                -----BEGIN PGP MESSAGE-----\n\
                data\n\
                -----END PGP MESSAGE-----\r\n";
    let out = String::from_utf8(pgp_mime_wrap_inline(raw).unwrap()).unwrap();
    assert!(out.contains("From: a@x\r\n"));
    assert!(out.contains("X-Keep: yes\r\n"));
    assert!(!out.contains("Content-Transfer-Encoding: 8bit"));
    // Exactly one Content-Type, the new one.
    assert_eq!(out.matches("Content-Type: text/plain").count(), 0);
    assert!(out.contains("Content-Type: multipart/encrypted; "));
}

/// The boundary is a hash of the ciphertext, so it cannot collide with
/// anything inside it — and it makes the whole output deterministic.
#[test]
fn the_boundary_is_derived_from_the_pgp_block() {
    let one = b"From: a@x\r\n\r\n-----BEGIN PGP MESSAGE-----\nAAA\n-----END PGP MESSAGE-----";
    let two = b"From: a@x\r\n\r\n-----BEGIN PGP MESSAGE-----\nBBB\n-----END PGP MESSAGE-----";
    let boundary = |raw: &[u8]| {
        String::from_utf8(pgp_mime_wrap_inline(raw).unwrap())
            .unwrap()
            .split("boundary=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string()
    };
    assert_ne!(boundary(one), boundary(two));
    assert_eq!(boundary(one), boundary(one), "and it is stable");
    assert!(boundary(one).starts_with("biset-pgp-"));
    assert_eq!(boundary(one).len(), "biset-pgp-".len() + 12);
}

#[test]
fn the_armour_is_converted_to_crlf_for_smtp() {
    let raw = b"From: a@x\r\n\r\n-----BEGIN PGP MESSAGE-----\nline\n-----END PGP MESSAGE-----";
    let out = String::from_utf8(pgp_mime_wrap_inline(raw).unwrap()).unwrap();
    assert!(out.contains("-----BEGIN PGP MESSAGE-----\r\nline\r\n-----END PGP MESSAGE-----"));
}
