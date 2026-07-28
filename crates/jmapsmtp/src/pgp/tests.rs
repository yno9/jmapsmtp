//! Key loading and peer-key storage.
//!
//! Encryption itself is checked by cross-decryption against the Go
//! implementation in `tests/pgp_interop.rs`; nothing here re-tests it.

use super::*;
use pgp::types::KeyDetails as _;
use pretty_assertions::assert_eq;

const PUBLIC_KEY: &str = include_str!("../../../../xtask/fixtures/pgp-public.asc");

fn key() -> SignedPublicKey {
    parse_public_key(PUBLIC_KEY.as_bytes()).expect("the fixture key must parse")
}

#[test]
fn both_armoured_and_binary_keys_parse() {
    let armoured = key();
    let binary = serialize_public_key(&armoured).unwrap();
    let reparsed = parse_public_key(&binary).expect("binary must parse");
    assert_eq!(
        reparsed.fingerprint(),
        armoured.fingerprint(),
        "the same key either way"
    );
}

#[test]
fn something_that_is_not_a_key_is_rejected() {
    for junk in [
        &b""[..],
        b"not a key",
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nbad\n",
    ] {
        assert!(
            parse_public_key(junk).is_err(),
            "{:?}",
            String::from_utf8_lossy(junk)
        );
    }
}

#[test]
fn encrypting_to_nobody_is_an_error_not_an_empty_message() {
    let err = encrypt_inline(b"text", &[]).unwrap_err();
    assert!(err.to_string().contains("no recipients"));
}

// ── account keys ──────────────────────────────────────────────────────────

#[test]
fn an_account_key_is_read_from_pubkey_pgp() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("pubkey.pgp"), PUBLIC_KEY).unwrap();
    let loaded = load_account_key(dir.path()).expect("must load");
    assert_eq!(loaded.fingerprint(), key().fingerprint());
}

/// An account with no key, or an unreadable one, simply gets its mail stored
/// in the clear. Failing the delivery instead would lose the message.
#[test]
fn a_missing_or_broken_account_key_is_none_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load_account_key(dir.path()).is_none());

    std::fs::write(dir.path().join("pubkey.pgp"), "not a key").unwrap();
    assert!(load_account_key(dir.path()).is_none());
}

// ── peer keys ─────────────────────────────────────────────────────────────

fn keydata() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(serialize_public_key(&key()).unwrap())
}

#[test]
fn a_peer_key_round_trips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    store_peer_key(dir.path(), "example.com", "Peer@Example.ORG", &keydata()).expect("store");

    let loaded = load_peer_key(dir.path(), "example.com", "peer@example.org").expect("load");
    assert_eq!(loaded.fingerprint(), key().fingerprint());
}

/// The address is lower-cased in the filename, so the same peer is one file
/// however the header spelled them.
#[test]
fn the_stored_address_is_lower_cased() {
    let dir = tempfile::tempdir().unwrap();
    store_peer_key(dir.path(), "example.com", "MiXeD@Example.COM", &keydata()).unwrap();
    assert!(
        dir.path()
            .join("example.com/peers/mixed@example.com.pgp")
            .exists()
    );
    // And it loads under any casing.
    assert!(load_peer_key(dir.path(), "example.com", "MIXED@EXAMPLE.COM").is_some());
}

/// Stored as the binary packets, not armour — that is the on-disk format.
#[test]
fn a_peer_key_is_stored_unarmoured() {
    let dir = tempfile::tempdir().unwrap();
    store_peer_key(dir.path(), "example.com", "peer@x", &keydata()).unwrap();
    let raw = std::fs::read(peer_key_path(dir.path(), "example.com", "peer@x")).unwrap();
    assert!(!raw.starts_with(b"-----BEGIN"), "must not be armoured");
    assert_eq!(raw, serialize_public_key(&key()).unwrap());
}

/// Folded across lines is how a long header arrives.
#[test]
fn folded_keydata_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let folded = keydata()
        .as_bytes()
        .chunks(60)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n ");
    store_peer_key(dir.path(), "example.com", "peer@x", &folded).expect("store");
    assert!(load_peer_key(dir.path(), "example.com", "peer@x").is_some());
}

/// A header that is not a key must leave nothing behind: a written file that
/// later fails to parse is worse than no file, because it looks like a key
/// the peer has and every send to them silently goes unencrypted anyway.
#[test]
fn a_header_that_is_not_a_key_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["not base64 at all!!", "aGVsbG8="] {
        assert!(store_peer_key(dir.path(), "example.com", "peer@x", bad).is_err());
        assert!(
            !peer_key_path(dir.path(), "example.com", "peer@x").exists(),
            "nothing may be written for {bad:?}"
        );
    }
}

#[test]
fn a_missing_peer_key_is_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load_peer_key(dir.path(), "example.com", "nobody@x").is_none());
}

#[cfg(unix)]
#[test]
fn a_stored_peer_key_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    store_peer_key(dir.path(), "example.com", "peer@x", &keydata()).unwrap();
    let mode = std::fs::metadata(peer_key_path(dir.path(), "example.com", "peer@x"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
}
