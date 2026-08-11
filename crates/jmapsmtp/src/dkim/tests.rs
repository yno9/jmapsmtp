//! Key management. Signing itself is checked against Go in
//! `tests/dkim_interop.rs`, which is the only judge that matters.

use super::*;
use pretty_assertions::assert_eq;

/// The fixture key, so nothing here pays for RSA-2048 generation.
const KEY_PEM: &str = include_str!("../../../../xtask/fixtures/dkim-key.pem");

fn fixture_key() -> RsaPrivateKey {
    parse_pkcs8_pem(KEY_PEM).expect("fixture key")
}

#[test]
fn an_existing_key_is_loaded_never_regenerated() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("key.pem"), KEY_PEM).unwrap();

    let key = load_or_generate_key(dir.path()).unwrap();
    assert_eq!(
        public_key_record(&key),
        public_key_record(&fixture_key()),
        "the key on disk must be the one used"
    );
    // And the file is untouched.
    assert_eq!(
        fs::read_to_string(dir.path().join("key.pem")).unwrap(),
        KEY_PEM
    );
}

/// A key that is published in DNS must survive every restart, so a corrupt
/// file is the one case worth thinking about: the Go original silently
/// generates a new one, which strands the DNS record. Reproduced, because the
/// alternative — refusing to start — takes the whole relay down for one
/// domain's key.
#[test]
fn a_corrupt_key_file_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("key.pem"), "not a key").unwrap();
    // create_new fails on the existing file, so generation cannot persist and
    // the call reports the failure rather than returning an unsaved key.
    assert!(load_or_generate_key(dir.path()).is_err());
}

#[test]
fn a_generated_key_is_persisted_and_reloaded_identically() {
    let dir = tempfile::tempdir().unwrap();
    let first = load_or_generate_key(dir.path()).unwrap();
    assert!(dir.path().join("key.pem").exists());

    let second = load_or_generate_key(dir.path()).unwrap();
    assert_eq!(
        public_key_record(&first),
        public_key_record(&second),
        "a second call must load, not generate"
    );
}

#[cfg(unix)]
#[test]
fn a_generated_key_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    load_or_generate_key(dir.path()).unwrap();
    let mode = fs::metadata(dir.path().join("key.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "group and other must have no access");
}

#[test]
fn the_dns_record_file_names_the_record_to_publish() {
    let dir = tempfile::tempdir().unwrap();
    let key = fixture_key();
    write_record_file(dir.path(), "mail", "example.com", &key).unwrap();

    let content = fs::read_to_string(dir.path().join("dkim-dns.txt")).unwrap();
    assert!(content.starts_with("# Add this TXT record to DNS:\n"));
    assert!(content.contains("# mail._domainkey.example.com\n"));
    assert!(content.contains(&public_key_record(&key)));
    assert!(content.ends_with('\n'));
}

#[test]
fn the_public_key_record_is_stable_for_a_given_key() {
    let key = fixture_key();
    assert_eq!(public_key_record(&key), public_key_record(&key));
    assert!(public_key_record(&key).starts_with("v=DKIM1; k=rsa; p="));
}

#[test]
fn the_signed_header_list_is_the_one_go_uses() {
    // Spelled out rather than referenced: changing it changes what every
    // verifier checks, so it should take a deliberate edit here.
    assert_eq!(
        SIGNED_HEADERS,
        [
            "From",
            "To",
            "Cc",
            "Subject",
            "Date",
            "Message-Id",
            "Content-Type"
        ]
    );
    assert_eq!(DEFAULT_SELECTOR, "default");
}
