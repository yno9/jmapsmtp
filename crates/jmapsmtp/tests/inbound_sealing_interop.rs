//! Mail this relay **receives** is sealed to the recipient's own key.
//!
//! Go encrypts an inbound body with the recipient's public key at the moment
//! it files the message (`main.go`, right after the id, mailbox and receive
//! time), marking a body the sender already encrypted `$e2e` instead. This
//! port had no such path: `seal_stored_body` existed and was reachable only
//! from `submit.rs`, so mail the relay *sent* was sealed and mail it
//! *received* sat on disk in the clear.
//!
//! That is a confidentiality difference rather than a visible one, which is
//! exactly why it survived every comparison: a plaintext body and a sealed one
//! both deliver, both display, and only the disk tells them apart. It sat in
//! SPEC.md §11.23 as "not ported" while running in production.
//!
//! # What is compared, and why not the ciphertext
//!
//! PGP encryption picks a fresh session key per message, so two implementations
//! encrypting the same plaintext produce different bytes by design. Comparing
//! ciphertexts would compare randomness.
//!
//! What matters is that **Go can read what this port writes**: the recipient's
//! client is on the other side of this, and the Go helper decrypting with the
//! account's private key is the closest stand-in for it. So the assertion is a
//! round trip through the oracle's own OpenPGP implementation, plus a check
//! that nothing plaintext was left behind.
//!
//! `PGP_INTEROP=required` — the same helper `pgp_interop` needs.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;

fn require_helper() -> Option<PathBuf> {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/pgp-interop")
        .canonicalize()
        .ok()?;
    if bin.exists() {
        return Some(bin);
    }
    assert!(
        std::env::var("PGP_INTEROP").as_deref() != Ok("required"),
        "the Go PGP helper is missing — run `just interop`"
    );
    None
}

/// Ask Go to decrypt, with the private key the test generated.
fn go_decrypt(bin: &Path, private_key_armored: &str, ciphertext: &str) -> String {
    let request = serde_json::json!({
        "private_key": private_key_armored,
        "ciphertext": ciphertext,
    })
    .to_string();
    let mut child = Command::new(bin)
        .arg("decrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the helper should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "the helper should answer JSON: {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert!(
        v["err"].as_str().unwrap_or("").is_empty(),
        "Go could not decrypt what this port sealed: {v}"
    );
    let b64 = v["plaintext"].as_str().expect("plaintext field");
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("plaintext base64"),
    )
    .expect("plaintext utf-8")
}

/// The keypair `pgp_interop` uses — generated once with the Go implementation,
/// so a decrypt failure here is about this port's ciphertext and not about a
/// key rpgp happened to produce.
const PUBLIC_KEY: &str = include_str!("../../../xtask/fixtures/pgp-public.asc");
const PRIVATE_KEY: &str = include_str!("../../../xtask/fixtures/pgp-private.asc");

/// A throwaway account directory with that public key in it.
fn recipient_with_key() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("pubkey.pgp"), PUBLIC_KEY.as_bytes()).expect("write pubkey");
    dir
}

const PLAIN: &[u8] = b"From: someone@elsewhere.invalid\r\n\
     To: y@a.test\r\n\
     Subject: sealed on arrival\r\n\
     \r\n\
     the secret plaintext\r\n";

fn store(raw: &[u8], dir: &Path) -> jmap_types::email::Email {
    let received = jmap_types::JmapTime::now_utc();
    let mut msg = jmapserver::parse_mime_email(raw, received.as_str()).expect("parses");
    jmapsmtp::delivery::seal_inbound(&mut msg, "y@a.test", dir, raw);
    msg
}

fn bodies(msg: &jmap_types::email::Email) -> Vec<String> {
    msg.body_values.values().map(|v| v.value.clone()).collect()
}

#[test]
fn a_delivered_body_is_sealed_and_the_oracle_can_read_it() {
    let Some(bin) = require_helper() else { return };
    let dir = recipient_with_key();
    let msg = store(PLAIN, dir.path());

    let sealed = bodies(&msg);
    assert!(
        sealed
            .iter()
            .all(|b| b.contains("-----BEGIN PGP MESSAGE-----")),
        "the stored body is not encrypted: {sealed:?}"
    );
    // The point of the whole exercise: no copy of the plaintext survives
    // anywhere in what gets written to disk.
    let stored = serde_json::to_string(&msg).expect("serialise");
    assert!(
        !stored.contains("the secret plaintext"),
        "the plaintext is still in the stored message"
    );

    let recovered = go_decrypt(&bin, PRIVATE_KEY, &sealed[0]);
    assert!(
        recovered.contains("the secret plaintext"),
        "Go decrypted something else: {recovered:?}"
    );
}

/// A sender who already encrypted end to end gets left alone and labelled.
/// Re-encrypting would wrap ciphertext the recipient can read in a second
/// layer only the relay's key opens — the opposite of the intent.
#[test]
fn an_already_encrypted_body_is_marked_not_re_encrypted() {
    let dir = recipient_with_key();
    let raw = b"From: someone@elsewhere.invalid\r\n\
         To: y@a.test\r\n\
         Subject: already sealed\r\n\
         \r\n\
         -----BEGIN PGP MESSAGE-----\r\n\
         wcBMA0000000\r\n\
         -----END PGP MESSAGE-----\r\n";
    let msg = store(raw, dir.path());

    assert_eq!(
        msg.keywords.get("$e2e"),
        Some(&true),
        "an end-to-end encrypted body should be marked $e2e"
    );
    assert!(
        bodies(&msg).iter().all(|b| b.contains("wcBMA0000000")),
        "the sender's own ciphertext was replaced: {:?}",
        bodies(&msg)
    );
}

/// No key on file means the mail is stored as it arrived. Refusing to deliver
/// would be worse, and uploading a key is what turns sealing on.
#[test]
fn an_account_without_a_key_still_receives_mail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let msg = store(PLAIN, dir.path());
    assert!(
        bodies(&msg)
            .iter()
            .any(|b| b.contains("the secret plaintext")),
        "a message to an account with no key should be stored in the clear"
    );
    assert_eq!(msg.keywords.get("$e2e"), None);
}

/// Attachments have to travel *inside* the sealed plaintext: the parsed
/// message no longer carries them, so sealing the text alone would deliver a
/// message whose attachments had silently vanished.
#[test]
fn attachments_are_folded_into_the_sealed_plaintext() {
    let Some(bin) = require_helper() else { return };
    let dir = recipient_with_key();
    let raw = b"From: someone@elsewhere.invalid\r\n\
         To: y@a.test\r\n\
         Subject: with an attachment\r\n\
         Content-Type: multipart/mixed; boundary=\"bnd\"\r\n\
         \r\n\
         --bnd\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         the secret plaintext\r\n\
         --bnd\r\n\
         Content-Type: text/csv\r\n\
         Content-Disposition: attachment; filename=\"rows.csv\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         YSxiLGMK\r\n\
         --bnd--\r\n";
    let msg = store(raw, dir.path());

    let recovered = go_decrypt(&bin, PRIVATE_KEY, &bodies(&msg)[0]);
    assert!(
        recovered.contains("multipart/mixed"),
        "the sealed plaintext is not a multipart document: {recovered:?}"
    );
    assert!(
        recovered.contains("rows.csv"),
        "the attachment did not survive sealing: {recovered:?}"
    );
    assert!(
        recovered.contains("YSxiLGMK"),
        "the attachment's bytes did not survive sealing: {recovered:?}"
    );
    assert!(recovered.contains("the secret plaintext"), "{recovered:?}");
}
