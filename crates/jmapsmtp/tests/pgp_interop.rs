//! Go ↔ Rust OpenPGP interoperability.
//!
//! Encryption picks a fresh session key every time, so there is nothing to
//! compare byte for byte. Cross-decryption is the check, and both directions
//! matter for different reasons:
//!
//! * **Go opens what Rust sealed** is the migration direction. Every message
//!   this port stores encrypted has to remain readable if the deployment
//!   reverts to the Go build.
//! * **Rust opens what Go sealed** covers the other half: every message
//!   already on disk was sealed by Go.
//!
//! Decryption is not something the relay does — it holds no private key — so
//! the Rust side of the second direction is test-only, using rpgp directly.
//! That is still worth having: it is what proves the key parsing and the
//! packet shapes line up.
//!
//! `PGP_INTEROP=required` — set by `just test` — turns a missing helper into
//! an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};

/// A throwaway keypair, generated once with the Go implementation so both
/// sides read exactly the same key material.
const PUBLIC_KEY: &str = include_str!("../../../xtask/fixtures/pgp-public.asc");
const PRIVATE_KEY: &str = include_str!("../../../xtask/fixtures/pgp-private.asc");

#[derive(Default, Serialize)]
struct Request {
    #[serde(skip_serializing_if = "String::is_empty")]
    public_key: String,
    /// An unarmoured key: not UTF-8, so it cannot ride in a JSON string.
    #[serde(skip_serializing_if = "String::is_empty")]
    public_key_b64: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    private_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    plaintext: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ciphertext: String,
}

#[derive(Debug, Default, Deserialize)]
struct Response {
    #[serde(default)]
    ciphertext: String,
    #[serde(default)]
    plaintext: String,
    #[serde(default)]
    err: String,
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/pgp-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("PGP_INTEROP").is_none(),
        "PGP_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go PGP interop helper not built — run `just interop`. Set \
         PGP_INTEROP=required to make this an error instead."
    );
    None
}

fn go(bin: &PathBuf, cmd: &str, req: &Request) -> Response {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&serde_json::to_vec(req).unwrap())
        .unwrap();
    let out = child.wait_with_output().expect("waiting for the Go helper");
    assert!(
        out.status.success(),
        "go {cmd} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go output")
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64")
}

/// Bodies worth carrying: plain text, non-ASCII, the multipart shape the
/// receive path wraps attachments in, an empty message, and one large enough
/// to be chunked.
fn plaintexts() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("plain text", b"hello there".to_vec()),
        (
            "non-ascii",
            "日本語の本文 with emoji 🙂".as_bytes().to_vec(),
        ),
        (
            "a multipart body",
            b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
              --b\r\nContent-Type: text/plain\r\n\r\ntext\r\n--b--"
                .to_vec(),
        ),
        ("empty", Vec::new()),
        ("binary bytes", (0u8..=255).collect()),
        ("large", vec![b'x'; 200_000]),
    ]
}

fn rust_public_key() -> pgp::composed::SignedPublicKey {
    jmapsmtp::pgp::parse_public_key(PUBLIC_KEY.as_bytes()).expect("the fixture key must parse")
}

/// **The migration direction.** A message this port sealed must stay readable
/// if the deployment goes back to the Go build.
#[test]
fn go_decrypts_what_rust_encrypts() {
    let Some(bin) = require_helper() else { return };
    let key = rust_public_key();

    for (name, plaintext) in plaintexts() {
        let ciphertext = jmapsmtp::pgp::encrypt_inline(&plaintext, std::slice::from_ref(&key))
            .unwrap_or_else(|e| panic!("{name}: encrypting: {e}"));
        let ciphertext = String::from_utf8(ciphertext).expect("armour is ascii");
        assert!(
            ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"),
            "{name}: the output must be an armoured PGP MESSAGE"
        );

        let resp = go(
            &bin,
            "decrypt",
            &Request {
                private_key: PRIVATE_KEY.into(),
                ciphertext,
                ..Default::default()
            },
        );
        assert!(
            resp.err.is_empty(),
            "{name}: Go failed to decrypt: {}",
            resp.err
        );
        assert_eq!(
            unb64(&resp.plaintext),
            plaintext,
            "{name}: the plaintext came back different"
        );
    }
}

/// The other half: every message already on disk was sealed by Go.
#[test]
fn rust_decrypts_what_go_encrypts() {
    let Some(bin) = require_helper() else { return };

    for (name, plaintext) in plaintexts() {
        let resp = go(
            &bin,
            "encrypt",
            &Request {
                public_key: PUBLIC_KEY.into(),
                plaintext: b64(&plaintext),
                ..Default::default()
            },
        );
        assert!(
            resp.err.is_empty(),
            "{name}: Go failed to encrypt: {}",
            resp.err
        );
        let decrypted = decrypt_with_rpgp(&resp.ciphertext);
        assert_eq!(
            decrypted, plaintext,
            "{name}: the plaintext came back different"
        );
    }
}

/// Decrypt with rpgp directly. Test-only: the relay holds no private key and
/// never decrypts.
fn decrypt_with_rpgp(armored: &str) -> Vec<u8> {
    use pgp::composed::{Deserializable, Message, SignedSecretKey};

    let (secret, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(PRIVATE_KEY))
        .expect("the fixture private key must parse");
    let (message, _) = Message::from_armor(std::io::Cursor::new(armored.as_bytes()))
        .expect("the ciphertext must parse");
    let mut decrypted = message
        .decrypt(&String::new().into(), &secret)
        .expect("decrypting");
    let mut out = Vec::new();
    std::io::copy(&mut decrypted, &mut out).expect("reading the plaintext");
    out
}

/// A key with an encryption subkey must be encrypted to the subkey, not the
/// primary — and the round trip is what proves the right one was chosen.
#[test]
fn the_encryption_subkey_is_used() {
    let Some(bin) = require_helper() else { return };
    let key = rust_public_key();
    assert!(
        !key.public_subkeys.is_empty(),
        "the fixture key is expected to have a subkey, or this proves nothing"
    );

    let ciphertext = String::from_utf8(
        jmapsmtp::pgp::encrypt_inline(b"subkey test", std::slice::from_ref(&key)).unwrap(),
    )
    .unwrap();
    let resp = go(
        &bin,
        "decrypt",
        &Request {
            private_key: PRIVATE_KEY.into(),
            ciphertext,
            ..Default::default()
        },
    );
    assert!(resp.err.is_empty(), "Go failed to decrypt: {}", resp.err);
    assert_eq!(unb64(&resp.plaintext), b"subkey test");
}

/// The binary form an Autocrypt header carries has to parse too, and produce
/// a key that works.
#[test]
fn a_binary_key_round_trips_through_autocrypt_form() {
    let Some(bin) = require_helper() else { return };

    let key = rust_public_key();
    let binary = jmapsmtp::pgp::serialize_public_key(&key).expect("serialising");
    assert!(
        !binary.starts_with(b"-----BEGIN"),
        "the Autocrypt form is unarmoured packets"
    );

    let reparsed = jmapsmtp::pgp::parse_public_key(&binary).expect("binary must parse");
    let ciphertext = String::from_utf8(
        jmapsmtp::pgp::encrypt_inline(b"via autocrypt", std::slice::from_ref(&reparsed)).unwrap(),
    )
    .unwrap();

    let resp = go(
        &bin,
        "decrypt",
        &Request {
            private_key: PRIVATE_KEY.into(),
            ciphertext,
            ..Default::default()
        },
    );
    assert!(resp.err.is_empty(), "Go failed to decrypt: {}", resp.err);
    assert_eq!(unb64(&resp.plaintext), b"via autocrypt");

    // And Go reads the same bytes as a key, exactly as loadPeerKeyForDomain
    // does for a stored peer. Sent base64-encoded because the packets are not
    // UTF-8 — passing them through a JSON string mangles them, which is how
    // the first version of this test managed to blame the key for its own
    // encoding mistake.
    let resp = go(
        &bin,
        "encrypt",
        &Request {
            public_key_b64: b64(&binary),
            plaintext: b64(b"go side"),
            ..Default::default()
        },
    );
    assert!(
        resp.err.is_empty(),
        "Go failed to parse the binary key: {}",
        resp.err
    );
    assert!(
        resp.ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"),
        "and it encrypts to it"
    );
}
