//! Go ↔ Rust DKIM interoperability.
//!
//! A signature only its own signer accepts is worthless, so the check that
//! matters is that **Go verifies what this port signs** — Go's verifier
//! recomputes both canonicalisations from the message, so its acceptance
//! covers header canonicalisation, body canonicalisation, the signed-header
//! list and the key encoding at once.
//!
//! The reverse direction is not tested, and does not need to be: this relay
//! only ever signs. Nothing in it verifies DKIM, so a Rust verifier would be
//! testing code that does not exist.
//!
//! The body hash carries no timestamp, so `bh=` is compared byte for byte as
//! well. Cross-verification would catch a body-canonicalisation difference
//! anyway, but only as an opaque "signature invalid"; this says which half
//! moved.
//!
//! `DKIM_INTEROP=required` — set by `just test` — turns a missing helper into
//! an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use pretty_assertions::assert_eq;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "example.com";
const SELECTOR: &str = "default";

/// The same throwaway key the difftest fixtures use. Generating one here would
/// cost a second per test and make the input random.
const KEY_PEM: &str = include_str!("../../../xtask/fixtures/dkim-key.pem");

#[derive(Serialize)]
struct SignRequest {
    key_pem: String,
    domain: String,
    selector: String,
    message: String,
}

#[derive(Deserialize)]
struct SignResponse {
    #[serde(default)]
    signed: String,
    #[serde(default)]
    err: String,
}

#[derive(Serialize)]
struct VerifyRequest {
    message: String,
    record: String,
    domain: String,
    selector: String,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    ok: bool,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    err: String,
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/dkim-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("DKIM_INTEROP").is_none(),
        "DKIM_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go DKIM interop helper not built — run `just interop`. Set \
         DKIM_INTEROP=required to make this an error instead."
    );
    None
}

fn go<T: serde::de::DeserializeOwned>(bin: &PathBuf, cmd: &str, body: &[u8]) -> Vec<T> {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    child.stdin.as_mut().unwrap().write_all(body).unwrap();
    let out = child.wait_with_output().expect("waiting for the Go helper");
    assert!(
        out.status.success(),
        "go {cmd} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go output")
}

fn key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(KEY_PEM).expect("the fixture key must parse")
}

fn key_pem() -> String {
    key().to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
}

fn record() -> String {
    jmapsmtp::dkim::public_key_record(&key())
}

/// The set of headers `h=` names, order discarded.
///
/// mail-auth emits them in reverse of their appearance in the message (the
/// bottom-up convention of RFC 6376 §5.4.2) and go-msgauth in the order it
/// was given. Each signs consistently with its own `h=`, which is why the
/// cross-verification test passes; only the set is a shared invariant.
/// SPEC.md §11.10.
fn signed_header_set(signed: &str) -> Vec<String> {
    let mut v: Vec<String> = sig_tag(signed, "h")
        .split(':')
        .map(str::to_lowercase)
        .collect();
    v.sort();
    v
}

/// Messages chosen for the canonicalisation: header folding, runs of
/// whitespace, a signed header that is absent, an empty body, trailing blank
/// lines, and characters that JSON escaping would touch elsewhere.
fn messages() -> Vec<(&'static str, String)> {
    vec![
        (
            "a plain message",
            "From: Alice <alice@example.com>\r\n\
             To: Bob <bob@example.org>\r\n\
             Subject: hello\r\n\
             Date: Mon, 27 Jul 2026 23:49:16 +0000\r\n\
             Message-Id: <abc@example.com>\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             hello there\r\n"
                .to_string(),
        ),
        (
            "a signed header that is absent",
            "From: alice@example.com\r\n\
             Subject: no cc\r\n\
             Date: Mon, 27 Jul 2026 23:49:16 +0000\r\n\
             \r\n\
             body\r\n"
                .to_string(),
        ),
        (
            "folded headers and runs of whitespace",
            "From: alice@example.com\r\n\
             Subject: this   subject\r\n has   folding\r\n\
             Date: Mon, 27 Jul 2026 23:49:16 +0000\r\n\
             \r\n\
             body   with   spaces\r\n"
                .to_string(),
        ),
        (
            "an empty body",
            "From: alice@example.com\r\nSubject: empty\r\n\r\n".to_string(),
        ),
        (
            "trailing blank lines",
            "From: alice@example.com\r\nSubject: trailing\r\n\r\nbody\r\n\r\n\r\n".to_string(),
        ),
        (
            "angle brackets and an ampersand",
            "From: alice@example.com\r\n\
             Subject: a & b <c>\r\n\
             \r\n\
             text with <tags> & entities\r\n"
                .to_string(),
        ),
        (
            "a non-ascii subject and body",
            "From: alice@example.com\r\n\
             Subject: =?utf-8?B?44GT44KT44Gr44Gh44Gv?=\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             日本語の本文\r\n"
                .to_string(),
        ),
    ]
}

/// Pull one tag's value out of the DKIM-Signature header, whitespace removed.
///
/// Split on `;` first and match the tag name exactly. Searching for `"h="`
/// anywhere in the header finds it inside `bh=` — which is how the first
/// version of this compared a header list against a base64 body hash and
/// reported the wrong thing as broken.
fn sig_tag(signed: &str, tag: &str) -> String {
    let header: String = signed
        .lines()
        .take_while(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("");
    let header = header.strip_prefix("DKIM-Signature:").unwrap_or(&header);
    for field in header.split(';') {
        let field: String = field.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some((k, v)) = field.split_once('=')
            && k == tag
        {
            return v.to_string();
        }
    }
    String::new()
}

/// The check that matters: every signature this port produces must verify at
/// the far end.
#[test]
fn go_verifies_every_signature_rust_produces() {
    let Some(bin) = require_helper() else { return };
    let key = key();

    let reqs: Vec<VerifyRequest> = messages()
        .into_iter()
        .map(|(_, msg)| VerifyRequest {
            message: String::from_utf8(jmapsmtp::dkim::sign(
                msg.as_bytes(),
                &key,
                DOMAIN,
                SELECTOR,
            ))
            .expect("a signed message must stay utf-8"),
            record: record(),
            domain: DOMAIN.into(),
            selector: SELECTOR.into(),
        })
        .collect();

    let results: Vec<VerifyResponse> = go(&bin, "verify", &serde_json::to_vec(&reqs).unwrap());
    assert_eq!(results.len(), messages().len());
    for ((name, _), r) in messages().iter().zip(results.iter()) {
        assert!(
            r.ok,
            "{name}: Go rejected a Rust signature: {}",
            if r.err.is_empty() {
                "no reason given"
            } else {
                &r.err
            }
        );
        assert_eq!(r.domain, DOMAIN, "{name}: signed for the wrong domain");
    }
}

/// Body canonicalisation, pinned directly. Cross-verification would catch a
/// difference here too, but only as "invalid"; this names the half that moved.
#[test]
fn body_hashes_match_the_go_implementation() {
    let Some(bin) = require_helper() else { return };
    let key = key();

    let reqs: Vec<SignRequest> = messages()
        .into_iter()
        .map(|(_, msg)| SignRequest {
            key_pem: key_pem(),
            domain: DOMAIN.into(),
            selector: SELECTOR.into(),
            message: msg,
        })
        .collect();
    let from_go: Vec<SignResponse> = go(&bin, "sign", &serde_json::to_vec(&reqs).unwrap());

    for ((name, msg), go_signed) in messages().iter().zip(from_go.iter()) {
        assert!(
            go_signed.err.is_empty(),
            "{name}: Go failed: {}",
            go_signed.err
        );
        let rust_signed =
            String::from_utf8(jmapsmtp::dkim::sign(msg.as_bytes(), &key, DOMAIN, SELECTOR))
                .unwrap();
        assert_eq!(
            sig_tag(&rust_signed, "bh"),
            sig_tag(&go_signed.signed, "bh"),
            "{name}: body hash differs — body canonicalisation diverged"
        );
        assert_eq!(
            signed_header_set(&rust_signed),
            signed_header_set(&go_signed.signed),
            "{name}: a different set of headers was signed"
        );
        for tag in ["d", "s", "a", "c"] {
            assert_eq!(
                sig_tag(&rust_signed, tag),
                sig_tag(&go_signed.signed, tag),
                "{name}: the {tag}= tag differs"
            );
        }
    }
}

/// Everything in the header agrees except the `h=` ordering (SPEC.md §11.10),
/// the `t=` timestamp — each signer's own clock reading — and `b=`, which
/// covers both.
///
/// Pinned because an earlier version of this file recorded a divergence that
/// did not exist: a grep of the wrong file claimed go-msgauth omitted `t=`,
/// and a tag extractor that matched `h=` inside `bh=` made the evidence look
/// consistent. Both write `t=`.
#[test]
fn only_the_header_order_timestamp_and_signature_differ() {
    let Some(bin) = require_helper() else { return };

    let (_, msg) = messages().into_iter().next().unwrap();
    let rust_signed = String::from_utf8(jmapsmtp::dkim::sign(
        msg.as_bytes(),
        &key(),
        DOMAIN,
        SELECTOR,
    ))
    .unwrap();

    let reqs = vec![SignRequest {
        key_pem: key_pem(),
        domain: DOMAIN.into(),
        selector: SELECTOR.into(),
        message: msg,
    }];
    let from_go: Vec<SignResponse> = go(&bin, "sign", &serde_json::to_vec(&reqs).unwrap());
    let go_signed = &from_go[0].signed;

    assert_eq!(
        signed_header_set(&rust_signed),
        signed_header_set(go_signed),
        "the same headers must be signed, whatever order h= lists them in"
    );
    for tag in ["v", "a", "c", "d", "s", "bh"] {
        assert_eq!(
            sig_tag(&rust_signed, tag),
            sig_tag(go_signed, tag),
            "the {tag}= tag differs"
        );
    }
    assert!(!sig_tag(&rust_signed, "t").is_empty(), "both write t=");
    assert!(!sig_tag(go_signed, "t").is_empty(), "both write t=");
}

/// A signature must be prepended, leaving the message it signs untouched
/// below it.
#[test]
fn the_signature_header_goes_first_and_the_message_is_unchanged() {
    let msg = "From: a@x\r\nSubject: s\r\n\r\nbody\r\n";
    let signed = String::from_utf8(jmapsmtp::dkim::sign(
        msg.as_bytes(),
        &key(),
        DOMAIN,
        SELECTOR,
    ))
    .unwrap();
    assert!(signed.starts_with("DKIM-Signature:"));
    assert!(signed.ends_with(msg), "the original message must be intact");
}

/// Signing is best-effort: whatever happens, something deliverable comes
/// back. A message with no header block at all is still signed here — the
/// signer treats it as having no headers rather than refusing — so the
/// guarantee is that the original survives, not that signing is skipped.
#[test]
fn signing_never_destroys_the_message() {
    for raw in [
        &b"not a message at all"[..],
        &b""[..],
        &b"From: a@x\r\n\r\nbody"[..],
    ] {
        let out = jmapsmtp::dkim::sign(raw, &key(), DOMAIN, SELECTOR);
        assert!(
            out.ends_with(raw),
            "the original bytes must survive signing: {:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[test]
fn the_public_key_record_has_the_shape_dns_expects() {
    let record = record();
    assert!(record.starts_with("v=DKIM1; k=rsa; p="));
    assert!(
        record.len() > 300,
        "an RSA-2048 SPKI is nearly 400 base64 characters"
    );
}
