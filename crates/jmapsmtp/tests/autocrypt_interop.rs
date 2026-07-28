//! Go ↔ Rust Autocrypt interoperability.
//!
//! Everything checked here is a deterministic byte-level rewrite, so the two
//! implementations must agree exactly — no normalisation, no allowances.
//!
//! The Go side of the helper is the original functions **copied verbatim**,
//! because they are unexported in `package main` and cannot be linked. That
//! copy is not taken on trust: this comparison is what pins it, so if
//! go-jmapsmtp changes one of them the test starts failing and the copy gets
//! updated deliberately.
//!
//! `AUTOCRYPT_INTEROP=required` — set by `just test` — turns a missing helper
//! into an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Request {
    op: &'static str,
    #[serde(default)]
    raw: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    key_data: String,
    #[serde(default)]
    header: String,
}

impl Request {
    fn new(op: &'static str) -> Self {
        Request {
            op,
            raw: String::new(),
            from: String::new(),
            key_data: String::new(),
            header: String::new(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
struct Response {
    #[serde(default)]
    raw: String,
    #[serde(default)]
    addr: String,
    #[serde(default)]
    key_data: String,
    #[serde(default)]
    failed: bool,
    /// The Go original crashed. See SPEC.md §11.11.
    #[serde(default)]
    panicked: bool,
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/autocrypt-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("AUTOCRYPT_INTEROP").is_none(),
        "AUTOCRYPT_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go Autocrypt interop helper not built — run `just interop`. \
         Set AUTOCRYPT_INTEROP=required to make this an error instead."
    );
    None
}

fn go(bin: &PathBuf, reqs: &[Request]) -> Vec<Response> {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&serde_json::to_vec(reqs).unwrap())
        .unwrap();
    let out = child.wait_with_output().expect("waiting for the Go helper");
    assert!(
        out.status.success(),
        "go helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go output")
}

/// Messages for the header-injection paths.
fn injection_cases() -> Vec<(&'static str, String)> {
    vec![
        (
            "a plain message",
            "From: a@x\r\nSubject: s\r\n\r\nbody\r\n".to_string(),
        ),
        (
            "headers only, no body",
            "From: a@x\r\nSubject: s\r\n\r\n".to_string(),
        ),
        (
            "no header/body separator at all",
            "From: a@x\r\nSubject: s\r\n".to_string(),
        ),
        ("a single header", "From: a@x\r\n\r\nbody".to_string()),
        (
            "the header is already present",
            "From: a@x\r\nChat-Version: 1.0\r\n\r\nbody\r\n".to_string(),
        ),
        (
            "the message starts with the header",
            "Chat-Version: 1.0\r\nFrom: a@x\r\n\r\nbody\r\n".to_string(),
        ),
        (
            "the header appears in the body",
            // Substring matching means this counts as present. Reproduced.
            "From: a@x\r\n\r\nquoting a\nChat-Version: 1.0 line\r\n".to_string(),
        ),
        (
            "bare LF line endings",
            "From: a@x\nSubject: s\n\nbody\n".to_string(),
        ),
        ("empty input", String::new()),
    ]
}

#[test]
fn chat_version_injection_matches_go() {
    let Some(bin) = require_helper() else { return };
    let reqs: Vec<Request> = injection_cases()
        .into_iter()
        .map(|(_, raw)| Request {
            raw,
            ..Request::new("chat_version")
        })
        .collect();
    let from_go = go(&bin, &reqs);

    for ((name, raw), go_result) in injection_cases().iter().zip(from_go.iter()) {
        let rust = String::from_utf8(jmapsmtp::autocrypt::inject_chat_version(raw.as_bytes()))
            .expect("utf-8");
        assert_eq!(rust, go_result.raw, "{name}");
    }
}

#[test]
fn autocrypt_injection_matches_go() {
    let Some(bin) = require_helper() else { return };
    const KEY: &str = "mDMEZAAAAAAAAAAAAAAA";
    let reqs: Vec<Request> = injection_cases()
        .into_iter()
        .map(|(_, raw)| Request {
            raw,
            from: "alice@example.com".into(),
            key_data: KEY.into(),
            ..Request::new("autocrypt")
        })
        .collect();
    let from_go = go(&bin, &reqs);

    for ((name, raw), go_result) in injection_cases().iter().zip(from_go.iter()) {
        let rust = String::from_utf8(jmapsmtp::autocrypt::inject_autocrypt(
            raw.as_bytes(),
            "alice@example.com",
            KEY,
        ))
        .expect("utf-8");
        assert_eq!(rust, go_result.raw, "{name}");
    }
}

/// Header values covering the shapes a real Autocrypt header takes, plus the
/// malformed ones a peer might send.
fn header_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "the ordinary shape",
            "addr=alice@example.com; prefer-encrypt=mutual; keydata=mDMEZAAA",
        ),
        ("attributes reordered", "keydata=mDMEZAAA; addr=a@x"),
        ("extra whitespace", "  addr = a@x ;  keydata = mDMEZ "),
        ("an attribute with no value", "addr; keydata=mDMEZ"),
        ("an unknown attribute", "addr=a@x; unknown=1; keydata=k"),
        ("a value containing =", "addr=a@x; keydata=mDMEZ=="),
        ("empty", ""),
        ("only a semicolon", ";"),
        ("no attributes at all", "garbage"),
        ("a repeated attribute", "addr=first@x; addr=second@x"),
    ]
}

#[test]
fn header_parsing_matches_go() {
    let Some(bin) = require_helper() else { return };
    let reqs: Vec<Request> = header_cases()
        .into_iter()
        .map(|(_, header)| Request {
            header: header.into(),
            ..Request::new("parse")
        })
        .collect();
    let from_go = go(&bin, &reqs);

    for ((name, header), go_result) in header_cases().iter().zip(from_go.iter()) {
        let (addr, key_data) = jmapsmtp::autocrypt::parse_autocrypt_header(header);
        assert_eq!(addr, go_result.addr, "{name}: addr");
        assert_eq!(key_data, go_result.key_data, "{name}: keydata");
    }
}

/// Messages for the PGP/MIME wrapper. The boundary is a hash of the PGP
/// block, so the whole output is deterministic.
fn wrap_cases() -> Vec<(&'static str, String)> {
    let block = "-----BEGIN PGP MESSAGE-----\n\
                 \n\
                 hQEMA1234567890abcdef\n\
                 =abcd\n\
                 -----END PGP MESSAGE-----";
    vec![
        (
            "an inline PGP body",
            format!(
                "From: a@x\r\n\
                 To: b@y\r\n\
                 Subject: s\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Transfer-Encoding: 8bit\r\n\
                 \r\n\
                 {block}\r\n"
            ),
        ),
        (
            "no Content-Type to drop",
            format!("From: a@x\r\nSubject: s\r\n\r\n{block}\r\n"),
        ),
        (
            "text around the PGP block",
            format!("From: a@x\r\n\r\npreamble\n{block}\ntrailer\r\n"),
        ),
        (
            "custom headers are kept",
            format!("From: a@x\r\nChat-Version: 1.0\r\nX-Keep: yes\r\n\r\n{block}\r\n"),
        ),
        (
            "no PGP block",
            "From: a@x\r\nSubject: s\r\n\r\njust text\r\n".to_string(),
        ),
        ("no header/body separator", format!("From: a@x\r\n{block}")),
        (
            // The Go original panics here, and the panic is unrecovered in
            // sendEmail's goroutine, so it takes the whole relay down. See
            // SPEC.md §11.11 and the dedicated test below.
            "an END marker before the BEGIN marker",
            "From: a@x\r\n\r\n-----END PGP MESSAGE-----\nstuff\n-----BEGIN PGP MESSAGE-----\r\n"
                .to_string(),
        ),
    ]
}

#[test]
fn pgp_mime_wrapping_matches_go() {
    let Some(bin) = require_helper() else { return };
    let reqs: Vec<Request> = wrap_cases()
        .into_iter()
        .map(|(_, raw)| Request {
            raw,
            ..Request::new("wrap")
        })
        .collect();
    let from_go = go(&bin, &reqs);

    for ((name, raw), go_result) in wrap_cases().iter().zip(from_go.iter()) {
        if go_result.panicked {
            // A declared divergence, checked as strictly as an agreement:
            // Rust must decline cleanly where Go crashes.
            assert!(
                jmapsmtp::autocrypt::pgp_mime_wrap_inline(raw.as_bytes()).is_none(),
                "{name}: Go panics here and Rust must decline, not wrap"
            );
            continue;
        }
        match jmapsmtp::autocrypt::pgp_mime_wrap_inline(raw.as_bytes()) {
            None => assert!(go_result.failed, "{name}: Rust refused, Go did not"),
            Some(wrapped) => {
                assert!(!go_result.failed, "{name}: Go refused, Rust did not");
                assert_eq!(
                    String::from_utf8(wrapped).expect("utf-8"),
                    go_result.raw,
                    "{name}"
                );
            }
        }
    }
}

/// The crash itself, pinned.
///
/// `sendEmail` calls `pgpMIMEWrapInline` whenever the outgoing message
/// contains a BEGIN marker, from inside a bare `go func()`. An unrecovered
/// panic in a goroutine ends the Go process, so this is a message body — a
/// value any authenticated sender chooses — that stops the relay for every
/// account on it. Declared, so that a refactor which reintroduced the
/// backwards slice would fail here rather than ship.
#[test]
fn a_reversed_pgp_block_crashes_go_and_is_declined_here() {
    let Some(bin) = require_helper() else { return };

    let raw = "From: a@x\r\n\r\n\
               -----END PGP MESSAGE-----\n\
               -----BEGIN PGP MESSAGE-----\r\n";
    let reqs = vec![Request {
        raw: raw.into(),
        ..Request::new("wrap")
    }];
    let from_go = go(&bin, &reqs);
    assert!(
        from_go[0].panicked,
        "the Go original is expected to panic on a reversed PGP block; if it \
         no longer does, this divergence has been fixed upstream and the note \
         in SPEC.md §11.11 should be revisited"
    );
    assert!(
        jmapsmtp::autocrypt::pgp_mime_wrap_inline(raw.as_bytes()).is_none(),
        "there is no complete PGP block here, so wrapping must decline"
    );
}

/// And the ordinary case still works, so the fix did not simply disable
/// wrapping.
#[test]
fn a_well_formed_block_after_a_stray_end_marker_still_wraps() {
    let raw = "From: a@x\r\n\r\n\
               a line mentioning -----END PGP MESSAGE----- in passing\n\
               -----BEGIN PGP MESSAGE-----\n\
               body\n\
               -----END PGP MESSAGE-----\r\n";
    let wrapped = jmapsmtp::autocrypt::pgp_mime_wrap_inline(raw.as_bytes())
        .expect("a complete block follows, so this must wrap");
    let wrapped = String::from_utf8(wrapped).unwrap();
    assert!(wrapped.contains("multipart/encrypted"));
    assert!(wrapped.contains("-----BEGIN PGP MESSAGE-----"));
}
