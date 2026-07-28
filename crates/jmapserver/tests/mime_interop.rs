//! Go ↔ Rust MIME interoperability.
//!
//! The parser here is hand-rolled to match `net/mail` and `mime/multipart`
//! specifically, not MIME in general, so the only meaningful check is against
//! those. Every message below goes through the real Go functions and this
//! port, and the parsed Email, the extracted body and the attachments must
//! agree.
//!
//! `MIME_INTEROP=required` — set by `just test` — turns a missing helper into
//! an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use jmap_types::email::Email;
use pretty_assertions::assert_eq;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Parsed {
    #[serde(default)]
    err: String,
    #[serde(default)]
    email: Option<Value>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    attachments: Vec<AttachmentJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AttachmentJson {
    filename: String,
    content_type: String,
    bytes: String,
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/mime-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("MIME_INTEROP").is_none(),
        "MIME_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go MIME interop helper not built — run `just interop`. Set \
         MIME_INTEROP=required to make this an error instead."
    );
    None
}

fn go(bin: &PathBuf, cmd: &str, body: &[u8]) -> Vec<u8> {
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
    out.stdout
}

/// The corpus. Each entry names what it is there to pin down.
fn corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "plain text",
            "From: Alice <alice@example.com>\r\n\
             To: Bob <bob@example.org>\r\n\
             Subject: hello\r\n\
             Date: Mon, 27 Jul 2026 23:49:16 +0000\r\n\
             Message-Id: <abc@example.com>\r\n\
             \r\n\
             hello there\r\n",
        ),
        (
            "no content-type at all",
            "From: alice@example.com\r\nSubject: bare\r\n\r\nbody text\r\n",
        ),
        (
            "an encoded-word subject",
            "From: alice@example.com\r\n\
             Subject: =?UTF-8?B?44GT44KT44Gr44Gh44Gv?=\r\n\
             \r\n\
             body\r\n",
        ),
        (
            "a quoted-printable encoded-word subject",
            "From: alice@example.com\r\n\
             Subject: =?utf-8?q?caf=C3=A9_time?=\r\n\
             \r\n\
             body\r\n",
        ),
        (
            "quoted-printable body",
            "From: alice@example.com\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             caf=C3=A9 and =3D signs\r\n",
        ),
        (
            "base64 body",
            "From: alice@example.com\r\n\
             Content-Type: text/plain\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             aGVsbG8gYmFzZTY0\r\n",
        ),
        (
            "multipart/alternative prefers text/plain",
            "From: alice@example.com\r\n\
             Content-Type: multipart/alternative; boundary=\"bnd\"\r\n\
             \r\n\
             --bnd\r\n\
             Content-Type: text/html\r\n\
             \r\n\
             <p>html version</p>\r\n\
             --bnd\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             plain version\r\n\
             --bnd--\r\n",
        ),
        (
            "multipart with an attachment",
            "From: alice@example.com\r\n\
             Content-Type: multipart/mixed; boundary=\"bnd\"\r\n\
             \r\n\
             --bnd\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             see attached\r\n\
             --bnd\r\n\
             Content-Type: application/pdf; name=\"doc.pdf\"\r\n\
             Content-Disposition: attachment; filename=\"doc.pdf\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             SGVsbG8gUERG\r\n\
             --bnd--\r\n",
        ),
        (
            "an inline part is not an attachment",
            "From: alice@example.com\r\n\
             Content-Type: multipart/related; boundary=\"bnd\"\r\n\
             \r\n\
             --bnd\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             body\r\n\
             --bnd\r\n\
             Content-Type: image/png\r\n\
             Content-Disposition: inline; filename=\"pic.png\"\r\n\
             \r\n\
             binary\r\n\
             --bnd--\r\n",
        ),
        (
            "PGP/MIME keeps the ciphertext and drops the plaintext fallback",
            "From: alice@example.com\r\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"bnd\"\r\n\
             \r\n\
             --bnd\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             this fallback must not be stored\r\n\
             --bnd\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             -----BEGIN PGP MESSAGE-----\r\n\
             abc\r\n\
             -----END PGP MESSAGE-----\r\n\
             --bnd--\r\n",
        ),
        (
            "nested multipart",
            "From: alice@example.com\r\n\
             Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
             \r\n\
             --outer\r\n\
             Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
             \r\n\
             --inner\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             nested plain\r\n\
             --inner--\r\n\
             --outer--\r\n",
        ),
        (
            "custom headers are preserved",
            "From: alice@example.com\r\n\
             Chat-Group-Id: grp1\r\n\
             Chat-Group-Name: Friends\r\n\
             X-Custom: value\r\n\
             Chat-Version: 1.0\r\n\
             \r\n\
             body\r\n",
        ),
        (
            "an address list",
            "From: Alice <alice@example.com>\r\n\
             To: Bob <bob@example.org>, carol@example.net\r\n\
             Cc: \"Dave, Jr\" <dave@example.com>\r\n\
             \r\n\
             body\r\n",
        ),
        (
            "references and in-reply-to",
            "From: alice@example.com\r\n\
             In-Reply-To: <parent@x>\r\n\
             References: <a@x> <b@x>\r\n\
             \r\n\
             body\r\n",
        ),
        (
            "a folded header",
            "From: alice@example.com\r\n\
             Subject: this subject\r\n is folded across lines\r\n\
             \r\n\
             body\r\n",
        ),
        (
            "bare LF line endings",
            "From: alice@example.com\nSubject: lf only\n\nbody with lf\n",
        ),
        (
            "no body at all",
            "From: alice@example.com\r\nSubject: headerless body\r\n\r\n",
        ),
    ]
}

/// Sort the `headers` array by name.
///
/// `ParseMIMEEmail` builds it by ranging over Go's header map, so its order is
/// whatever that run's hash seed produced — two Go runs disagree, and the
/// first version of this test passed only by luck. That order reaches disk, so
/// the Rust side sorts (SPEC.md §11.5) and the comparison does too.
fn sort_headers(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(headers) = v.get_mut("headers").and_then(Value::as_array_mut) {
        headers.sort_by_key(|h| {
            h.get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        });
    }
    v
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// What the Rust side reports, in the helper's shape.
fn rust_parse(raw: &[u8]) -> Parsed {
    let Some(mut m) = jmapserver::parse_mime_email(raw, "<NOW>") else {
        return Parsed {
            err: "parse failed".into(),
            email: None,
            body: String::new(),
            attachments: vec![],
        };
    };
    let body = jmapserver::message_body(&m);
    // Dropped on both sides: an absent Date makes this the wall clock.
    m.received_at = None;
    Parsed {
        err: String::new(),
        email: Some(serde_json::to_value(&m).unwrap()),
        body,
        attachments: jmapserver::extract_attachments(raw)
            .into_iter()
            .map(|a| AttachmentJson {
                filename: a.filename,
                content_type: a.content_type,
                bytes: b64(&a.bytes),
            })
            .collect(),
    }
}

#[test]
fn parsing_matches_the_go_implementation() {
    let Some(bin) = require_helper() else { return };

    let inputs: Vec<String> = corpus()
        .iter()
        .map(|(_, raw)| b64(raw.as_bytes()))
        .collect();
    let out = go(&bin, "parse", &serde_json::to_vec(&inputs).unwrap());
    let from_go: Vec<Parsed> = serde_json::from_slice(&out).expect("parsing go output");

    assert_eq!(from_go.len(), corpus().len());
    for ((name, raw), go_result) in corpus().iter().zip(from_go.iter()) {
        let rust_result = rust_parse(raw.as_bytes());
        assert_eq!(&rust_result.err, &go_result.err, "{name}: error differs");
        assert_eq!(&rust_result.body, &go_result.body, "{name}: body differs");
        assert_eq!(
            &rust_result.attachments, &go_result.attachments,
            "{name}: attachments differ"
        );
        assert_eq!(
            rust_result.email.as_ref().map(sort_headers),
            go_result.email.as_ref().map(sort_headers),
            "{name}: parsed Email differs"
        );
    }
}

/// The Date header is the one input that makes `receivedAt` deterministic, so
/// it is checked on its own rather than dropped with the rest.
#[test]
fn a_date_header_becomes_received_at() {
    let raw = b"From: a@x\r\nDate: Mon, 27 Jul 2026 23:49:16 +0900\r\n\r\nbody\r\n";
    let m = jmapserver::parse_mime_email(raw, "<NOW>").expect("must parse");
    assert_eq!(
        m.received_at.map(|t| t.as_str().to_string()),
        Some("2026-07-27T23:49:16+09:00".to_string()),
        "the Date header's offset must be preserved, not normalised to UTC"
    );
}

#[test]
fn an_absent_date_falls_back_to_the_supplied_now() {
    let m = jmapserver::parse_mime_email(b"From: a@x\r\n\r\nbody\r\n", "<NOW>").unwrap();
    assert_eq!(
        m.received_at.map(|t| t.as_str().to_string()),
        Some("<NOW>".into())
    );
}

#[derive(serde::Serialize)]
struct BuildInput {
    email: Email,
    domain: String,
}

#[test]
fn building_matches_the_go_implementation() {
    let Some(bin) = require_helper() else { return };

    let mut cases: Vec<(&str, BuildInput)> = Vec::new();

    let mut simple = Email {
        subject: "hello".into(),
        from: vec![jmap_types::mail::Address {
            name: "Alice".into(),
            email: "alice@example.com".into(),
        }],
        to: vec![jmap_types::mail::Address {
            name: String::new(),
            email: "bob@example.org".into(),
        }],
        message_id: vec!["fixed@example.com".into()],
        sent_at: Some(jmap_types::JmapTime::from_raw("2026-07-27T23:49:16Z")),
        ..Default::default()
    };
    simple
        .body_values
        .insert("1".into(), jmap_types::email::BodyValue::new("hello there"));
    simple.text_body = vec![jmap_types::email::BodyPart {
        part_id: "1".into(),
        type_: "text/plain".into(),
        ..Default::default()
    }];
    cases.push((
        "a plain message",
        BuildInput {
            email: simple.clone(),
            domain: "mail.example.com".into(),
        },
    ));

    let mut reply = simple.clone();
    reply.in_reply_to = vec!["parent@x".into()];
    reply.references = vec!["a@x".into(), "<b@x>".into()];
    cases.push((
        "a reply gains Re: and bracketed references",
        BuildInput {
            email: reply,
            domain: "mail.example.com".into(),
        },
    ));

    let mut already_re = simple.clone();
    already_re.subject = "RE: hello".into();
    already_re.in_reply_to = vec!["parent@x".into()];
    cases.push((
        "an existing Re: is not doubled",
        BuildInput {
            email: already_re,
            domain: "mail.example.com".into(),
        },
    ));

    let mut custom = simple.clone();
    custom.headers = vec![
        jmap_types::email::Header {
            name: "Chat-Group-Id".into(),
            value: "grp1".into(),
        },
        // A header that duplicates a generated one must be skipped.
        jmap_types::email::Header {
            name: "Subject".into(),
            value: "should not appear twice".into(),
        },
    ];
    cases.push((
        "custom headers, minus the ones already generated",
        BuildInput {
            email: custom,
            domain: "mail.example.com".into(),
        },
    ));

    let mut multi = simple.clone();
    multi.cc = vec![jmap_types::mail::Address {
        name: "Dave, Jr".into(),
        email: "dave@example.com".into(),
    }];
    multi.to.push(jmap_types::mail::Address {
        name: "Carol".into(),
        email: "carol@example.net".into(),
    });
    multi.bcc = vec![jmap_types::mail::Address {
        name: String::new(),
        email: "eve@example.net".into(),
    }];
    cases.push((
        "a display name needing quotes, and Bcc in the envelope only",
        BuildInput {
            email: multi,
            domain: "mail.example.com".into(),
        },
    ));

    let mut no_domain = simple.clone();
    no_domain.message_id = vec![];
    cases.push((
        "no Message-ID and no default domain",
        BuildInput {
            email: no_domain,
            domain: String::new(),
        },
    ));

    let inputs: Vec<&BuildInput> = cases.iter().map(|(_, i)| i).collect();
    let out = go(&bin, "build", &serde_json::to_vec(&inputs).unwrap());
    let from_go: Vec<Value> = serde_json::from_slice(&out).expect("parsing go output");

    for ((name, input), go_result) in cases.iter().zip(from_go.iter()) {
        let now = ::time::OffsetDateTime::UNIX_EPOCH;
        let (raw, msg_id) =
            jmapserver::mime::build_rfc5322(&input.email, &input.domain, now, "aabbccddeeff");
        let raw = String::from_utf8(raw).unwrap();
        let go_raw = go_result["raw"].as_str().unwrap();

        // A generated Message-ID embeds the clock and six random bytes, so
        // the two can only agree when the Email carried one.
        if input.email.message_id.is_empty() {
            let strip = |s: &str| {
                s.lines()
                    .filter(|l| !l.starts_with("Message-Id:") && !l.starts_with("Date:"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            assert_eq!(strip(&raw), strip(go_raw), "{name}: raw differs");
        } else {
            // The Date still differs: Go falls back to its own clock when
            // neither sentAt nor receivedAt is set. Every case here sets
            // sentAt, so the dates must match too.
            assert_eq!(raw, go_raw, "{name}: raw differs");
            assert_eq!(
                msg_id,
                go_result["msg_id"].as_str().unwrap(),
                "{name}: msg_id"
            );
        }

        let go_env = go_result.get("envelope").cloned();
        let rust_env =
            jmapserver::build_envelope(&input.email).map(|e| serde_json::to_value(e).unwrap());
        assert_eq!(rust_env, go_env, "{name}: envelope differs");
    }
}
