//! A delivery that parses into nothing must not be filed.
//!
//! Four of these sat in a production inbox for a day. They were probes sent
//! into port 25 while debugging delivery on 2026-08-10 — six and twelve bytes,
//! no headers — and `parse_mime_email` answered `Some` for each: an `Email`
//! with no addresses, no subject, no Message-ID, and a body part whose value
//! was absent.
//!
//! Filed into the inbox, they render as nothing and cannot be opened, so they
//! can never be marked read. The account's unread badge read **4** with
//! nothing to click, and no amount of reading mail moved it.
//!
//! `store_message` already carried the sentence "an entry with no headers and
//! no body is worse than an absence, because it looks like mail arrived". Only
//! the `parse → None` half of it was implemented.
//!
//! The inputs below are the real ones, not invented small cases.

use jmapsmtp::delivery::carries_nothing;

fn parse(raw: &[u8]) -> jmap_types::email::Email {
    jmapserver::parse_mime_email(raw, "2026-08-10T22:44:38Z")
        .expect("the parser answers Some for all of these — that is the problem")
}

/// The six-byte probe. `probe@x.invalid`, 2026-08-10 22:44:38 and 22:44:39.
#[test]
fn a_six_byte_probe_carries_nothing() {
    assert!(carries_nothing(&parse(b"hello\n")));
}

/// The twelve-byte one, 22:42:48 and 22:42:50.
#[test]
fn a_twelve_byte_probe_carries_nothing() {
    assert!(carries_nothing(&parse(b"hello world\n")));
}

#[test]
fn so_does_an_empty_delivery() {
    // `b""` is not here: the parser answers `None` for it, so it never
    // reaches this predicate. Checked rather than assumed — printing what the
    // parser does for each shape is how the case below was found.
    assert!(carries_nothing(&parse(b"\r\n")));
    assert!(carries_nothing(&parse(b"   \r\n\r\n   ")));
}

/// A delivery that is *only* a body loses it in the parser, so by the time
/// anything can judge it there is nothing left to keep.
///
/// `"\r\nthe whole message is this line\r\n"` — a leading blank line, which in
/// SMTP means "no headers, body follows" — parses to an `Email` whose body
/// value is the empty string. So does the six-byte probe. Refusing these is
/// not the predicate being harsh: there is no content to file, and storing the
/// husk is what produced four rows nobody could open.
///
/// Written down because it is surprising and it is the parser's behaviour, not
/// this crate's: anything relying on "a body-only message survives delivery"
/// is relying on something that is not true.
#[test]
fn a_body_with_no_headers_does_not_survive_the_parser() {
    let m = parse(b"\r\nthe whole message is this line\r\n");
    assert!(
        m.body_values.values().all(|v| v.value.is_empty()),
        "the parser kept the body after all — then this refusal is wrong: {:?}",
        m.body_values
    );
    assert!(carries_nothing(&m));
}

/// The other half, and the one that matters more: real mail must not be
/// refused. Each of these is missing something a strict reading might demand,
/// and every one of them is a message a person sent.
#[test]
fn real_mail_is_kept_however_sparse() {
    let cases: &[(&str, &[u8])] = &[
        (
            "no From, but a body — a broken sender is still mail",
            b"To: y@biset.md\r\nSubject: hi\r\n\r\nthe body\r\n",
        ),
        (
            "no Subject",
            b"From: a@x.test\r\nTo: y@biset.md\r\n\r\nthe body\r\n",
        ),
        (
            "no body, but headers — a bare acknowledgement",
            b"From: a@x.test\r\nTo: y@biset.md\r\nSubject: ack\r\n\r\n",
        ),
        (
            "nothing but a Message-ID",
            b"Message-ID: <abc@x.test>\r\n\r\n",
        ),
        // The cases that make the body clause load-bearing. One header line —
        // any header, even one this crate never reads — is enough for the
        // parser to keep the body, and then there is real text to deliver with
        // no From, no Subject and no Message-ID anywhere. Judging on headers
        // alone would refuse all three.
        //
        // Added after a mutation slipped: deleting the body clause left every
        // other case green, because none of them had content without headers.
        (
            "an unmapped header and a body",
            b"X-Foo: bar\r\n\r\nhello there\r\n",
        ),
        (
            "an empty Subject and a body",
            b"Subject:\r\n\r\nhello there\r\n",
        ),
        (
            "a Date and a body",
            b"Date: Mon, 10 Aug 2026 22:44:38 +0000\r\n\r\nhello there\r\n",
        ),
    ];
    for (name, raw) in cases {
        assert!(
            !carries_nothing(&parse(raw)),
            "{name}: real mail was refused"
        );
    }
}

/// Whitespace is not content. A body of blank lines reads as nothing, and a
/// subject of spaces is not a subject — otherwise the same phantom row comes
/// back wearing a space.
#[test]
fn whitespace_does_not_count_as_content() {
    assert!(carries_nothing(&parse(
        b"Subject:    \r\n\r\n   \r\n  \r\n"
    )));
}
