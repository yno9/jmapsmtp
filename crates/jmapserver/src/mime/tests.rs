//! Unit tests for the pieces the interop corpus cannot isolate.
//!
//! The corpus in `tests/mime_interop.rs` is the real check — it compares
//! against the Go functions. These pin the internals that a whole-message
//! comparison would only reach indirectly.

use super::*;
use pretty_assertions::assert_eq;

// ── headers ───────────────────────────────────────────────────────────────

#[test]
fn a_folded_header_is_unfolded_onto_one_line() {
    let (h, _) = split_message(b"Subject: one\r\n two\r\n\tthree\r\n\r\nbody").unwrap();
    assert_eq!(h.get("Subject"), "one two three");
}

#[test]
fn header_lookup_is_case_insensitive_and_takes_the_first() {
    let (h, _) = split_message(b"X-A: first\r\nx-a: second\r\n\r\n").unwrap();
    assert_eq!(h.get("x-A"), "first");
}

#[test]
fn both_crlf_and_bare_lf_separate_headers_from_body() {
    let (_, body) = split_message(b"A: 1\r\n\r\nbody").unwrap();
    assert_eq!(body, b"body");
    let (_, body) = split_message(b"A: 1\n\nbody").unwrap();
    assert_eq!(body, b"body");
}

#[test]
fn a_message_that_is_only_headers_still_parses() {
    let (h, body) = split_message(b"A: 1\r\n").unwrap();
    assert_eq!(h.get("A"), "1");
    assert!(body.is_empty());
}

// ── media types ───────────────────────────────────────────────────────────

#[test]
fn media_types_lowercase_and_carry_parameters() {
    let (media, params) =
        parse_media_type("Multipart/Mixed; Boundary=\"a=b;c\"; charset=UTF-8").unwrap();
    assert_eq!(media, "multipart/mixed");
    // A semicolon inside quotes is part of the value, not a separator.
    assert_eq!(params["boundary"], "a=b;c");
    assert_eq!(params["charset"], "UTF-8", "values keep their case");
}

#[test]
fn an_empty_media_type_is_none() {
    assert!(parse_media_type("").is_none());
    assert!(parse_media_type("   ").is_none());
}

// ── transfer encodings ────────────────────────────────────────────────────

#[test]
fn quoted_printable_decodes_hex_and_soft_breaks() {
    assert_eq!(decode_transfer("quoted-printable", b"caf=C3=A9"), "café");
    assert_eq!(
        decode_transfer("quoted-printable", b"one=\r\ntwo"),
        "onetwo",
        "a soft line break joins the lines"
    );
    assert_eq!(
        decode_transfer("quoted-printable", b"100=25"),
        "100%",
        "=25 is a literal percent"
    );
}

#[test]
fn base64_ignores_whitespace() {
    assert_eq!(decode_transfer("base64", b"aGVs\r\nbG8="), "hello");
}

#[test]
fn an_unknown_transfer_encoding_passes_through() {
    assert_eq!(decode_transfer("7bit", b"plain"), "plain");
    assert_eq!(decode_transfer("", b"plain"), "plain");
}

// ── encoded words ─────────────────────────────────────────────────────────

#[test]
fn encoded_words_decode_in_both_encodings() {
    assert_eq!(
        decode_words("=?UTF-8?B?44GT44KT44Gr44Gh44Gv?="),
        "こんにちは"
    );
    assert_eq!(decode_words("=?utf-8?q?caf=C3=A9_time?="), "café time");
}

#[test]
fn text_around_an_encoded_word_is_kept() {
    assert_eq!(
        decode_words("Re: =?utf-8?q?caf=C3=A9?= now"),
        "Re: café now"
    );
}

#[test]
fn a_plain_subject_is_untouched() {
    assert_eq!(decode_words("just a subject"), "just a subject");
}

/// An unknown charset is left encoded rather than mangled — the same choice
/// `mime.WordDecoder` makes without a CharsetReader.
#[test]
fn an_unknown_charset_is_left_alone() {
    let s = "=?iso-2022-jp?B?GyRCJUYlOSVIGyhC?=";
    assert_eq!(decode_words(s), s);
}

// ── addresses ─────────────────────────────────────────────────────────────

#[test]
fn addresses_parse_with_and_without_a_display_name() {
    assert_eq!(
        parse_address("Alice <alice@example.com>"),
        Some(Address {
            name: "Alice".into(),
            email: "alice@example.com".into()
        })
    );
    assert_eq!(
        parse_address("bare@example.com"),
        Some(Address {
            name: String::new(),
            email: "bare@example.com".into()
        })
    );
}

#[test]
fn something_without_an_at_sign_is_not_an_address() {
    assert_eq!(parse_address("not an address"), None);
    assert_eq!(parse_address(""), None);
}

/// `mail.ParseAddressList` is all-or-nothing: one bad entry drops the header.
#[test]
fn an_address_list_is_all_or_nothing() {
    assert_eq!(parse_address_list("a@x, b@y").map(|v| v.len()), Some(2));
    assert_eq!(parse_address_list("a@x, garbage"), None);
}

#[test]
fn a_comma_inside_a_quoted_name_does_not_split_the_list() {
    let list = parse_address_list("\"Dave, Jr\" <dave@x>, eve@y").unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].name, "Dave, Jr");
}

// ── display names ─────────────────────────────────────────────────────────

/// Go quotes an all-ASCII name unconditionally, which is not what RFC 5322
/// requires and is what goes on the wire.
#[test]
fn display_names_are_always_quoted_when_ascii() {
    assert_eq!(render_display_name("Alice"), "\"Alice\"");
    assert_eq!(render_display_name("Dave, Jr"), "\"Dave, Jr\"");
    assert_eq!(render_display_name("say \"hi\""), "\"say \\\"hi\\\"\"");
}

#[test]
fn a_non_ascii_display_name_becomes_an_encoded_word() {
    assert_eq!(render_display_name("あ"), "=?utf-8?q?=E3=81=82?=");
}

#[test]
fn an_address_with_no_name_borrows_its_localpart() {
    assert_eq!(
        format_addr(&Address {
            name: String::new(),
            email: "bob@example.org".into()
        }),
        "\"bob\" <bob@example.org>"
    );
}

// ── multipart splitting ───────────────────────────────────────────────────

#[test]
fn the_preamble_and_epilogue_are_discarded() {
    let body = b"preamble text\r\n\
        --bnd\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        first\r\n\
        --bnd\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        second\r\n\
        --bnd--\r\n\
        epilogue";
    let parts = split_parts(body, "bnd");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].body, b"first");
    assert_eq!(parts[1].body, b"second");
}

#[test]
fn a_missing_boundary_yields_no_parts() {
    assert!(split_parts(b"no boundary here", "bnd").is_empty());
}

// ── envelope ──────────────────────────────────────────────────────────────

fn addr(email: &str) -> Address {
    Address {
        name: String::new(),
        email: email.into(),
    }
}

#[test]
fn the_envelope_collapses_duplicate_recipients() {
    let e = Email {
        from: vec![addr("a@x")],
        to: vec![addr("b@y"), addr("c@z")],
        cc: vec![addr("b@y")],
        bcc: vec![addr("d@w")],
        ..Default::default()
    };
    let env = build_envelope(&e).unwrap();
    assert_eq!(env.mail_from.unwrap().email, "a@x");
    let rcpts: Vec<String> = env.rcpt_to.into_iter().map(|a| a.email).collect();
    assert_eq!(
        rcpts,
        ["b@y", "c@z", "d@w"],
        "first occurrence keeps its place"
    );
}

#[test]
fn no_from_or_no_recipient_means_no_envelope() {
    assert!(
        build_envelope(&Email {
            to: vec![addr("b@y")],
            ..Default::default()
        })
        .is_none()
    );
    assert!(
        build_envelope(&Email {
            from: vec![addr("a@x")],
            ..Default::default()
        })
        .is_none()
    );
}

// ── message body ──────────────────────────────────────────────────────────

#[test]
fn the_body_comes_from_the_first_text_part() {
    let mut e = Email {
        text_body: vec![BodyPart {
            part_id: "1".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    e.body_values.insert("1".into(), BodyValue::new("the body"));
    assert_eq!(message_body(&e), "the body");

    // A text part pointing at a body value that is not there yields nothing.
    e.body_values.clear();
    assert_eq!(message_body(&e), "");
}
