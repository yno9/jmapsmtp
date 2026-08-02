//! Command parsing and the responses a real client never provokes.
//!
//! The interop corpus in `tests/smtp_interop.rs` drives the Go client through
//! the ordinary paths; these cover the parsing corners and the error replies
//! a well-behaved client will not reach.

use super::*;
use pretty_assertions::assert_eq;

// ── command splitting ─────────────────────────────────────────────────────

#[test]
fn a_verb_is_upper_cased_and_the_rest_kept() {
    assert_eq!(
        split_command("mail FROM:<a@x>"),
        ("MAIL".into(), "FROM:<a@x>")
    );
    assert_eq!(split_command("QUIT"), ("QUIT".into(), ""));
    assert_eq!(split_command("  ehlo  host  "), ("EHLO".into(), "host  "));
    assert_eq!(split_command(""), (String::new(), ""));
}

// ── address paths ─────────────────────────────────────────────────────────

#[test]
fn a_bracketed_path_yields_the_address() {
    assert_eq!(parse_path("FROM:<a@x>", "FROM:"), Some("a@x".into()));
    assert_eq!(parse_path("TO:<b@y>", "TO:"), Some("b@y".into()));
}

#[test]
fn the_prefix_is_matched_case_insensitively() {
    assert_eq!(parse_path("from:<a@x>", "FROM:"), Some("a@x".into()));
    assert_eq!(parse_path("From: <a@x>", "FROM:"), Some("a@x".into()));
}

/// Real senders omit the brackets often enough that go-smtp accepts it, so
/// this does too.
#[test]
fn an_unbracketed_path_is_accepted() {
    assert_eq!(parse_path("FROM:a@x", "FROM:"), Some("a@x".into()));
    assert_eq!(parse_path("FROM: a@x", "FROM:"), Some("a@x".into()));
}

#[test]
fn esmtp_parameters_after_the_address_are_ignored() {
    assert_eq!(
        parse_path("FROM:<a@x> SIZE=100 BODY=8BITMIME", "FROM:"),
        Some("a@x".into())
    );
    assert_eq!(parse_path("FROM:a@x SIZE=100", "FROM:"), Some("a@x".into()));
}

/// The empty return path of a bounce.
#[test]
fn an_empty_bracketed_path_is_the_null_sender() {
    assert_eq!(parse_path("FROM:<>", "FROM:"), Some(String::new()));
}

#[test]
fn a_malformed_path_is_rejected() {
    assert_eq!(parse_path("", "FROM:"), None);
    assert_eq!(parse_path("TO:<a@x>", "FROM:"), None);
    assert_eq!(parse_path("FROM:<unterminated", "FROM:"), None);
    assert_eq!(parse_path("FROM:", "FROM:"), None);
    // Shorter than the prefix: must not panic on the slice.
    assert_eq!(parse_path("FR", "FROM:"), None);
}

// ── EHLO ──────────────────────────────────────────────────────────────────

#[test]
fn the_ehlo_response_is_a_well_formed_multiline_reply() {
    let out = ehlo_response(&Config {
        hostname: "mail.example.com".into(),
        starttls: true,
        tls_available: false,
        enable_smtputf8: true,
    });
    let lines: Vec<&str> = out.trim_end_matches("\r\n").split("\r\n").collect();

    assert_eq!(lines[0], "250-mail.example.com greets you");
    // Every line but the last uses the continuation form.
    for line in &lines[..lines.len() - 1] {
        assert!(line.starts_with("250-"), "{line} should continue");
    }
    assert!(
        lines.last().unwrap().starts_with("250 "),
        "the last line ends the reply"
    );
    assert_eq!(*lines.last().unwrap(), "250 SIZE");
}

#[test]
fn disabling_starttls_and_smtputf8_drops_exactly_those() {
    let out = ehlo_response(&Config {
        hostname: "h".into(),
        starttls: false,
        tls_available: false,
        enable_smtputf8: false,
    });
    assert!(!out.contains("STARTTLS"));
    assert!(!out.contains("SMTPUTF8"));
    assert!(out.contains("250-PIPELINING\r\n"));
    assert!(out.ends_with("250 SIZE\r\n"));
}

/// AUTH is never advertised. This is a public MX on port 25; offering
/// authentication would invite clients to send credentials that go nowhere.
#[test]
fn auth_is_never_advertised() {
    for starttls in [true, false] {
        let out = ehlo_response(&Config {
            hostname: "h".into(),
            starttls,
            tls_available: false,
            enable_smtputf8: true,
        });
        assert!(!out.contains("AUTH"), "AUTH must not appear");
    }
}

// ── DATA ──────────────────────────────────────────────────────────────────

/// Feed a DATA payload through the reader and get back what the backend sees.
fn read_payload(input: &[u8]) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut reader = tokio::io::BufReader::new(input);
        read_data(&mut reader).await.unwrap()
    })
}

#[test]
fn the_terminator_ends_the_payload_and_is_not_part_of_it() {
    assert_eq!(
        read_payload(b"line one\r\nline two\r\n.\r\n"),
        b"line one\r\nline two\r\n"
    );
}

#[test]
fn a_leading_dot_is_unstuffed() {
    assert_eq!(read_payload(b".hidden\r\n.\r\n"), b"hidden\r\n");
    assert_eq!(read_payload(b"..two\r\n.\r\n"), b".two\r\n");
}

#[test]
fn bare_lf_lines_are_normalised_to_crlf() {
    // A sender that omits the CR still produces a message the store can hold.
    assert_eq!(read_payload(b"one\ntwo\n.\n"), b"one\r\ntwo\r\n");
}

#[test]
fn an_empty_payload_is_empty_not_an_error() {
    assert_eq!(read_payload(b".\r\n"), b"");
}

/// A connection that dies mid-DATA yields what arrived; the caller answers no
/// 250, so the sender retries.
#[test]
fn a_truncated_payload_returns_what_arrived() {
    assert_eq!(read_payload(b"partial\r\n"), b"partial\r\n");
}

/// A line that merely starts with a dot is not a terminator.
#[test]
fn only_a_lone_dot_terminates() {
    assert_eq!(read_payload(b".. \r\n.\r\n"), b". \r\n");
    assert_eq!(read_payload(b".stuff\r\n.\r\n"), b"stuff\r\n");
}
