//! Dot-stuffing, reply parsing and routing.
//!
//! The wire behaviour is checked against a real go-smtp server in
//! `tests/smtp_interop.rs`; these cover the pieces a successful delivery
//! never distinguishes.

use super::*;
use pretty_assertions::assert_eq;

// ── dot stuffing ──────────────────────────────────────────────────────────

fn stuffed(raw: &[u8]) -> String {
    String::from_utf8(dot_stuff(raw)).unwrap()
}

#[test]
fn a_line_beginning_with_a_dot_gains_one() {
    assert_eq!(stuffed(b".hidden\r\n"), "..hidden\r\n");
    assert_eq!(stuffed(b"a\r\n.b\r\n"), "a\r\n..b\r\n");
}

/// The first line counts as the start of a line too — a body that opens with
/// a dot would otherwise end the message immediately.
#[test]
fn the_very_first_character_is_a_line_start() {
    assert_eq!(stuffed(b"."), "..");
}

#[test]
fn a_dot_that_is_not_at_a_line_start_is_left_alone() {
    assert_eq!(stuffed(b"a.b\r\n"), "a.b\r\n");
    assert_eq!(stuffed(b"end.\r\n"), "end.\r\n");
}

#[test]
fn ordinary_text_passes_through_untouched() {
    assert_eq!(
        stuffed(b"From: a@x\r\n\r\nbody\r\n"),
        "From: a@x\r\n\r\nbody\r\n"
    );
    assert_eq!(stuffed(b""), "");
}

/// Bare LF also starts a line, since messages do arrive that way.
#[test]
fn a_bare_lf_also_starts_a_line() {
    assert_eq!(stuffed(b"a\n.b\n"), "a\n..b\n");
}

// ── replies ───────────────────────────────────────────────────────────────

fn read(input: &str) -> std::io::Result<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut r = tokio::io::BufReader::new(input.as_bytes());
        read_reply(&mut r).await
    })
}

#[test]
fn a_single_line_reply_is_returned_whole() {
    assert_eq!(read("250 OK\r\n").unwrap(), "250 OK\r\n");
}

/// A hyphen in the fourth column continues the reply; a space ends it.
#[test]
fn a_multiline_reply_is_read_to_its_last_line() {
    let got = read("250-mail greets you\r\n250-PIPELINING\r\n250 SIZE\r\nnext").unwrap();
    assert_eq!(got, "250-mail greets you\r\n250-PIPELINING\r\n250 SIZE\r\n");
}

#[test]
fn a_connection_closing_mid_reply_is_an_error() {
    assert!(read("").is_err());
    assert!(read("250-continued\r\n").is_err());
}

// ── reply classification ──────────────────────────────────────────────────

/// Any reply in the expected class is a success — 250 and 251 are both an
/// accepted recipient, and servers differ on which they send.
#[test]
fn the_reply_class_is_what_decides() {
    assert!(check("250 OK\r\n".into(), 250, "x").is_ok());
    assert!(check("251 User not local\r\n".into(), 250, "x").is_ok());
    assert!(check("354 Go ahead\r\n".into(), 354, "x").is_ok());
    assert!(check("220 Ready\r\n".into(), 220, "x").is_ok());
}

#[test]
fn a_failure_reply_carries_the_server_text() {
    let err = check("550 5.1.1 No such user\r\n".into(), 250, "RCPT TO").unwrap_err();
    let text = err.to_string();
    assert!(text.contains("RCPT TO"), "{text}");
    assert!(text.contains("550 5.1.1 No such user"), "{text}");
    assert!(!text.ends_with('\n'), "the trailing newline is trimmed");
}

#[test]
fn a_temporary_failure_is_still_a_failure() {
    assert!(check("451 Try later\r\n".into(), 250, "x").is_err());
    assert!(check("".into(), 250, "x").is_err());
}

// ── routing ───────────────────────────────────────────────────────────────

struct NoMx;

impl MxResolver for NoMx {
    fn lookup_mx(&self, _domain: &str) -> Vec<String> {
        Vec::new()
    }
}

fn sender() -> Sender {
    Sender {
        hostname: "mail.example.com".into(),
        relay_host: None,
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

#[test]
fn no_recipients_is_refused_before_any_connection() {
    let err = block_on(sender().deliver(&NoMx, "a@x", &[], b"msg")).unwrap_err();
    assert!(matches!(err, SendError::NoRecipients));
}

#[test]
fn a_domain_with_no_mx_reports_which_one() {
    let err =
        block_on(sender().deliver(&NoMx, "a@x", &["b@nowhere.test".into()], b"msg")).unwrap_err();
    assert_eq!(err.to_string(), "no MX for nowhere.test");
}

/// A recipient with no `@` cannot be routed, and the Go original abandons the
/// whole send rather than skipping it.
#[test]
fn a_recipient_without_a_domain_fails_the_send() {
    let err =
        block_on(sender().deliver(&NoMx, "a@x", &["not-an-address".into()], b"msg")).unwrap_err();
    assert!(matches!(err, SendError::InvalidRecipient(_)));
    assert!(err.to_string().contains("not-an-address"));
}

/// Every domain is attempted even when an earlier one fails, and the first
/// error is what comes back.
#[test]
fn one_failing_domain_does_not_stop_the_others() {
    struct CountingMx(std::sync::Mutex<Vec<String>>);
    impl MxResolver for CountingMx {
        fn lookup_mx(&self, domain: &str) -> Vec<String> {
            self.0.lock().unwrap().push(domain.to_string());
            Vec::new()
        }
    }
    let resolver = CountingMx(std::sync::Mutex::new(Vec::new()));
    let err = block_on(sender().deliver(
        &resolver,
        "a@x",
        &["b@one.test".into(), "c@two.test".into()],
        b"msg",
    ))
    .unwrap_err();

    let looked_up = resolver.0.lock().unwrap().clone();
    assert_eq!(looked_up, ["one.test", "two.test"], "both were attempted");
    assert_eq!(
        err.to_string(),
        "no MX for one.test",
        "the first error wins"
    );
}

/// A relay host short-circuits routing entirely: no domain grouping, no MX.
#[test]
fn a_relay_host_skips_mx_lookup() {
    struct Explode;
    impl MxResolver for Explode {
        fn lookup_mx(&self, _domain: &str) -> Vec<String> {
            panic!("a relay host must not consult DNS");
        }
    }
    let sender = Sender {
        hostname: "mail.example.com".into(),
        // Nothing is listening; the point is only that DNS is not consulted.
        relay_host: Some("127.0.0.1:1".into()),
    };
    let err = block_on(sender.deliver(&Explode, "a@x", &["b@y".into()], b"msg")).unwrap_err();
    assert!(matches!(err, SendError::Dial(..)));
}

/// A trailing dot makes an MX name absolute in DNS but is not part of a
/// connect string.
#[test]
fn a_trailing_dot_on_an_mx_name_is_dropped() {
    struct AbsoluteMx;
    impl MxResolver for AbsoluteMx {
        fn lookup_mx(&self, _domain: &str) -> Vec<String> {
            vec!["mx.example.test.".into()]
        }
    }
    let err =
        block_on(sender().deliver(&AbsoluteMx, "a@x", &["b@y.test".into()], b"msg")).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("mx.example.test:25"), "{text}");
    assert!(!text.contains("test.:25"), "the dot must be gone: {text}");
}
