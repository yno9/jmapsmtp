//! The inbound buffer: mail Go accepts and then throws away (SPEC.md §11.17).
//!
//! Go does not store an inbound message when it arrives. It pushes it onto a
//! 256-slot channel (`main.go`'s `bufCh`) which is drained only when a JMAP
//! request comes in (`drainBuffer`, called at the top of `Dispatch`). If more
//! than 256 messages arrive between two JMAP requests, `bufferEmail` takes
//! its `default` branch, logs, and **drops** the message — after the SMTP
//! conversation already answered `250`, which tells the sending MTA the mail
//! was accepted and it must not retry.
//!
//! This port stores on arrival, so there is nothing to overflow. That is a
//! declared divergence, and this file asserts it is **still** a divergence:
//! it requires the oracle to keep dropping. If Go were fixed, this test fails
//! and says so, rather than quietly becoming a test of nothing.
//!
//! The unit half — that this port keeps all 300 — lives next to the code, in
//! `delivery::tests::more_than_256_messages_arriving_between_requests_are_all_stored`.
//! Both halves are needed: one alone would pass if the other side changed.
//!
//! `INBOUND_BUFFER_INTEROP=required` — set by `just test` — turns a missing
//! oracle into an error rather than a silent pass.

use base64::Engine as _;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

mod oracle_harness;
use oracle_harness::Oracle;

/// Go's channel capacity, from `main.go`: `make(chan incoming, 256)`.
const GO_BUFFER: usize = 256;

/// Enough past the buffer that an off-by-one cannot be mistaken for the
/// behaviour, and few enough that the delivery loop stays quick.
const DELIVERED: usize = 300;

/// The static credential for `alice`. `Email/query` is authenticated, and it
/// is also what drains Go's channel — so this test cannot ask its question
/// without one.
const AUTH_TOKEN: &[u8] = b"inbound-buffer-token-0000000000";

fn basic_auth() -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{password}"))
}

fn seed(root: &std::path::Path) {
    let acct = root.join("data/a.test/alice");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(AUTH_TOKEN),
    )
    .unwrap();
}

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

/// Deliver `n` messages down **one** SMTP connection, with no JMAP request
/// anywhere in between — which is the condition that fills Go's channel.
///
/// `first` numbers the Message-IDs. It is a parameter rather than always
/// starting at zero because the store is keyed by Message-ID: a second batch
/// reusing `m0..` **overwrites** the first, and the batched test then counts
/// one batch and looks like the drop it was written to rule out.
fn deliver(port: u16, first: usize, n: usize) {
    let stream = connect_smtp(port);
    let mut r = BufReader::new(stream.try_clone().unwrap());
    let mut w = stream;

    let expect = |r: &mut BufReader<TcpStream>, want: u8| {
        loop {
            let mut line = String::new();
            assert!(
                r.read_line(&mut line).unwrap() > 0,
                "the SMTP connection closed early"
            );
            if line.as_bytes().get(3) == Some(&b'-') {
                continue; // continuation of a multi-line reply
            }
            assert_eq!(
                line.as_bytes().first().copied(),
                Some(want),
                "unexpected SMTP reply: {}",
                line.trim()
            );
            return;
        }
    };

    expect(&mut r, b'2');
    writeln!(w, "EHLO test.invalid\r").unwrap();
    expect(&mut r, b'2');

    for i in first..first + n {
        writeln!(w, "MAIL FROM:<bob@x.test>\r").unwrap();
        expect(&mut r, b'2');
        writeln!(w, "RCPT TO:<alice@a.test>\r").unwrap();
        expect(&mut r, b'2');
        writeln!(w, "DATA\r").unwrap();
        expect(&mut r, b'3');
        write!(
            w,
            "From: bob@x.test\r\n\
             To: alice@a.test\r\n\
             Subject: m{i}\r\n\
             Message-ID: <m{i}@x.test>\r\n\
             Date: Wed, 05 Aug 2026 12:00:00 +0000\r\n\
             \r\n\
             body {i}\r\n\
             .\r\n"
        )
        .unwrap();
        w.flush().unwrap();
        // The 250 here is the promise this test is about: the sender is told
        // the message was accepted, and for 44 of them that is not true.
        expect(&mut r, b'2');
    }
    writeln!(w, "QUIT\r").unwrap();
}

/// Connect to the oracle's SMTP listener, waiting for it to appear.
///
/// The wait is needed because **Go brings SMTP up after HTTP**: `main.go`
/// starts it with `go startSMTP(h, dataDir)` and then calls
/// `http.ListenAndServe` on the main goroutine, so the harness's readiness
/// check — which is an HTTP request — can succeed while port 25 is still
/// unbound. Connecting straight away failed roughly one run in three.
///
/// This port binds SMTP **first** and awaits the bind (`main.rs` step 14), so
/// by the time it answers HTTP the mail port is already up. An operator's
/// health check can therefore see Go serving JMAP while refusing mail, and
/// can never see that here — SPEC.md §11.18.
fn connect_smtp(port: u16) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                return s;
            }
            Err(e) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the oracle's SMTP listener never came up on {port}: {e}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// How many messages the account holds, asked over JMAP. This request is also
/// what triggers Go's drain, so it must come after every delivery.
fn stored(oracle: &Oracle) -> usize {
    let (status, body) = oracle.post_json_auth(
        "/jmap/api/",
        &format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
                 "methodCalls":[["Email/query",{{"accountId":"alice@a.test","limit":{}}},"c0"]]}}"#,
            DELIVERED * 2
        ),
        &basic_auth(),
    );
    assert_eq!(status, 200, "Email/query should answer: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("a JSON response");
    v["methodResponses"][0][1]["ids"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
}

/// **Declared divergence, asserted to persist.**
///
/// The oracle must still lose mail here. A green run of this test is the
/// evidence that §11.17 describes the Go build as it is today.
#[test]
fn the_oracle_still_drops_everything_past_its_256_slot_buffer() {
    let Some(oracle) = Oracle::start_with("INBOUND_BUFFER_INTEROP", config_json, seed) else {
        return;
    };

    deliver(oracle.smtp_port, 0, DELIVERED);

    let got = stored(&oracle);
    assert_eq!(
        got, GO_BUFFER,
        "the oracle accepted {DELIVERED} messages and should have kept only \
         the {GO_BUFFER} its channel holds. Holding {DELIVERED} would mean Go \
         fixed this and SPEC.md §11.17 is stale; holding something else means \
         the buffer changed size."
    );
    assert!(
        got < DELIVERED,
        "at least {} accepted messages were silently discarded — this is the \
         behaviour the port does not reproduce",
        DELIVERED - GO_BUFFER
    );
}

/// The same messages, delivered in batches small enough to fit, with a JMAP
/// request between them to trigger the drain: now Go keeps all of them.
///
/// Without this, the test above could be explained by the oracle refusing
/// mail for some unrelated reason — a wrong account name, a rejected
/// envelope — and would prove nothing about the buffer. This pins the cause.
#[test]
fn the_oracle_keeps_everything_when_the_buffer_is_drained_in_time() {
    let Some(oracle) = Oracle::start_with("INBOUND_BUFFER_INTEROP", config_json, seed) else {
        return;
    };

    let batch = GO_BUFFER / 2;
    let mut sent = 0;
    while sent < DELIVERED {
        let n = batch.min(DELIVERED - sent);
        deliver(oracle.smtp_port, sent, n);
        sent += n;
        // Drains the channel, making room for the next batch.
        stored(&oracle);
    }

    assert_eq!(
        stored(&oracle),
        DELIVERED,
        "with the channel drained between batches nothing is lost, so the \
         loss above is the buffer and not the delivery path"
    );
}
