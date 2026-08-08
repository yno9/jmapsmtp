//! The SMTP conversation, compared against the **running** oracle.
//!
//! `smtp_interop` checks the greeting and the extension list against literal
//! strings, with a comment saying they are "the list go-smtp advertises".
//! That is a reading of the Go source frozen into an assertion: if go-smtp
//! changed its wording, or the relay set a different option, the two servers
//! would diverge and the test would stay green. Everything else in this port
//! is compared against the Go binary running, and the SMTP dialogue is the
//! one observable surface that was not.
//!
//! `difftest` cannot cover it either — it speaks HTTP only.
//!
//! # What a sender can act on
//!
//! Every reply here is something a real MTA reads: the greeting names the
//! host, the EHLO lines decide whether it may pipeline or use SMTPUTF8, and
//! the codes decide whether it retries, bounces, or gives up. A different
//! wording is survivable; a different *code* is a different delivery outcome.
//! Both are compared, and the codes are compared separately so a wording
//! difference cannot be mistaken for a behavioural one.
//!
//! `SMTP_DIALOGUE_INTEROP=required` — set by `just test` — turns a missing
//! oracle into an error rather than a silent pass.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jmapsmtp::smtp_in::{Backend, Config};
use pretty_assertions::assert_eq;
use tokio::net::TcpListener;

mod oracle_harness;
use oracle_harness::Oracle;

/// Both sides must greet with the same name, or every line differs for a
/// reason that is only configuration.
const HOSTNAME: &str = "mail.example.com";

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"{HOSTNAME}",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

struct Served {
    served: Vec<String>,
    delivered: Mutex<usize>,
}

impl Backend for Served {
    fn accepts(&self, rcpt: &str) -> bool {
        self.served.iter().any(|s| s.eq_ignore_ascii_case(rcpt))
    }
    fn deliver(&self, _from: &str, _rcpts: &[String], _raw: &[u8]) {
        *self.delivered.lock().unwrap() += 1;
    }
}

/// This port's SMTP server, configured to match the oracle's.
///
/// `tls_available: false` because the oracle's fixture has no certificate
/// either — `start_with` seeds no `data/smtp-tls-*.pem`, so it logs "STARTTLS
/// disabled". If one side advertised STARTTLS and the other did not, the EHLO
/// lists would differ for a reason that is about the fixture.
async fn start_ours() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let cfg = Arc::new(Config {
        hostname: HOSTNAME.into(),
        starttls: true,
        tls_available: false,
        enable_smtputf8: true,
    });
    let backend = Arc::new(Served {
        served: vec!["alice@a.test".into()],
        delivered: Mutex::new(0),
    });
    tokio::spawn(async move {
        jmapsmtp::smtp_in::serve(listener, cfg, backend).await;
    });
    addr
}

/// One command and the reply it drew, kept as text so a diff is readable.
#[derive(Debug, PartialEq, Eq)]
struct Exchange {
    sent: String,
    reply: Vec<String>,
}

/// Run a fixed conversation and record every reply.
///
/// Waits for the oracle's listener rather than assuming it is up: Go starts
/// SMTP in a goroutine and serves HTTP from the main one, so the port can
/// still be unbound when the relay is answering HTTP (SPEC.md §11.18).
fn converse(addr: &str, script: &[&str]) -> Vec<Exchange> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let stream = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the SMTP listener never came up on {addr}: {e}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut r = BufReader::new(stream.try_clone().unwrap());
    let mut w = stream;

    let read_reply = |r: &mut BufReader<TcpStream>| -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let more = line.as_bytes().get(3) == Some(&b'-');
            lines.push(line);
            if !more {
                break;
            }
        }
        lines
    };

    let mut out = vec![Exchange {
        sent: "(greeting)".into(),
        reply: read_reply(&mut r),
    }];
    for cmd in script {
        write!(w, "{cmd}\r\n").unwrap();
        w.flush().unwrap();
        out.push(Exchange {
            sent: (*cmd).to_string(),
            reply: read_reply(&mut r),
        });
    }
    out
}

/// The conversation. Ordinary delivery first, then each way a sender can be
/// wrong — every one of which a real MTA does eventually.
const SCRIPT: &[&str] = &[
    "EHLO sender.invalid",
    "MAIL FROM:<bob@x.invalid>",
    "RCPT TO:<alice@a.test>",
    // Not served here. Go answers 250 and drops it rather than telling a
    // stranger which addresses exist — the behaviour, in the reply.
    "RCPT TO:<nobody@a.test>",
    "RCPT TO:<someone@elsewhere.invalid>",
    "DATA",
    "From: bob@x.invalid\r\nTo: alice@a.test\r\nSubject: dialogue\r\n\r\nbody\r\n.",
    "RSET",
    "NOOP",
    // Wrong order: DATA with no recipient.
    "DATA",
    // Syntax the RFC does not allow.
    "MAIL FROM bob@x.invalid",
    "RCPT TO:<alice@a.test>",
    "VRFY alice@a.test",
    "NONSENSE",
    "HELO sender.invalid",
    "QUIT",
];

/// Reply codes only, for the assertion that matters most.
fn codes(exchanges: &[Exchange]) -> Vec<(String, Vec<String>)> {
    exchanges
        .iter()
        .map(|e| {
            (
                e.sent.lines().next().unwrap_or("").to_string(),
                e.reply
                    .iter()
                    .map(|l| l.chars().take(3).collect())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn the_smtp_dialogue_matches_the_oracle_line_for_line() {
    let Some(oracle) = Oracle::start_with("SMTP_DIALOGUE_INTEROP", config_json, |_| {}) else {
        return;
    };
    let go = converse(&format!("127.0.0.1:{}", oracle.smtp_port), SCRIPT);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ours = rt.block_on(async {
        let addr = start_ours().await;
        tokio::task::spawn_blocking(move || converse(&addr, SCRIPT))
            .await
            .unwrap()
    });

    // Codes first: a wording difference is cosmetic, a code difference is a
    // different delivery outcome, and reporting them together would let the
    // second hide behind the first.
    assert_eq!(
        codes(&ours),
        codes(&go),
        "the reply CODES differ — this changes what a sending MTA does"
    );
    assert_eq!(ours, go, "the reply text differs");
}

/// The greeting and EHLO list, called out separately because `smtp_interop`
/// asserts them against literal strings and this is where those literals stop
/// being a guess.
#[test]
fn the_greeting_and_extension_list_come_from_the_oracle_not_a_literal() {
    let Some(oracle) = Oracle::start_with("SMTP_DIALOGUE_INTEROP", config_json, |_| {}) else {
        return;
    };
    let go = converse(
        &format!("127.0.0.1:{}", oracle.smtp_port),
        &["EHLO t.invalid"],
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ours = rt.block_on(async {
        let addr = start_ours().await;
        tokio::task::spawn_blocking(move || converse(&addr, &["EHLO t.invalid"]))
            .await
            .unwrap()
    });

    assert_eq!(ours[0].reply, go[0].reply, "the greeting differs");
    assert_eq!(
        ours[1].reply, go[1].reply,
        "the EHLO response differs — order included, since it is what a \
         client parses"
    );
    // A guard on the fixture rather than on the code: if the oracle stopped
    // advertising anything at all, the comparison above would pass on two
    // empty lists.
    assert!(
        go[1].reply.len() > 3,
        "the oracle should advertise several extensions, got {:?}",
        go[1].reply
    );
}
