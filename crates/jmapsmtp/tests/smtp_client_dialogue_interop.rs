//! What this port **says** when it delivers, compared against `net/smtp`.
//!
//! The mirror of `smtp_dialogue_interop`, which compared the two servers. This
//! compares the two clients: both are pointed at one recording server and the
//! commands they issue are diffed.
//!
//! `smtp_interop` already checks that the Go server *accepts* what this port
//! sends — the envelope and the body arrive intact. That is the outcome, not
//! the conversation. A receiving MTA acts on the conversation: the name in
//! `EHLO`, whether `MAIL FROM` carries ESMTP parameters, whether the client
//! tries `STARTTLS`, whether it ends with `QUIT` or drops the connection.
//! Greylisters and reputation systems read exactly those.
//!
//! `net/smtp` is the client `smtpSend` uses, and the Go helper's `send` mode
//! drives it, so the transcript on the far side is what the Go relay would
//! have produced.
//!
//! # The server here answers, it does not judge
//!
//! It speaks just enough SMTP to keep a client talking, and records every line
//! it is sent. Judging anything would make the comparison depend on this
//! file's opinions rather than on the two clients.
//!
//! `SMTP_INTEROP=required` — the same helper this suite's sibling needs.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use pretty_assertions::assert_eq;

const HELO_NAME: &str = "mail.example.com";
const FROM: &str = "alice@example.com";
const TO: &str = "bob@example.org";
const MESSAGE: &str = "From: alice@example.com\r\n\
     To: bob@example.org\r\n\
     Subject: client dialogue\r\n\
     \r\n\
     body\r\n";

fn require_helper() -> Option<PathBuf> {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/smtp-interop")
        .canonicalize()
        .ok()?;
    if bin.exists() {
        return Some(bin);
    }
    assert!(
        std::env::var("SMTP_INTEROP").as_deref() != Ok("required"),
        "the Go SMTP helper is missing — run `just interop`"
    );
    None
}

/// Answers well enough to keep a client going, and records what it hears.
///
/// `extensions` is what EHLO advertises. Run both ways: with nothing, which
/// isolates the bare conversation, and with a realistic list, which is where
/// two clients actually diverge — one uses `SIZE` or `BODY=8BITMIME` and the
/// other does not, and the far end sees a different `MAIL FROM`.
fn start_recorder(extensions: &[&str]) -> (String, Arc<Mutex<Vec<String>>>) {
    let extensions: Vec<String> = extensions.iter().map(|e| (*e).to_string()).collect();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    std::thread::spawn(move || {
        // One connection per run; the test drives one client at a time.
        for stream in listener.incoming().take(2) {
            let Ok(stream) = stream else { continue };
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let mut w = stream;
            let _ = write!(w, "220 recorder ESMTP\r\n");
            let _ = w.flush();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let cmd = line.trim_end_matches(['\r', '\n']).to_string();
                sink.lock().unwrap().push(cmd.clone());
                let upper = cmd.to_uppercase();
                let reply: String = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    let mut out = String::new();
                    for e in &extensions {
                        out.push_str(&format!("250-{e}\r\n"));
                    }
                    out.push_str("250 recorder\r\n");
                    out
                } else if upper.starts_with("DATA") {
                    "354 go ahead\r\n".into()
                } else if upper.starts_with("QUIT") {
                    "221 bye\r\n".into()
                } else {
                    "250 ok\r\n".into()
                };
                let _ = write!(w, "{reply}");
                let _ = w.flush();
                if upper.starts_with("QUIT") {
                    break;
                }
                if upper.starts_with("DATA") {
                    // Swallow the payload; the body is compared by
                    // `smtp_interop`, and keeping it here would drown the
                    // command transcript in message text.
                    loop {
                        let mut l = String::new();
                        if r.read_line(&mut l).unwrap_or(0) == 0 {
                            break;
                        }
                        if l.trim_end_matches(['\r', '\n']) == "." {
                            sink.lock().unwrap().push("<message body>".into());
                            let _ = write!(w, "250 queued\r\n");
                            let _ = w.flush();
                            break;
                        }
                    }
                }
            }
        }
    });
    (addr, log)
}

/// Everything up to and including the end of the message, as commands.
fn transcript(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    std::mem::take(&mut *log.lock().unwrap())
}

/// Drive both clients at one recorder and return `(go, ours)`.
fn both_transcripts(bin: &PathBuf, extensions: &[&str]) -> (Vec<String>, Vec<String>) {
    let (addr, log) = start_recorder(extensions);

    // Go first, so a failure to reach the helper is reported before anything
    // else has run.
    let request = serde_json::json!({
        "from": FROM,
        "rcpts": [TO],
        "message": MESSAGE,
        "helo": HELO_NAME,
    })
    .to_string();
    let mut child = Command::new(bin)
        .args(["send", &addr])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the helper should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let response: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("the helper should answer JSON");
    assert!(
        response["ok"].as_bool().unwrap_or(false),
        "the Go client failed: {response}"
    );
    let go = transcript(&log);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let sender = jmapsmtp::smtp_out::Sender {
            hostname: HELO_NAME.into(),
            relay_host: None,
            extra_roots: Vec::new(),
        };
        sender
            .send_one(&addr, FROM, &[TO.to_string()], MESSAGE.as_bytes())
            .await
            .expect("the send should succeed");
    });
    let ours = transcript(&log);
    (go, ours)
}

/// A bare server: no extensions, so nothing but the required commands.
#[test]
fn this_port_and_net_smtp_issue_the_same_commands() {
    let Some(bin) = require_helper() else { return };
    let (go, ours) = both_transcripts(&bin, &[]);
    assert_eq!(
        ours, go,
        "the two clients say different things to the same server — a \
         receiving MTA acts on this"
    );
    // A guard on the recorder rather than on the clients: if it stopped
    // recording, both transcripts would be empty and equal.
    assert!(
        go.len() >= 5,
        "the recorder should have captured a full conversation, got {go:?}"
    );
}

/// The same, against a server that advertises what a real one does.
///
/// This is where two clients diverge in practice: a `SIZE` the far end
/// announced, `BODY=8BITMIME` on `MAIL FROM`, pipelining that changes nothing
/// about the bytes but everything about their order.
#[test]
fn the_same_holds_when_the_far_end_advertises_extensions() {
    let Some(bin) = require_helper() else { return };
    let (go, ours) = both_transcripts(
        &bin,
        &[
            "PIPELINING",
            "SIZE 35882577",
            "8BITMIME",
            "ENHANCEDSTATUSCODES",
            "SMTPUTF8",
        ],
    );
    assert_eq!(
        ours, go,
        "the clients use the advertised extensions differently"
    );
    assert!(go.len() >= 5, "captured too little: {go:?}");
}
