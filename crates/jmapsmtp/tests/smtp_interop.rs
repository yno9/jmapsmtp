//! Go ↔ Rust SMTP interoperability.
//!
//! The check that matters for an inbound server is that real clients can
//! deliver to it, so the Go helper drives `net/smtp` — the very client
//! `smtpSend` uses — against this port's server. Anything a sending MTA does
//! that this cannot answer shows up as a failed delivery, not as a subtle
//! difference.
//!
//! The mirror direction matters too, and is checked the same way: a real
//! go-smtp server, configured as the relay configures its own, receives what
//! the Rust client sends.
//!
//! `SMTP_INTEROP=required` — set by `just test` — turns a missing helper into
//! an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use jmapsmtp::smtp_in::{Backend, Config};
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Serialize)]
struct SendRequest {
    from: String,
    rcpts: Vec<String>,
    message: String,
    helo: String,
}

#[derive(Debug, Deserialize)]
struct SendResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    err: String,
    #[serde(default)]
    rejected: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProbeResponse {
    #[serde(default)]
    greeting: String,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    err: String,
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/smtp-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("SMTP_INTEROP").is_none(),
        "SMTP_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go SMTP interop helper not built — run `just interop`. Set \
         SMTP_INTEROP=required to make this an error instead."
    );
    None
}

/// What the server was asked to deliver.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Delivery {
    from: String,
    rcpts: Vec<String>,
    raw: String,
}

/// Accepts a fixed set of addresses and records everything delivered.
struct Recorder {
    served: Vec<String>,
    delivered: Mutex<Vec<Delivery>>,
}

impl Backend for Recorder {
    fn accepts(&self, rcpt: &str) -> bool {
        self.served.iter().any(|s| s == rcpt)
    }
    fn deliver(&self, from: &str, rcpts: &[String], raw: &[u8]) {
        self.delivered.lock().unwrap().push(Delivery {
            from: from.to_string(),
            rcpts: rcpts.to_vec(),
            raw: String::from_utf8_lossy(raw).into_owned(),
        });
    }
}

/// Start the server on an ephemeral port and return it with the recorder.
async fn start_server(served: &[&str]) -> (String, Arc<Recorder>) {
    let backend = Arc::new(Recorder {
        served: served.iter().map(|s| (*s).to_string()).collect(),
        delivered: Mutex::new(Vec::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let cfg = Arc::new(Config {
        hostname: "mail.example.com".into(),
        starttls: true,
        tls_available: false,
        enable_smtputf8: true,
    });
    let for_task = backend.clone();
    tokio::spawn(async move {
        jmapsmtp::smtp_in::serve(listener, cfg, for_task).await;
    });
    (addr, backend)
}

/// Run the Go helper and parse its output.
///
/// This blocks the calling thread, so every test here uses a multi-threaded
/// runtime: on the current-thread flavour the server task never gets to run
/// while this waits, and the two deadlock.
fn go<T: serde::de::DeserializeOwned>(
    bin: &PathBuf,
    cmd: &str,
    addr: &str,
    body: Option<&[u8]>,
) -> T {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .args([cmd, addr])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    if let Some(body) = body {
        child.stdin.as_mut().unwrap().write_all(body).unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("waiting for the Go helper");
    assert!(
        out.status.success(),
        "go {cmd} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go output")
}

const MESSAGE: &str = "From: Alice <alice@example.com>\r\n\
                       To: Bob <bob@example.com>\r\n\
                       Subject: hello\r\n\
                       \r\n\
                       hello there\r\n";

/// The whole point: the client the relay itself sends with can deliver here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_go_client_delivers_to_the_rust_server() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    let req = SendRequest {
        from: "alice@example.com".into(),
        rcpts: vec!["bob@example.com".into()],
        message: MESSAGE.into(),
        helo: "sender.example.org".into(),
    };
    let resp: SendResponse = go(
        &bin,
        "send",
        &addr,
        Some(&serde_json::to_vec(&req).unwrap()),
    );
    assert!(resp.ok, "delivery failed: {}", resp.err);
    assert!(resp.rejected.is_empty());

    let delivered = recorder.delivered.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].from, "alice@example.com");
    assert_eq!(delivered[0].rcpts, ["bob@example.com"]);
    assert_eq!(delivered[0].raw, MESSAGE);
}

/// An unknown recipient is accepted and dropped, never rejected — otherwise
/// the relay tells anyone who can reach port 25 which addresses exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_recipient_is_accepted_and_dropped() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    let req = SendRequest {
        from: "alice@example.com".into(),
        rcpts: vec!["bob@example.com".into(), "nobody@example.com".into()],
        message: MESSAGE.into(),
        helo: "sender.example.org".into(),
    };
    let resp: SendResponse = go(
        &bin,
        "send",
        &addr,
        Some(&serde_json::to_vec(&req).unwrap()),
    );
    assert!(resp.ok, "delivery failed: {}", resp.err);
    assert!(
        resp.rejected.is_empty(),
        "no RCPT may be rejected: {:?}",
        resp.rejected
    );

    let delivered = recorder.delivered.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(
        delivered[0].rcpts,
        ["bob@example.com"],
        "only the served address is kept"
    );
}

/// Every recipient unknown: still a clean 250, and nothing delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_for_nobody_is_accepted_and_discarded() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    let req = SendRequest {
        from: "alice@example.com".into(),
        rcpts: vec!["nobody@example.com".into()],
        message: MESSAGE.into(),
        helo: "sender.example.org".into(),
    };
    let resp: SendResponse = go(
        &bin,
        "send",
        &addr,
        Some(&serde_json::to_vec(&req).unwrap()),
    );
    assert!(resp.ok, "delivery failed: {}", resp.err);
    assert!(recorder.delivered.lock().unwrap().is_empty());
}

/// Recipients are matched case-insensitively, as the alias map is lowercased.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recipient_matching_ignores_case() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    let req = SendRequest {
        from: "alice@example.com".into(),
        rcpts: vec!["BOB@Example.COM".into()],
        message: MESSAGE.into(),
        helo: "sender.example.org".into(),
    };
    let resp: SendResponse = go(
        &bin,
        "send",
        &addr,
        Some(&serde_json::to_vec(&req).unwrap()),
    );
    assert!(resp.ok, "delivery failed: {}", resp.err);

    let delivered = recorder.delivered.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].rcpts, ["bob@example.com"]);
}

/// A body line that begins with a dot is stuffed by the sender and must be
/// unstuffed here, or the message arrives corrupted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_stuffing_is_undone() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    let message = "From: a@x\r\nTo: bob@example.com\r\n\r\n\
                   .a line starting with a dot\r\n\
                   ..two dots\r\n\
                   normal\r\n";
    let req = SendRequest {
        from: "a@x".into(),
        rcpts: vec!["bob@example.com".into()],
        message: message.into(),
        helo: "sender.example.org".into(),
    };
    let resp: SendResponse = go(
        &bin,
        "send",
        &addr,
        Some(&serde_json::to_vec(&req).unwrap()),
    );
    assert!(resp.ok, "delivery failed: {}", resp.err);

    let delivered = recorder.delivered.lock().unwrap().clone();
    assert_eq!(
        delivered[0].raw, message,
        "the body must arrive exactly as it was sent"
    );
}

/// A message big enough to cross buffer boundaries, so the DATA reader is not
/// only exercised on payloads that fit in one read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_message_survives_intact() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    let mut message = String::from("From: a@x\r\nTo: bob@example.com\r\n\r\n");
    for i in 0..5000 {
        message.push_str(&format!("line {i} with some padding to make it longer\r\n"));
    }
    let req = SendRequest {
        from: "a@x".into(),
        rcpts: vec!["bob@example.com".into()],
        message: message.clone(),
        helo: "sender.example.org".into(),
    };
    let resp: SendResponse = go(
        &bin,
        "send",
        &addr,
        Some(&serde_json::to_vec(&req).unwrap()),
    );
    assert!(resp.ok, "delivery failed: {}", resp.err);

    let delivered = recorder.delivered.lock().unwrap().clone();
    assert_eq!(delivered[0].raw.len(), message.len());
    assert_eq!(delivered[0].raw, message);
}

/// The extensions the Go client detects, which is what an ESMTP sender acts
/// on. Compared against the list go-smtp advertises for the options this
/// relay sets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_advertised_extensions_match_go_smtp() {
    let Some(bin) = require_helper() else { return };
    let (addr, _) = start_server(&["bob@example.com"]).await;

    let resp: ProbeResponse = go(&bin, "probe", &addr, None);
    assert!(resp.err.is_empty(), "probe failed: {}", resp.err);
    assert_eq!(
        resp.greeting, "220 mail.example.com ESMTP Service Ready",
        "the greeting is go-smtp's, with the configured hostname"
    );
    assert_eq!(
        resp.extensions,
        [
            "8BITMIME",
            "CHUNKING",
            "ENHANCEDSTATUSCODES",
            "PIPELINING",
            "SIZE",
            "SMTPUTF8",
            "STARTTLS",
        ],
        "AUTH must not be advertised: this is a public MX"
    );
}

/// Two messages down one connection, with a RSET between, which is what a
/// sending MTA with a queue does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_message_on_the_same_connection_works() {
    let Some(bin) = require_helper() else { return };
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    for _ in 0..2 {
        let req = SendRequest {
            from: "alice@example.com".into(),
            rcpts: vec!["bob@example.com".into()],
            message: MESSAGE.into(),
            helo: "sender.example.org".into(),
        };
        let resp: SendResponse = go(
            &bin,
            "send",
            &addr,
            Some(&serde_json::to_vec(&req).unwrap()),
        );
        assert!(resp.ok, "delivery failed: {}", resp.err);
    }
    assert_eq!(recorder.delivered.lock().unwrap().len(), 2);
}

// ── the mirror direction: Rust client → Go server ─────────────────────────

#[derive(Debug, Deserialize)]
struct Received {
    #[serde(default)]
    from: String,
    #[serde(default)]
    rcpts: Vec<String>,
    #[serde(default)]
    message: String,
    #[serde(default)]
    err: String,
}

/// An MX resolver with a fixed answer, so nothing here touches DNS.
struct FixedMx(Vec<String>);

impl jmapsmtp::smtp_out::MxResolver for FixedMx {
    fn lookup_mx(&self, _domain: &str) -> Vec<String> {
        self.0.clone()
    }
}

/// Start the Go server on an ephemeral port and return the address it chose
/// along with the running child.
fn start_go_server(bin: &PathBuf) -> (String, std::process::Child) {
    use std::io::{BufRead, BufReader as StdBufReader};
    let mut child = Command::new(bin)
        .args(["serve", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go server");
    // The chosen address is announced on stderr before it starts serving.
    let stderr = child.stderr.take().expect("stderr");
    let mut lines = StdBufReader::new(stderr).lines();
    let line = lines
        .next()
        .expect("the Go server must announce its address")
        .expect("reading the announcement");
    let addr = line
        .strip_prefix("listening ")
        .expect("unexpected announcement")
        .to_string();
    (addr, child)
}

fn finish_go_server(child: std::process::Child) -> Received {
    let out = child.wait_with_output().expect("waiting for the Go server");
    serde_json::from_slice(&out.stdout).expect("parsing go server output")
}

fn sender() -> jmapsmtp::smtp_out::Sender {
    jmapsmtp::smtp_out::Sender {
        hostname: "mail.example.com".into(),
        relay_host: None,
    }
}

/// The Go server accepts what this port sends, byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_go_server_receives_what_the_rust_client_sends() {
    let Some(bin) = require_helper() else { return };
    let (addr, child) = start_go_server(&bin);

    let sender = sender();
    sender
        .send_one(
            &addr,
            "alice@example.com",
            &["bob@example.org".to_string()],
            MESSAGE.as_bytes(),
        )
        .await
        .expect("the send must succeed");

    let got = finish_go_server(child);
    assert!(got.err.is_empty(), "server error: {}", got.err);
    assert_eq!(got.from, "alice@example.com");
    assert_eq!(got.rcpts, ["bob@example.org"]);
    assert_eq!(got.message, MESSAGE);
}

/// A rejected recipient is logged and the send continues — the others still
/// get the message. The Go server rejects anything at `reject@`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_recipient_does_not_abort_the_send() {
    let Some(bin) = require_helper() else { return };
    let (addr, child) = start_go_server(&bin);

    sender()
        .send_one(
            &addr,
            "alice@example.com",
            &[
                "reject@example.org".to_string(),
                "bob@example.org".to_string(),
            ],
            MESSAGE.as_bytes(),
        )
        .await
        .expect("one rejected recipient must not fail the send");

    let got = finish_go_server(child);
    assert_eq!(
        got.rcpts,
        ["bob@example.org"],
        "the accepted recipient still receives it"
    );
    assert_eq!(got.message, MESSAGE);
}

/// Dot-stuffing on the way out is undone by the receiver, so a body line
/// beginning with a dot survives the round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dotted_body_line_survives() {
    let Some(bin) = require_helper() else { return };
    let (addr, child) = start_go_server(&bin);

    let message = "From: a@x\r\nTo: b@y\r\n\r\n\
                   .a dotted line\r\n\
                   . \r\n\
                   normal\r\n";
    sender()
        .send_one(&addr, "a@x", &["b@y".to_string()], message.as_bytes())
        .await
        .expect("send");

    let got = finish_go_server(child);
    assert_eq!(got.message, message, "the body must arrive unchanged");
}

/// MX routing: recipients are grouped by domain and the best MX is used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mx_routing_reaches_the_resolved_host() {
    let Some(bin) = require_helper() else { return };
    let (addr, child) = start_go_server(&bin);

    // The resolver answers with the real address, minus the :25 the sender
    // appends — so the port is taken from the MX name itself here.
    let (host, port) = addr.rsplit_once(':').expect("host:port");
    let sender = jmapsmtp::smtp_out::Sender {
        hostname: "mail.example.com".into(),
        // Routing through relay_host is the same code path a fixed smarthost
        // takes, and lets the test use a port other than 25.
        relay_host: Some(format!("{host}:{port}")),
    };
    sender
        .deliver(
            &FixedMx(vec![]),
            "alice@example.com",
            &["bob@example.org".to_string()],
            MESSAGE.as_bytes(),
        )
        .await
        .expect("delivery through a relay host must succeed");

    let got = finish_go_server(child);
    assert_eq!(got.rcpts, ["bob@example.org"]);
}

/// A round trip through both implementations at once: the Rust client sends
/// to the Rust server. Catches anything the two agree on but Go would not —
/// nothing here should pass that the Go tests above do not also cover.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_rust_client_and_server_agree_with_each_other() {
    let (addr, recorder) = start_server(&["bob@example.com"]).await;

    sender()
        .send_one(
            &addr,
            "alice@example.com",
            &["bob@example.com".to_string()],
            MESSAGE.as_bytes(),
        )
        .await
        .expect("send");

    let delivered = recorder.delivered.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].from, "alice@example.com");
    assert_eq!(delivered[0].raw, MESSAGE);
}
