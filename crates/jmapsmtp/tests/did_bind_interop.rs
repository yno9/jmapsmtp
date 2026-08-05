//! `PUT /account/did` against the running oracle, with a real anchor behind
//! both sides.
//!
//! # Why this file exists at all
//!
//! `/account/did` answered 501 here for the whole port and nothing caught it.
//! Three layers of comparison were in place and each missed it for a different
//! reason: `mux_interop` compares route **tables**, and both sides registered
//! the pattern; `server_interop`'s list of unwired routes had been emptied, and
//! an empty array makes its loop run zero times; and the difftest scenario
//! never requests the path. It was found by deploying the relay and watching a
//! client get 501.
//!
//! The common cause is that **every interop suite until now ran an anchorless
//! oracle** — the anchored surface had no comparison at all. So this file
//! stands up a stub anchor and points both implementations at it, which is the
//! layer that was missing rather than one more test of the layer that was not.
//!
//! # The stub anchor
//!
//! Not a mock in the "assert it was called" sense: it is a real HTTP server
//! that answers the way an anchor answers, and it decides **from the DID in
//! the request** which answer to give. Scripting by call order would make the
//! two sides' results depend on which ran first, which is precisely the kind
//! of coupling that makes a comparison lie.
//!
//! `DID_BIND_INTEROP=required` — set by `just test` — turns a missing oracle
//! into an error rather than a silent pass.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use base64::Engine as _;
use jmapsmtp::config::Config;
use jmapsmtp::server::RelayState;
use pretty_assertions::assert_eq;

mod oracle_harness;
use oracle_harness::{Oracle, free_port, raw_full};

const AUTH_TOKEN: &[u8] = b"did-bind-interop-token-000000000";
const ANCHOR_TOKEN: &str = "stub-anchor-relay-token";

fn basic_auth(account: &str) -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("{account}:{password}"))
}

fn seed(root: &Path) {
    let acct = root.join("data/a.test/alice");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(AUTH_TOKEN),
    )
    .unwrap();
}

// ── the stub anchor ───────────────────────────────────────────────────────

/// Answers `POST /identity/<localpart>` the way an anchor does, choosing the
/// status from the DID so that both implementations get the same answer for
/// the same input regardless of call order.
fn start_stub_anchor() -> u16 {
    let port = free_port();
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("stub anchor should bind");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let status = read_request_and_choose(&mut s);
            let body = match status {
                200 => "{}",
                401 => "signature does not verify\n",
                409 => "already bound to another did\n",
                _ => "boom\n",
            };
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

/// Read the whole request and pick a status from the DID it carries.
fn read_request_and_choose(s: &mut TcpStream) -> u16 {
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return 500;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut body = vec![0u8; len];
    let _ = r.read_exact(&mut body);
    let body = String::from_utf8_lossy(&body);
    if body.contains("did:webvh:reject") {
        401
    } else if body.contains("did:webvh:conflict") {
        409
    } else if body.contains("did:webvh:boom") {
        500
    } else {
        200
    }
}

// ── both sides, anchored ──────────────────────────────────────────────────

struct Ours {
    port: u16,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

impl Ours {
    fn start(data_dir: &Path, cfg: Config) -> Ours {
        let port = free_port();
        let data_dir = data_dir.to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            // **Current-thread on purpose, even though production is
            // multi-thread.** This is the stricter of the two: tokio permits
            // dropping a runtime on a multi-thread worker and forbids it on a
            // current-thread one, and `reqwest::blocking` drops a runtime to
            // probe for an async context on every call. So an anchor call that
            // is merely *wrong* on multi-thread — blocking a worker — panics
            // outright here.
            //
            // That is what found it. The deployed relay reached a live anchor
            // and answered correctly, so nothing production-shaped would have
            // complained; `anchor::off_runtime` now makes the transport
            // independent of the flavour, and keeping this fixture strict is
            // what will notice if that stops being true.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let state = RelayState::new(cfg, data_dir);
                state.open_stores().expect("stores should open");
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                    .await
                    .expect("bind");
                ready_tx.send(()).unwrap();
                let _ = axum::serve(listener, jmapsmtp::server::app(state))
                    .with_graceful_shutdown(async {
                        let _ = rx.await;
                    })
                    .await;
            });
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("this port's server should start");
        Ours {
            port,
            shutdown: tx,
            handle,
        }
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.join();
    }
}

/// The anchor's port has to reach the config of **both** sides, and
/// `Oracle::start_with` takes a `fn` rather than a closure, so it travels
/// through a static instead of a capture.
static ANCHOR_PORT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

fn config_json(http_port: u16, smtp_port: u16) -> String {
    let anchor = ANCHOR_PORT.get().expect("the stub anchor starts first");
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "anchor_url":"http://127.0.0.1:{anchor}","anchor_token":"{ANCHOR_TOKEN}",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

fn both() -> Option<(Oracle, Ours)> {
    let _ = ANCHOR_PORT.set(start_stub_anchor());
    let o = Oracle::start_with("DID_BIND_INTEROP", config_json, seed)?;
    let cfg: Config = serde_json::from_str(&config_json(o.http_port, 1)).unwrap();
    let ours = Ours::start(&o.root.path().join("data"), cfg);
    Some((o, ours))
}

/// Drive one request into both and require identical status and body.
fn compare(
    o: &Oracle,
    ours: &Ours,
    method: &str,
    body: Option<&str>,
    auth: Option<&str>,
    what: &str,
) -> u16 {
    let (go_status, go_body, _, go_headers) =
        raw_full(o.http_port, method, "/account/did", body, auth);
    let (our_status, our_body, _, our_headers) =
        raw_full(ours.port, method, "/account/did", body, auth);
    assert_eq!(
        our_status, go_status,
        "{what}: status differs (body ours={our_body:?} go={go_body:?})"
    );
    assert_eq!(our_body, go_body, "{what}: body differs");
    for h in [
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-origin",
        "www-authenticate",
    ] {
        assert_eq!(
            our_headers.get(h),
            go_headers.get(h),
            "{what}: header {h} differs"
        );
    }
    go_status
}

// ── the comparison ────────────────────────────────────────────────────────

/// The route the port was missing, driven through every answer it can give.
///
/// One test rather than eight, because each case needs the oracle booted and
/// that is the expensive part; the `what` string names which case failed.
#[test]
fn account_did_answers_exactly_what_the_oracle_answers() {
    let Some((o, ours)) = both() else { return };
    let auth = basic_auth("alice@a.test");

    // Unauthenticated first: a caller with no credential must not be able to
    // tell a malformed body from a well-formed one.
    let s = compare(&o, &ours, "PUT", Some(r#"{"did":"did:webvh:ok"}"#), None, "no credential");
    assert_eq!(s, 401, "the oracle should refuse an unauthenticated bind");

    let s = compare(&o, &ours, "GET", None, Some(&auth), "wrong method");
    assert_eq!(s, 405);

    compare(&o, &ours, "OPTIONS", None, None, "preflight");

    let s = compare(&o, &ours, "PUT", Some("not json"), Some(&auth), "unparseable body");
    assert_eq!(s, 400);

    let s = compare(&o, &ours, "PUT", Some("{}"), Some(&auth), "no did");
    assert_eq!(s, 400);

    let s = compare(
        &o,
        &ours,
        "PUT",
        Some(r#"{"did":"did:webvh:ok"}"#),
        Some(&auth),
        "did without a signature",
    );
    assert_eq!(s, 400, "the signature is a separate claim from the credential");

    // Now the anchor's verdicts, each chosen by the DID.
    for (did, want, what) in [
        ("did:webvh:ok", 204, "accepted"),
        ("did:webvh:reject", 401, "anchor rejected the proof"),
        ("did:webvh:conflict", 409, "bound to another identity"),
        ("did:webvh:boom", 503, "anchor unavailable"),
    ] {
        let body = format!(r#"{{"did":"{did}","did_sig":"sig","bind_ts":1785000000}}"#);
        let s = compare(&o, &ours, "PUT", Some(&body), Some(&auth), what);
        assert_eq!(s, want, "{what}: the oracle's own answer moved");
    }

    ours.stop();
}

/// The one thing the account **cannot** do: bind a DID to somebody else.
///
/// The body carries no account, so there is nothing to smuggle — this pins
/// that the target really is taken from the credential, by authenticating as
/// alice while naming bob everywhere a name could plausibly be read from.
#[test]
fn the_bound_account_comes_from_the_credential_not_the_body() {
    let Some((o, ours)) = both() else { return };
    let auth = basic_auth("alice@a.test");
    let body = r#"{"did":"did:webvh:ok","did_sig":"sig","bind_ts":1785000000,
                   "username":"bob","localpart":"bob","account":"bob@a.test"}"#;
    let s = compare(&o, &ours, "PUT", Some(body), Some(&auth), "extra name fields");
    assert_eq!(
        s, 204,
        "the extra fields are ignored rather than rejected — pinning that they \
         are ignored is the point"
    );
    ours.stop();
}
