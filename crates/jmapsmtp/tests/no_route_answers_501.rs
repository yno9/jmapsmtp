//! Every mounted route must reach a handler.
//!
//! `501 not implemented` is this port's marker for a pattern that `routes.rs`
//! mounts and `dispatch` has no arm for. Three such routes shipped —
//! `PUT /account/did`, `/pkarr/`, `POST /admin/drain-anchor` — and each was
//! found by a person using it, not by a test.
//!
//! They hid for the same structural reason each time: **nothing drove the
//! route the way it is actually used.** `mux_interop` compares route tables,
//! so a mounted-but-unhandled pattern matches. `server_interop` issues
//! unauthenticated `GET`s, so a bearer route answers 401 before reaching the
//! handler and a `POST`-only route answers 405 — both of which look like
//! opinions rather than absences. And the anchor-gated routes are not mounted
//! at all unless `anchor_url` is set, which no test config did.
//!
//! So this file takes the route table itself and, for every pattern in it,
//! tries every method with **full credentials**, and fails on any 501. It
//! needs no oracle, so it always runs.
//!
//! It does not care what the routes answer. A 405, a 400, a 404 are all fine
//! — they mean a handler ran and had an opinion. Only 501 means nobody is
//! home.

use std::path::Path;

use base64::Engine as _;
use jmapsmtp::config::Config;
use jmapsmtp::routes::route_specs;
use jmapsmtp::server::RelayState;

mod oracle_harness;
use oracle_harness::{free_port, raw_status};

const AUTH_TOKEN: &[u8] = b"route-coverage-token-0000000000";
const BEARER: &str = "route-coverage-bearer";

fn basic_auth() -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{password}"))
}

/// Anchored, because three of the routes only exist when an anchor is
/// configured — and all three of the 501s were among them. The URL points
/// nowhere on purpose: a handler that tries to reach it and fails has still
/// run, which is all this asks.
fn config(http_port: u16, anchored: bool) -> Config {
    let anchor = if anchored {
        r#""anchor_url":"http://127.0.0.1:9","anchor_token":"t","#
    } else {
        ""
    };
    serde_json::from_str(&format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":1,
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            {anchor}
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    ))
    .expect("the config should parse")
}

struct Server {
    port: u16,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

impl Server {
    fn start(data_dir: &Path, cfg: Config) -> Server {
        let port = free_port();
        let data_dir = data_dir.to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let state = RelayState::with_tokens(cfg, data_dir, BEARER, BEARER);
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
            .expect("the server should start");
        Server {
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

fn seed(root: &Path) {
    let acct = root.join("a.test/alice");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(AUTH_TOKEN),
    )
    .unwrap();
}

/// A concrete path for a pattern. Go's `ServeMux` subtree patterns end in `/`
/// and match anything below, so a bare request to the pattern itself is not
/// always what a client sends.
fn sample_path(pattern: &str) -> String {
    match pattern {
        "/pkarr/" => "/pkarr/somekey".into(),
        "/jmap/api/" => "/jmap/api/".into(),
        "/contacts/" => "/contacts/someone@b.test".into(),
        "/admin/accounts/" => "/admin/accounts/alice@a.test".into(),
        ".well-known/openpgpkey/hu/" | "/.well-known/openpgpkey/hu/" => {
            "/.well-known/openpgpkey/hu/abc?l=alice".into()
        }
        "/jmap/eventsource/" => "/jmap/eventsource/".into(),
        other => other.into(),
    }
}

fn check(anchored: bool) {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let cfg = config(1, anchored);
    let specs = route_specs(&cfg, false);
    let server = Server::start(tmp.path(), config(1, anchored));

    let basic = basic_auth();
    let bearer = format!("Bearer {BEARER}");
    let mut unhandled = Vec::new();

    for spec in &specs {
        let path = sample_path(spec.pattern);
        for method in ["GET", "POST", "PUT", "DELETE"] {
            // Everything a handler could ask for, at once. A route that wants
            // one and gets the other answers 401 or 403 — an opinion, which
            // is all this test needs; it is looking for silence.
            //
            // Status line only: `/jmap/eventsource/` streams and never closes,
            // so reading its body means waiting out the socket timeout.
            let as_account = raw_status(server.port, method, &path, Some("{}"), Some(&basic), None);
            if as_account == 501 {
                unhandled.push(format!("{method} {path} (as an account)"));
            }
            let as_admin = raw_status(
                server.port,
                method,
                &path,
                Some("{}"),
                None,
                Some(("Authorization", &bearer)),
            );
            if as_admin == 501 {
                unhandled.push(format!("{method} {path} (as admin)"));
            }
        }
    }

    server.stop();
    assert!(
        unhandled.is_empty(),
        "{} route/method pair(s) are mounted with no handler behind them \
         (anchored={anchored}). Each is a pattern in routes.rs with no arm in \
         dispatch:\n  {}",
        unhandled.len(),
        unhandled.join("\n  ")
    );
}

/// The configuration all three shipped 501s lived in.
#[test]
fn every_route_an_anchored_relay_mounts_reaches_a_handler() {
    check(true);
}

/// And the anchorless one, where the route table is smaller but the same rule
/// holds.
#[test]
fn every_route_an_anchorless_relay_mounts_reaches_a_handler() {
    check(false);
}

/// The test above is only worth anything if a 501 is reachable at all — this
/// asks for a path that really is unregistered and requires the marker.
///
/// Without it, a change that stopped 501 being produced anywhere (a catch-all
/// 404, say) would make the coverage test vacuous and green.
#[test]
fn an_unregistered_path_still_answers_something_other_than_a_handler() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let server = Server::start(tmp.path(), config(1, true));
    let status = raw_status(server.port, "GET", "/no/such/route", None, None, None);
    server.stop();
    assert_eq!(
        status, 404,
        "an unregistered path is a 404 from the mux; if this became 501 the \
         coverage test above would be reporting the mux, not missing handlers"
    );
}
