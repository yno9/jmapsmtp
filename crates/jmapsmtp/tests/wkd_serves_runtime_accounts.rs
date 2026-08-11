//! WKD has to answer for the accounts the relay actually serves.
//!
//! It did not. `resolve_wkd` asked `config.json` whether the address existed,
//! and on the production deployment `config.json` declares **no accounts at
//! all** — every one of them is provisioned at runtime, which is what biset
//! does. So every WKD lookup returned 404 while the keys sat on disk beside
//! their mailboxes. Both implementations, for as long as either had run.
//!
//! Nobody reported it because the only people who would are strangers using
//! GnuPG or Thunderbird to encrypt to an address they have never written to,
//! and all they see is "no key found".
//!
//! # Why this drives the route
//!
//! The bug was not inside `resolve_wkd`. It was in what the handler asked it
//! about — the closure. A unit test on the function passes either way, because
//! the closure is the part that changed: the test supplies it. Reverting the
//! handler to the config-only lookup leaves every `wkd::tests` case green.
//!
//! So this goes through the mux, over HTTP, against an account that exists the
//! way real ones do.

use std::path::Path;

use jmapsmtp::config::Config;
use jmapsmtp::server::RelayState;

const BEARER: &str = "wkd-runtime-test-token";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .unwrap()
        .port()
}

/// The production shape: a served domain, and not one account named.
fn config_without_accounts() -> Config {
    serde_json::from_str(r#"{"domain":{"biset.md":{}}}"#).expect("the config should parse")
}

struct Server {
    port: u16,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

impl Server {
    /// Start a relay and provision `y@biset.md` the way the running one does —
    /// through `register_dyn_account`, not by naming it in the config.
    fn start(data_dir: &Path) -> Server {
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
                let state =
                    RelayState::with_tokens(config_without_accounts(), data_dir, BEARER, BEARER);
                state.open_stores().expect("stores should open");
                state.register_dyn_account("y", "biset.md");
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

    fn get(&self, path: &str) -> (u16, Vec<u8>) {
        let url = format!("http://127.0.0.1:{}{path}", self.port);
        let res = reqwest::blocking::get(url).expect("request");
        let status = res.status().as_u16();
        (status, res.bytes().expect("body").to_vec())
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.join();
    }
}

/// An account exists iff it has an `auth_token_hash` (ARC.md §5), so that is
/// what makes this one real. The key is what WKD is being asked for.
fn seed_runtime_account(root: &Path, key: &[u8]) {
    let acct = root.join("biset.md/y");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(acct.join("auth_token_hash"), "not-checked-here").unwrap();
    std::fs::write(acct.join("pubkey.pgp"), key).unwrap();
}

const PUBKEY: &[u8] = include_bytes!("../../../xtask/fixtures/pgp-public.asc");

#[test]
fn a_runtime_provisioned_account_is_reachable_over_wkd() {
    let tmp = tempfile::tempdir().unwrap();
    seed_runtime_account(tmp.path(), PUBKEY);
    let server = Server::start(tmp.path());

    let hash = jmapsmtp::wkd::wkd_hash("y");
    let (status, body) = server.get(&format!("/.well-known/openpgpkey/hu/{hash}?l=y"));
    server.stop();

    assert_eq!(
        status, 200,
        "the key is on disk and the address is served, and WKD still said {status}"
    );
    assert!(!body.is_empty(), "an empty key is not a key");
    assert_eq!(
        body,
        jmapsmtp::wkd::serve_pubkey(tmp.path(), "biset.md", "y").expect("stored key"),
        "WKD served something other than the account's key"
    );
}

/// The other half: a key file with no account behind it must not be published.
/// Otherwise "does this relay serve you" stops being part of the answer.
#[test]
fn a_key_left_behind_by_a_deleted_account_is_not_published() {
    let tmp = tempfile::tempdir().unwrap();
    // Key present, but nothing provisions `ghost`, so it is not served.
    let acct = tmp.path().join("biset.md/ghost");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(acct.join("pubkey.pgp"), PUBKEY).unwrap();
    seed_runtime_account(tmp.path(), PUBKEY);

    let server = Server::start(tmp.path());
    let hash = jmapsmtp::wkd::wkd_hash("ghost");
    let (status, _) = server.get(&format!("/.well-known/openpgpkey/hu/{hash}?l=ghost"));
    server.stop();

    assert_eq!(
        status, 404,
        "a key with no served address behind it was published"
    );
}
