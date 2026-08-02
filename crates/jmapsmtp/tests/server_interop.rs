//! This port's own HTTP server, running beside the oracle and answering the
//! same requests.
//!
//! Every earlier interop test compared a *function* against the oracle. This
//! one compares the **server** — the same bytes on the wire, from a process
//! started the way a deployment starts it. That is what makes the remaining
//! gaps visible: a route with no handler answers 501, so it shows up here as a
//! difference rather than passing on a coincidence.

use std::path::Path;

use jmapsmtp::config::Config;
use jmapsmtp::server::RelayState;

mod oracle_harness;
use oracle_harness::{Oracle, free_port};

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r##"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "relay_label":"Biset","relay_color":"#123456",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"##
    )
}

/// This port's server, on its own port, over the oracle's data directory.
///
/// Sharing the directory is deliberate: both sides then answer from the same
/// on-disk state, so a difference is a difference in the code and not in the
/// fixture.
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
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let state = RelayState::new(cfg, data_dir);
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

    fn get(&self, target: &str) -> (u16, String, String) {
        oracle_harness::raw_get(self.port, target)
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.join();
    }
}

fn both(seed: fn(&Path)) -> Option<(Oracle, Ours)> {
    let o = Oracle::start_with("SERVER_INTEROP", config_json, seed)?;
    let cfg: Config = serde_json::from_str(&config_json(1, 1)).unwrap();
    let ours = Ours::start(&o.root.path().join("data"), cfg);
    Some((o, ours))
}

fn no_seed(_: &Path) {}

/// Compare a request against both servers.
fn compare(o: &Oracle, ours: &Ours, target: &str) -> (u16, String, String) {
    let (go_status, go_body, go_location) = o.get(target);
    let (our_status, our_body, our_location) = ours.get(target);
    assert_eq!(
        our_status, go_status,
        "{target}: status — oracle said {go_status} {go_body:.120}"
    );
    assert_eq!(our_location, go_location, "{target}: Location");
    assert_eq!(our_body, go_body, "{target}: body");
    (go_status, go_body, go_location)
}

// ── routing, on the wire ──────────────────────────────────────────────────

/// The routing rules, compared between two running servers rather than between
/// a function and a server.
#[test]
fn the_two_servers_route_identically() {
    let Some((o, ours)) = both(no_seed) else {
        return;
    };

    for target in [
        // redirects
        "/jmap/api",
        "/jmap/api?x=1",
        "//relay-info",
        "/a/../relay-info?y=2",
        "/jmap/eventsource",
        // the mux's own 404
        "/nope",
        "/jmap/nope",
        "/relay-info/",
        "/relay-info/x",
        "/account/storage/nope",
        // traversal cannot escape the root
        "/../../relay-info",
    ] {
        compare(&o, &ours, target);
    }
    ours.stop();
}

/// The header set, which is the same on every response including a 404 —
/// Go's wrapper runs before the mux.
#[test]
fn the_two_servers_send_the_same_cors_headers() {
    let Some((o, ours)) = both(no_seed) else {
        return;
    };

    for target in ["/relay-info", "/nope"] {
        let go = o.headers(target);
        let mine = ours_headers(&ours, target);
        for name in [
            "access-control-allow-origin",
            "access-control-allow-headers",
            "access-control-allow-methods",
        ] {
            assert_eq!(
                mine.get(name).map(String::as_str),
                go.get(name).map(String::as_str),
                "{target}: {name}"
            );
        }
    }
    ours.stop();
}

fn ours_headers(ours: &Ours, target: &str) -> std::collections::BTreeMap<String, String> {
    oracle_harness::raw_headers(ours.port, target)
}

// ── the wired handlers ────────────────────────────────────────────────────

#[test]
fn relay_info_is_byte_identical() {
    let Some((o, ours)) = both(no_seed) else {
        return;
    };
    let (status, body, _) = compare(&o, &ours, "/relay-info");
    assert_eq!(status, 200);
    assert!(body.contains("\"type\":\"mail\""), "{body}");
    ours.stop();
}

/// The /setup page, from both servers. It is the largest response either
/// serves, so it is also the one that arrives chunked.
#[test]
fn the_setup_page_is_byte_identical_from_both_servers() {
    let Some((o, ours)) = both(no_seed) else {
        return;
    };
    let token = std::fs::read_to_string(o.data_dir().join("a.test/alice/setup.token"))
        .expect("the oracle issued a token");

    let (status, body, _) = compare(&o, &ours, &format!("/setup?token={token}"));
    assert_eq!(status, 200);
    assert!(body.contains("biset-jmapsmtp/auth/v1"), "the real page");

    // …and the refusals, which depend on the order of the token and method
    // checks.
    compare(&o, &ours, "/setup");
    compare(&o, &ours, "/setup?token=not-a-real-token");
    ours.stop();
}

// ── what is not wired ─────────────────────────────────────────────────────

/// The routes still to be wired answer 501 here and something else on the
/// oracle. Listed by name so finishing one means deleting a line, and so the
/// remaining work is visible from the test suite rather than only from a plan.
#[test]
fn the_unwired_routes_are_the_ones_named_here() {
    let Some((o, ours)) = both(no_seed) else {
        return;
    };

    let unwired = [
        "/.well-known/jmap",
        "/jmap/api/",
        "/jmap/eventsource/",
        "/jmap/push/vapid-public-key",
        "/.well-known/openpgpkey/policy",
        "/pgp/pubkey",
        "/auth/envelope?email=alice@a.test",
        "/auth/signup",
        "/account/provision",
        "/account/session",
        "/account/devices",
        "/contacts",
        "/account/delete",
        "/account/storage",
        "/admin/dashboard",
    ];

    for target in unwired {
        let (our_status, _, _) = ours.get(target);
        let (go_status, _, _) = o.get(target);
        assert_eq!(
            our_status, 501,
            "{target} is no longer 501 — if it is now wired, remove it from \
             this list and add it to the comparison above"
        );
        assert_ne!(
            go_status, 501,
            "{target}: the oracle serves it, so this is real work remaining"
        );
    }

    // The bearer routes are a different state: the **guard** is wired and the
    // body is not, so they answer 401 rather than 501 — and they answer 401
    // with no token configured, which is the deliberate divergence in
    // SPEC.md §11.13. The oracle serves them wide open.
    for target in ["/metrics", "/admin/accounts"] {
        assert_eq!(ours.get(target).0, 401, "{target}: this port closes it");
        assert_eq!(
            o.get(target).0,
            200,
            "{target}: the oracle is expected to still serve it unauthenticated"
        );
    }
    ours.stop();
}
