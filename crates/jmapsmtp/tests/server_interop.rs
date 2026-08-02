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
            "domain_verify_secret":"s3cret-shared-with-the-oracle",
            "domain":{{
              "a.test":{{"account":{{"alice":{{}}}}}},
              "open.test":{{"allow_provision":true}}
            }}}}"##
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
    // The **oracle's** port, because `base_url` is what the session object
    // reports as its apiUrl and friends. This port's server binds its own
    // port; only the advertised URLs come from here, and those have to match
    // or the comparison is measuring the fixture.
    let cfg: Config = serde_json::from_str(&config_json(o.http_port, 1)).unwrap();
    let ours = Ours::start(&o.root.path().join("data"), cfg);
    Some((o, ours))
}

fn no_seed(_: &Path) {}

/// Compare a request against both servers: status, body, and every header a
/// client can act on.
///
/// The headers are part of it because the per-route CORS lists differ from the
/// wrapper's and from each other — that is precisely where guessing goes
/// unnoticed, and it is what the CORS layering bug hid behind.
fn compare(o: &Oracle, ours: &Ours, target: &str) -> (u16, String, String) {
    let (go_status, go_body, go_location) = o.get(target);
    let (our_status, our_body, our_location) = ours.get(target);
    assert_eq!(
        our_status, go_status,
        "{target}: status — oracle said {go_status} {go_body:.120}"
    );
    assert_eq!(our_location, go_location, "{target}: Location");
    assert_eq!(our_body, go_body, "{target}: body");

    let go_headers = o.headers(target);
    let our_headers = ours_headers(ours, target);
    for name in [
        "access-control-allow-origin",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "content-type",
        "www-authenticate",
        "x-content-type-options",
    ] {
        assert_eq!(
            our_headers.get(name).map(String::as_str),
            go_headers.get(name).map(String::as_str),
            "{target}: {name}"
        );
    }
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

// ── the newly wired routes ────────────────────────────────────────────────

/// The unauthenticated half of the surface, compared byte for byte.
#[test]
fn the_public_routes_are_byte_identical() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };

    for target in [
        "/.well-known/openpgpkey/policy",
        // A key that exists, one that does not, and a mismatched l= — the
        // case where serving the wrong key would be a privacy failure.
        &format!(
            "/.well-known/openpgpkey/hu/{}?l=alice",
            jmapsmtp::wkd::wkd_hash("alice")
        ),
        &format!(
            "/.well-known/openpgpkey/hu/{}?l=bob",
            jmapsmtp::wkd::wkd_hash("bob")
        ),
        &format!(
            "/.well-known/openpgpkey/hu/{}?l=bob",
            jmapsmtp::wkd::wkd_hash("alice")
        ),
        // The envelope is public: the client needs it before it has a
        // credential, and it is inert without the password.
        "/auth/envelope?email=alice@a.test",
        "/auth/envelope?email=nobody@a.test",
        "/auth/envelope?email=alice@nope.test",
        "/auth/envelope",
        "/auth/envelope?email=alice",
        // A hash that is not one, and signup's refusals — all reachable
        // without a credential, so all part of what a stranger can learn.
        "/.well-known/openpgpkey/hu/notahash?l=alice",
        "/auth/signup",
        "/auth/signup?token=not-a-real-token",
    ] {
        compare(&o, &ours, target);
    }
    ours.stop();
}

/// The authenticated routes, refused the same way when unauthenticated. A
/// difference here is a route that is open on one side and closed on the
/// other.
#[test]
fn the_authenticated_routes_refuse_identically() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    for target in ["/pgp/privkey", "/pgp/peerkey?addr=x@y.test", "/contacts"] {
        let (status, _, _) = compare(&o, &ours, target);
        assert_eq!(status, 401, "{target} should need a credential");
    }

    // `/contacts/<uid>` and `/pgp/pubkey` are PUT-only, so a GET is refused on
    // the method before the credential is looked at — on both sides. Compared
    // rather than assumed, since the order decides whether a wrong-method
    // request can be used to probe which accounts exist.
    for target in ["/contacts/uid-1", "/pgp/pubkey"] {
        let (status, _, _) = compare(&o, &ours, target);
        assert_eq!(status, 405, "{target}: the method is checked first");
    }
    ours.stop();
}

/// `alice` has a public key and an envelope; `bob` has neither. One boot
/// covers both the found and the not-found branches of every lookup.
fn seed_accounts(root: &Path) {
    const PUBKEY: &str = include_str!("../../../xtask/fixtures/pgp-public.asc");
    for lp in ["alice", "bob"] {
        let acct = root.join("data/a.test").join(lp);
        std::fs::create_dir_all(&acct).unwrap();
        std::fs::write(
            acct.join("auth_token_hash"),
            jmapserver::hash_auth_token(b"server-interop-token-0000000000"),
        )
        .unwrap();
    }
    std::fs::write(root.join("data/a.test/alice/pubkey.pgp"), PUBKEY).unwrap();
    std::fs::write(
        root.join("data/a.test/alice/envelope.json"),
        br#"{"v":1,"salt":"AAAA","kdf":{"t":3,"m":65536,"p":4},"wrapped_secret":"AAAA","auth_token_hash":"AAAA"}"#,
    )
    .unwrap();
}

/// The account, storage and admin routes wired in this pass — the refusals
/// each answers without a credential, which is all that is reachable here.
#[test]
fn the_account_and_storage_routes_are_byte_identical() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    for target in [
        "/account/session",
        "/account/devices",
        "/account/storage",
        "/account/storage/messages",
        "/account/storage/export",
    ] {
        compare(&o, &ours, target);
    }
    ours.stop();
}

/// The admin listing, compared figure by figure rather than byte for byte:
/// the *set* of accounts differs on purpose (SPEC.md §11.16 — the oracle
/// reports the domain registry as an account), so what is checked is that
/// every real account's numbers agree.
#[test]
fn the_admin_listing_agrees_on_every_real_account() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    let (go_status, go_body, _) = o.get("/admin/accounts");
    assert_eq!(go_status, 200, "{go_body:.200}");
    let go: serde_json::Value = serde_json::from_str(&go_body).unwrap();

    for account in jmapserver::admin::list_provisioned(&o.data_dir()) {
        let go_row = go["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["address"] == account.address())
            .unwrap_or_else(|| panic!("the oracle should list {}", account.address()));
        let (messages, bytes) =
            jmapserver::admin::message_stats(&o.data_dir(), &account.domain, &account.localpart);
        assert_eq!(
            go_row["messages"].as_u64(),
            Some(messages),
            "{}",
            account.address()
        );
        assert_eq!(
            go_row["bytes"].as_u64(),
            Some(bytes),
            "{}",
            account.address()
        );
    }
    assert_eq!(go["version"], "dev", "the default version label");
    ours.stop();
}

/// The JMAP core: the session object and a method batch, from both servers.
///
/// This is the relay's actual purpose, and the first thing here that needs the
/// per-account stores — so it is also the first test that would fail if the
/// startup sequence assembled them differently.
#[test]
fn the_jmap_session_and_api_agree() {
    use base64::Engine as _;
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    let password =
        base64::engine::general_purpose::STANDARD.encode(b"server-interop-token-0000000000");
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{password}"));

    // Unauthenticated, both refuse the same way — including a GET on the API
    // route, which is POST-only.
    compare(&o, &ours, "/.well-known/jmap");
    compare(&o, &ours, "/jmap/api/");

    // The session object. Compared as JSON rather than bytes: it carries a
    // state string derived from the store, which is not expected to match
    // across two independently-opened stores.
    let go: serde_json::Value =
        serde_json::from_str(&o.get_auth("/.well-known/jmap", &auth).1).unwrap();
    let mine: serde_json::Value = serde_json::from_str(
        &oracle_harness::raw_get_auth(ours.port, "/.well-known/jmap", &auth).1,
    )
    .unwrap();

    assert_eq!(mine["capabilities"], go["capabilities"], "capabilities");
    assert_eq!(mine["accounts"], go["accounts"], "accounts");
    assert_eq!(mine["primaryAccounts"], go["primaryAccounts"]);
    assert_eq!(mine["username"], go["username"]);
    assert_eq!(mine["apiUrl"], go["apiUrl"]);
    assert_eq!(mine["downloadUrl"], go["downloadUrl"]);
    assert_eq!(mine["uploadUrl"], go["uploadUrl"]);
    assert_eq!(mine["eventSourceUrl"], go["eventSourceUrl"]);

    // A method batch against an empty account.
    let batch = r#"{"using":["urn:ietf:params:jmap:mail"],
        "methodCalls":[["Mailbox/get",{"accountId":"alice@a.test"},"c0"]]}"#;
    let go: serde_json::Value =
        serde_json::from_str(&o.post_json_auth("/jmap/api/", batch, &auth).1).unwrap();
    let mine: serde_json::Value = serde_json::from_str(
        &oracle_harness::raw_post_auth(ours.port, "/jmap/api/", batch, &auth).1,
    )
    .unwrap();

    // An authenticated GET on the API route. The credential is checked before
    // the method, so this is the only way to reach the method check at all —
    // an unauthenticated GET is refused first and says nothing about it.
    let (go_status, go_body, _) = o.get_auth("/jmap/api/", &auth);
    let (our_status, our_body) = oracle_harness::raw_get_auth(ours.port, "/jmap/api/", &auth);
    assert_eq!(our_status, go_status, "GET /jmap/api/: {go_body:.120}");
    assert_eq!(our_body, go_body, "GET /jmap/api/");

    let strip_state = |mut v: serde_json::Value| {
        // `state` is a per-store counter, and the two stores were opened
        // independently. Everything else about the response is the contract.
        if let Some(r) = v["methodResponses"][0][1].as_object_mut() {
            r.remove("state");
        }
        v
    };
    assert_eq!(strip_state(mine), strip_state(go), "Mailbox/get");

    // An account this relay does not serve is refused, not answered with
    // somebody else's data.
    let batch = r#"{"using":["urn:ietf:params:jmap:mail"],
        "methodCalls":[["Mailbox/get",{"accountId":"nobody@a.test"},"c0"]]}"#;
    let go: serde_json::Value =
        serde_json::from_str(&o.post_json_auth("/jmap/api/", batch, &auth).1).unwrap();
    let mine: serde_json::Value = serde_json::from_str(
        &oracle_harness::raw_post_auth(ours.port, "/jmap/api/", batch, &auth).1,
    )
    .unwrap();
    assert_eq!(mine, go, "an unknown accountId");
    // The error entry keeps the **method name** in slot 0, not the string
    // "error" — `error_response` is called with the method it is answering.
    // Worth pinning: a client matching on slot 0 to detect failure never
    // would.
    assert_eq!(go["methodResponses"][0][0], "Mailbox/get");
    assert_eq!(
        go["methodResponses"][0][1]["type"], "serverFail",
        "and the failure is in the payload: {}",
        go["methodResponses"][0][1]
    );
    assert!(
        go["methodResponses"][0][1]["description"]
            .as_str()
            .is_some_and(|d| d.contains("accountNotFound")),
        "the message carries the distinction: {}",
        go["methodResponses"][0][1]
    );

    ours.stop();
}

/// Provisioning, end to end, on both servers — with a genuine did:dht
/// identity and a real vouch, since the whole flow turns on the signature.
#[test]
fn provisioning_creates_the_same_account_on_both_servers() {
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };

    let make = |seed: u8, username: &str| {
        let root = SigningKey::from_bytes(&[seed; 32]);
        let did = format!(
            "did:dht:{}",
            jmapserver::diddht::zbase32_encode(&root.verifying_key().to_bytes())
        );
        let device = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
        let device_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(device.verifying_key().to_bytes());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sig = base64::engine::general_purpose::STANDARD.encode(
            root.sign(
                jmapserver::diddht::vouch_statement(&did, &device_id, "Laptop", ts).as_bytes(),
            )
            .to_bytes(),
        );
        serde_json::json!({
            "username": username, "domain": "open.test", "did": did,
            "did_sig": "c2ln", "bind_ts": ts,
            "device_pub_key": device_id, "device_label": "Laptop",
            "device_vouch_ts": ts, "device_vouch_sig": sig,
        })
        .to_string()
    };

    // Each server creates a different name, so neither collides with the
    // other's — they share a data directory.
    let (go_status, go_body) = o.post_json("/account/provision", &make(31, "viaoracle"));
    assert_eq!(go_status, 201, "{go_body}");
    let (our_status, our_body) =
        oracle_harness::raw_post(ours.port, "/account/provision", &make(41, "viaport"));
    assert_eq!(our_status, 201, "{our_body}");

    let go: serde_json::Value = serde_json::from_str(&go_body).unwrap();
    let mine: serde_json::Value = serde_json::from_str(&our_body).unwrap();
    assert_eq!(go["email"], "viaoracle@open.test");
    assert_eq!(mine["email"], "viaport@open.test");
    assert_eq!(
        mine["did_bound"], go["did_bound"],
        "neither relay has an anchor, so neither binds"
    );

    // Both accounts are on disk in the same shape: a device key and no static
    // credential.
    for lp in ["viaoracle", "viaport"] {
        let acct = o.data_dir().join("open.test").join(lp);
        assert_eq!(
            jmapserver::devicekeys::list_device_keys(&acct).len(),
            1,
            "{lp}: the device key is the credential"
        );
        assert!(
            !acct.join("auth_token_hash").exists(),
            "{lp}: this flow writes no static credential"
        );
    }

    // …and each refuses the other's name, from either server.
    let (status, _) = o.post_json("/account/provision", &make(51, "viaport"));
    assert_eq!(status, 409, "the oracle sees the account this port created");
    let (status, _) =
        oracle_harness::raw_post(ours.port, "/account/provision", &make(61, "viaoracle"));
    assert_eq!(status, 409, "and this port sees the oracle's");

    ours.stop();
}

/// The refusals, compared. Each is reachable without a credential, so each is
/// something anyone on the internet can learn.
#[test]
fn provisioning_refuses_identically() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    let body = |v: serde_json::Value| v.to_string();

    for (name, req) in [
        ("no fields at all", body(serde_json::json!({}))),
        (
            "a bad username",
            body(
                serde_json::json!({"username": "Bad Name", "did": "did:dht:x",
                                    "device_pub_key": "k", "device_vouch_sig": "s"}),
            ),
        ),
        (
            "no did",
            body(
                serde_json::json!({"username": "carol", "device_pub_key": "k",
                                    "device_vouch_sig": "s"}),
            ),
        ),
        (
            "an unknown domain",
            body(
                serde_json::json!({"username": "carol", "domain": "nope.test",
                                    "did": "did:dht:x", "device_pub_key": "k",
                                    "device_vouch_sig": "s"}),
            ),
        ),
        (
            // On the OPEN domain, so it reaches the vouch path rather than
            // being refused on the domain gate first. That is what makes this
            // case about the DID method at all.
            "a did:webvh with no anchor",
            body(serde_json::json!({
                "username": "carol", "domain": "open.test",
                "did": "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:c",
                "device_pub_key": "k", "device_vouch_sig": "s"})),
        ),
        (
            // Well-formed all the way through, with a signature that is real
            // ed25519 over the WRONG statement. Nothing before the vouch check
            // rejects it, so this is the only case that exercises the check.
            "a did:dht vouch signed for a different label",
            {
                use base64::Engine as _;
                use ed25519_dalek::{Signer as _, SigningKey};
                let root = SigningKey::from_bytes(&[71u8; 32]);
                let did = format!(
                    "did:dht:{}",
                    jmapserver::diddht::zbase32_encode(&root.verifying_key().to_bytes())
                );
                let device = SigningKey::from_bytes(&[72u8; 32]);
                let device_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(device.verifying_key().to_bytes());
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let sig = base64::engine::general_purpose::STANDARD.encode(
                    root.sign(
                        jmapserver::diddht::vouch_statement(&did, &device_id, "Laptop", ts)
                            .as_bytes(),
                    )
                    .to_bytes(),
                );
                body(serde_json::json!({
                    "username": "dave", "domain": "open.test", "did": did,
                    "did_sig": "c2ln", "bind_ts": ts,
                    "device_pub_key": device_id,
                    // The vouch was signed for "Laptop".
                    "device_label": "Attacker's box",
                    "device_vouch_ts": ts, "device_vouch_sig": sig}))
            },
        ),
    ] {
        let (go_status, go_body) = o.post_json("/account/provision", &req);
        let (our_status, our_body) =
            oracle_harness::raw_post(ours.port, "/account/provision", &req);
        assert_eq!(our_status, go_status, "{name}: oracle said {go_body:?}");
        assert_eq!(our_body, go_body, "{name}");
    }

    // None of them left an account behind on either side.
    for lp in ["carol", "dave"] {
        assert!(
            !o.data_dir().join("open.test").join(lp).exists(),
            "{lp}: a refused provision must create nothing"
        );
    }
    ours.stop();
}

/// The dashboard shell, byte for byte. It is a released client and the JSON it
/// fetches is this port's output, so it is carried over rather than rewritten.
#[test]
fn the_admin_dashboard_is_byte_identical() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    let (status, body, _) = compare(&o, &ours, "/admin/dashboard");
    assert_eq!(status, 200);
    assert!(body.len() > 1000, "the real page, not a stub");
    assert!(
        !body.contains("alice@a.test"),
        "the shell embeds no account data: it is served without a token"
    );
    ours.stop();
}

/// The relay's own metric series, compared line by line.
///
/// **Not the whole scrape.** The Go build also registers the Go runtime and
/// process collectors, which describe the Go process and have no counterpart
/// here. The `biset_*` series are the ones this relay defines, and they are
/// the contract.
#[test]
fn every_biset_metric_series_matches() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };
    let (status, go_body, _) = o.get("/metrics");
    assert_eq!(status, 200);

    // This port closes /metrics with no token (§11.13), so its own scrape is
    // read through the renderer with the same inputs.
    // The **raw** configured label, not the `Mail` default `relay_label()`
    // applies elsewhere: the metric reports what the operator set, and an
    // empty one stays empty.
    let cfg: Config = serde_json::from_str(&config_json(o.http_port, 1)).unwrap();
    let mut mine = jmapserver::admin::collect(&o.data_dir(), &cfg.relay_label, "dev");
    mine.extend(jmapserver::admin::smtp_outbound_metrics(0, 0));
    let our_body = jmapserver::admin::render_prometheus(&mine);

    let biset_series = |text: &str| -> std::collections::BTreeSet<String> {
        text.lines()
            .filter(|l| l.starts_with("biset_"))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        biset_series(&our_body),
        biset_series(&go_body),
        "the relay's own series"
    );

    // The HELP and TYPE lines too — a counter graphed as a gauge is wrong.
    for name in [
        "biset_build_info",
        "biset_data_disk_bytes",
        "biset_smtp_outbound_total",
        "biset_accounts",
    ] {
        for kind in ["# HELP", "# TYPE"] {
            let go_line = go_body
                .lines()
                .find(|l| l.starts_with(&format!("{kind} {name} ")))
                .unwrap_or_else(|| panic!("the oracle should declare {kind} {name}"));
            assert!(
                our_body.lines().any(|l| l == go_line),
                "{kind} {name}: this port sent something else\n  oracle: {go_line}"
            );
        }
    }

    // The §11.16 divergence — the oracle counting `peers` and the registry —
    // needs a seed that has them, and is asserted in `admin_interop`. This
    // seed deliberately has neither, so every account series matches here and
    // the comparison above is not filtered.
    assert!(
        go_body.contains(r#"biset_accounts{domain="open.test"} 0"#),
        "a domain with no accounts still reports zero: {go_body}"
    );
    ours.stop();
}

/// The custom-domain flow. `/domain/add` cannot be driven to success here —
/// it needs a live TXT record on a domain nobody controls — so what is
/// compared is the record set an owner is told to publish, and the refusal.
#[test]
fn the_custom_domain_records_and_refusals_match() {
    let Some((o, ours)) = both(seed_accounts) else {
        return;
    };

    for target in [
        "/domain/verify-token?domain=y.jp",
        "/domain/verify-token?domain=sub.example.com",
        "/domain/verify-token?domain=Example.COM",
        "/domain/verify-token?domain=",
        "/domain/verify-token?domain=example",
        "/domain/verify-token?domain=-bad.com",
    ] {
        compare(&o, &ours, target);
    }

    // Asking twice must not rotate the DKIM key: an owner who already
    // published the record would silently start failing DKIM.
    let (_, first, _) = o.get("/domain/verify-token?domain=y.jp");
    let (_, again, _) = o.get("/domain/verify-token?domain=y.jp");
    assert_eq!(first, again, "the oracle does not rotate");
    let (_, ours_first, _) = ours.get("/domain/verify-token?domain=y.jp");
    let (_, ours_again, _) = ours.get("/domain/verify-token?domain=y.jp");
    assert_eq!(ours_first, ours_again, "neither does this port");

    // The registration attempt: no TXT record exists, so both refuse with 412
    // — the request is well formed and a precondition on the world is not met.
    for body in [r#"{"domain":"y.jp"}"#, r#"{"domain":"not a domain"}"#] {
        let (go_status, go_body) = o.post_json("/domain/add", body);
        let (our_status, our_body) = oracle_harness::raw_post(ours.port, "/domain/add", body);
        assert_eq!(our_status, go_status, "{body}: oracle said {go_body:?}");
        assert_eq!(our_body, go_body, "{body}");
    }
    assert!(
        !o.data_dir().join("_domains/y.jp/domain.json").exists(),
        "an unverified domain must not be registered"
    );

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
        "/jmap/eventsource/",
        "/jmap/push/vapid-public-key",
        "/jmap/push/subscribe",
        "/jmap/push/unsubscribe",
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
    // The dashboard shell is wired and public on both sides.
    assert_eq!(ours.get("/admin/dashboard").0, 200);

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
