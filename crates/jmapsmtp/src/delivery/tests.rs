//! Inbound delivery and the maintenance sweep, driven through the real types.
//!
//! The delivery tests are async because `deliver` spawns the push
//! notification. Guarding that spawn instead would let them pass without the
//! push path ever running, which is the opposite of what a test is for.

use super::*;
use crate::config::Config;
use crate::smtp_in::Backend as _;
use pretty_assertions::assert_eq;

fn relay(json: &str) -> Arc<RelayState> {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(json).expect("config should parse");
    let state = RelayState::with_tokens(cfg, tmp, "", "");
    state.open_stores().expect("stores should open");
    state
}

fn one_account() -> Arc<RelayState> {
    relay(r#"{"domain":{"a.test":{"account":{"alice":{"alias":["postmaster"]}}}}}"#)
}

fn message(subject: &str, message_id: &str) -> Vec<u8> {
    format!(
        "From: bob@x.test\r\nTo: alice@a.test\r\nSubject: {subject}\r\n\
         Message-Id: <{message_id}>\r\nDate: Mon, 2 Aug 2026 12:00:00 +0000\r\n\r\nbody\r\n"
    )
    .into_bytes()
}

// ── who is accepted ───────────────────────────────────────────────────────

/// An address that is not served here is still answered `250` and dropped.
/// Rejecting at RCPT would tell anyone who can reach port 25 which addresses
/// exist.
#[tokio::test]
async fn an_unknown_recipient_is_not_accepted_but_is_not_rejected_either() {
    let backend = Delivery {
        state: one_account(),
    };
    assert!(backend.accepts("alice@a.test"));
    assert!(backend.accepts("postmaster@a.test"), "aliases too");
    assert!(backend.accepts("ALICE@A.TEST"), "folded");
    assert!(!backend.accepts("nobody@a.test"));

    // …and delivering to it stores nothing rather than erroring.
    backend.deliver(
        "bob@x.test",
        &["nobody@a.test".into()],
        &message("hi", "m1@x"),
    );
    assert!(
        jmapserver::storage::list_message_files(&backend.state.data_dir, "a.test", "alice")
            .unwrap_or_default()
            .is_empty()
    );
}

// ── storing ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_delivered_message_is_stored_and_readable() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    backend.deliver(
        "bob@x.test",
        &["alice@a.test".into()],
        &message("hello", "m1@x.test"),
    );

    let account = state.accounts.get("alice@a.test").unwrap();
    let stored = account.store.all();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].subject, "hello");
    assert!(stored[0].received_at.is_some());
}

/// The id comes from the RFC Message-ID, so a retry or a second MX overwrites
/// rather than duplicating.
#[tokio::test]
async fn redelivering_the_same_message_overwrites_rather_than_duplicating() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    for _ in 0..3 {
        backend.deliver(
            "bob@x.test",
            &["alice@a.test".into()],
            &message("hello", "same@x.test"),
        );
    }
    let stored = state.accounts.get("alice@a.test").unwrap().store.all();
    assert_eq!(stored.len(), 1);
    // Asserted on the **id**, not only the count. Without the Message-ID the
    // id falls back to address-plus-millisecond, and three deliveries inside
    // one millisecond collapse to a single message anyway — so the count alone
    // passes or fails depending on how fast the machine is. It did both.
    assert_eq!(
        stored[0].id.as_str(),
        "msg-same@x.test",
        "the id is derived from the RFC Message-ID"
    );

    // A different Message-ID is a different message.
    backend.deliver(
        "bob@x.test",
        &["alice@a.test".into()],
        &message("other", "other@x.test"),
    );
    assert_eq!(
        state
            .accounts
            .get("alice@a.test")
            .unwrap()
            .store
            .all()
            .len(),
        2
    );
}

/// An alias delivers into the account it points at, not one of its own.
#[tokio::test]
async fn an_alias_delivers_into_its_primary_account() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    backend.deliver(
        "bob@x.test",
        &["postmaster@a.test".into()],
        &message("via alias", "m1@x.test"),
    );
    assert_eq!(
        state
            .accounts
            .get("alice@a.test")
            .unwrap()
            .store
            .all()
            .len(),
        1
    );
}

/// A message that will not parse is dropped rather than stored empty — an
/// entry with no headers and no body looks like mail arrived.
#[tokio::test]
async fn an_unparseable_message_is_not_stored() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    backend.deliver("bob@x.test", &["alice@a.test".into()], b"");
    assert!(
        state
            .accounts
            .get("alice@a.test")
            .unwrap()
            .store
            .all()
            .is_empty()
    );
}

/// The cap applies on the way in as well as on the way out: either direction
/// can be what fills the disk.
#[tokio::test]
async fn delivery_stops_at_the_storage_cap() {
    let state =
        relay(r#"{"domain":{"a.test":{"account":{"alice":{}}}},"max_account_storage_mb":1}"#);
    let backend = Delivery {
        state: state.clone(),
    };
    let account = state.accounts.get("alice@a.test").unwrap();
    std::fs::write(account.dir.join("big"), vec![0u8; 1024 * 1024]).unwrap();

    backend.deliver(
        "bob@x.test",
        &["alice@a.test".into()],
        &message("too late", "m1@x.test"),
    );
    assert!(
        account.store.all().is_empty(),
        "the cap refuses at the limit, not past it"
    );
}

/// **A declared divergence (SPEC.md §11.17): mail is stored on arrival, so
/// there is no queue to overflow.**
///
/// Go buffers inbound mail in a 256-slot channel and drains it only when a
/// JMAP request arrives (`main.go`'s `bufCh` / `drainBuffer`). Past 256
/// messages between requests, `bufferEmail` takes its `default` branch and
/// **discards** the message — after the sender was already told 250. That is
/// silent mail loss, so it is not reproduced.
///
/// 300 is chosen to sit past Go's 256 with no JMAP request anywhere in the
/// test: under Go's design 44 of these would be gone.
#[tokio::test]
async fn more_than_256_messages_arriving_between_requests_are_all_stored() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    let account = state.accounts.get("alice@a.test").unwrap();

    for i in 0..300 {
        backend.deliver(
            "bob@x.test",
            &["alice@a.test".into()],
            &message(&format!("m{i}"), &format!("m{i}@x.test")),
        );
    }

    assert_eq!(
        account.store.all().len(),
        300,
        "every accepted message must be stored; Go would have dropped the          44 past its 256-slot buffer"
    );
}

/// Delivery is recorded, and a failure is recorded as a failure — the log is
/// how an operator sees mail arriving at all.
#[tokio::test]
async fn delivery_is_logged_with_its_outcome() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    backend.deliver(
        "bob@x.test",
        &["alice@a.test".into()],
        &message("hello", "m1@x.test"),
    );
    let events =
        jmapserver::activity::read_activity(&state.data_dir, "a.test", "alice", 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].dir, "in");
    assert_eq!(events[0].kind, "email");
    assert_eq!(events[0].peer, "bob@x.test");
    assert_eq!(events[0].result, "ok");
    assert!(events[0].bytes > 0);

    backend.deliver("bob@x.test", &["alice@a.test".into()], b"");
    let events =
        jmapserver::activity::read_activity(&state.data_dir, "a.test", "alice", 0).unwrap();
    assert_eq!(events[0].result, "failed", "newest first");
}

// ── STARTTLS ──────────────────────────────────────────────────────────────

/// The upgrade, over a real socket: advertised, accepted, and the session
/// continues on the encrypted stream.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_can_upgrade_the_session_with_starttls() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    let state = one_account();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_smtp(listener, state).await;
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    let mut line = String::new();

    read.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220 "), "greeting: {line}");

    write.write_all(b"EHLO client.test\r\n").await.unwrap();
    let mut caps = String::new();
    loop {
        line.clear();
        read.read_line(&mut line).await.unwrap();
        caps.push_str(&line);
        if line.starts_with("250 ") {
            break;
        }
    }
    assert!(caps.contains("STARTTLS"), "advertised: {caps}");

    write.write_all(b"STARTTLS\r\n").await.unwrap();
    line.clear();
    read.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with("220 "),
        "the server agreed to upgrade: {line}"
    );

    // The plaintext side is finished; anything after this is TLS records.
    // Reading one confirms the server is speaking TLS rather than SMTP.
    let mut first = [0u8; 1];
    use tokio::io::AsyncReadExt as _;
    write.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        read.read_exact(&mut first),
    )
    .await;
    assert_ne!(
        first[0], b'5',
        "an SMTP error line here would mean no upgrade happened"
    );
}

/// After the upgrade, `STARTTLS` is **not** advertised again. RFC 3207 §4.2
/// forbids it, and a client that saw it twice would have no way to tell
/// whether the first upgrade took.
///
/// This is the only test that completes the handshake, because it is the only
/// question that needs the encrypted side.
#[tokio::test(flavor = "multi_thread")]
async fn starttls_is_not_advertised_again_after_the_upgrade() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    let state = one_account();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_smtp(listener, state).await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Greeting, EHLO, STARTTLS — read line by line off the plaintext side.
    {
        let mut buf = vec![0u8; 4096];
        use tokio::io::AsyncReadExt as _;
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(b"EHLO client.test\r\n").await.unwrap();
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(b"STARTTLS\r\n").await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("220 "),
            "the server agreed"
        );
    }

    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(accept_any_client_config()));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let upgraded = tls.connect(server_name, stream).await.expect("handshake");

    let (read, mut write) = tokio::io::split(upgraded);
    let mut read = BufReader::new(read);
    write.write_all(b"EHLO client.test\r\n").await.unwrap();

    let mut caps = String::new();
    loop {
        let mut line = String::new();
        read.read_line(&mut line).await.unwrap();
        caps.push_str(&line);
        if line.starts_with("250 ") || line.is_empty() {
            break;
        }
    }
    assert!(!caps.is_empty(), "the session continued over TLS");
    assert!(
        !caps.contains("STARTTLS"),
        "RFC 3207 §4.2: not advertised again — {caps}"
    );
    // …and the session is otherwise intact.
    assert!(caps.contains("SMTPUTF8"), "{caps}");
}

/// A client that accepts the relay's self-signed certificate.
///
/// Test-only, and it is what a real sending MX does on port 25 anyway: it
/// cannot authenticate an arbitrary recipient domain, so it either accepts an
/// unverified certificate or falls back to plaintext.
fn accept_any_client_config() -> rustls::ClientConfig {
    crate::inbound_tls::install_crypto_provider();

    #[derive(Debug)]
    struct AcceptAny;
    impl rustls::client::danger::ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
        .with_no_client_auth()
}

/// Without a certificate the capability is still advertised and answered 454.
/// Refusing keeps an opportunistic sender on plaintext — a delivered message
/// rather than a timed-out one.
#[tokio::test(flavor = "multi_thread")]
async fn starttls_without_a_certificate_is_refused_not_stalled() {
    use crate::smtp_in::{Config as SmtpConfig, Outcome};

    let state = one_account();
    let backend = Delivery { state };
    let cfg = SmtpConfig {
        hostname: "mx.a.test".into(),
        starttls: true,
        tls_available: false,
        enable_smtputf8: true,
    };

    let (client, server) = tokio::io::duplex(4096);
    let session = tokio::spawn(async move {
        let mut server = server;
        crate::smtp_in::handle(&mut server, &cfg, &backend).await
    });

    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    let mut line = String::new();
    read.read_line(&mut line).await.unwrap();

    write.write_all(b"STARTTLS\r\n").await.unwrap();
    line.clear();
    read.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("454 "), "refused, not stalled: {line}");

    write.write_all(b"QUIT\r\n").await.unwrap();
    assert_eq!(session.await.unwrap().unwrap(), Outcome::Done);
}

// ── the maintenance sweep ─────────────────────────────────────────────────

/// A purge removes the routing as well as the data. Leaving an alias behind
/// would take delivery into a store nobody can reach.
#[test]
fn purging_removes_the_account_its_aliases_and_its_data() {
    let state =
        relay(r#"{"domain":{"open.test":{"allow_provision":true}},"inactive_purge_days":1}"#);

    // A dynamic account, idle, with an alias registered.
    let dir = state.data_dir.join("open.test/idle");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("mail.json"), b"precious").unwrap();
    let store = jmapserver::Store::open(&dir).unwrap();
    state.accounts.insert(
        crate::handler::AccountStore {
            email: "idle@open.test".into(),
            domain: "open.test".into(),
            localpart: "idle".into(),
            dir: dir.clone(),
            store: Arc::new(store),
        },
        &["alias@open.test".to_string()],
    );
    state.dyn_accounts.insert("idle@open.test".into());

    // Backdate everything so it is past the cutoff.
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let long_ago = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        filetime::set_file_mtime(entry.path(), filetime::FileTime::from_system_time(long_ago))
            .unwrap();
    }

    purge_inactive(&state);

    assert!(!dir.exists(), "the data is gone");
    assert!(state.accounts.get("idle@open.test").is_none());
    assert!(
        state.accounts.resolve("alias@open.test").is_none(),
        "a dangling alias would swallow mail silently"
    );
    assert!(!state.dyn_accounts.contains("idle@open.test"));
}

/// With the setting absent, the sweep does nothing at all.
#[test]
fn purging_is_a_no_op_when_it_is_not_configured() {
    let state = relay(r#"{"domain":{"open.test":{"allow_provision":true}}}"#);
    let dir = state.data_dir.join("open.test/ancient");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("mail.json"), b"precious").unwrap();
    filetime::set_file_mtime(
        dir.join("mail.json"),
        filetime::FileTime::from_unix_time(1_000_000, 0),
    )
    .unwrap();

    purge_inactive(&state);
    assert!(dir.exists(), "nothing is purged without the setting");
}

// ── dynamic accounts survive a restart ────────────────────────────────────

/// **A dynamic account must be deliverable after a restart.**
///
/// Every other delivery test here uses an account declared in the config, and
/// that is why this was missed: `scan_dyn_accounts` recorded the address in
/// `dyn_accounts` without opening a store or adding an alias, so `accepts`
/// answered `false` and delivery took the accepted-and-dropped path. Mail was
/// answered `250` and thrown away.
///
/// A relay whose config declares no accounts at all — which is the normal
/// shape once provisioning is in use — lost **every** incoming message after
/// its first restart. Found on a production deployment, where the config has
/// two domains and zero static accounts under them.
#[tokio::test]
async fn a_dynamic_account_receives_mail_after_a_restart() {
    // No accounts in the config: every account here is dynamic, as on a relay
    // that provisions.
    let state = relay(r#"{"domain":{"a.test":{}}}"#);

    // What provisioning leaves on disk: a directory with a credential.
    let acct = state.data_dir.join("a.test/dynamic");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(b"token-for-the-dynamic-account"),
    )
    .unwrap();

    // The restart path.
    crate::startup::scan_dyn_accounts(
        &state.cfg,
        &state.dynamic_domains,
        &state.data_dir,
        |lp, d| state.register_dyn_account(lp, d),
    );

    let backend = Delivery {
        state: state.clone(),
    };
    assert!(
        backend.accepts("dynamic@a.test"),
        "the scan must make the address deliverable, not merely known"
    );

    backend.deliver(
        "bob@x.test",
        &["dynamic@a.test".into()],
        &message("after restart", "restart@x.test"),
    );

    let account = state
        .accounts
        .get("dynamic@a.test")
        .expect("the scan must open a store for it");
    assert_eq!(
        account.store.all().len(),
        1,
        "the message was accepted with a 250; it has to be somewhere"
    );
}

/// The scan and the sweep must agree, or a restart deletes what the other
/// restores. An account with no credential is swept, so the scan must not
/// register it either.
#[tokio::test]
async fn the_scan_ignores_what_the_sweep_would_delete() {
    let state = relay(r#"{"domain":{"a.test":{}}}"#);
    std::fs::create_dir_all(state.data_dir.join("a.test/nocredential")).unwrap();

    crate::startup::scan_dyn_accounts(
        &state.cfg,
        &state.dynamic_domains,
        &state.data_dir,
        |lp, d| state.register_dyn_account(lp, d),
    );

    let backend = Delivery {
        state: state.clone(),
    };
    assert!(
        !backend.accepts("nocredential@a.test"),
        "no auth_token_hash means the sweep removes it; registering it here \
         would make the two disagree"
    );
}

/// **A dynamic account must be able to compose, not only receive.**
///
/// `Email/set create` and `EmailSubmission/set` are hooks the relay installs
/// on each store — the store cannot mint an id or a Message-ID on its own — so
/// a store opened without them answers
/// `serverFail: Email/set create not configured` to every create.
///
/// The sibling above pins that a recovered account can *receive*. It passed
/// while this failed, because delivery goes through `Delivery::deliver` and
/// composing goes through the store's hooks: two halves of "the account
/// works", and only one of them was checked. On a relay whose config declares
/// no accounts — the normal shape once provisioning is in use — nobody could
/// send at all.
#[tokio::test]
async fn a_dynamic_account_can_create_an_email() {
    let state = relay(r#"{"domain":{"a.test":{}}}"#);
    let acct = state.data_dir.join("a.test/dynamic");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(b"token-for-the-dynamic-account"),
    )
    .unwrap();

    crate::startup::scan_dyn_accounts(
        &state.cfg,
        &state.dynamic_domains,
        &state.data_dir,
        |lp, d| state.register_dyn_account(lp, d),
    );

    let account = state
        .accounts
        .get("dynamic@a.test")
        .expect("the scan must register it");

    let created = account.store.dispatch(
        &jmap_types::Id::from("dynamic@a.test"),
        "Email/set",
        &serde_json::json!({
            "accountId": "dynamic@a.test",
            "create": {
                "draft": {
                    "mailboxIds": { "mbx-dynamic@a.test": true },
                    "keywords": { "$draft": true },
                    "from": [{ "email": "dynamic@a.test" }],
                    "to": [{ "email": "bob@x.test" }],
                    "subject": "compose probe",
                    "textBody": [{ "partId": "1", "type": "text/plain" }],
                    "bodyValues": { "1": { "value": "hello" } },
                }
            }
        }),
        "2026-08-11T00:00:00Z",
    );

    let response = created.expect("Email/set should dispatch");
    let not_created = &response["notCreated"];
    assert!(
        not_created.as_object().is_none_or(|m| m.is_empty()),
        "the create was refused — the store has no hooks: {not_created}"
    );
    assert!(
        response["created"]["draft"]["id"].is_string(),
        "a create must answer with an id, which is what the client reads: {response}"
    );
}

/// **The resumed session must not greet again.**
///
/// The banner answers the connection, not a command. A second one puts an
/// extra reply on the wire and every later reply then answers the previous
/// command: the client's `EHLO` gets the `220`, its `MAIL` gets the `EHLO`
/// lines, its `DATA` gets the reply to `RCPT`. A Postfix relay bounced real
/// mail with exactly that — `250 … I'll make sure <…> gets this (in reply to
/// DATA command)` — so **every message from a TLS-capable MTA was refused**,
/// which is every MTA.
///
/// `a_client_can_upgrade_the_session_with_starttls` above checks that the
/// handshake happens. It passed throughout: the upgrade worked, and what came
/// after it was never looked at.
///
/// Driven through `handle_upgraded` directly rather than through a real TLS
/// socket — the banner decision is the whole subject, and wrapping it in a
/// handshake would test rustls.
#[tokio::test]
async fn a_session_resumed_after_starttls_does_not_greet_again() {
    let state = one_account();
    let backend = Delivery { state };
    let cfg = crate::smtp_in::Config {
        hostname: "mail.example.com".into(),
        starttls: false,
        tls_available: false,
        enable_smtputf8: true,
    };

    // A whole conversation, as a pipelining MTA sends it.
    let script = b"EHLO sender.invalid\r\n\
                   MAIL FROM:<bob@x.test>\r\n\
                   RCPT TO:<alice@a.test>\r\n\
                   DATA\r\n\
                   From: bob@x.test\r\nTo: alice@a.test\r\nSubject: s\r\n\r\nbody\r\n.\r\n\
                   QUIT\r\n"
        .to_vec();
    // `&[u8]` is an `AsyncRead`, which is all the script needs to be.
    let mut stream: &[u8] = &script;
    let mut out: Vec<u8> = Vec::new();
    {
        let mut duplex = ReadWrite {
            read: &mut stream,
            write: &mut out,
        };
        let _ = crate::smtp_in::handle_upgraded(&mut duplex, &cfg, &backend).await;
    }
    let text = String::from_utf8_lossy(&out);
    let replies: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();

    assert!(
        !replies[0].starts_with("220 "),
        "the resumed session must open with the EHLO answer, not a banner: {replies:?}"
    );
    assert!(
        replies[0].starts_with("250"),
        "first reply should answer EHLO: {replies:?}"
    );
    // The one that mattered: DATA is answered by 354, not by the RCPT reply.
    let data_reply = replies
        .iter()
        .find(|l| l.starts_with("354"))
        .unwrap_or(&"<none>");
    assert!(
        data_reply.starts_with("354"),
        "DATA must be answered with 354: {replies:?}"
    );
}

/// A tiny duplex so a scripted reader and a `Vec` writer can be handed to
/// `handle`, which wants one `AsyncRead + AsyncWrite`.
struct ReadWrite<'a, R, W> {
    read: &'a mut R,
    write: &'a mut W,
}

impl<R: tokio::io::AsyncRead + Unpin, W: Unpin> tokio::io::AsyncRead for ReadWrite<'_, R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.read).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ReadWrite<'_, R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.write).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.write).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.write).poll_shutdown(cx)
    }
}

/// **A delivered message must be filed into the account's inbox.**
///
/// Every delivery test here asserted the message was *stored* — `store.all()`
/// counts it, `get` returns it by id. None looked at `mailboxIds`, and a
/// message with none is in no mailbox: a client that lists the inbox sees an
/// empty one while the file sits on disk. Real mail arrived and never
/// appeared, for exactly that reason.
///
/// The id is the account's own inbox (`mbx-<address>`), which is the mailbox
/// `default_inbox` writes at start-up and the only one an account has.
#[tokio::test]
async fn a_delivered_message_is_filed_into_the_inbox() {
    let state = one_account();
    let backend = Delivery {
        state: state.clone(),
    };
    backend.deliver(
        "bob@x.test",
        &["alice@a.test".into()],
        &message("filed", "filed@x.test"),
    );

    let account = state.accounts.get("alice@a.test").unwrap();
    let stored = account.store.all();
    assert_eq!(stored.len(), 1);
    let inbox = jmap_types::Id::from(crate::handler::make_mailbox_id("alice@a.test").as_str());
    assert_eq!(
        stored[0].mailbox_ids.get(&inbox),
        Some(&true),
        "not filed into {inbox:?} — stored but invisible to any client that \
         lists a mailbox: {:?}",
        stored[0].mailbox_ids
    );
}
