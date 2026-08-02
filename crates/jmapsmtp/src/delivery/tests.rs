//! Inbound delivery and the maintenance sweep, driven through the real types.

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
#[test]
fn an_unknown_recipient_is_not_accepted_but_is_not_rejected_either() {
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

#[test]
fn a_delivered_message_is_stored_and_readable() {
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
#[test]
fn redelivering_the_same_message_overwrites_rather_than_duplicating() {
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
#[test]
fn an_alias_delivers_into_its_primary_account() {
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
#[test]
fn an_unparseable_message_is_not_stored() {
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
#[test]
fn delivery_stops_at_the_storage_cap() {
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

/// Delivery is recorded, and a failure is recorded as a failure — the log is
/// how an operator sees mail arriving at all.
#[test]
fn delivery_is_logged_with_its_outcome() {
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
