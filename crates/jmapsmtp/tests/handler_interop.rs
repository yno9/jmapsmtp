//! What the oracle writes to disk at startup, compared byte for byte.
//!
//! `defaultInbox`, `makeMailboxID` and `writeDKIMDNSFile` are unexported
//! functions in `package main`, so there is nothing to link against — but
//! their *output* is on disk after a normal boot. Reading it is a stronger
//! check than a helper program anyway: it is the file a real deployment has.
//!
//! These are the files that outlive the process. `mailboxes.json` is read back
//! by whichever build starts next, so a difference here is a client seeing its
//! mailbox change id or lose a right across an upgrade.

use jmapsmtp::handler::default_inbox;

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}},"od~d":{{}}}}}}}}}}"#
    )
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("HANDLER_INTEROP", config_json, |_| {})
}

/// The mailbox the account is defined by, as the oracle stored it.
#[test]
fn the_default_inbox_serialises_exactly_as_the_oracle_wrote_it() {
    let Some(o) = oracle() else { return };

    for localpart in ["alice", "od~d"] {
        let path = o
            .data_dir()
            .join("a.test")
            .join(localpart)
            .join("mailboxes.json");
        let go = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the oracle should have written {path:?}: {e}"));

        let addr = format!("{localpart}@a.test");
        let ours = jmap_types::go_json::to_string(&[default_inbox(&addr)]).unwrap();

        assert_eq!(
            ours, go,
            "mailboxes.json for {addr} — this file is read back by whichever \
             build starts next"
        );
    }
}

/// The one field a client caches and would notice changing.
#[test]
fn the_mailbox_id_the_oracle_stored_is_derived_from_the_address() {
    let Some(o) = oracle() else { return };
    let go = std::fs::read_to_string(o.data_dir().join("a.test/alice/mailboxes.json")).unwrap();
    let parsed: Vec<jmap_types::mailbox::Mailbox> = serde_json::from_str(&go).unwrap();
    assert_eq!(parsed.len(), 1, "one mailbox per account");
    assert_eq!(
        parsed[0].id,
        default_inbox("alice@a.test").id,
        "a client's cached mailbox id has to survive the port"
    );
}

/// `dkim-dns.txt` is what the operator pastes into DNS. A difference in it is
/// mail that fails DKIM after a migration.
#[test]
fn the_dkim_dns_file_matches_the_oracles_format() {
    let Some(o) = oracle() else { return };
    let go = std::fs::read_to_string(o.data_dir().join("a.test/dkim-dns.txt")).unwrap();

    // Load the oracle's own key so the record body is identical and only the
    // framing is under test — the signing itself is checked by dkim_interop.
    // `load_or_generate_key` reads an existing key.pem, so pointing it at the
    // oracle's directory loads rather than generates.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::copy(
        o.data_dir().join("a.test/key.pem"),
        tmp.path().join("key.pem"),
    )
    .unwrap();
    let key = jmapsmtp::dkim::load_or_generate_key(tmp.path())
        .expect("the oracle's key should load, not be regenerated");
    jmapsmtp::dkim::write_record_file(tmp.path(), "default", "a.test", &key).unwrap();
    let ours = std::fs::read_to_string(tmp.path().join("dkim-dns.txt")).unwrap();

    assert_eq!(ours, go);
}

/// The setup token the operator hands to an account's owner.
#[test]
fn the_setup_token_has_the_shape_this_port_generates() {
    let Some(o) = oracle() else { return };
    let go = std::fs::read_to_string(o.data_dir().join("a.test/alice/setup.token")).unwrap();

    assert_eq!(go.len(), 32, "16 random bytes as hex, with no newline");
    assert!(go.chars().all(|c| c.is_ascii_hexdigit()), "{go:?}");
    assert_eq!(
        jmapsmtp::startup::generate_token().len(),
        go.len(),
        "this port issues the same length"
    );

    // An account with an envelope gets no token. Both of these have none, so
    // both should have been issued one — the negative case is a unit test,
    // since seeding a valid envelope needs a real Argon2 run.
    assert!(o.data_dir().join("a.test/od~d/setup.token").exists());
}
