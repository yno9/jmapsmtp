//! The handler's derived identifiers, the storage accounting, and the alias
//! routing table.
//!
//! `tests/handler_interop.rs` compares the id and inbox formats against the Go
//! functions; these pin the reasoning a byte comparison would not show.

use super::*;
use pretty_assertions::assert_eq;

// ── derived identifiers ───────────────────────────────────────────────────

/// Mailbox ids are derived, not minted, so a client's cached id survives a
/// restart. Minting one would invalidate every cached reference on every boot.
#[test]
fn a_mailbox_id_is_derived_from_the_address_and_is_stable() {
    assert_eq!(make_mailbox_id("alice@a.test"), "mbx-alice@a.test");
    assert_eq!(
        make_mailbox_id("alice@a.test"),
        make_mailbox_id("alice@a.test"),
        "same input, same id — nothing random in it"
    );
}

/// The id becomes a path segment, so a `/` in the address cannot survive
/// literally.
#[test]
fn a_slash_in_an_address_is_replaced_in_ids() {
    assert_eq!(make_mailbox_id("od/d@a.test"), "mbx-od~d@a.test");
    assert_eq!(make_message_id("", "od/d@a.test", 7), "msg-od-d@a.test-7");
    assert_eq!(make_message_id("a/b@x", "who@a.test", 7), "msg-a_b@x");
}

/// Three different replacement characters across two functions (`~`, `_`,
/// `-`). Ugly, and deliberately kept: these appear in filenames already
/// written to disk, so unifying them would orphan every stored message.
#[test]
fn the_replacement_characters_differ_between_id_kinds() {
    assert!(make_mailbox_id("a/b").contains('~'));
    assert!(make_message_id("a/b", "x", 0).contains('_'));
    assert!(make_message_id("", "a/b", 0).contains("a-b"));
}

/// Deriving from the RFC Message-ID means a redelivery — a retry, a second MX
/// — overwrites rather than duplicating.
#[test]
fn a_message_id_prefers_the_rfc_header_so_redelivery_overwrites() {
    let first = make_message_id("abc@sender.test", "alice@a.test", 1000);
    let later = make_message_id("abc@sender.test", "alice@a.test", 9999);
    assert_eq!(first, later, "the timestamp is not part of it");
    assert_eq!(first, "msg-abc@sender.test");
}

#[test]
fn without_an_rfc_header_the_timestamp_keeps_messages_apart() {
    assert_ne!(
        make_message_id("", "alice@a.test", 1000),
        make_message_id("", "alice@a.test", 1001)
    );
}

// ── minted identifiers ────────────────────────────────────────────────────

#[test]
fn a_server_id_has_the_expected_shape_and_is_unique() {
    let id = new_id();
    let s = id.as_str();
    let rest = s.strip_prefix("srv-").expect("srv- prefix");
    let (millis, hex) = rest.split_once('-').expect("srv-<millis>-<hex>");
    assert!(millis.parse::<i64>().is_ok(), "{millis:?}");
    assert_eq!(hex.len(), 16, "8 random bytes");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(new_id(), new_id());
}

/// Assigned at creation, not at send, so a client can quote it as
/// `In-Reply-To` on the next message immediately — the reply chain is built
/// locally and stays correct even if the send fails.
#[test]
fn an_rfc_message_id_is_scoped_to_the_domain_and_carries_no_brackets() {
    let id = new_rfc_message_id("a.test");
    assert!(id.ends_with("@a.test"), "{id}");
    assert!(!id.starts_with('<') && !id.ends_with('>'), "{id}");
    let (nanos, rest) = id.split_once('.').unwrap();
    assert!(nanos.parse::<i128>().is_ok(), "{nanos:?}");
    let hex = rest.strip_suffix("@a.test").unwrap();
    assert_eq!(hex.len(), 12, "6 random bytes");
    assert_ne!(new_rfc_message_id("a.test"), new_rfc_message_id("a.test"));
}

// ── the inbox ─────────────────────────────────────────────────────────────

/// There is exactly one mailbox per account and it cannot be renamed, deleted
/// or given children. The account *is* its inbox.
#[test]
fn the_default_inbox_grants_use_but_not_restructuring() {
    let mb = default_inbox("alice@a.test");
    assert_eq!(mb.id.as_str(), "mbx-alice@a.test");
    assert_eq!(mb.name, "alice@a.test");
    assert_eq!(mb.role.as_str(), "inbox");
    assert!(mb.is_subscribed);

    let r = mb.rights.unwrap();
    assert!(r.may_read_items && r.may_add_items && r.may_remove_items);
    assert!(r.may_set_seen && r.may_set_keywords && r.may_submit);
    assert!(!r.may_create_child && !r.may_rename && !r.may_delete);
}

// ── storage accounting ────────────────────────────────────────────────────

#[test]
fn the_directory_size_is_whole_megabytes_and_recurses() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(dir_size_mb(tmp.path()), 0, "empty");

    std::fs::write(tmp.path().join("a"), vec![0u8; 1024 * 1024]).unwrap();
    assert_eq!(dir_size_mb(tmp.path()), 1);

    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub/b"), vec![0u8; 1024 * 1024]).unwrap();
    assert_eq!(dir_size_mb(tmp.path()), 2, "nested files count");
}

/// Truncating, matching Go: the cap is crossed only once a full megabyte over.
/// Rounding up instead would reject an account sitting just under its limit.
#[test]
fn a_partial_megabyte_rounds_down() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a"), vec![0u8; 1024 * 1024 + 999_999]).unwrap();
    assert_eq!(dir_size_mb(tmp.path()), 1);
}

/// A cap check must never become a way to break sending, so an unreadable
/// tree reads as zero rather than erroring.
#[test]
fn a_missing_directory_measures_as_zero() {
    assert_eq!(dir_size_mb(Path::new("/nonexistent/nowhere")), 0);
}

// ── header:X-Foo:asText ───────────────────────────────────────────────────

#[test]
fn custom_text_headers_are_extracted() {
    let v = serde_json::json!({
        "subject": "hi",
        "header:X-Ticket:asText": "  ABC-1  ",
        "header:X-Mood:asText": "calm",
    });
    assert_eq!(
        extract_text_headers(&v),
        [
            ("X-Mood".to_string(), "calm".to_string()),
            ("X-Ticket".to_string(), "ABC-1".to_string()),
        ],
        "trimmed, and sorted by name"
    );
}

/// The assumption `extract_text_headers`'s sort is defensive *against*.
///
/// Written as its own test because removing that sort currently breaks
/// nothing — `serde_json::Map` is a `BTreeMap` without the `preserve_order`
/// feature, so the input is already ordered. If some crate in the tree ever
/// enables it, this test fails first and names the reason, instead of the
/// nondeterminism reappearing silently in message bytes.
#[test]
fn serde_json_object_iteration_is_already_ordered() {
    let mut map = serde_json::Map::new();
    for k in ["z", "a", "m", "b"] {
        map.insert(k.to_string(), serde_json::Value::from(1));
    }
    assert_eq!(
        map.keys().collect::<Vec<_>>(),
        ["a", "b", "m", "z"],
        "serde_json's Map is no longer sorted — the sort in \
         extract_text_headers is now load-bearing, and anything else that \
         iterates a parsed object needs the same treatment"
    );
}

/// Go ranges over a map here, so a message with two custom headers has no
/// stable byte form between runs. Sorting makes it reproducible.
/// SPEC.md §11.5.
#[test]
fn two_custom_headers_come_out_in_the_same_order_every_time() {
    let v = serde_json::json!({
        "header:X-Z:asText": "1",
        "header:X-A:asText": "2",
        "header:X-M:asText": "3",
    });
    let first = extract_text_headers(&v);
    for _ in 0..20 {
        assert_eq!(extract_text_headers(&v), first);
    }
    assert_eq!(
        first.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        ["X-A", "X-M", "X-Z"]
    );
}

/// An empty value means the client meant to unset it, not to send a bare
/// `X-Foo:` line.
#[test]
fn an_empty_or_malformed_header_property_is_ignored() {
    let v = serde_json::json!({
        "header:X-Blank:asText": "   ",
        "header::asText": "no name",
        "header:X-Wrong:asHtml": "wrong suffix",
        "X-Bare": "not a header property",
        "header:X-NotAString:asText": 42,
    });
    assert!(extract_text_headers(&v).is_empty());
    assert!(extract_text_headers(&serde_json::json!("not an object")).is_empty());
}

// ── reply-only correspondents ─────────────────────────────────────────────

#[test]
fn correspondents_come_from_every_stored_senders_address() {
    use jmap_types::mail::Address;
    let msgs = vec![
        Email {
            from: vec![Address {
                email: "Bob@Other.test".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        Email {
            from: vec![
                Address {
                    email: "carol@x.test".into(),
                    ..Default::default()
                },
                Address {
                    email: String::new(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    ];
    let known = known_correspondents(&msgs);
    assert!(known.contains("bob@other.test"), "folded");
    assert!(known.contains("carol@x.test"));
    assert_eq!(known.len(), 2, "the empty address is not a correspondent");
}

// ── the alias routing table ───────────────────────────────────────────────

fn account(email: &str) -> AccountStore {
    let (localpart, domain) = email.split_once('@').unwrap();
    let dir = tempfile::tempdir().unwrap().keep();
    AccountStore {
        email: email.to_string(),
        domain: domain.to_string(),
        localpart: localpart.to_string(),
        store: std::sync::Arc::new(jmapserver::Store::open(&dir).unwrap()),
        dir,
    }
}

#[test]
fn an_alias_resolves_to_its_primary_account() {
    let accounts = Accounts::default();
    accounts.insert(
        account("alice@a.test"),
        &["postmaster@a.test".into(), "Sales@A.test".into()],
    );

    for addr in [
        "alice@a.test",
        "postmaster@a.test",
        "sales@a.test",
        "SALES@A.TEST",
    ] {
        assert_eq!(
            accounts.resolve(addr).map(|a| a.email.clone()),
            Some("alice@a.test".into()),
            "{addr}"
        );
    }
    assert!(accounts.resolve("nobody@a.test").is_none());
}

/// Removing an account has to take its aliases with it. Leaving one behind
/// resolves to a store nobody can reach, and mail to that address disappears
/// without an error anywhere.
#[test]
fn removing_an_account_removes_its_aliases_too() {
    let accounts = Accounts::default();
    accounts.insert(account("alice@a.test"), &["postmaster@a.test".into()]);
    accounts.insert(account("bob@a.test"), &[]);

    accounts.remove("alice@a.test");
    assert!(accounts.resolve("alice@a.test").is_none());
    assert!(
        accounts.resolve("postmaster@a.test").is_none(),
        "a dangling alias would swallow mail silently"
    );
    assert_eq!(accounts.primaries(), ["bob@a.test"]);
    assert_eq!(accounts.aliases().len(), 1, "only bob's own address");
}

#[test]
fn a_later_account_can_claim_an_alias_from_an_earlier_one() {
    let accounts = Accounts::default();
    accounts.insert(account("alice@a.test"), &["info@a.test".into()]);
    accounts.insert(account("bob@a.test"), &["info@a.test".into()]);
    assert_eq!(
        accounts.resolve("info@a.test").map(|a| a.email.clone()),
        Some("bob@a.test".into()),
        "last registration wins, as inserting into a map does"
    );
}
