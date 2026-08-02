//! The storage-transparency endpoints.
//!
//! The purge tests carry the weight: this is the one route in the family that
//! deletes, and what it must *not* delete is the whole safety of exposing it.

use super::*;
use pretty_assertions::assert_eq;

/// An account with the shape a real one has: some top-level files, a
/// `messages/` directory, and a subdirectory that is not `messages/`.
fn account() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let acct = tmp.path().join("a.test/alice");
    std::fs::create_dir_all(acct.join("messages")).unwrap();
    std::fs::create_dir_all(acct.join("devices")).unwrap();

    std::fs::write(acct.join("mailboxes.json"), vec![b'a'; 100]).unwrap();
    std::fs::write(acct.join("auth_token_hash"), vec![b'b'; 44]).unwrap();
    std::fs::write(acct.join("messages/msg-1.json"), vec![b'c'; 1000]).unwrap();
    std::fs::write(acct.join("messages/msg-2.json"), vec![b'd'; 2000]).unwrap();
    // A directory *inside* messages/. Not expected in the current layout, but
    // its size is not a message's, and counting it would report a message
    // count the account does not have.
    std::fs::create_dir_all(acct.join("messages/stray")).unwrap();
    std::fs::write(acct.join("messages/stray/inner.json"), vec![b'f'; 500]).unwrap();
    std::fs::write(acct.join("devices/KEY.json"), vec![b'e'; 60]).unwrap();
    tmp
}

// ── the one-level listing ─────────────────────────────────────────────────

/// `messages/` is summarised, not listed: an account can hold thousands, and a
/// per-message tree is not what "how your data is stored" is asking to see.
#[test]
fn the_listing_summarises_messages_and_names_every_top_level_file() {
    let tmp = account();
    let entries = list_account_storage(tmp.path(), "a.test", "alice").unwrap();

    assert_eq!(
        entries,
        [
            StorageEntry {
                name: "auth_token_hash".into(),
                kind: "file",
                count: 0,
                size_bytes: 44
            },
            StorageEntry {
                name: "mailboxes.json".into(),
                kind: "file",
                count: 0,
                size_bytes: 100
            },
            StorageEntry {
                name: "messages".into(),
                kind: "dir",
                count: 2,
                size_bytes: 3000
            },
        ],
        "sorted; `devices/` is not reported, and messages/stray/ counts as \
         neither a message nor a size"
    );
}

/// A directory inside `messages/` is neither counted nor sized. Its bytes are
/// not a message's, and counting it reports a message count the account does
/// not have.
#[test]
fn a_directory_inside_messages_is_not_counted_as_a_message() {
    let tmp = account();
    let messages = list_account_storage(tmp.path(), "a.test", "alice")
        .unwrap()
        .into_iter()
        .find(|e| e.name == "messages")
        .unwrap();
    assert_eq!(messages.count, 2, "two files, not three");
    assert_eq!(
        messages.size_bytes, 3000,
        "and 500 stray bytes are not added"
    );

    // The drill-down agrees.
    let files = list_message_files(tmp.path(), "a.test", "alice").unwrap();
    assert_eq!(files.len(), 2);
    assert!(!files.iter().any(|f| f.name == "stray"));
}

/// Any subdirectory other than `messages/` is skipped. Reporting one would give
/// it a size that is not its own — the walk is one level deep.
#[test]
fn other_subdirectories_are_not_reported() {
    let tmp = account();
    let names: Vec<String> = list_account_storage(tmp.path(), "a.test", "alice")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(!names.contains(&"devices".to_string()));
}

/// Sorted, so two identical requests give identical answers. Directory order is
/// filesystem-dependent otherwise.
#[test]
fn the_listing_is_stable_between_identical_requests() {
    let tmp = account();
    let first = list_account_storage(tmp.path(), "a.test", "alice").unwrap();
    for _ in 0..10 {
        assert_eq!(
            list_account_storage(tmp.path(), "a.test", "alice").unwrap(),
            first
        );
    }
}

#[test]
fn an_account_with_no_directory_is_an_error_not_an_empty_listing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(list_account_storage(tmp.path(), "a.test", "nobody").is_err());
}

#[test]
fn the_summary_totals_what_it_listed() {
    let tmp = account();
    let summary = storage_summary(list_account_storage(tmp.path(), "a.test", "alice").unwrap());
    assert_eq!(summary.total_size_bytes, 44 + 100 + 3000);
    assert_eq!(
        serde_json::to_value(&summary).unwrap()["totalSizeBytes"],
        3144
    );
}

/// `count` is omitted for files rather than serialised as 0 — a file with "0
/// files inside" reads as a broken directory.
#[test]
fn the_count_appears_only_for_directories() {
    let tmp = account();
    let json =
        serde_json::to_value(list_account_storage(tmp.path(), "a.test", "alice").unwrap()).unwrap();
    assert!(json[0].get("count").is_none(), "a file: {:?}", json[0]);
    assert_eq!(json[2]["count"], 2, "the messages directory");
    assert_eq!(json[0]["type"], "file");
    assert_eq!(json[2]["type"], "dir");
}

// ── the drill-down ────────────────────────────────────────────────────────

#[test]
fn the_drill_down_lists_every_message_file() {
    let tmp = account();
    let files = list_message_files(tmp.path(), "a.test", "alice").unwrap();
    assert_eq!(
        files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        ["msg-1.json", "msg-2.json"],
        "the stray directory is not a file"
    );
    assert_eq!(files[0].size_bytes, 1000);
}

#[test]
fn an_account_with_no_messages_directory_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("a.test/fresh")).unwrap();
    assert!(list_message_files(tmp.path(), "a.test", "fresh").is_err());
}

// ── the export ────────────────────────────────────────────────────────────

/// Every file exactly as it sits on disk, including inside subdirectories —
/// which the one-level listing deliberately does not show. "How your data is
/// stored", literally.
#[test]
fn the_export_carries_every_file_including_nested_ones() {
    let tmp = account();
    let files = export_account_storage(tmp.path(), "a.test", "alice");

    assert_eq!(
        files.keys().collect::<Vec<_>>(),
        [
            "auth_token_hash",
            "devices/KEY.json",
            "mailboxes.json",
            "messages/msg-1.json",
            "messages/msg-2.json",
            "messages/stray/inner.json",
        ],
        "including devices/, which the listing does not report"
    );
    assert_eq!(files["messages/msg-1.json"], vec![b'c'; 1000]);
}

/// Paths use forward slashes regardless of platform: these become JSON keys a
/// client treats as paths.
#[test]
fn export_paths_are_slash_separated_and_relative() {
    let tmp = account();
    for key in export_account_storage(tmp.path(), "a.test", "alice").keys() {
        assert!(!key.contains('\\'), "{key}");
        assert!(!key.starts_with('/'), "{key}");
        assert!(!key.contains("a.test"), "relative to the account: {key}");
    }
}

#[test]
fn exporting_a_missing_account_yields_nothing_rather_than_failing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(export_account_storage(tmp.path(), "a.test", "nobody").is_empty());
}

/// Raw bytes, not text: a message body can hold anything, and an export that
/// mangled non-UTF-8 would not be the data as stored.
#[test]
fn the_export_is_bytes_not_text() {
    let tmp = tempfile::tempdir().unwrap();
    let acct = tmp.path().join("a.test/alice");
    std::fs::create_dir_all(&acct).unwrap();
    let raw = [0u8, 0xff, 0xfe, b'{'];
    std::fs::write(acct.join("blob.bin"), raw).unwrap();
    assert_eq!(
        export_account_storage(tmp.path(), "a.test", "alice")["blob.bin"],
        raw
    );
}

// ── what a purge must not touch ───────────────────────────────────────────

/// The purge clears `messages/` and nothing else. Every name here would either
/// corrupt the account or lock it out permanently — that is what full account
/// deletion is for, and it is a different request with a different name.
///
/// Listed explicitly so that widening the purge means deleting a line that says
/// why it should not be widened.
#[test]
fn the_files_a_purge_must_not_touch_are_the_ones_that_would_lock_the_account_out() {
    for name in [
        "auth_token_hash", // the credential itself
        "envelope.json",   // the wrapped master secret — no other copy exists
        "privkey.enc",     // likewise
        "devices",         // every device credential
        "sessions",        // every live login
        "mailboxes.json",  // the account's only mailbox
        "identities.json",
        "contacts.json",
        "pubkey.pgp",
        "setup.token",
    ] {
        assert!(
            PURGE_MUST_NOT_TOUCH.contains(&name),
            "{name} is missing from the do-not-touch list"
        );
    }
}

/// The account directory, minus `messages/`, is exactly the protected set plus
/// whatever a purge legitimately leaves alone. If a real account grows a file
/// that is not on the list, this fails and asks whether it should be.
#[test]
fn every_top_level_file_a_real_account_has_is_protected() {
    let tmp = account();
    for entry in list_account_storage(tmp.path(), "a.test", "alice").unwrap() {
        if entry.name == "messages" {
            continue;
        }
        assert!(
            PURGE_MUST_NOT_TOUCH.contains(&entry.name.as_str()),
            "{} is not on the do-not-touch list — should a purge delete it?",
            entry.name
        );
    }
}
