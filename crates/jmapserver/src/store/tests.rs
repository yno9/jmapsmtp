//! Store behaviour.
//!
//! The bytes written to disk are checked here against strings captured from
//! the Go implementation. The end-to-end check that a Go-written `data/`
//! loads and a Rust-written one loads back in Go lives in
//! `tests/store_interop.rs`.

use super::*;
use jmap_types::email::Header;
use pretty_assertions::assert_eq;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn msg(id: &str) -> Email {
    Email {
        id: Id::from(id),
        received_at: Some(JmapTime::from_raw("2026-07-27T23:49:16Z")),
        ..Default::default()
    }
}

// ── delta.json wire format ────────────────────────────────────────────────

/// Captured from the Go implementation. Three things this pins that a reading
/// of the struct would get wrong: the change-record keys are capitalised
/// (the Go struct has no JSON tags), absent slices are `null` rather than
/// `[]` or omitted, and every top-level field is always present.
#[test]
fn persisted_state_matches_go_byte_for_byte() {
    let zero = PersistedState::default();
    assert_eq!(
        serde_json::to_string(&zero).unwrap(),
        r#"{"state":0,"changes":{},"mailboxState":0,"mailboxChanges":{},"submissions":null,"submissionState":0}"#
    );

    let mut changes = BTreeMap::new();
    changes.insert(
        "1".to_string(),
        ChangeRecord {
            added: vec![Id::from("msg-a")],
            ..Default::default()
        },
    );
    changes.insert(
        "2".to_string(),
        ChangeRecord {
            updated: vec![Id::from("msg-a")],
            ..Default::default()
        },
    );
    let mut mailbox_changes = BTreeMap::new();
    mailbox_changes.insert(
        "1".to_string(),
        MailboxChangeRecord {
            created: vec![Id::from("mbx-x")],
            ..Default::default()
        },
    );
    let mut sub = JsonObject::new();
    sub.insert("id".into(), Value::String("sub-1".into()));
    sub.insert("zz".into(), Value::from(1));
    sub.insert("aa".into(), Value::from(2));

    let ps = PersistedState {
        state: 2,
        changes,
        mailbox_state: 1,
        mailbox_changes,
        submissions: vec![sub],
        submission_state: 1,
    };
    assert_eq!(
        serde_json::to_string(&ps).unwrap(),
        r#"{"state":2,"changes":{"1":{"Added":["msg-a"],"Updated":null,"Removed":null},"2":{"Added":null,"Updated":["msg-a"],"Removed":null}},"mailboxState":1,"mailboxChanges":{"1":{"Created":["mbx-x"],"Updated":null,"Destroyed":null}},"submissions":[{"aa":2,"id":"sub-1","zz":1}],"submissionState":1}"#
    );
}

/// Go's zero value for `changes` is a made map, not a nil one, so an empty
/// state file has `{}` there but `null` for the never-populated submissions.
#[test]
fn empty_change_maps_are_objects_but_empty_submissions_are_null() {
    let json = serde_json::to_string(&PersistedState::default()).unwrap();
    assert!(json.contains(r#""changes":{}"#));
    assert!(json.contains(r#""submissions":null"#));
}

// ── state counter ─────────────────────────────────────────────────────────

#[test]
fn only_new_messages_advance_state() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.state(), "0");

    store.put(msg("msg-a")).unwrap();
    assert_eq!(store.state(), "1");

    // Rewriting the same id must not advance it.
    store.put(msg("msg-a")).unwrap();
    assert_eq!(store.state(), "1", "a rewrite is not a new message");

    store.put(msg("msg-b")).unwrap();
    assert_eq!(store.state(), "2");
}

#[test]
fn state_and_messages_survive_a_reopen() {
    let dir = tmp();
    {
        let store = Store::open(dir.path()).unwrap();
        store.put(msg("msg-a")).unwrap();
        store.put(msg("msg-b")).unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.state(), "2", "state must come back from delta.json");
    assert_eq!(store.all().len(), 2);
    assert!(store.get(&Id::from("msg-a")).is_some());
}

#[test]
fn delete_advances_state_and_removes_the_file() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.put(msg("msg-a")).unwrap();
    store.delete(&Id::from("msg-a"));

    assert_eq!(store.state(), "2");
    assert!(store.get(&Id::from("msg-a")).is_none());
    assert!(!dir.path().join("messages/msg-a.json").exists());

    // Deleting again is a no-op, not an error, and does not advance state.
    store.delete(&Id::from("msg-a"));
    assert_eq!(store.state(), "2");
}

#[test]
fn purge_removes_everything_and_bumps_state_once() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.put(msg("msg-a")).unwrap();
    store.put(msg("msg-b")).unwrap();
    assert_eq!(store.state(), "2");

    assert_eq!(store.purge(), 2);
    assert_eq!(store.state(), "3", "one bump for the whole purge");
    assert!(store.all().is_empty());
    assert_eq!(
        std::fs::read_dir(dir.path().join("messages"))
            .unwrap()
            .count(),
        0
    );

    // Purging an empty store changes nothing.
    assert_eq!(store.purge(), 0);
    assert_eq!(store.state(), "3");
}

// ── ordering ──────────────────────────────────────────────────────────────

#[test]
fn all_returns_newest_first() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    for (id, at) in [
        ("msg-old", "2026-07-01T00:00:00Z"),
        ("msg-new", "2026-07-27T00:00:00Z"),
        ("msg-mid", "2026-07-14T00:00:00Z"),
    ] {
        store
            .put(Email {
                id: Id::from(id),
                received_at: Some(JmapTime::from_raw(at)),
                ..Default::default()
            })
            .unwrap();
    }
    let ids: Vec<String> = store.all().into_iter().map(|m| m.id.0).collect();
    assert_eq!(ids, ["msg-new", "msg-mid", "msg-old"]);
}

#[test]
fn a_message_without_a_timestamp_sorts_last() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store
        .put(Email {
            id: Id::from("msg-none"),
            ..Default::default()
        })
        .unwrap();
    store.put(msg("msg-dated")).unwrap();
    let ids: Vec<String> = store.all().into_iter().map(|m| m.id.0).collect();
    assert_eq!(ids, ["msg-dated", "msg-none"]);
}

// ── threading ─────────────────────────────────────────────────────────────

#[test]
fn a_group_id_header_wins_outright() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut m = msg("msg-a");
    m.headers = vec![Header {
        name: "Chat-Group-Id".into(),
        value: "grp1".into(),
    }];
    // An In-Reply-To that would otherwise be walked must be ignored.
    m.in_reply_to = vec!["<parent@x>".into()];
    store.put(m).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-a")).unwrap().thread_id,
        Id::from("thr-group-grp1")
    );
}

#[test]
fn group_id_header_name_is_matched_case_insensitively() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut m = msg("msg-a");
    m.headers = vec![Header {
        name: "chat-group-id".into(),
        value: "grp1".into(),
    }];
    store.put(m).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-a")).unwrap().thread_id,
        Id::from("thr-group-grp1")
    );
}

#[test]
fn a_reply_joins_its_parents_thread() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();

    let mut parent = msg("msg-parent");
    parent.message_id = vec!["parent@x".into()];
    store.put(parent).unwrap();
    let parent_thread = store.get(&Id::from("msg-parent")).unwrap().thread_id;
    assert_eq!(parent_thread, Id::from("thr-parent@x"));

    let mut reply = msg("msg-reply");
    reply.message_id = vec!["reply@x".into()];
    // Angle brackets must be stripped before matching.
    reply.in_reply_to = vec!["<parent@x>".into()];
    store.put(reply).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-reply")).unwrap().thread_id,
        parent_thread
    );
}

#[test]
fn references_are_walked_when_in_reply_to_misses() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut parent = msg("msg-parent");
    parent.message_id = vec!["<parent@x>".into()];
    store.put(parent).unwrap();

    // A fresh thread id embeds the Message-ID *verbatim*, brackets and all —
    // only the lookup index strips them. Asymmetric, and preserved as is.
    let parent_thread = store.get(&Id::from("msg-parent")).unwrap().thread_id;
    assert_eq!(parent_thread, Id::from("thr-<parent@x>"));

    let mut reply = msg("msg-reply");
    reply.in_reply_to = vec!["unknown@x".into()];
    // Unbracketed here, bracketed on the parent: the index normalises both,
    // which is the whole point of stripping.
    reply.references = vec!["parent@x".into()];
    store.put(reply).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-reply")).unwrap().thread_id,
        parent_thread
    );
}

#[test]
fn an_orphan_starts_its_own_thread() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut m = msg("msg-a");
    m.message_id = vec!["a@x".into()];
    m.in_reply_to = vec!["nobody@x".into()];
    store.put(m).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-a")).unwrap().thread_id,
        Id::from("thr-a@x")
    );
}

#[test]
fn without_a_message_id_the_thread_falls_back_to_the_object_id() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.put(msg("msg-a")).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-a")).unwrap().thread_id,
        Id::from("thr-msg-a")
    );
}

#[test]
fn an_explicit_thread_id_is_left_alone() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut m = msg("msg-a");
    m.thread_id = Id::from("thr-preset");
    m.message_id = vec!["a@x".into()];
    store.put(m).unwrap();
    assert_eq!(
        store.get(&Id::from("msg-a")).unwrap().thread_id,
        Id::from("thr-preset")
    );
}

// ── patching ──────────────────────────────────────────────────────────────

#[test]
fn patch_email_sets_and_clears_keywords_and_mailboxes() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut m = msg("msg-a");
    m.keywords.insert("$draft".into(), true);
    m.mailbox_ids.insert(Id::from("mbx-old"), true);
    store.put(m).unwrap();

    let mut patch = JsonObject::new();
    patch.insert("keywords/$seen".into(), Value::Bool(true));
    patch.insert("keywords/$draft".into(), Value::Null);
    patch.insert("mailboxIds/mbx-new".into(), Value::Bool(true));
    patch.insert("mailboxIds/mbx-old".into(), Value::Null);
    patch.insert("subject".into(), Value::String("ignored".into()));
    store.patch_email(&Id::from("msg-a"), &patch).unwrap();

    let got = store.get(&Id::from("msg-a")).unwrap();
    assert_eq!(got.keywords.get("$seen"), Some(&true));
    assert!(!got.keywords.contains_key("$draft"), "null must remove");
    assert_eq!(got.mailbox_ids.get(&Id::from("mbx-new")), Some(&true));
    assert!(!got.mailbox_ids.contains_key(&Id::from("mbx-old")));
    assert_eq!(got.subject, "", "a non-patch key must be ignored");
}

/// The Go original's keywords-only path handles a bool and nothing else — a
/// null does not remove there, unlike in PatchEmail.
#[test]
fn patch_keywords_ignores_null_and_mailbox_keys() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut m = msg("msg-a");
    m.keywords.insert("$draft".into(), true);
    store.put(m).unwrap();

    let mut patch = JsonObject::new();
    patch.insert("keywords/$draft".into(), Value::Null);
    patch.insert("mailboxIds/mbx-new".into(), Value::Bool(true));
    store.patch_keywords(&Id::from("msg-a"), &patch).unwrap();

    let got = store.get(&Id::from("msg-a")).unwrap();
    assert_eq!(
        got.keywords.get("$draft"),
        Some(&true),
        "null is ignored on the keywords-only path"
    );
    assert!(
        got.mailbox_ids.is_empty(),
        "mailboxIds are not touched here"
    );
}

#[test]
fn patching_an_unknown_message_is_a_no_op() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let mut patch = JsonObject::new();
    patch.insert("keywords/$seen".into(), Value::Bool(true));
    store.patch_email(&Id::from("nope"), &patch).unwrap();
    assert_eq!(store.state(), "0", "no state bump for a missing message");
}

#[test]
fn a_patch_advances_state_and_persists() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.put(msg("msg-a")).unwrap();
    let mut patch = JsonObject::new();
    patch.insert("keywords/$seen".into(), Value::Bool(true));
    store.patch_email(&Id::from("msg-a"), &patch).unwrap();
    assert_eq!(store.state(), "2");

    let reopened = Store::open(dir.path()).unwrap();
    assert_eq!(
        reopened
            .get(&Id::from("msg-a"))
            .unwrap()
            .keywords
            .get("$seen"),
        Some(&true)
    );
}

// ── pending ───────────────────────────────────────────────────────────────

#[test]
fn pending_drafts_are_memory_only() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.put_pending(msg("msg-draft"));

    assert!(store.get(&Id::from("msg-draft")).is_some(), "get sees it");
    assert!(store.all().is_empty(), "all does not");
    assert!(!dir.path().join("messages/msg-draft.json").exists());

    assert!(store.take_pending(&Id::from("msg-draft")).is_some());
    assert!(store.take_pending(&Id::from("msg-draft")).is_none());
}

// ── mailboxes ─────────────────────────────────────────────────────────────

fn mbox(id: &str) -> Mailbox {
    Mailbox {
        id: Id::from(id),
        name: id.into(),
        ..Default::default()
    }
}

#[test]
fn put_mailboxes_does_not_bump_state() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.put_mailboxes(&[mbox("mbx-a")]).unwrap();
    assert_eq!(store.mailbox_state(), "0");
    assert_eq!(store.mailboxes().len(), 1);
}

#[test]
fn sync_mailboxes_is_idempotent_and_bumps_only_on_change() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();

    store.sync_mailboxes(&[mbox("mbx-a")]).unwrap();
    assert_eq!(store.mailbox_state(), "1");

    store.sync_mailboxes(&[mbox("mbx-a")]).unwrap();
    assert_eq!(store.mailbox_state(), "1", "same id set is a no-op");

    store
        .sync_mailboxes(&[mbox("mbx-a"), mbox("mbx-b")])
        .unwrap();
    assert_eq!(store.mailbox_state(), "2");

    let changes = store.mailbox_changes();
    assert_eq!(changes[&2].created, vec![Id::from("mbx-b")]);
    assert!(changes[&2].destroyed.is_empty());

    store.sync_mailboxes(&[mbox("mbx-b")]).unwrap();
    assert_eq!(
        store.mailbox_changes()[&3].destroyed,
        vec![Id::from("mbx-a")]
    );
}

#[test]
fn a_missing_mailbox_file_reads_as_empty() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    assert!(store.mailboxes().is_empty());
}

// ── blobs and submissions ─────────────────────────────────────────────────

#[test]
fn blob_ids_are_content_addressed() {
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    let a = store.put_blob(b"hello");
    let b = store.put_blob(b"hello");
    assert_eq!(a, b, "same bytes, same id");
    assert_eq!(
        a, "blob-2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "sha256 of \"hello\", hex, behind a blob- prefix"
    );
    assert_eq!(store.get_blob(&a).unwrap(), b"hello");
    assert!(store.get_blob("blob-nope").is_none());
}

#[test]
fn submissions_accumulate_and_persist() {
    let dir = tmp();
    {
        let store = Store::open(dir.path()).unwrap();
        let mut sub = JsonObject::new();
        sub.insert("id".into(), Value::String("sub-1".into()));
        store.add_submission(sub);
        assert_eq!(store.submission_state(), "1");
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.submissions().len(), 1);
    assert_eq!(store.submission_state(), "1");
}

// ── filenames ─────────────────────────────────────────────────────────────

#[test]
fn safe_filename_replaces_every_character_go_does() {
    assert_eq!(safe_filename("plain-id"), "plain-id");
    assert_eq!(
        safe_filename(r#"a/b\c:d*e?f"g<h>i|j"#),
        "a-b-c-d-e-f-g-h-i-j"
    );
    // `@` and `.` are left alone; the relay mints ids full of both.
    assert_eq!(
        safe_filename("mbx-alice@example.com"),
        "mbx-alice@example.com"
    );
    assert_eq!(
        safe_filename("msg-https://ap.example/notes/1"),
        "msg-https---ap.example-notes-1"
    );
}

#[test]
fn safe_filename_truncates_at_200() {
    let long = "x".repeat(300);
    assert_eq!(safe_filename(&long).len(), 200);
}

/// Documenting the hazard rather than fixing it: the replacement is
/// many-to-one, so distinct ids can share a file. Preserved deliberately —
/// see the note on `safe_filename` and SPEC.md §11.6.
#[test]
fn safe_filename_collisions_are_a_known_hazard() {
    assert_eq!(safe_filename("a/b"), safe_filename("a:b"));
}

// ── resilience ────────────────────────────────────────────────────────────

#[test]
fn a_corrupt_message_file_is_skipped_not_fatal() {
    let dir = tmp();
    {
        let store = Store::open(dir.path()).unwrap();
        store.put(msg("msg-good")).unwrap();
    }
    std::fs::write(dir.path().join("messages/broken.json"), b"{not json").unwrap();
    // Valid JSON, but no id — Go drops these too.
    std::fs::write(dir.path().join("messages/noid.json"), br#"{"subject":"x"}"#).unwrap();
    std::fs::write(dir.path().join("messages/ignored.txt"), b"not json at all").unwrap();

    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.all().len(), 1);
    assert!(store.get(&Id::from("msg-good")).is_some());
}

#[test]
fn a_corrupt_delta_file_resets_state_rather_than_failing() {
    let dir = tmp();
    {
        let store = Store::open(dir.path()).unwrap();
        store.put(msg("msg-a")).unwrap();
    }
    std::fs::write(dir.path().join("delta.json"), b"{not json").unwrap();

    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.state(), "0", "state resets");
    assert_eq!(store.all().len(), 1, "messages still load");
}

// ── identities ────────────────────────────────────────────────────────────

#[test]
fn default_identity_matches_go() {
    let id = Store::default_identity("alice@example.com");
    assert_eq!(
        serde_json::to_string(&id).unwrap(),
        r#"{"bcc":null,"email":"alice@example.com","htmlSignature":"","id":"identity-alice@example.com","mayDelete":false,"name":"alice","replyTo":null,"textSignature":""}"#
    );
}

#[test]
fn default_identity_without_an_at_uses_the_whole_string_as_the_name() {
    let id = Store::default_identity("alice");
    assert_eq!(id["name"], Value::String("alice".into()));
}

#[test]
fn identities_persist() {
    let dir = tmp();
    let mut one = JsonObject::new();
    one.insert("id".into(), Value::String("identity-x".into()));
    {
        let store = Store::open(dir.path()).unwrap();
        store.set_identities(vec![one.clone()]);
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.identities(), vec![one]);
}
