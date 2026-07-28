//! Conformance against the Go types' JSON.
//!
//! Every expected string here was produced by running the real
//! `git.sr.ht/~rockorager/go-jmap` types through `encoding/json`, not by
//! reading the struct tags and guessing. These are the bytes that sit in
//! `data/.../messages/*.json` on a live deployment and that biset parses off
//! the wire; a difference here is a difference every client and every stored
//! message sees.

use std::collections::BTreeMap;

use jmap_types::email::{BodyPart, BodyValue, Email};
use jmap_types::mail::Address;
use jmap_types::mailbox::{Mailbox, Rights, Role};
use jmap_types::{Id, JmapTime};
use pretty_assertions::assert_eq;

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialising")
}

/// Go: `json.Marshal(email.Email{})` → `{}`.
///
/// Every field carries `omitempty`, so a zero Email has no representation at
/// all. Miss one `skip_serializing_if` and this catches it.
#[test]
fn zero_email_serialises_to_an_empty_object() {
    assert_eq!(to_json(&Email::default()), "{}");
}

#[test]
fn zero_mailbox_serialises_to_an_empty_object() {
    assert_eq!(to_json(&Mailbox::default()), "{}");
}

/// Captured verbatim from the Go implementation. Exercises, in one string:
/// field order, sorted map keys, a retained `false` map entry, address
/// omitempty, and `isTruncated` being present when nothing else is.
#[test]
fn populated_email_matches_go_byte_for_byte() {
    let mut mailbox_ids = BTreeMap::new();
    // Inserted out of order on purpose — the output must still be sorted.
    mailbox_ids.insert(Id::from("zzz"), true);
    mailbox_ids.insert(Id::from("aaa"), true);
    mailbox_ids.insert(Id::from("mmm"), false);

    let mut body_values = BTreeMap::new();
    body_values.insert("1".to_string(), BodyValue::new("hi"));

    let email = Email {
        id: Id::from("msg-1"),
        mailbox_ids,
        // An empty map is omitted exactly like a nil one.
        keywords: BTreeMap::new(),
        received_at: Some(JmapTime::from_raw("2026-07-27T23:49:16Z")),
        from: vec![
            Address {
                name: "A".into(),
                email: "a@x".into(),
            },
            Address {
                name: String::new(),
                email: "b@x".into(),
            },
        ],
        body_values,
        text_body: vec![BodyPart {
            part_id: "1".into(),
            type_: "text/plain".into(),
            ..Default::default()
        }],
        ..Default::default()
    };

    assert_eq!(
        to_json(&email),
        r#"{"id":"msg-1","mailboxIds":{"aaa":true,"mmm":false,"zzz":true},"receivedAt":"2026-07-27T23:49:16Z","from":[{"name":"A","email":"a@x"},{"email":"b@x"}],"bodyValues":{"1":{"value":"hi","isTruncated":false}},"textBody":[{"partId":"1","type":"text/plain"}]}"#
    );
}

/// Go: an empty map and a nil map both vanish under `omitempty`, so the two
/// are indistinguishable after a round trip. Worth pinning because it is what
/// makes round-tripping lossless in the first place.
#[test]
fn empty_collections_are_omitted_like_nil_ones() {
    let email = Email {
        id: Id::from("x"),
        keywords: BTreeMap::new(),
        mailbox_ids: BTreeMap::new(),
        message_id: vec![],
        ..Default::default()
    };
    assert_eq!(to_json(&email), r#"{"id":"x"}"#);
}

/// The one field in the whole set without `omitempty`.
#[test]
fn is_truncated_is_always_present() {
    assert_eq!(to_json(&BodyValue::default()), r#"{"isTruncated":false}"#);
    assert_eq!(
        to_json(&BodyValue {
            value: "v".into(),
            is_encoding_problem: true,
            is_truncated: true,
        }),
        r#"{"value":"v","isEncodingProblem":true,"isTruncated":true}"#
    );
}

/// The default inbox this relay creates for every account (main.go's
/// `defaultInbox`), as the Go implementation writes it to `mailboxes.json`.
#[test]
fn default_inbox_matches_go() {
    let mb = Mailbox {
        id: Id::from("mbx-alice@example.com"),
        name: "alice@example.com".into(),
        role: Role::from(Role::INBOX),
        rights: Some(Rights {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: true,
        }),
        is_subscribed: true,
        ..Default::default()
    };
    assert_eq!(
        to_json(&vec![mb]),
        r#"[{"id":"mbx-alice@example.com","name":"alice@example.com","role":"inbox","myRights":{"mayReadItems":true,"mayAddItems":true,"mayRemoveItems":true,"maySetSeen":true,"maySetKeywords":true,"maySubmit":true},"isSubscribed":true}]"#
    );
}

/// Unknown fields must be ignored, not rejected: a file written by a newer
/// version has to keep loading. Go's `encoding/json` does this by default.
#[test]
fn unknown_fields_are_ignored() {
    let json = r#"{"id":"msg-1","somethingNewer":{"a":1},"subject":"hi"}"#;
    let email: Email = serde_json::from_str(json).expect("must parse");
    assert_eq!(email.id, Id::from("msg-1"));
    assert_eq!(email.subject, "hi");
}

/// An id is a bare string in Go, so ids this relay actually mints — which
/// contain `@` and `:` and `/`, none of them legal under RFC 8620's id
/// grammar — have to survive.
#[test]
fn ids_are_unrestricted_strings() {
    for raw in [
        "mbx-alice@example.com",
        "msg-https://ap.example/notes/123",
        "thr-group-abc",
    ] {
        let json = format!(r#"{{"id":"{raw}"}}"#);
        let email: Email = serde_json::from_str(&json).unwrap();
        assert_eq!(email.id.as_str(), raw);
        assert_eq!(to_json(&email), json);
    }
}

/// Deserialise then reserialise: the bytes must come back unchanged. This is
/// the property the store depends on, since it reads a message, touches one
/// field, and writes the whole object back.
#[test]
fn round_trips_go_written_json_unchanged() {
    let cases = [
        r#"{"id":"msg-1","mailboxIds":{"aaa":true,"mmm":false,"zzz":true},"receivedAt":"2026-07-27T23:49:16Z","from":[{"name":"A","email":"a@x"},{"email":"b@x"}],"bodyValues":{"1":{"value":"hi","isTruncated":false}},"textBody":[{"partId":"1","type":"text/plain"}]}"#,
        r#"{"id":"x"}"#,
        // A local-offset timestamp: the SMTP receive path uses time.Now()
        // without .UTC(), so these do occur on disk.
        r#"{"id":"y","receivedAt":"2026-07-27T23:49:16.12+09:00"}"#,
        r#"{"id":"z","keywords":{"$draft":false,"$e2e":true,"$seen":true},"size":4096,"hasAttachment":true}"#,
    ];
    for json in cases {
        let email: Email = serde_json::from_str(json).expect("parse");
        assert_eq!(to_json(&email), json, "round trip changed the bytes");
    }
}
