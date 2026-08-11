//! Go ↔ Rust `data/` interoperability — M3's acceptance criterion.
//!
//! The unit tests show the Rust store is self-consistent. What has to hold
//! for a binary swap is stronger and needs both implementations running: a
//! directory written by Go must load in Rust and vice versa, with the same
//! messages, the same threads, the same counters.
//!
//! Rollback matters as much as migration. If the Go build cannot read what
//! Rust wrote, a deployment that reverts loses everything received in
//! between, which is worse than never having switched.
//!
//! The helper is built by `just interop`. As in the cryptenv interop tests, a
//! missing helper skips quietly for a machine without Go, but
//! `STORE_INTEROP=required` — set by `just test` — turns that into an error,
//! so the normal workflow can never report a pass for a test that ran nothing.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use jmap_types::email::{Email, Header};
use jmap_types::mailbox::{Mailbox, Role};
use jmap_types::{Id, JmapTime};
use jmapserver::{JsonObject, Store};
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What both implementations report about a directory. Deliberately a
/// projection rather than the whole Email: these are the fields the *store*
/// owns, so a mismatch here is a store bug, not a serialisation one — the
/// jmap-types tests already cover the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Dump {
    state: String,
    mailbox_state: String,
    submission_state: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    messages: Vec<DumpMessage>,
    #[serde(default, deserialize_with = "null_as_empty")]
    mailboxes: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    submissions: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    identities: Vec<String>,
}

/// The vectors go through `null_as_empty` because Go marshals a nil slice as
/// an explicit `null`, and `serde(default)` only fires for an *absent* field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DumpMessage {
    id: String,
    thread_id: String,
    subject: String,
    received_at: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    keywords: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    mailbox_ids: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    message_id: Vec<String>,
}

/// Accept `null` as an empty vector — a nil Go slice.
fn null_as_empty<'de, T, D>(d: D) -> Result<Vec<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/store-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("STORE_INTEROP").is_none(),
        "STORE_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go store interop helper not built — run `just interop`. Set \
         STORE_INTEROP=required to make this an error instead."
    );
    None
}

fn go(bin: &PathBuf, cmd: &str, dir: &std::path::Path) -> String {
    let out = Command::new(bin)
        .args([cmd, dir.to_str().expect("utf-8 path")])
        .output()
        .expect("running the Go helper");
    assert!(
        out.status.success(),
        "go {cmd} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 output")
}

/// The Rust equivalent of the helper's `dump`.
fn rust_dump(dir: &std::path::Path) -> Dump {
    let store = Store::open(dir).expect("opening the store");
    let messages = store
        .all()
        .into_iter()
        .map(|m| DumpMessage {
            id: m.id.0,
            thread_id: m.thread_id.0,
            subject: m.subject,
            received_at: m
                .received_at
                .map(|t| t.as_str().to_string())
                .unwrap_or_default(),
            keywords: sorted_true(m.keywords.into_iter()),
            mailbox_ids: sorted_true(m.mailbox_ids.into_iter().map(|(k, v)| (k.0, v))),
            message_id: m.message_id,
        })
        .collect();
    Dump {
        state: store.state(),
        mailbox_state: store.mailbox_state(),
        submission_state: store.submission_state(),
        messages,
        mailboxes: store.mailboxes().into_iter().map(|mb| mb.id.0).collect(),
        submissions: store
            .submissions()
            .iter()
            .map(|s| jmap_types::go_json::to_string(s).expect("submission json"))
            .collect(),
        identities: store
            .identities()
            .iter()
            .map(|s| jmap_types::go_json::to_string(s).expect("identity json"))
            .collect(),
    }
}

fn sorted_true(entries: impl Iterator<Item = (String, bool)>) -> Vec<String> {
    let mut v: Vec<String> = entries.filter(|(_, on)| *on).map(|(k, _)| k).collect();
    v.sort();
    v
}

/// The same corpus the Go helper's `seed` writes, so each side can produce a
/// directory the other reads. Exercises threading by reply chain, threading
/// by group header, a message with no timestamp, an id needing filename
/// escaping, a local-offset timestamp, keywords and mailbox membership.
fn seed_with_rust(dir: &std::path::Path) {
    let store = Store::open(dir).expect("opening the store");

    let mut parent = Email {
        id: Id::from("msg-parent"),
        message_id: vec!["parent@x".into()],
        subject: "parent".into(),
        received_at: Some(JmapTime::from_raw("2026-07-01T00:00:00Z")),
        from: vec![jmap_types::mail::Address {
            name: "A".into(),
            email: "a@x".into(),
        }],
        ..Default::default()
    };
    parent.mailbox_ids.insert(Id::from("mbx-inbox"), true);
    parent.keywords.insert("$seen".into(), true);
    store.put(parent).unwrap();

    let mut reply = Email {
        id: Id::from("msg-reply"),
        message_id: vec!["reply@x".into()],
        in_reply_to: vec!["<parent@x>".into()],
        subject: "reply".into(),
        received_at: Some(JmapTime::from_raw("2026-07-02T00:00:00Z")),
        ..Default::default()
    };
    reply.mailbox_ids.insert(Id::from("mbx-inbox"), true);
    store.put(reply).unwrap();

    store
        .put(Email {
            id: Id::from("msg-group"),
            message_id: vec!["group@x".into()],
            in_reply_to: vec!["<parent@x>".into()],
            headers: vec![Header {
                name: "Chat-Group-Id".into(),
                value: "grp1".into(),
            }],
            subject: "group".into(),
            received_at: Some(JmapTime::from_raw("2026-07-03T00:00:00Z")),
            ..Default::default()
        })
        .unwrap();

    store
        .put(Email {
            id: Id::from("msg-undated"),
            message_id: vec!["undated@x".into()],
            subject: "undated".into(),
            ..Default::default()
        })
        .unwrap();

    store
        .put(Email {
            id: Id::from(r#"msg-a/b\c:d*e?f"g<h>i|j"#),
            subject: "escaped".into(),
            received_at: Some(JmapTime::from_raw("2026-07-04T12:00:00+09:00")),
            ..Default::default()
        })
        .unwrap();

    let mut patch = JsonObject::new();
    patch.insert("keywords/$flagged".into(), Value::Bool(true));
    patch.insert("mailboxIds/mbx-archive".into(), Value::Bool(true));
    store.patch_email(&Id::from("msg-parent"), &patch).unwrap();

    store
        .sync_mailboxes(&[
            Mailbox {
                id: Id::from("mbx-inbox"),
                name: "Inbox".into(),
                role: Role::from(Role::INBOX),
                is_subscribed: true,
                ..Default::default()
            },
            Mailbox {
                id: Id::from("mbx-archive"),
                name: "Archive".into(),
                role: Role::from(Role::ARCHIVE),
                ..Default::default()
            },
        ])
        .unwrap();

    let mut sub = JsonObject::new();
    sub.insert("id".into(), Value::String("sub-1".into()));
    sub.insert("emailId".into(), Value::String("msg-parent".into()));
    store.add_submission(sub);
}

/// **The migration direction.** Every `data/` in production was written by Go.
#[test]
fn rust_reads_a_go_written_store() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();

    go(&bin, "seed", dir.path());
    let from_go: Dump = serde_json::from_str(&go(&bin, "dump", dir.path())).unwrap();
    let from_rust = rust_dump(dir.path());

    assert_eq!(
        from_rust, from_go,
        "Rust read a Go-written store differently"
    );
}

/// **The rollback direction.** A deployment that reverts must not lose the
/// messages it received while running the Rust build.
#[test]
fn go_reads_a_rust_written_store() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();

    seed_with_rust(dir.path());
    let from_rust = rust_dump(dir.path());
    let from_go: Dump = serde_json::from_str(&go(&bin, "dump", dir.path())).unwrap();

    assert_eq!(
        from_go, from_rust,
        "Go read a Rust-written store differently"
    );
}

/// Both implementations, given the same inputs, must produce the same
/// directory — not merely directories each can read. This is what makes the
/// difftest `data/` comparison meaningful once the relay itself is ported.
#[test]
fn both_implementations_produce_the_same_directory() {
    let Some(bin) = require_helper() else { return };
    let go_dir = tempfile::tempdir().unwrap();
    let rust_dir = tempfile::tempdir().unwrap();

    go(&bin, "seed", go_dir.path());
    seed_with_rust(rust_dir.path());

    assert_eq!(
        tree(go_dir.path()),
        tree(rust_dir.path()),
        "the two implementations wrote different files"
    );
}

/// Every file under `dir`, by relative path, with its contents.
///
/// `delta.json` is normalised first: the change-record arrays are built by
/// ranging over a Go map, so their order is whatever that run's hash seed
/// produced. Two Go runs disagree with each other there, which makes a
/// byte-for-byte comparison of that one file meaningless. Sorting the arrays
/// compares what the records actually are — sets of ids — and leaves every
/// other byte, including the counters and the escaping, strictly compared.
fn tree(dir: &std::path::Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            let content = if rel == "delta.json" {
                sort_delta_arrays(&content)
            } else {
                content
            };
            out.insert(rel, content);
        }
    }
    out
}

/// Sort every array inside a `delta.json` so map-iteration order stops
/// mattering. Returns the input unchanged if it does not parse.
fn sort_delta_arrays(json: &str) -> String {
    fn walk(v: &mut Value) {
        match v {
            Value::Array(items) => {
                for i in items.iter_mut() {
                    walk(i);
                }
                items.sort_by_key(|i| i.to_string());
            }
            Value::Object(map) => {
                for (_, i) in map.iter_mut() {
                    walk(i);
                }
            }
            _ => {}
        }
    }
    match serde_json::from_str::<Value>(json) {
        Ok(mut v) => {
            walk(&mut v);
            serde_json::to_string(&v).unwrap_or_else(|_| json.to_string())
        }
        Err(_) => json.to_string(),
    }
}

/// A round trip through both: Go writes, Rust modifies, Go reads the result.
/// Catches a divergence that only shows up once one implementation edits what
/// the other created, which neither one-way test would.
#[test]
fn a_rust_write_on_top_of_a_go_store_stays_readable() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();
    go(&bin, "seed", dir.path());

    {
        let store = Store::open(dir.path()).unwrap();
        store
            .put(Email {
                id: Id::from("msg-added-by-rust"),
                message_id: vec!["added@x".into()],
                in_reply_to: vec!["<parent@x>".into()],
                subject: "added".into(),
                received_at: Some(JmapTime::from_raw("2026-07-05T00:00:00Z")),
                ..Default::default()
            })
            .unwrap();
    }

    let from_go: Dump = serde_json::from_str(&go(&bin, "dump", dir.path())).unwrap();
    let added = from_go
        .messages
        .iter()
        .find(|m| m.id == "msg-added-by-rust")
        .expect("Go must see the message Rust added");
    assert_eq!(
        added.thread_id, "thr-parent@x",
        "the message Rust added must have joined the thread Go created"
    );
    assert_eq!(
        from_go.state, "7",
        "state must have advanced by exactly one"
    );
    assert_eq!(from_go, rust_dump(dir.path()));
}
