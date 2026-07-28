//! Go ↔ Rust `Dispatch` interoperability — M4's acceptance criterion.
//!
//! Both implementations seed the same store, run the same script of JMAP
//! method calls through their own `Dispatch`, and must produce the same
//! results. This is the strongest check available without the application
//! layer: it compares the actual JSON every method returns, against the real
//! Go handlers rather than against a reading of them.
//!
//! What it does *not* cover is the HTTP surface — routing, CORS, the Session
//! object, the event source. Those need the jmapsmtp binary, and arrive with
//! it; see PLAN.md M4/M6.
//!
//! `DISPATCH_INTEROP=required` — set by `just test` — turns a missing helper
//! into an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use jmap_types::Id;
use jmap_types::email::Email;
use jmap_types::emailsubmission::Envelope;
use jmapserver::{Hooks, Store};
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// One call in the script. Kept as `{method, args}` rather than the JMAP
/// triple because the call id plays no part below `Dispatch`.
#[derive(Serialize)]
struct Call {
    method: &'static str,
    args: Value,
    /// Set when the two implementations are *expected* to disagree, naming
    /// the SPEC.md §11 entry that says why.
    ///
    /// A declared divergence is checked as strictly as an agreement: the
    /// results must actually differ. One that quietly stopped diverging means
    /// the fix was lost in a refactor, and silence there would be worse than
    /// the original bug.
    #[serde(skip)]
    divergence: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Outcome {
    method: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<String>,
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
        std::env::var_os("DISPATCH_INTEROP").is_none(),
        "DISPATCH_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go dispatch interop helper not built — run `just interop`. \
         Set DISPATCH_INTEROP=required to make this an error instead."
    );
    None
}

/// The timestamp `EmailSubmission/set` stamps into its records. Go reads the
/// clock; Rust takes it as a parameter, so the two can never agree and it is
/// normalised away instead.
const NOW: &str = "<NOW>";

/// The response fields JMAP defines as sets (RFC 8620 §5.2). The Go
/// implementation builds each by ranging over a map, so their order is
/// whatever that run's hash seed produced — two Go runs disagree with each
/// other. Sorting compares what the field means rather than how it happened
/// to come out. See SPEC.md §11.5.
const SET_VALUED: &[&str] = &["created", "updated", "destroyed", "removed"];

/// Replace anything the two implementations cannot agree on: the submission
/// timestamp, the id built from it, and the ordering of set-valued fields.
fn normalise(v: &Value) -> Value {
    match v {
        // sub-<key>-<RFC3339>, and the bare sendAt timestamp.
        Value::String(s) => Value::String(rewrite_timestamps(s)),
        Value::Array(a) => Value::Array(a.iter().map(normalise).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let v = normalise(v);
                    let v = match (k.as_str(), &v) {
                        // `created` and friends are arrays in */changes and
                        // objects in */set; only the arrays are sets.
                        (k, Value::Array(_)) if SET_VALUED.contains(&k) => sorted(v),
                        // queryChanges' `added` carries an index assigned by
                        // the same map iteration, so it is renumbered too.
                        ("added", Value::Array(_)) => renumber(sorted(v)),
                        _ => v,
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn sorted(v: Value) -> Value {
    let Value::Array(mut items) = v else { return v };
    items.sort_by_key(|i| {
        // For `added` the meaningful key is the id, not the whole object,
        // whose index is exactly what differs.
        i.get("id")
            .and_then(Value::as_str)
            .map_or_else(|| i.to_string(), str::to_string)
    });
    Value::Array(items)
}

fn renumber(v: Value) -> Value {
    let Value::Array(items) = v else { return v };
    Value::Array(
        items
            .into_iter()
            .enumerate()
            .map(|(i, mut item)| {
                if let Some(o) = item.as_object_mut()
                    && o.contains_key("index")
                {
                    o.insert("index".into(), Value::from(i));
                }
                item
            })
            .collect(),
    )
}

/// Rewrite every RFC 3339 timestamp in `s` to `<NOW>`. Hand-rolled rather
/// than pulled from a regex crate: the shape is fixed and this keeps the test
/// dependency-free.
fn rewrite_timestamps(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if looks_like_timestamp(&bytes[i..]) {
            out.push_str(NOW);
            i += timestamp_len(&bytes[i..]);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn looks_like_timestamp(b: &[u8]) -> bool {
    b.len() >= 20
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
}

fn timestamp_len(b: &[u8]) -> usize {
    let mut n = 19; // yyyy-mm-ddThh:mm:ss
    if b.len() > n && b[n] == b'.' {
        n += 1;
        while n < b.len() && b[n].is_ascii_digit() {
            n += 1;
        }
    }
    if n < b.len() && b[n] == b'Z' {
        return n + 1;
    }
    if n < b.len() && (b[n] == b'+' || b[n] == b'-') && b.len() >= n + 6 {
        return n + 6;
    }
    n
}

fn call(method: &'static str, args: Value) -> Call {
    Call {
        method,
        args,
        divergence: None,
    }
}

/// A call whose result is expected to differ, naming the SPEC.md §11 entry.
fn diverging(method: &'static str, args: Value, why: &'static str) -> Call {
    Call {
        method,
        args,
        divergence: Some(why),
    }
}

/// The script both sides run. Ordered so the reads happen against a known
/// seeded state before anything mutates it.
fn script() -> Vec<Call> {
    let acct = "alice@example.com";
    vec![
        // ── reads over the seeded corpus ──────────────────────────────────
        call("Mailbox/get", json!({"accountId": acct})),
        call("Mailbox/query", json!({"accountId": acct})),
        call(
            "Mailbox/query",
            json!({"accountId": acct, "filter": {"role": "inbox"}}),
        ),
        call(
            "Mailbox/query",
            json!({"accountId": acct, "filter": {"name": "ARCH"}}),
        ),
        call(
            "Mailbox/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        call(
            "Mailbox/changes",
            json!({"accountId": acct, "sinceState": "99"}),
        ),
        call(
            "Mailbox/changes",
            json!({"accountId": acct, "sinceState": "bogus"}),
        ),
        call(
            "Mailbox/queryChanges",
            json!({"accountId": acct, "sinceQueryState": "0"}),
        ),
        call("Email/query", json!({"accountId": acct})),
        call(
            "Email/query",
            json!({"accountId": acct, "filter": {"inMailbox": "mbx-inbox"}}),
        ),
        call(
            "Email/query",
            json!({"accountId": acct, "filter": {"text": "REPLY"}}),
        ),
        call(
            "Email/query",
            json!({"accountId": acct, "filter": {"text": "a@x"}}),
        ),
        call(
            "Email/query",
            json!({"accountId": acct, "position": 1, "limit": 2}),
        ),
        call("Email/query", json!({"accountId": acct, "position": 99})),
        call(
            "Email/get",
            json!({"accountId": acct, "ids": ["msg-parent", "nope"]}),
        ),
        call("Email/get", json!({"accountId": acct, "ids": []})),
        call(
            "Email/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        call(
            "Email/changes",
            json!({"accountId": acct, "sinceState": "3"}),
        ),
        call(
            "Email/queryChanges",
            json!({"accountId": acct, "sinceQueryState": "0"}),
        ),
        call(
            "Thread/get",
            json!({"accountId": acct, "ids": ["thr-parent@x", "thr-group-grp1", "nope"]}),
        ),
        call(
            "Thread/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        call("Identity/get", json!({"accountId": acct})),
        call(
            "Identity/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        call("EmailSubmission/get", json!({"accountId": acct})),
        call("EmailSubmission/query", json!({"accountId": acct})),
        call(
            "EmailSubmission/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        call(
            "EmailSubmission/queryChanges",
            json!({"accountId": acct, "sinceQueryState": "0"}),
        ),
        call("VacationResponse/get", json!({"accountId": acct})),
        call(
            "SearchSnippet/get",
            json!({"accountId": acct, "emailIds": ["msg-parent", "nope"], "filter": {"text": "parent"}}),
        ),
        call(
            "SearchSnippet/get",
            json!({"accountId": acct, "emailIds": ["msg-parent"]}),
        ),
        call("Nonexistent/get", json!({"accountId": acct})),
        // ── writes, then reads that must observe them ─────────────────────
        call(
            "Email/set",
            json!({
                "accountId": acct,
                "create": {"draft1": {"subject": "a draft", "keywords": {"$draft": true}}},
            }),
        ),
        call(
            "Email/set",
            json!({
                "accountId": acct,
                "update": {"msg-parent": {"keywords/$seen": null, "keywords/$answered": true}},
            }),
        ),
        call(
            "Email/set",
            json!({"accountId": acct, "update": {"nope": {"keywords/$seen": true}}}),
        ),
        call(
            "Email/get",
            json!({"accountId": acct, "ids": ["msg-parent"]}),
        ),
        call(
            "EmailSubmission/set",
            json!({
                "accountId": acct,
                "create": {"s1": {"emailId": "msg-created", "envelope": {"mailFrom": {"email": "a@x"}, "rcptTo": [{"email": "b@y"}]}}},
            }),
        ),
        call(
            "EmailSubmission/set",
            json!({"accountId": acct, "create": {"s2": {"emailId": "nope"}}}),
        ),
        call("EmailSubmission/get", json!({"accountId": acct})),
        // An update on its own: both implementations rename correctly.
        call(
            "Mailbox/set",
            json!({
                "accountId": acct,
                "update": {"mbx-inbox": {"name": "RenamedAlone"}},
            }),
        ),
        call("Mailbox/get", json!({"accountId": acct})),
        // A create and an update in the same call. The Go implementation
        // silently discards the rename here while reporting it as updated —
        // see SPEC.md §11.7. Its own response is identical on both sides; the
        // difference only shows in the Mailbox/get that follows.
        call(
            "Mailbox/set",
            json!({
                "accountId": acct,
                "create": {"m1": {"name": "New"}},
                "update": {"mbx-inbox": {"name": "RenamedTogether"}},
                "destroy": ["mbx-archive", "nope"],
            }),
        ),
        diverging(
            "Mailbox/get",
            json!({"accountId": acct}),
            "§11.7 Mailbox/set drops an update made alongside a create",
        ),
        call(
            "Mailbox/changes",
            json!({"accountId": acct, "sinceState": "1"}),
        ),
        call(
            "Identity/set",
            json!({
                "accountId": acct,
                "update": {"identity-alice@example.com": {"name": "Alice A"}},
            }),
        ),
        call("Identity/get", json!({"accountId": acct})),
        call(
            "VacationResponse/set",
            json!({
                "accountId": acct,
                "update": {"singleton": {"isEnabled": true, "subject": "away"}},
            }),
        ),
        call("VacationResponse/get", json!({"accountId": acct})),
        call(
            "Email/set",
            json!({"accountId": acct, "destroy": ["msg-undated"]}),
        ),
        call("Email/query", json!({"accountId": acct})),
        call(
            "Email/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        // Email/copy comes last on purpose. A copy inherits its source's
        // receivedAt, so the two tie in Email/query's ordering — and Go's
        // sort.Slice is not stable, over input that arrives in map order, so
        // which of the pair comes first is unspecified there. Nothing queries
        // after this point, so the tie is never observed. The copy is still
        // checked, by id, where order plays no part.
        call(
            "Email/copy",
            json!({
                "accountId": acct,
                "create": {"c1": {"id": "msg-parent", "mailboxIds": {"mbx-inbox": true}}},
            }),
        ),
        call(
            "Email/copy",
            json!({"accountId": acct, "create": {"c2": {"id": "nope"}}}),
        ),
        call(
            "Email/get",
            json!({"accountId": acct, "ids": ["msg-parent-cp-c1"]}),
        ),
    ]
}

fn go_dispatch(bin: &PathBuf, dir: &std::path::Path) -> Vec<Outcome> {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .args(["dispatch", dir.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    let body = serde_json::to_vec(&script()).unwrap();
    child.stdin.as_mut().unwrap().write_all(&body).unwrap();
    let out = child.wait_with_output().expect("waiting for the Go helper");
    assert!(
        out.status.success(),
        "go dispatch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go dispatch output")
}

/// Seed exactly as the Go helper's `seed` does, then run the script through
/// the Rust dispatcher with the same hooks installed.
fn rust_dispatch(dir: &std::path::Path) -> Vec<Outcome> {
    seed(dir);
    let store = std::sync::Arc::new(Store::open(dir).expect("opening the store"));

    let for_hook = store.clone();
    store.set_hooks(Hooks {
        create_email: Some(std::sync::Arc::new(move |raw| {
            let mut m: Email = serde_json::from_str(raw.get()).map_err(|e| e.to_string())?;
            m.id = Id::from("msg-created");
            for_hook.put_pending(m.clone());
            Ok(m)
        })),
        submit_email: Some(std::sync::Arc::new(|_: Email, _: Envelope| Ok(()))),
        ..Default::default()
    });

    let acct = Id::from("alice@example.com");
    script()
        .into_iter()
        .map(|c| match store.dispatch(&acct, c.method, &c.args, NOW) {
            Ok(result) => Outcome {
                method: c.method.to_string(),
                result: Some(result),
                error: None,
            },
            Err(e) => Outcome {
                method: c.method.to_string(),
                result: None,
                error: Some(e.to_string()),
            },
        })
        .collect()
}

/// The Go helper's `seed`, in Rust. Kept in step with it by hand; the store
/// interop tests already prove the two produce identical directories.
fn seed(dir: &std::path::Path) {
    use jmap_types::JmapTime;
    use jmap_types::email::Header;
    use jmap_types::mail::Address;
    use jmap_types::mailbox::{Mailbox, Role};
    use jmapserver::JsonObject;

    let store = Store::open(dir).expect("opening the store");
    let at = |s: &str| Some(JmapTime::from_raw(s));

    let mut parent = Email {
        id: Id::from("msg-parent"),
        message_id: vec!["parent@x".into()],
        subject: "parent".into(),
        received_at: at("2026-07-01T00:00:00Z"),
        from: vec![Address {
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
        received_at: at("2026-07-02T00:00:00Z"),
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
            received_at: at("2026-07-03T00:00:00Z"),
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
            received_at: at("2026-07-04T12:00:00+09:00"),
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

#[test]
fn dispatch_matches_the_go_implementation() {
    let Some(bin) = require_helper() else { return };

    let go_dir = tempfile::tempdir().unwrap();
    let rust_dir = tempfile::tempdir().unwrap();
    let from_go = go_dispatch(&bin, go_dir.path());
    let from_rust = rust_dispatch(rust_dir.path());

    assert_eq!(
        from_go.len(),
        from_rust.len(),
        "both sides must answer every call"
    );

    // Compared call by call so a failure names the method that diverged
    // rather than dumping the whole script.
    for ((go, rust), call) in from_go.iter().zip(from_rust.iter()).zip(script()) {
        assert_eq!(go.method, rust.method);
        let go_result = go.result.as_ref().map(normalise);
        let rust_result = rust.result.as_ref().map(normalise);

        match call.divergence {
            None => {
                assert_eq!(go.error, rust.error, "{}: error differs", go.method);
                assert_eq!(go_result, rust_result, "{}: result differs", go.method);
            }
            Some(why) => assert_ne!(
                (go_result, &go.error),
                (rust_result, &rust.error),
                "{}: a divergence is declared here ({why}) but the two \
                 implementations agreed — the fix appears to have been lost",
                go.method
            ),
        }
    }
}
