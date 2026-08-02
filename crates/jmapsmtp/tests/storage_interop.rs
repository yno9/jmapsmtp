//! The storage-transparency endpoints, against the oracle.
//!
//! `POST /account/storage/purge-messages` is the one route in this family that
//! deletes, so the test that matters is not that it removes messages — it is
//! that it removes *nothing else*. The account directory is captured before and
//! after and the difference is compared to the expected one, so a purge that
//! widened its reach fails here rather than in production.

use base64::Engine as _;
use jmapserver::storage::{
    PURGE_MUST_NOT_TOUCH, export_account_storage, list_account_storage, list_message_files,
    storage_summary,
};

mod oracle_harness;
use oracle_harness::Oracle;

const AUTH_TOKEN: &[u8] = b"storage-interop-token-0000000000";

fn basic_auth(account: &str) -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("{account}:{password}"))
}

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}},"bob":{{}}}}}}}}}}"#
    )
}

/// An account holding one of each thing a purge must not touch, plus messages.
fn seed(root: &std::path::Path) {
    for lp in ["alice", "bob"] {
        let acct = root.join("data/a.test").join(lp);
        std::fs::create_dir_all(acct.join("messages")).unwrap();
        std::fs::create_dir_all(acct.join("devices")).unwrap();
        std::fs::write(
            acct.join("auth_token_hash"),
            jmapserver::hash_auth_token(AUTH_TOKEN),
        )
        .unwrap();
        std::fs::write(acct.join("envelope.json"), b"{}").unwrap();
        std::fs::write(acct.join("privkey.enc"), b"opaque").unwrap();
        std::fs::write(acct.join("devices/KEY.json"), b"{}").unwrap();
        std::fs::write(acct.join("messages/msg-1.json"), br#"{"id":"msg-1"}"#).unwrap();
        std::fs::write(acct.join("messages/msg-2.json"), br#"{"id":"msg-2"}"#).unwrap();
        // A directory inside messages/, so "how many messages" is not the same
        // number as "how many entries". Both implementations must skip it.
        std::fs::create_dir_all(acct.join("messages/stray")).unwrap();
        std::fs::write(acct.join("messages/stray/inner.json"), b"{}").unwrap();
    }
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("STORAGE_INTEROP", config_json, seed)
}

/// Every file under an account directory, relative and sorted.
fn files_under(acct: &std::path::Path) -> Vec<String> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if e.path().is_dir() {
                walk(base, &e.path(), out);
            } else {
                out.push(
                    e.path()
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    let mut out = Vec::new();
    walk(acct, acct, &mut out);
    out.sort();
    out
}

// ── the listing ───────────────────────────────────────────────────────────

#[test]
fn the_listing_matches_what_this_port_computes() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get_auth("/account/storage", &basic_auth("alice@a.test"));
    assert_eq!(status, 200, "{body:?}");

    let ours =
        storage_summary(list_account_storage(&o.data_dir(), "a.test", "alice").expect("readable"));
    let go: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        go["totalSizeBytes"], ours.total_size_bytes,
        "totals disagree: {go}"
    );
    // Compared as sets: the Go listing's order is ReadDir's, and this port
    // sorts. Both are stable; only the names and sizes are the contract.
    let mut go_entries: Vec<serde_json::Value> = go["entries"].as_array().unwrap().clone();
    go_entries.sort_by_key(|e| e["name"].as_str().unwrap_or_default().to_string());
    assert_eq!(
        go_entries,
        serde_json::to_value(&ours.entries)
            .unwrap()
            .as_array()
            .unwrap()
            .clone(),
        "entries disagree"
    );

    // Specifically: the directory inside messages/ is neither counted nor
    // sized, on either side.
    let messages = go_entries
        .iter()
        .find(|e| e["name"] == "messages")
        .expect("a messages entry");
    assert_eq!(messages["count"], 2, "two files, not three: {messages}");
}

#[test]
fn the_drill_down_matches() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get_auth("/account/storage/messages", &basic_auth("alice@a.test"));
    assert_eq!(status, 200, "{body:?}");

    let ours = list_message_files(&o.data_dir(), "a.test", "alice").unwrap();
    let go: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut names: Vec<&str> = go["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ours.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
    );
}

/// The target comes from the credential, never from the request, so one
/// account's listing can never be another's.
#[test]
fn the_listing_is_scoped_to_the_credential() {
    let Some(o) = oracle() else { return };
    let (status, _, _) = o.get("/account/storage");
    assert_eq!(status, 401, "unauthenticated");

    // Even asking with a query naming someone else returns the caller's own.
    let (_, body, _) = o.get_auth(
        "/account/storage?email=bob@a.test",
        &basic_auth("alice@a.test"),
    );
    let ours = storage_summary(list_account_storage(&o.data_dir(), "a.test", "alice").unwrap());
    let go: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        go["totalSizeBytes"], ours.total_size_bytes,
        "the email in the query must be ignored"
    );
}

// ── the export ────────────────────────────────────────────────────────────

/// Every file exactly as stored, including inside `devices/` — which the
/// one-level listing deliberately does not report.
#[test]
fn the_export_carries_the_same_files_this_port_would() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get_auth("/account/storage/export", &basic_auth("alice@a.test"));
    assert_eq!(status, 200, "{body:?}");

    let go: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(go["email"], "alice@a.test");

    let mut go_paths: Vec<&str> = go["files"]
        .as_object()
        .expect("files is an object")
        .keys()
        .map(String::as_str)
        .collect();
    go_paths.sort_unstable();

    let ours = export_account_storage(&o.data_dir(), "a.test", "alice");
    assert_eq!(
        go_paths,
        ours.keys().map(String::as_str).collect::<Vec<_>>()
    );
    assert!(
        go_paths.contains(&"devices/KEY.json"),
        "nested files are included: {go_paths:?}"
    );
    assert!(
        go_paths.contains(&"messages/stray/inner.json"),
        "…at any depth: {go_paths:?}"
    );

    // …and the bytes match, decoded.
    for (path, bytes) in &ours {
        let encoded = go["files"][path].as_str().expect(path);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        assert_eq!(&decoded, bytes, "{path}");
    }
}

// ── the purge ─────────────────────────────────────────────────────────────

/// The test this module exists for. A purge clears `messages/` and **nothing
/// else** — every other file in the account either holds a credential with no
/// second copy, or is the account's only mailbox.
#[test]
fn a_purge_removes_messages_and_leaves_everything_else_untouched() {
    let Some(o) = oracle() else { return };
    let acct = o.data_dir().join("a.test/alice");

    let before = files_under(&acct);
    assert!(before.contains(&"messages/msg-1.json".to_string()));

    let (status, body) = o.post_json_auth(
        "/account/storage/purge-messages",
        "",
        &basic_auth("alice@a.test"),
    );
    assert_eq!(status, 200, "{body:?}");
    let purged: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(purged["purged"], 2);

    let after = files_under(&acct);
    let removed: Vec<&String> = before.iter().filter(|f| !after.contains(f)).collect();
    assert_eq!(
        removed,
        ["messages/msg-1.json", "messages/msg-2.json"],
        "a purge removed something other than messages"
    );
    // Not recursive: `messages/stray/inner.json` survives. Consistent with the
    // listing, which does not count it as a message either — a purge that
    // reached deeper would delete bytes it never told the user it had.
    assert!(
        acct.join("messages/stray/inner.json").exists(),
        "a purge clears messages, not everything under messages/"
    );

    // Stated the other way round too, so a purge that widened its reach names
    // the file it should not have touched.
    for name in PURGE_MUST_NOT_TOUCH {
        let path = acct.join(name);
        if before.iter().any(|f| f.starts_with(name)) {
            assert!(path.exists(), "{name} was removed by a purge");
        }
    }
    assert!(
        acct.join("auth_token_hash").exists() && acct.join("envelope.json").exists(),
        "the account must still be able to log in and unwrap its secret"
    );
}

/// One account's purge never reaches another's messages.
#[test]
fn a_purge_is_scoped_to_the_credential() {
    let Some(o) = oracle() else { return };
    let bob = o.data_dir().join("a.test/bob");
    let before = files_under(&bob);

    o.post_json_auth(
        "/account/storage/purge-messages",
        r#"{"email":"bob@a.test"}"#,
        &basic_auth("alice@a.test"),
    );

    assert_eq!(
        files_under(&bob),
        before,
        "an email in the body must not redirect the purge"
    );
}

#[test]
fn a_purge_without_a_credential_removes_nothing() {
    let Some(o) = oracle() else { return };
    let acct = o.data_dir().join("a.test/alice");
    let before = files_under(&acct);

    let (status, _) = o.post_json("/account/storage/purge-messages", "");
    assert_eq!(status, 401);
    assert_eq!(files_under(&acct), before);
}
