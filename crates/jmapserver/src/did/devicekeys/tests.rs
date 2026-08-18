//! Device and session storage.
//!
//! The disk format is compared against the Go implementation in
//! `tests/devicekeys_interop.rs`; these cover the behaviour around it.

use super::*;
use pretty_assertions::assert_eq;

const NOW: i64 = 1_700_000_000;

fn key(id: &str) -> DeviceKey {
    DeviceKey {
        id: id.into(),
        label: "Laptop".into(),
        created_at: NOW,
    }
}

/// Never absent, even before `devices/` exists. A null reaches the client and
/// `null.length` throws, which blanked the Devices view in production.
#[test]
fn listing_an_account_with_no_devices_is_an_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(list_device_keys(dir.path()), Vec::new());
    let json = jmap_types::go_json::to_string(&list_device_keys(dir.path())).unwrap();
    assert_eq!(json, "[]", "must serialise as [], never null");
}

#[test]
fn a_written_device_is_listed_and_found() {
    let dir = tempfile::tempdir().unwrap();
    write_device_key(dir.path(), &key("AAA")).unwrap();
    assert_eq!(list_device_keys(dir.path()), vec![key("AAA")]);
    assert!(has_device_key(dir.path(), "AAA"));
    assert!(!has_device_key(dir.path(), "BBB"));
}

#[test]
fn devices_are_listed_in_a_stable_order() {
    let dir = tempfile::tempdir().unwrap();
    for id in ["CCC", "AAA", "BBB"] {
        write_device_key(dir.path(), &key(id)).unwrap();
    }
    let ids: Vec<String> = list_device_keys(dir.path())
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(ids, ["AAA", "BBB", "CCC"]);
}

#[test]
fn a_corrupt_device_file_is_skipped_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    write_device_key(dir.path(), &key("AAA")).unwrap();
    std::fs::write(dir.path().join("devices/broken.json"), b"{not json").unwrap();
    std::fs::write(dir.path().join("devices/ignored.txt"), b"x").unwrap();
    assert_eq!(list_device_keys(dir.path()).len(), 1);
}

// ── sessions ──────────────────────────────────────────────────────────────

#[test]
fn an_issued_token_authenticates_until_it_expires() {
    let dir = tempfile::tempdir().unwrap();
    let token = issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();

    assert_eq!(
        check_session_token(dir.path(), &token, NOW).as_deref(),
        Some("AAA")
    );
    assert_eq!(
        check_session_token(dir.path(), &token, NOW + 3600).as_deref(),
        Some("AAA"),
        "the expiry instant itself is still valid"
    );
    assert!(check_session_token(dir.path(), &token, NOW + 3601).is_none());
}

/// The token is never stored — only its hash. A stolen `data/` yields nothing
/// presentable.
#[test]
fn the_token_itself_is_not_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let token = issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();

    for entry in std::fs::read_dir(dir.path().join("sessions")).unwrap() {
        let path = entry.unwrap().path();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            !contents.contains(&token),
            "the token must not appear in {}",
            path.display()
        );
        // Nor in the filename, which is its hash.
        assert!(!path.to_string_lossy().contains(&token));
    }
}

#[test]
fn an_unknown_or_malformed_token_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();
    for token in ["", "not base64!!", "QUJDREVGRw=="] {
        assert!(
            check_session_token(dir.path(), token, NOW).is_none(),
            "{token}"
        );
    }
}

#[test]
fn two_tokens_for_one_device_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let a = issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();
    let b = issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();
    assert_ne!(a, b, "each issue mints fresh randomness");
    assert!(check_session_token(dir.path(), &a, NOW).is_some());
    assert!(check_session_token(dir.path(), &b, NOW).is_some());
}

/// Revoking one device must not touch another's sessions.
#[test]
fn revoking_one_device_leaves_the_others_alone() {
    let dir = tempfile::tempdir().unwrap();
    write_device_key(dir.path(), &key("AAA")).unwrap();
    write_device_key(dir.path(), &key("BBB")).unwrap();
    let a = issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();
    let b = issue_session_token(dir.path(), "BBB", 3600, NOW).unwrap();

    remove_device_key(dir.path(), "AAA").unwrap();
    assert!(check_session_token(dir.path(), &a, NOW).is_none());
    assert!(
        check_session_token(dir.path(), &b, NOW).is_some(),
        "the other device keeps working"
    );
    assert_eq!(list_device_keys(dir.path()).len(), 1);
}

#[test]
fn revoking_a_device_that_was_never_there_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    remove_device_key(dir.path(), "nobody").expect("must not fail");
}

#[cfg(unix)]
#[test]
fn neither_devices_nor_sessions_are_world_readable() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    write_device_key(dir.path(), &key("AAA")).unwrap();
    issue_session_token(dir.path(), "AAA", 3600, NOW).unwrap();

    for sub in ["devices", "sessions"] {
        for entry in std::fs::read_dir(dir.path().join(sub)).unwrap() {
            let path = entry.unwrap().path();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{}", path.display());
        }
    }
}
