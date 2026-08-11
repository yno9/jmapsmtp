//! The activity log.
//!
//! The first test is the one that matters: this file is exposed over the admin
//! API, so what it *cannot* contain is the property being protected.

use super::*;
use pretty_assertions::assert_eq;

fn event(dir: &str, peer: &str, bytes: i64, result: &str) -> ActivityEvent {
    ActivityEvent {
        time: jmap_types::JmapTime::from_raw("2026-07-30T12:00:00Z"),
        dir: dir.into(),
        kind: "email".into(),
        peer: peer.into(),
        bytes,
        result: result.into(),
        ..Default::default()
    }
}

fn account() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("a.test/alice")).unwrap();
    tmp
}

// ── what a line may contain ───────────────────────────────────────────────

/// Metadata only. The log is readable by the operator through the admin API,
/// so an event carries who and how much and whether it worked — never what was
/// said.
#[test]
fn an_event_records_metadata_and_has_nowhere_to_put_a_body() {
    let json = jmap_types::go_json::to_string(&event("out", "bob@x.test", 4096, "ok")).unwrap();
    assert_eq!(
        json,
        r#"{"t":"2026-07-30T12:00:00Z","dir":"out","kind":"email","peer":"bob@x.test","bytes":4096,"result":"ok"}"#,
        "declaration order, and nothing empty"
    );

    // The complete line with every field populated, so adding one is a
    // deliberate act rather than something that slips in beside a subject.
    //
    // Compared as a string rather than through `serde_json::Value`: that maps
    // to a BTreeMap, so parsing and re-reading the keys sorts them and the
    // declaration order this pins would be invisible.
    assert_eq!(
        jmap_types::go_json::to_string(&ActivityEvent {
            note: "n".into(),
            msgid: "m".into(),
            ..event("in", "p", 1, "ok")
        })
        .unwrap(),
        r#"{"t":"2026-07-30T12:00:00Z","dir":"in","kind":"email","peer":"p","msgid":"m","bytes":1,"result":"ok","note":"n"}"#,
        "eight fields, none of them a body or a subject"
    );
}

/// The optional fields are omitted rather than written empty, so a line stays
/// short and a reader can tell "not recorded" from "recorded as empty".
#[test]
fn empty_optional_fields_are_omitted() {
    let json = jmap_types::go_json::to_string(&ActivityEvent {
        time: jmap_types::JmapTime::from_raw("2026-07-30T12:00:00Z"),
        dir: "in".into(),
        kind: "email".into(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        json,
        r#"{"t":"2026-07-30T12:00:00Z","dir":"in","kind":"email"}"#
    );
}

// ── appending and reading ─────────────────────────────────────────────────

#[test]
fn events_come_back_newest_first() {
    let tmp = account();
    for i in 1..=3 {
        append_activity(
            tmp.path(),
            "a.test",
            "alice",
            &event("out", &format!("p{i}@x.test"), i, "ok"),
        )
        .unwrap();
    }
    let events = read_activity(tmp.path(), "a.test", "alice", 0).unwrap();
    assert_eq!(
        events.iter().map(|e| e.peer.as_str()).collect::<Vec<_>>(),
        ["p3@x.test", "p2@x.test", "p1@x.test"],
        "newest first, though the file is newest last"
    );
}

#[test]
fn the_limit_takes_the_newest_and_defaults_to_a_hundred() {
    let tmp = account();
    for i in 1..=5 {
        append_activity(
            tmp.path(),
            "a.test",
            "alice",
            &event("out", &format!("p{i}"), i, "ok"),
        )
        .unwrap();
    }
    let two = read_activity(tmp.path(), "a.test", "alice", 2).unwrap();
    assert_eq!(
        two.iter().map(|e| e.peer.as_str()).collect::<Vec<_>>(),
        ["p5", "p4"],
        "the newest two, not the oldest"
    );
    assert_eq!(
        read_activity(tmp.path(), "a.test", "alice", 0)
            .unwrap()
            .len(),
        5
    );
    assert_eq!(DEFAULT_LIMIT, 100);
}

/// An account that has simply never had activity is not a failure.
#[test]
fn a_missing_log_reads_as_empty() {
    let tmp = account();
    assert_eq!(
        read_activity(tmp.path(), "a.test", "alice", 0).unwrap(),
        Vec::new()
    );
    assert_eq!(
        read_activity(tmp.path(), "a.test", "nobody", 0).unwrap(),
        Vec::new()
    );
}

/// The log is appended to from more than one code path, so a torn write must
/// not make the rest unreadable.
#[test]
fn an_unparseable_line_is_skipped_rather_than_failing_the_read() {
    let tmp = account();
    append_activity(
        tmp.path(),
        "a.test",
        "alice",
        &event("in", "good1", 1, "ok"),
    )
    .unwrap();

    let path = activity_log_path(tmp.path(), "a.test", "alice");
    let mut contents = std::fs::read_to_string(&path).unwrap();
    contents.push_str("{\"t\":\"truncated\n");
    contents.push_str("\n   \n");
    contents.push_str("not json at all\n");
    std::fs::write(&path, contents).unwrap();

    append_activity(
        tmp.path(),
        "a.test",
        "alice",
        &event("in", "good2", 2, "ok"),
    )
    .unwrap();

    let events = read_activity(tmp.path(), "a.test", "alice", 0).unwrap();
    assert_eq!(
        events.iter().map(|e| e.peer.as_str()).collect::<Vec<_>>(),
        ["good2", "good1"],
        "the good lines survive on both sides of the damage"
    );
}

#[test]
fn the_log_is_written_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = account();
        append_activity(tmp.path(), "a.test", "alice", &event("in", "p", 1, "ok")).unwrap();
        let mode = std::fs::metadata(activity_log_path(tmp.path(), "a.test", "alice"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "it names who wrote to whom");
    }
}

/// Best-effort: a missing account directory is an error the caller swallows,
/// not a panic and not a partially written file.
#[test]
fn appending_to_a_missing_account_fails_without_creating_anything() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(append_activity(tmp.path(), "a.test", "nobody", &event("in", "p", 1, "ok")).is_err());
    assert!(!tmp.path().join("a.test").exists(), "nothing was created");
}

// ── rotation ──────────────────────────────────────────────────────────────

/// One generation, so the log is **bounded rather than archived**. An
/// unbounded per-account audit log is a way to fill a disk from outside.
#[test]
fn the_log_rotates_once_past_its_cap_and_keeps_one_generation() {
    let tmp = account();
    let path = activity_log_path(tmp.path(), "a.test", "alice");
    let rotated = path.with_extension("log.1");

    // Just past the cap.
    std::fs::write(&path, vec![b'\n'; ACTIVITY_ROTATE_BYTES as usize]).unwrap();
    append_activity(
        tmp.path(),
        "a.test",
        "alice",
        &event("in", "after-first", 1, "ok"),
    )
    .unwrap();

    assert!(rotated.exists(), "the old log was kept as one generation");
    let events = read_activity(tmp.path(), "a.test", "alice", 0).unwrap();
    assert_eq!(
        events.iter().map(|e| e.peer.as_str()).collect::<Vec<_>>(),
        ["after-first"],
        "the live log starts fresh"
    );

    // A second rotation overwrites the generation rather than accumulating.
    std::fs::write(&path, vec![b'\n'; ACTIVITY_ROTATE_BYTES as usize]).unwrap();
    append_activity(
        tmp.path(),
        "a.test",
        "alice",
        &event("in", "after-second", 1, "ok"),
    )
    .unwrap();
    assert!(
        !path.with_extension("log.2").exists(),
        "there is exactly one generation, not a growing archive"
    );
}

#[test]
fn a_log_under_the_cap_is_not_rotated() {
    let tmp = account();
    let path = activity_log_path(tmp.path(), "a.test", "alice");
    std::fs::write(&path, vec![b'\n'; (ACTIVITY_ROTATE_BYTES - 1) as usize]).unwrap();
    append_activity(tmp.path(), "a.test", "alice", &event("in", "p", 1, "ok")).unwrap();
    assert!(!path.with_extension("log.1").exists());
}

/// The bound is what it is because the file is per account and appended to by
/// remote activity — 2 MiB times the account count is the worst case an
/// operator has to plan for.
#[test]
fn the_cap_is_two_mebibytes() {
    assert_eq!(ACTIVITY_ROTATE_BYTES, 2 * 1024 * 1024);
}
