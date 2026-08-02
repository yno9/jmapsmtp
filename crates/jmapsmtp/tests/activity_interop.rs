//! The activity log, against the oracle.
//!
//! The file is appended to by whichever implementation is running and read by
//! whichever starts next, so a line written by one must be readable by the
//! other. It is also exposed over the admin API, which is why the shape of a
//! line is a contract and not an internal detail.

use jmapserver::activity::{ActivityEvent, activity_log_path, append_activity, read_activity};

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

fn seed(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("data/a.test/alice")).unwrap();
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("ACTIVITY_INTEROP", config_json, seed)
}

fn event(peer: &str, bytes: i64) -> ActivityEvent {
    ActivityEvent {
        time: jmap_types::JmapTime::from_raw("2026-07-30T12:00:00Z"),
        dir: "out".into(),
        kind: "email".into(),
        // An address with characters Go's encoding/json escapes, so the byte
        // comparison below is sensitive to the escaping at all (SPEC.md §4).
        peer: format!("{peer}&co@x.test"),
        bytes,
        result: "ok".into(),
        note: "sent <1> message".into(),
        ..Default::default()
    }
}

/// The line this port writes, compared to what the oracle's admin API reads
/// back out of it.
#[test]
fn the_oracle_reads_the_lines_this_port_wrote() {
    let Some(o) = oracle() else { return };
    let data = o.data_dir();

    for i in 1..=3 {
        append_activity(&data, "a.test", "alice", &event(&format!("p{i}"), i)).unwrap();
    }

    let (status, body, _) = o.get("/admin/accounts/alice@a.test");
    assert_eq!(status, 200, "{body:?}");
    let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
    let activity = detail["activity"]
        .as_array()
        .unwrap_or_else(|| panic!("an activity array: {detail}"));

    assert_eq!(activity.len(), 3);
    assert_eq!(activity[0]["bytes"], 3);
    assert_eq!(activity[0]["result"], "ok");
    assert_eq!(
        activity[0]["note"], "sent <1> message",
        "the escaped characters decode back to what was written"
    );

    // Order, compared side by side rather than asserted against a literal.
    // Checking the oracle's output alone says nothing about this port's reader
    // — mutating it to return oldest-first left an earlier version of this
    // test green, because this port's `read_activity` was never called.
    let go_order: Vec<&str> = activity
        .iter()
        .map(|e| e["peer"].as_str().unwrap())
        .collect();
    let our_order: Vec<String> = read_activity(&data, "a.test", "alice", 0)
        .unwrap()
        .into_iter()
        .map(|e| e.peer)
        .collect();
    assert_eq!(
        go_order,
        our_order.iter().map(String::as_str).collect::<Vec<_>>(),
        "newest first on both sides"
    );
    assert_eq!(
        go_order[0], "p3&co@x.test",
        "and that order is newest-first"
    );

    // …and the limit takes the same end of the log on both sides.
    let (_, body, _) = o.get("/admin/accounts/alice@a.test?limit=2");
    let limited: serde_json::Value = serde_json::from_str(&body).unwrap();
    let go_limited: Vec<&str> = limited["activity"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["peer"].as_str().unwrap())
        .collect();
    let our_limited: Vec<String> = read_activity(&data, "a.test", "alice", 2)
        .unwrap()
        .into_iter()
        .map(|e| e.peer)
        .collect();
    assert_eq!(
        go_limited,
        our_limited.iter().map(String::as_str).collect::<Vec<_>>(),
        "a limit takes the newest, not the oldest, on both sides"
    );
}

/// The bytes on disk, compared directly. This file is a JSONL log both
/// implementations append to, so a difference in field order or escaping
/// accumulates line by line.
#[test]
fn a_line_is_byte_identical_between_implementations() {
    let Some(o) = oracle() else { return };
    let data = o.data_dir();

    // Drive the oracle into writing a line of its own, by sending a message
    // that fails: the delivery path logs the attempt either way.
    append_activity(&data, "a.test", "alice", &event("mine", 7)).unwrap();
    let ours = std::fs::read_to_string(activity_log_path(&data, "a.test", "alice")).unwrap();

    // The escaped form, not the literal one: finding a bare `&` here would
    // mean the escaping was *not* applied. Go writes \u0026 and \u003c
    // (SPEC.md §4), and this line is what the oracle parses back below.
    assert!(
        ours.contains(r"\u0026") && ours.contains(r"\u003c"),
        "the fixture must carry characters Go escapes, or this comparison \
         holds whether or not the escaping is reproduced: {ours}"
    );

    // Round-trip it through the oracle's reader and back through this port's,
    // so the line is proven parseable by both.
    let (_, body, _) = o.get("/admin/accounts/alice@a.test");
    let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
    let go_line = &detail["activity"][0];
    let ours_parsed = &read_activity(&data, "a.test", "alice", 0).unwrap()[0];

    assert_eq!(go_line["t"], ours_parsed.time.as_str());
    assert_eq!(go_line["peer"], ours_parsed.peer);
    assert_eq!(go_line["bytes"], ours_parsed.bytes);
    assert_eq!(go_line["note"], ours_parsed.note);
}

/// An account that has never had activity reports an empty list, not null. A
/// client doing `.length` on a null blanks the view — the same failure the Go
/// comment on `ListDeviceKeys` records from production.
#[test]
fn an_account_with_no_activity_reports_an_empty_list() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get("/admin/accounts/alice@a.test");
    assert_eq!(status, 200, "{body:?}");
    let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(detail["activity"], serde_json::json!([]), "not null");

    assert_eq!(
        read_activity(&o.data_dir(), "a.test", "alice", 0).unwrap(),
        Vec::new(),
        "this port agrees"
    );
}

/// The log holds metadata only. Asserted against a real account detail
/// response, since that is where an operator reads it.
#[test]
fn the_admin_view_of_the_log_carries_no_message_content() {
    let Some(o) = oracle() else { return };
    append_activity(&o.data_dir(), "a.test", "alice", &event("bob", 4096)).unwrap();

    let (_, body, _) = o.get("/admin/accounts/alice@a.test");
    let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
    let line = detail["activity"][0].as_object().expect("one line");

    let mut keys: Vec<&str> = line.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["bytes", "dir", "kind", "note", "peer", "result", "t"],
        "no field carrying a body or a subject reached the admin API"
    );
}
